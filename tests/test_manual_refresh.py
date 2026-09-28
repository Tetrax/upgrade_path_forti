"""On-demand collection relaunch: /api/cert/data-refresh and the lock behind it.

The home page's relaunch button must run exactly the scheduled full pass
(scripts/scheduled_refresh.py's full run) under the same cross-process collection lock the
scheduler container and the systemd timers use, answer 202/409 instead of waiting for a scan, and
never report success before that pass really returned.

The HTTP tests run the real server from a throwaway copy of the tree (never the checkout's own
data/ or docs/) with the collectors replaced through the same inert FORTIOS_E2E_MOCK_NETWORK gate
the browser suite uses: no real scan, no network call, no email.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import cert_admin  # type: ignore[import-not-found]
import fortios_watch as fw  # type: ignore[import-not-found]
import scheduled_refresh  # type: ignore[import-not-found]

ADMIN_USERNAME = "valentin"
ADMIN_PASSWORD = "mot-de-passe-solide"

# A child process that takes the *scheduled* collection lock and holds it, exactly like the
# scheduler container or a systemd timer would while collecting.
LOCK_HOLDER_SCRIPT = """\
import sys
import time
from pathlib import Path

sys.path.insert(0, sys.argv[1])
import scheduled_refresh

with scheduled_refresh.refresh_lock(Path(sys.argv[2])):
    print("locked", flush=True)
    time.sleep(float(sys.argv[3]))
"""

SCHEDULED_FULL_COMMAND = [
    "scripts/import_forticlient_compat.py",
    "--commit",
]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _Completed:
    def __init__(self, returncode: int) -> None:
        self.returncode = returncode


class _RecordingRunner:
    """Stands in for subprocess.run: records the argv of every phase, returns a fixed status.

    The compatibility phase is the one scheduled_refresh.py double-checks afterwards ("exited
    without finalizing health"): the real importer finalizes its own health record, so the fake
    one does too, otherwise a successful fake run would still be reported as a failed pass.
    """

    def __init__(self, *, root: Path, returncode: int = 0) -> None:
        self.root = root
        self.returncode = returncode
        self.commands: list[list[str]] = []

    def __call__(self, command, *, cwd=None, check=False):
        self.commands.append(list(command))
        if any(str(part).endswith("import_forticlient_compat.py") for part in command):
            health_path = self.root / fw.DEFAULT_HEALTH_PATH
            started_at = fw.health_mark_running(health_path, fw.SOURCE_COMPAT_MATRIX)
            fw.record_health_results(
                health_path,
                {
                    fw.SOURCE_COMPAT_MATRIX: fw.HealthSourceResult(
                        status=fw.HEALTH_STATUS_OK,
                        started_at=started_at,
                        duration_seconds=0.0,
                    )
                },
            )
        return _Completed(self.returncode)


class ApiClient:
    """Cookie-aware JSON client for the isolated server under test."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict]:
        request_headers = dict(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        request_headers.setdefault("Origin", self.base_url)
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            method=method,
            headers=request_headers,
        )
        try:
            response = self.opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = {"raw": raw.decode("utf-8", "replace")}
        return response.status, payload

    def login(self) -> str:
        status, payload = self.request(
            "POST",
            "/api/cert/login",
            body={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        )
        assert status == 200, payload
        return payload["csrfToken"]


class CopiedTreeServer:
    """A real fortios_server.py running from a temp copy of the app tree."""

    def __init__(self, tree: Path, process: subprocess.Popen, port: int) -> None:
        self.tree = tree
        self.process = process
        self.port = port

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def root(self) -> Path:
        return self.tree

    @property
    def data_dir(self) -> Path:
        return self.tree / "data"

    @property
    def state_path(self) -> Path:
        return self.data_dir / "fortios-manual-refresh.json"

    @property
    def health_path(self) -> Path:
        return self.data_dir / "fortios-health.json"

    @property
    def hold_path(self) -> Path:
        return self.tree / "e2e-refresh-hold"

    @property
    def command_log(self) -> Path:
        return self.tree / "e2e-refresh-commands.jsonl"

    def logged_commands(self) -> list[list[str]]:
        if not self.command_log.exists():
            return []
        return [
            json.loads(line)["command"]
            for line in self.command_log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        if self.process.stdout:
            self.process.stdout.close()


def build_tree_copy(destination: Path) -> Path:
    """Copy the served tree (app/, scripts/, a minimal data/) into `destination`.

    The generated catalog is deliberately not copied: these tests exercise the relaunch API, not
    the catalog, and the copy must stay small. Same for advisory images and lock leftovers.
    """
    for name in ("app", "scripts"):
        shutil.copytree(ROOT / name, destination / name)
    data_dir = destination / "data"
    data_dir.mkdir()
    shutil.copy(
        ROOT / "data" / "fortios-data.sample.json",
        data_dir / "fortios-data.sample.json",
    )
    (destination / "docs").mkdir()
    return destination


def start_server(tree: Path) -> CopiedTreeServer:
    credentials = tree / "admin" / "credentials.json"
    cert_admin.write_credentials(
        credentials,
        cert_admin.credential_payload(ADMIN_USERNAME, ADMIN_PASSWORD),
    )
    port = free_port()
    env = dict(os.environ)
    # A real SMTP/Microsoft 365 configuration leaking from the host environment into a test run
    # would be surprising, and nothing here needs it.
    for key in list(env):
        if key.startswith(("FORTIOS_SMTP_", "FORTIOS_MICROSOFT365_")) or key in {
            "FORTIOS_EMAIL_ENABLED",
            "FORTIOS_EMAIL_TRANSPORT",
        }:
            env.pop(key, None)
    # FORTIOS_TEST_DATA_DIR is deliberately left unset: the copy's own data/ is the data dir, so
    # the relaunch writes into the copy exactly like production writes into the deployed tree.
    env.pop("FORTIOS_TEST_DATA_DIR", None)
    env.update(
        {
            "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
            "FORTIOS_E2E_MOCK_NETWORK": "1",
            "FORTIOS_E2E_REFRESH_HOLD_FILE": str(tree / "e2e-refresh-hold"),
            "FORTIOS_E2E_REFRESH_COMMAND_LOG": str(tree / "e2e-refresh-commands.jsonl"),
        }
    )
    process = subprocess.Popen(
        [
            sys.executable,
            str(tree / "scripts" / "fortios_server.py"),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=tree,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            raise AssertionError(f"fortios_server.py exited early:\n{output}")
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/index.html", timeout=1
            ):
                return CopiedTreeServer(tree, process, port)
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            time.sleep(0.1)
    process.kill()
    raise AssertionError("fortios_server.py never became ready")


@contextmanager
def running_copied_server():
    with tempfile.TemporaryDirectory() as tmp:
        tree = build_tree_copy(Path(tmp) / "fortios")
        server = start_server(tree)
        try:
            yield server
        finally:
            server.stop()


def wait_for_state(
    client: ApiClient, server: CopiedTreeServer, expected: str, timeout: float = 20
) -> dict:
    deadline = time.monotonic() + timeout
    payload: dict = {}
    while time.monotonic() < deadline:
        status, payload = client.request("GET", "/api/cert/data-refresh")
        if status == 200 and payload.get("state") == expected:
            return payload
        time.sleep(0.05)
    raise AssertionError(
        f"state never reached {expected!r} (last: {payload}); "
        f"state file: {server.state_path.read_text(encoding='utf-8') if server.state_path.exists() else 'absent'}"
    )


@contextmanager
def external_lock_holder(root: Path, hold_seconds: float = 30):
    """Hold the scheduled collection lock from a *separate process* (as the scheduler does)."""
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / "hold_lock.py"
        script.write_text(LOCK_HOLDER_SCRIPT, encoding="utf-8")
        process = subprocess.Popen(
            [sys.executable, str(script), str(SCRIPTS), str(root), str(hold_seconds)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            assert process.stdout is not None
            line = process.stdout.readline().strip()
            if line != "locked":
                raise AssertionError(f"lock holder failed to start: {line!r}")
            yield
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            if process.stdout:
                process.stdout.close()


class CollectionLockTests(unittest.TestCase):
    """The relaunch takes the very same lock as the scheduled runs — and never waits for it."""

    def test_second_manual_lock_is_refused_until_released(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = scheduled_refresh.acquire_refresh_lock(root)
            try:
                with self.assertRaises(scheduled_refresh.RefreshLockBusy):
                    scheduled_refresh.acquire_refresh_lock(root)
            finally:
                first.release()

            second = scheduled_refresh.acquire_refresh_lock(root)
            second.release()
            self.assertFalse(second.held)

    def test_lock_is_shared_with_the_scheduled_runner_across_processes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with external_lock_holder(root), self.assertRaises(
                scheduled_refresh.RefreshLockBusy
            ):
                scheduled_refresh.acquire_refresh_lock(root)
            # Released: the relaunch can take it again.
            scheduled_refresh.acquire_refresh_lock(root).release()

    def test_released_lock_refuses_to_run_the_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock = scheduled_refresh.acquire_refresh_lock(root)
            lock.release()
            with self.assertRaises(RuntimeError):
                lock.run_full_refresh(root=root, runner=_RecordingRunner(root=root))


class ManualFullPassTests(unittest.TestCase):
    """The relaunch runs exactly the scheduled full pass, and marks it like one."""

    def test_reuses_the_scheduled_full_command_and_writes_the_attempt_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner = _RecordingRunner(root=root)
            lock = scheduled_refresh.acquire_refresh_lock(root)
            try:
                status = lock.run_full_refresh(
                    root=root,
                    runner=runner,
                    python="python3",
                    compatibility_python="compat-python",
                )
            finally:
                lock.release()

            self.assertEqual(status, 0)
            self.assertEqual(
                runner.commands,
                [
                    ["compat-python", *SCHEDULED_FULL_COMMAND],
                    [
                        "python3",
                        "scripts/fortios_watch.py",
                        "--base",
                        "data/fortios-data.generated.json",
                        "--docs-catalog",
                        "--tool-products",
                        "fortianalyzer,fortimanager",
                        "--forticlient-catalog",
                        "--cve-catalog",
                    ],
                ],
            )
            marker = json.loads(
                (root / "data" / "fortios-full-refresh-attempt.lock").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(marker["status"], 0)
            self.assertTrue(marker["parisDate"])
            # The lock is free again: a relaunch never leaves a collection running behind it.
            scheduled_refresh.acquire_refresh_lock(root).release()

    def test_failing_pass_returns_a_nonzero_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner = _RecordingRunner(root=root, returncode=1)
            lock = scheduled_refresh.acquire_refresh_lock(root)
            try:
                status = lock.run_full_refresh(
                    root=root, runner=runner, python="python3"
                )
            finally:
                lock.release()
            self.assertEqual(status, 1)


class DataRefreshEndpointTests(unittest.TestCase):
    def test_anonymous_get_and_post_start_nothing(self) -> None:
        with running_copied_server() as server:
            client = ApiClient(server.base_url)

            read_status, read_payload = client.request(
                "GET", "/api/cert/data-refresh"
            )
            post_status, post_payload = client.request(
                "POST", "/api/cert/data-refresh", body={}
            )

            self.assertEqual(read_status, 401)
            self.assertEqual(post_status, 401)
            self.assertIn("Session administrateur", read_payload["error"])
            self.assertIn("Session administrateur", post_payload["error"])
            self.assertFalse(server.state_path.exists())
            self.assertFalse(server.command_log.exists())

    def test_cross_origin_and_missing_csrf_are_refused(self) -> None:
        with running_copied_server() as server:
            client = ApiClient(server.base_url)
            csrf_token = client.login()

            foreign_status, _ = client.request(
                "POST",
                "/api/cert/data-refresh",
                body={},
                headers={
                    "Origin": "https://evil.example",
                    "X-CSRF-Token": csrf_token,
                },
            )
            no_csrf_status, no_csrf_payload = client.request(
                "POST", "/api/cert/data-refresh", body={}
            )

            self.assertEqual(foreign_status, 403)
            self.assertEqual(no_csrf_status, 403)
            self.assertIn("CSRF", no_csrf_payload["error"])
            self.assertFalse(server.state_path.exists())
            self.assertFalse(server.command_log.exists())

    def test_authenticated_state_is_idle_before_any_relaunch(self) -> None:
        with running_copied_server() as server:
            client = ApiClient(server.base_url)
            client.login()

            status, payload = client.request("GET", "/api/cert/data-refresh")

            self.assertEqual(status, 200)
            self.assertEqual(payload["state"], "idle")
            self.assertIsNone(payload["startedAt"])
            self.assertFalse(server.state_path.exists())

    def test_one_run_at_a_time_success_only_after_the_real_end(self) -> None:
        with running_copied_server() as server:
            client = ApiClient(server.base_url)
            csrf_token = client.login()
            headers = {"X-CSRF-Token": csrf_token}

            started_status, started = client.request(
                "POST", "/api/cert/data-refresh", body={}, headers=headers
            )
            self.assertEqual(started_status, 202)
            self.assertEqual(started["state"], "running")

            # A second trigger while the first run still holds the collection lock is refused —
            # with the current state, not with a queued second scan.
            duplicate_status, duplicate = client.request(
                "POST", "/api/cert/data-refresh", body={}, headers=headers
            )
            self.assertEqual(duplicate_status, 409)
            self.assertEqual(duplicate["state"], "running")

            read_status, running = client.request("GET", "/api/cert/data-refresh")
            self.assertEqual(read_status, 200)
            self.assertEqual(running["state"], "running")
            self.assertIsNone(running["finishedAt"])

            # The state file is served to the admin API only, never as a static /data/ file.
            with self.assertRaises(urllib.error.HTTPError) as refused:
                urllib.request.urlopen(
                    f"{server.base_url}/data/fortios-manual-refresh.json", timeout=5
                )
            self.assertEqual(refused.exception.code, 404)

            server.hold_path.write_text("0", encoding="utf-8")
            finished = wait_for_state(client, server, "success")
            self.assertEqual(finished["status"], 0)
            self.assertIsNotNone(finished["finishedAt"])

            # Exactly one pass ran: the compatibility importer then the full catalog command,
            # word for word the scheduled ones — no second scan was queued behind the first.
            # (Element 0 of each entry is the interpreter the runner was given.)
            self.assertEqual(
                [command[1:] for command in server.logged_commands()],
                [
                    ["scripts/import_forticlient_compat.py", "--commit"],
                    [
                        "scripts/fortios_watch.py",
                        "--base",
                        "data/fortios-data.generated.json",
                        "--docs-catalog",
                        "--tool-products",
                        "fortianalyzer,fortimanager",
                        "--forticlient-catalog",
                        "--cve-catalog",
                    ],
                ],
            )
            health = json.loads(server.health_path.read_text(encoding="utf-8"))
            self.assertEqual(health["sources"]["daily-run"]["status"], "ok")

            # The lock is free again, and the whole flow can be started again.
            restarted_status, restarted = client.request(
                "POST", "/api/cert/data-refresh", body={}, headers=headers
            )
            self.assertEqual(restarted_status, 202)
            self.assertEqual(restarted["state"], "running")
            server.hold_path.write_text("0", encoding="utf-8")
            wait_for_state(client, server, "success")

    def test_failing_pass_is_reported_as_an_error(self) -> None:
        with running_copied_server() as server:
            client = ApiClient(server.base_url)
            csrf_token = client.login()
            server.hold_path.write_text("1", encoding="utf-8")

            status, _ = client.request(
                "POST", "/api/cert/data-refresh", body={}, headers={"X-CSRF-Token": csrf_token}
            )
            self.assertEqual(status, 202)

            finished = wait_for_state(client, server, "error")
            self.assertEqual(finished["status"], 1)

    def test_scheduled_collection_holding_the_lock_refuses_the_relaunch(self) -> None:
        with running_copied_server() as server:
            client = ApiClient(server.base_url)
            csrf_token = client.login()

            with external_lock_holder(server.root):
                status, payload = client.request(
                    "POST",
                    "/api/cert/data-refresh",
                    body={},
                    headers={"X-CSRF-Token": csrf_token},
                )

            self.assertEqual(status, 409)
            self.assertIn("collecte", payload["message"].lower())
            self.assertFalse(server.command_log.exists())

    def test_restart_during_a_run_is_reported_as_interrupted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tree = build_tree_copy(Path(tmp) / "fortios")
            first = start_server(tree)
            try:
                client = ApiClient(first.base_url)
                csrf_token = client.login()
                status, _ = client.request(
                    "POST",
                    "/api/cert/data-refresh",
                    body={},
                    headers={"X-CSRF-Token": csrf_token},
                )
                self.assertEqual(status, 202)
                self.assertEqual(
                    json.loads(first.state_path.read_text(encoding="utf-8"))["state"],
                    "running",
                )
            finally:
                # Killed mid-collection: the collector subprocesses go with the web process.
                first.stop()

            second = start_server(tree)
            try:
                client = ApiClient(second.base_url)
                client.login()
                read_status, payload = client.request("GET", "/api/cert/data-refresh")
                self.assertEqual(read_status, 200)
                self.assertEqual(payload["state"], "interrupted")
                self.assertIsNone(payload["finishedAt"])
            finally:
                second.stop()


if __name__ == "__main__":
    unittest.main()
