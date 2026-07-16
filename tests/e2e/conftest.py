"""Shared fixtures for the Playwright E2E suite.

Every test gets a fresh, fully isolated instance of scripts/fortios_server.py: its own temp data
directory (never the real data/fortios-data.generated.json or advisory-images/), its own free
port, and Fortinet calls replaced by a deterministic mock (see FORTIOS_E2E_MOCK_NETWORK in
scripts/fortios_server.py) — no real network call ever leaves this process. The server is a real
subprocess, torn down after every test even on failure, so nothing lingers between tests or in
the repo afterward.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
SERVER_STARTUP_TIMEOUT_SECONDS = 15


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_until_ready(base_url: str, process: subprocess.Popen, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            raise RuntimeError(f"fortios_server.py exited early (code {process.returncode}):\n{output}")
        try:
            with urllib.request.urlopen(f"{base_url}/app/index.html", timeout=1) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, ConnectionError, TimeoutError) as error:
            last_error = error
        time.sleep(0.1)
    raise TimeoutError(f"fortios_server.py never became ready on {base_url}: {last_error}")


@dataclass
class FortiosTestServer:
    base_url: str
    data_dir: Path
    mock_response_path: Path
    process: subprocess.Popen

    def set_mock_path_response(self, hops: list[str]) -> None:
        """Next official-path request(s) will simulate a successful Fortinet fetch returning
        exactly these hops."""
        self.mock_response_path.write_text(json.dumps({"hops": hops}))

    def set_mock_path_error(self, message: str = "Simulated Fortinet outage") -> None:
        """Next official-path request(s) will simulate Fortinet being unreachable."""
        self.mock_response_path.write_text(json.dumps({"error": message}))

    def read_state(self) -> dict:
        return json.loads((self.data_dir / "fortios-data.generated.json").read_text())

    def image_files(self) -> list[Path]:
        image_dir = self.data_dir / "advisory-images"
        return sorted(image_dir.iterdir()) if image_dir.exists() else []


@pytest.fixture
def fortios_server(tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    shutil.copy(FIXTURES_DIR / "catalog.json", data_dir / "fortios-data.generated.json")

    mock_response_path = tmp_path / "mock_response.json"
    mock_response_path.write_text(json.dumps({}))  # no hops configured yet -> "no path" until set

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"

    env = dict(os.environ)
    env["FORTIOS_TEST_DATA_DIR"] = str(data_dir)
    env["FORTIOS_E2E_MOCK_NETWORK"] = "1"
    env["FORTIOS_E2E_MOCK_RESPONSE_FILE"] = str(mock_response_path)
    # A real SMTP config leaking from the host environment into a test run would be surprising
    # and is never needed by anything in this suite.
    for key in list(env):
        if key.startswith("FORTIOS_SMTP_") or key == "FORTIOS_EMAIL_ENABLED":
            env.pop(key, None)

    process = subprocess.Popen(
        [sys.executable, str(REPO_ROOT / "scripts" / "fortios_server.py"), "--host", "127.0.0.1", "--port", str(port)],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_until_ready(base_url, process, SERVER_STARTUP_TIMEOUT_SECONDS)
        yield FortiosTestServer(
            base_url=base_url, data_dir=data_dir, mock_response_path=mock_response_path, process=process,
        )
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


@pytest.fixture
def app_page(page, fortios_server):
    """A page already navigated to the isolated app, with the catalog loaded."""
    page.on("dialog", lambda dialog: dialog.accept())  # window.confirm() on delete flows
    page.goto(f"{fortios_server.base_url}/app/")
    page.wait_for_selector("#productSelect option")
    return page
