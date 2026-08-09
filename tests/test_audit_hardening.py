"""TDD coverage for audit hardening: bounded calls, safe errors, temp files and field limits."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import contextmanager
from functools import partial
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import fortios_server as server
import fortios_watch as fw
import import_forticlient_compat as compat


@contextmanager
def local_api_server(semaphore: threading.BoundedSemaphore):
    """Run the real request handler locally while all Fortinet calls stay patched."""
    with tempfile.TemporaryDirectory() as tmp:
        data_dir = Path(tmp)
        with (
            patch.object(server, "DATA_PATH", data_dir / "state.json"),
            patch.object(server, "SAMPLE_PATH", data_dir / "sample.json"),
            patch.object(server, "OFFICIAL_PATH_SEMAPHORE", semaphore, create=True),
        ):
            httpd = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                partial(server.FortiosHandler, timeout=2),
            )
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://127.0.0.1:{httpd.server_port}"
            try:
                yield base_url
            finally:
                httpd.shutdown()
                httpd.server_close()
                thread.join(timeout=3)


def post_json(base_url: str, endpoint: str, payload: dict[str, object]) -> tuple[int, dict]:
    request = urllib.request.Request(
        f"{base_url}{endpoint}",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Origin": base_url,
        },
    )
    try:
        response = urllib.request.urlopen(request, timeout=4)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, json.load(response)


class OfficialPathConcurrencyTests(unittest.TestCase):
    def request_payload(self) -> dict[str, object]:
        return {
            "model": "FGT60F",
            "from": "7.2.10",
            "to": "7.4.11",
        }

    def test_saturated_official_path_returns_429_without_a_second_fortinet_call(self) -> None:
        semaphore = threading.BoundedSemaphore(1)
        started = threading.Event()
        release = threading.Event()
        calls = 0

        def blocked_fetch(request: fw.OfficialPathRequest, timeout: int):
            nonlocal calls
            calls += 1
            started.set()
            self.assertTrue(release.wait(timeout=3))
            return (
                fw.UpgradePath(
                    product=request.product,
                    model=request.model,
                    from_version=request.from_version,
                    to_version=request.to_version,
                    hops=(request.from_version, request.to_version),
                    source="test",
                ),
                [],
            )

        with (
            patch.object(server, "fetch_official_upgrade_path", side_effect=blocked_fetch),
            local_api_server(semaphore) as base_url,
        ):
            first = threading.Thread(
                target=post_json,
                args=(base_url, "/api/official-path", self.request_payload()),
            )
            first.start()
            self.assertTrue(started.wait(timeout=3))

            status, body = post_json(
                base_url,
                "/api/official-path",
                self.request_payload(),
            )
            self.assertEqual(status, HTTPStatus.TOO_MANY_REQUESTS)
            self.assertEqual(body["error"], "Trop de requêtes Fortinet en cours.")
            self.assertEqual(calls, 1)

            release.set()
            first.join(timeout=4)
            self.assertFalse(first.is_alive())

    def test_official_path_slot_is_released_after_fortinet_exception(self) -> None:
        semaphore = threading.BoundedSemaphore(1)
        request = self.request_payload()
        successful_path = fw.UpgradePath(
            product=fw.DEFAULT_PRODUCT_ID,
            model="FGT60F",
            from_version="7.2.10",
            to_version="7.4.11",
            hops=("7.2.10", "7.4.11"),
            source="test",
        )
        fetch_results = [RuntimeError("upstream detail"), (successful_path, [])]

        def fetch(_request: fw.OfficialPathRequest, _timeout: int):
            result = fetch_results.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result

        with (
            patch.object(server, "fetch_official_upgrade_path", side_effect=fetch),
            local_api_server(semaphore) as base_url,
        ):
            first_status, _first_body = post_json(
                base_url,
                "/api/official-path",
                request,
            )
            second_status, _second_body = post_json(
                base_url,
                "/api/official-path",
                request,
            )

        self.assertEqual(first_status, HTTPStatus.BAD_GATEWAY)
        self.assertEqual(second_status, HTTPStatus.OK)


class InternalErrorResponseTests(unittest.TestCase):
    def test_unexpected_persistence_error_does_not_reveal_exception_text(self) -> None:
        payload = {
            "title": "Alerte valide",
            "description": "Description valide",
            "versions": ["7.4.11"],
        }
        with (
            patch.object(server, "write_json", side_effect=RuntimeError("secret database path")),
            patch.object(server.FortiosHandler, "log_exception") as log_exception,
            local_api_server(threading.BoundedSemaphore(1)) as base_url,
        ):
            status, body = post_json(base_url, "/api/advisories", payload)

        self.assertEqual(status, HTTPStatus.BAD_GATEWAY)
        self.assertEqual(body, {"error": "Erreur interne du serveur."})
        log_exception.assert_called_once_with("handle_create_advisory")


class CompatibilityTempFileTests(unittest.TestCase):
    def _run_import_with_parser(self, parser):
        with tempfile.TemporaryDirectory() as tmp:
            health_path = Path(tmp) / "health.json"
            with (
                patch.object(compat, "find_pdf_url", return_value="https://example.test/matrix.pdf"),
                patch.object(compat, "fetch_url", return_value=b"fake-pdf"),
                patch.object(compat, "parse_matrix", side_effect=parser),
                patch.object(compat, "MIN_EXPECTED_ENTRIES", 1),
            ):
                result = compat.main(["--health-output", str(health_path)])
        return result

    def test_pdf_path_is_private_unique_and_removed_after_success(self) -> None:
        observed: dict[str, object] = {}

        def parse(path: Path):
            observed["path"] = path
            observed["exists_during_parse"] = path.exists()
            observed["mode"] = path.stat().st_mode & 0o777
            return [{"emsVersion": "7.4.1", "clientVersions": ["7.4.1"]}]

        result = self._run_import_with_parser(parse)
        self.assertEqual(result, 0)
        self.assertIn("path", observed)
        path = observed["path"]
        self.assertIsInstance(path, Path)
        self.assertNotEqual(path, Path("/tmp/forticlient_ems_compat.pdf"))
        self.assertTrue(observed["exists_during_parse"])
        self.assertEqual(observed["mode"], 0o600)
        self.assertFalse(path.exists())
        self.assertFalse(path.parent.exists())

    def test_pdf_path_is_removed_after_parser_exception(self) -> None:
        observed: dict[str, Path] = {}

        def parse(path: Path):
            observed["path"] = path
            raise ValueError("malformed PDF")

        result = self._run_import_with_parser(parse)
        self.assertEqual(result, 1)
        self.assertIn("path", observed)
        self.assertFalse(observed["path"].exists())
        self.assertFalse(observed["path"].parent.exists())


class PersistedFieldLimitTests(unittest.TestCase):
    MAX_VERSION_LENGTH = 32
    MAX_MODEL_LENGTH = 64
    MAX_ADVISORY_TITLE_LENGTH = 200
    MAX_ADVISORY_DESCRIPTION_LENGTH = 20_000
    MAX_ADVISORY_COMMAND_LENGTH = 8_000
    MAX_ADVISORY_VERSION_ITEMS = 128
    MAX_ADVISORY_MODEL_ITEMS = 512
    MAX_COMPAT_CLIENT_VERSION_ITEMS = 128
    MAX_COMPAT_NOTE_LENGTH = 4_000

    @staticmethod
    def advisory_payload(**overrides: object) -> dict[str, object]:
        return {
            "title": "Titre valide",
            "description": "Description valide",
            "versions": ["7.4.11"],
            **overrides,
        }

    def test_advisory_text_fields_have_reasonable_upper_bounds(self) -> None:
        cases = (
            ("title", self.MAX_ADVISORY_TITLE_LENGTH),
            ("description", self.MAX_ADVISORY_DESCRIPTION_LENGTH),
            ("command", self.MAX_ADVISORY_COMMAND_LENGTH),
        )
        for field, limit in cases:
            with self.subTest(field=field), self.assertRaises(ValueError):
                server.parse_advisory_fields(
                    self.advisory_payload(**{field: "x" * (limit + 1)})
                )

    def test_advisory_version_and_model_lists_are_bounded(self) -> None:
        with self.assertRaises(ValueError):
            server.parse_advisory_fields(
                self.advisory_payload(
                    versions=["7.4.11"] * (self.MAX_ADVISORY_VERSION_ITEMS + 1)
                )
            )
        with self.assertRaises(ValueError):
            server.parse_advisory_fields(
                self.advisory_payload(
                    models=["FGT60F"] * (self.MAX_ADVISORY_MODEL_ITEMS + 1)
                )
            )

    def test_version_and_model_values_are_bounded(self) -> None:
        with self.assertRaises(ValueError):
            server.parse_advisory_fields(
                self.advisory_payload(versions=["x" * (self.MAX_VERSION_LENGTH + 1)])
            )
        with self.assertRaises(ValueError):
            server.parse_advisory_fields(
                self.advisory_payload(models=["x" * (self.MAX_MODEL_LENGTH + 1)])
            )

    def test_compatibility_fields_are_bounded(self) -> None:
        valid = {
            "emsVersion": "7.4.1",
            "clientVersions": ["7.4.1"],
        }
        with self.assertRaises(ValueError):
            server.parse_compatibility_fields(
                {**valid, "clientVersions": ["7.4.1"] * (self.MAX_COMPAT_CLIENT_VERSION_ITEMS + 1)}
            )
        with self.assertRaises(ValueError):
            server.parse_compatibility_fields(
                {**valid, "note": "x" * (self.MAX_COMPAT_NOTE_LENGTH + 1)}
            )

    def test_official_path_request_fields_are_bounded(self) -> None:
        parse_request = getattr(server, "parse_official_path_request", lambda _payload: None)
        with self.assertRaises(ValueError):
            parse_request(
                {
                    "model": "x" * (self.MAX_MODEL_LENGTH + 1),
                    "from": "7.2.10",
                    "to": "7.4.11",
                }
            )
        with self.assertRaises(ValueError):
            parse_request(
                {
                    "model": "FGT60F",
                    "from": "x" * (self.MAX_VERSION_LENGTH + 1),
                    "to": "7.4.11",
                }
            )


if __name__ == "__main__":
    unittest.main()
