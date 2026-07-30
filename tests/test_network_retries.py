"""Regression tests for transient HTTP failures while reading Fortinet responses."""

import http.client
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_watch as fw  # noqa: E402
import import_forticlient_compat as compat  # noqa: E402


class _Response:
    def __init__(self, result):
        self.result = result

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


class HttpReadRetryTests(unittest.TestCase):
    def test_fetch_text_retries_the_whole_request_after_incomplete_read(self):
        incomplete = http.client.IncompleteRead(b"partial", 42)
        responses = [_Response(incomplete), _Response(b"complete response")]

        with (
            patch("urllib.request.urlopen", side_effect=responses) as urlopen,
            patch.object(fw.time, "sleep") as sleep,
            patch.object(fw.random, "uniform", return_value=0),
        ):
            result = fw.fetch_text("https://docs.fortinet.com/example", timeout=12)

        self.assertEqual(result, "complete response")
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_fetch_text_raises_after_all_incomplete_read_attempts(self):
        responses = [
            _Response(http.client.IncompleteRead(b"partial", 42)),
            _Response(http.client.IncompleteRead(b"partial", 42)),
            _Response(http.client.IncompleteRead(b"partial", 42)),
        ]

        with (
            patch("urllib.request.urlopen", side_effect=responses) as urlopen,
            patch.object(fw.time, "sleep"),
            patch.object(fw.random, "uniform", return_value=0),
        ):
            with self.assertRaises(http.client.IncompleteRead):
                fw.fetch_text("https://docs.fortinet.com/example", timeout=12)

        self.assertEqual(urlopen.call_count, 3)

    def test_http_error_is_not_retried(self):
        error = urllib.error.HTTPError(
            "https://docs.fortinet.com/missing", 404, "Not Found", {}, MagicMock()
        )
        with patch("urllib.request.urlopen", side_effect=error) as urlopen:
            with self.assertRaises(urllib.error.HTTPError):
                fw.fetch_text("https://docs.fortinet.com/missing", timeout=12)

        self.assertEqual(urlopen.call_count, 1)

    def test_transient_server_error_is_retried(self):
        error = urllib.error.HTTPError(
            "https://docs.fortinet.com/busy", 503, "Service Unavailable", {}, MagicMock()
        )
        with (
            patch("urllib.request.urlopen", side_effect=[error, _Response(b"recovered")]) as urlopen,
            patch.object(fw.time, "sleep") as sleep,
            patch.object(fw.random, "uniform", return_value=0),
        ):
            result = fw.fetch_text("https://docs.fortinet.com/busy", timeout=12)

        self.assertEqual(result, "recovered")
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_any_server_error_is_retried(self):
        error = urllib.error.HTTPError(
            "https://docs.fortinet.com/full", 507, "Insufficient Storage", MagicMock(), MagicMock()
        )
        with (
            patch("urllib.request.urlopen", side_effect=[error, _Response(b"recovered")]) as urlopen,
            patch.object(fw.time, "sleep"),
            patch.object(fw.random, "uniform", return_value=0),
        ):
            result = fw.fetch_text("https://docs.fortinet.com/full", timeout=12)

        self.assertEqual(result, "recovered")
        self.assertEqual(urlopen.call_count, 2)


class CompatibilityHealthTests(unittest.TestCase):
    def test_exhausted_incomplete_read_is_recorded_as_a_source_failure(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            health_path = Path(tmp) / "health.json"
            with (
                patch.object(compat, "find_pdf_url", return_value="https://example.test/matrix.pdf"),
                patch.object(
                    compat,
                    "fetch_url",
                    side_effect=http.client.IncompleteRead(b"partial", 42),
                ),
            ):
                result = compat.main(["--commit", "--health-output", str(health_path)])

            health = fw.read_health_state(health_path)

        self.assertEqual(result, 1)
        self.assertEqual(
            health["sources"][fw.SOURCE_COMPAT_MATRIX]["status"],
            fw.HEALTH_STATUS_ERROR,
        )

    def test_pdf_parser_exception_is_recorded_as_a_source_failure(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            health_path = Path(tmp) / "health.json"
            with (
                patch.object(compat, "find_pdf_url", return_value="https://example.test/matrix.pdf"),
                patch.object(compat, "fetch_url", return_value=b"not-a-pdf"),
                patch.object(compat, "parse_matrix", side_effect=ValueError("malformed PDF")),
            ):
                result = compat.main(["--commit", "--health-output", str(health_path)])

            health = fw.read_health_state(health_path)

        self.assertEqual(result, 1)
        record = health["sources"][fw.SOURCE_COMPAT_MATRIX]
        self.assertEqual(record["status"], fw.HEALTH_STATUS_ERROR)
        self.assertIn("malformed PDF", record["lastError"])


if __name__ == "__main__":
    unittest.main()
