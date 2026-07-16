"""Path traversal coverage for FortiosHandler.translate_path() (scripts/fortios_server.py).

The prefix check used to run on the raw, undecoded request path before the parent class had a
chance to percent-decode and normalize it — "/data/%2e%2e/scripts/fortios_server.py" passed the
"starts with /data/" check as a literal string, but resolved outside data/ once decoded. The fix
checks where the request actually resolves on disk instead.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_server as fs  # noqa: E402


def translate(path: str) -> str:
    handler = fs.FortiosHandler.__new__(fs.FortiosHandler)
    handler.directory = str(fs.ROOT)
    return fs.FortiosHandler.translate_path(handler, path)


def is_served(path: str) -> bool:
    return translate(path) != str(fs.ROOT / "__not_served__")


class StaticFileTraversalTests(unittest.TestCase):
    def test_allowed_app_file(self):
        self.assertTrue(is_served("/app/index.html"))
        self.assertEqual(translate("/app/index.html"), str(fs.ROOT / "app" / "index.html"))

    def test_allowed_data_file(self):
        self.assertTrue(is_served("/data/fortios-data.generated.json"))

    def test_allowed_nested_app_paths(self):
        self.assertTrue(is_served("/app/"))
        self.assertTrue(is_served("/app/alerte/"))
        self.assertTrue(is_served("/app/alerte/app.js"))

    def test_denies_direct_script_access(self):
        self.assertFalse(is_served("/scripts/fortios_server.py"))

    def test_denies_literal_traversal(self):
        self.assertFalse(is_served("/data/../scripts/fortios_server.py"))

    def test_denies_encoded_traversal(self):
        self.assertFalse(is_served("/data/%2e%2e/scripts/fortios_server.py"))

    def test_denies_encoded_traversal_with_encoded_slash(self):
        self.assertFalse(is_served("/data/%2e%2e%2fscripts/fortios_server.py"))

    def test_denies_traversal_into_git(self):
        self.assertFalse(is_served("/app/../.git/config"))

    def test_denies_bare_root(self):
        self.assertFalse(is_served("/"))

    def test_denies_deep_traversal(self):
        self.assertFalse(is_served("/../../../etc/passwd"))


class OriginCheckTests(unittest.TestCase):
    """is_safe_origin() must compare hostname only, not full netloc: nginx's $host strips the
    port from the forwarded Host header while a non-default-port Origin keeps it."""

    def make_handler(self, host: str, origin: str | None = None, referer: str | None = None):
        handler = fs.FortiosHandler.__new__(fs.FortiosHandler)
        headers = {}
        if host is not None:
            headers["Host"] = host
        if origin is not None:
            headers["Origin"] = origin
        if referer is not None:
            headers["Referer"] = referer
        handler.headers = headers
        return handler

    def test_matching_origin_with_nonstandard_port_is_safe(self):
        handler = self.make_handler(host="valdev.me", origin="https://valdev.me:3001")
        self.assertTrue(handler.is_safe_origin())

    def test_foreign_origin_is_rejected(self):
        handler = self.make_handler(host="valdev.me", origin="https://evil.example")
        self.assertFalse(handler.is_safe_origin())

    def test_no_origin_or_referer_is_treated_as_same_origin_navigation(self):
        handler = self.make_handler(host="valdev.me")
        self.assertTrue(handler.is_safe_origin())


if __name__ == "__main__":
    unittest.main()
