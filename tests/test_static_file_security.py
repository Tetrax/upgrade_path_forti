"""Path traversal coverage for FortiosHandler.translate_path() (scripts/fortios_server.py).

The prefix check used to run on the raw, undecoded request path before the parent class had a
chance to percent-decode and normalize it — "/data/%2e%2e/scripts/fortios_server.py" passed the
"starts with /data/" check as a literal string, but resolved outside data/ once decoded. The fix
checks where the request actually resolves on disk instead.
"""

import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_server as fs


def translate(path: str) -> str:
    handler = fs.FortiosHandler.__new__(fs.FortiosHandler)
    handler.directory = str(fs.ROOT)
    return fs.FortiosHandler.translate_path(handler, path)


def is_served(path: str) -> bool:
    return translate(path) != str(fs.ROOT / "__not_served__")


class StaticFileTraversalTests(unittest.TestCase):
    def test_data_directory_itself_is_never_served(self):
        for path in ("/data", "/data/", "/data/.", "/data/%2e"):
            with self.subTest(path=path):
                self.assertFalse(is_served(path))

    def test_smtp_private_temporary_files_are_ignored_by_git(self):
        repository = Path(__file__).resolve().parents[1]
        for relative in (
            "data/.smtp-password.tmp-123",
            "data/.smtp-password.transaction-backup",
            "data/.smtp-settings.json.transaction",
        ):
            with self.subTest(relative=relative):
                result = subprocess.run(
                    ["git", "check-ignore", "--no-index", "--quiet", relative],
                    cwd=repository,
                    check=False,
                )
                self.assertEqual(result.returncode, 0)

    def test_site_root_serves_the_application_tree(self):
        # The application is mounted on "/": the root URL maps onto app/, never onto the repository
        # root — that is what keeps /scripts, /deploy or /.git out of the web surface.
        self.assertTrue(is_served("/"))
        self.assertEqual(translate("/"), str(fs.ROOT / "app"))
        self.assertEqual(translate("/index.html"), str(fs.ROOT / "app" / "index.html"))

    def test_translate_path_never_leaves_the_public_trees(self):
        """Whatever the request, the resolved path stays inside app/, data/ or the admin tree."""
        public_trees = (
            fs.ALLOWED_STATIC_DIR_APP,
            fs.ALLOWED_STATIC_DIR_DATA,
            fs.ALLOWED_STATIC_DIR_CERT,
        )
        for path in (
            "/",
            "/index.html",
            "/shared.css",
            "/alerte/",
            "/forticlient/app.js",
            "/common.js",
            "/scripts/fortios_server.py",
            "/AGENTS.md",
            "/Dockerfile",
            "/.git/config",
            "/admin/cert.js",
            "/data/fortios-data.generated.json",
            "/cert/",
            "/app/",
        ):
            resolved = Path(translate(path))
            with self.subTest(path=path):
                if resolved == fs.ROOT / "__not_served__":
                    continue
                self.assertTrue(
                    any(resolved.is_relative_to(tree) for tree in public_trees),
                    f"{path} resolved outside the public trees: {resolved}",
                )

    def test_legacy_ui_prefixes_are_never_served(self):
        # /app/* and /cert/* are redirect-only (see do_GET/do_HEAD): serving them here too would
        # give every page two valid URLs, which is exactly what the migration removes.
        for path in (
            "/app",
            "/app/",
            "/app/index.html",
            "/app/alerte/",
            "/app/forticlient/app.js",
            "/app/cert",
            "/app/cert/",
            "/app/cert/cert.js",
            "/cert",
            "/cert/",
            "/cert/cert.js",
            "/cert/verify-email",
        ):
            with self.subTest(path=path):
                self.assertFalse(is_served(path))

    def test_legacy_redirect_targets(self):
        handler = fs.FortiosHandler.__new__(fs.FortiosHandler)
        cases = {
            "/app": "/",
            "/app/": "/",
            "/app/index.html": "/index.html",
            "/app/alerte/": "/alerte/",
            "/app/forticlient/": "/forticlient/",
            "/app/cert": "/admin/",
            "/app/cert/": "/admin/",
            "/app/cert/cert.js": "/admin/cert.js",
            "/cert": "/admin/",
            "/cert/": "/admin/",
            "/cert/cert.js": "/admin/cert.js",
            "/cert/verify-email": "/admin/verify-email",
            "/cert/reset-password": "/admin/reset-password",
            "/cert/microsoft365-help": "/admin/microsoft365-help",
            "/cert/microsoft365-guide.md": "/admin/microsoft365-guide.md",
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(handler.legacy_redirect_target(path), expected)

    def test_canonical_paths_are_never_redirected(self):
        handler = fs.FortiosHandler.__new__(fs.FortiosHandler)
        for path in (
            "/",
            "/index.html",
            "/alerte/",
            "/forticlient/",
            "/admin",
            "/admin/",
            "/admin/cert.js",
            "/api/cert/status",
            "/api/official-path",
            "/data/fortios-data.generated.json",
        ):
            with self.subTest(path=path):
                self.assertIsNone(handler.legacy_redirect_target(path))

    def test_allowed_data_file(self):
        self.assertTrue(is_served("/data/fortios-data.generated.json"))

    def test_notification_settings_are_never_served_as_a_static_data_file(self):
        self.assertFalse(is_served("/data/notification-settings.json"))
        self.assertFalse(is_served("/data/notification-settings.json.corrupt-123"))

    def test_notification_history_is_never_served_as_static_data(self):
        for name in (
            "fortios-notify-history.json",
            "fortios-notify-history.json.lock",
            "fortios-notify-history.json.corrupt-123",
            ".fortios-notify-history.json.tmp-123",
        ):
            with self.subTest(name=name):
                self.assertFalse(is_served(f"/data/{name}"))

    def test_smtp_settings_and_secrets_are_never_served_as_static_data(self):
        for name in (
            "smtp-settings.json",
            "smtp-settings.json.lock",
            "smtp-settings.json.corrupt-123",
            ".smtp-settings.json.tmp-123",
            "smtp-password",
            "smtp-password.corrupt-123",
            ".smtp-password.tmp-123",
        ):
            with self.subTest(name=name):
                self.assertFalse(is_served(f"/data/{name}"))

    def test_allowed_nested_app_paths(self):
        self.assertTrue(is_served("/"))
        self.assertTrue(is_served("/alerte/"))
        self.assertTrue(is_served("/alerte/app.js"))

    def test_allowed_certificate_ui_files(self):
        self.assertTrue(is_served("/admin/"))
        self.assertEqual(
            translate("/admin/cert.js"), str(fs.ROOT / "app" / "cert" / "cert.js")
        )

    def test_denies_direct_script_access(self):
        # /scripts/... can only resolve inside app/ (where no scripts/ tree exists), never to the
        # repository's own scripts/ directory. The HTTP-level 404 is asserted by the running-server
        # tests, which is where the real guarantee lives.
        resolved = Path(translate("/scripts/fortios_server.py"))
        self.assertNotEqual(resolved, fs.ROOT / "scripts" / "fortios_server.py")
        self.assertTrue(resolved.is_relative_to(fs.ALLOWED_STATIC_DIR_APP))
        self.assertFalse(resolved.exists())

    def test_denies_literal_traversal(self):
        self.assertFalse(is_served("/data/../scripts/fortios_server.py"))

    def test_denies_encoded_traversal(self):
        self.assertFalse(is_served("/data/%2e%2e/scripts/fortios_server.py"))

    def test_denies_encoded_traversal_with_encoded_slash(self):
        self.assertFalse(is_served("/data/%2e%2e%2fscripts/fortios_server.py"))

    def test_denies_certificate_ui_traversal(self):
        self.assertFalse(is_served("/cert/../scripts/fortios_server.py"))
        self.assertFalse(is_served("/cert/%2e%2e%2fscripts/fortios_server.py"))

    def test_denies_traversal_into_git(self):
        self.assertFalse(is_served("/app/../.git/config"))

    def test_denies_bare_root_of_the_repository(self):
        # "/" now serves the application: the guarantee is not "no bare root" anymore, it is that
        # the repository root itself is never reachable through it.
        self.assertEqual(translate("/"), str(fs.ALLOWED_STATIC_DIR_APP))
        for path in ("/.git/config", "/AGENTS.md", "/requirements-runtime.txt", "/pytest.ini"):
            with self.subTest(path=path):
                resolved = Path(translate(path))
                self.assertTrue(
                    resolved == fs.ROOT / "__not_served__"
                    or resolved.is_relative_to(fs.ALLOWED_STATIC_DIR_APP)
                )
                self.assertFalse(resolved == fs.ROOT / path.lstrip("/"))

    def test_denies_traversal_out_of_the_legacy_prefixes(self):
        for path in (
            "/app/../.git/config",
            "/app/%2e%2e%2f.git/config",
            "/admin/../scripts/fortios_server.py",
            "/admin/%2e%2e%2fscripts/fortios_server.py",
        ):
            with self.subTest(path=path):
                self.assertFalse(is_served(path))

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

    def test_certificate_origin_requires_exact_scheme_host_and_port(self):
        handler = self.make_handler(
            host="upgrade-path.sns-security.lan:8443",
            origin="https://upgrade-path.sns-security.lan:8443",
        )
        handler.tls_active = True
        self.assertTrue(handler.is_safe_cert_origin())

        handler.headers["Origin"] = "https://upgrade-path.sns-security.lan"
        self.assertFalse(handler.is_safe_cert_origin())
        handler.headers["Origin"] = "http://upgrade-path.sns-security.lan:8443"
        self.assertFalse(handler.is_safe_cert_origin())


class CertificateAccessTests(unittest.TestCase):
    def test_insecure_development_mode_is_restricted_to_loopback_clients(self):
        handler = fs.FortiosHandler.__new__(fs.FortiosHandler)
        handler.tls_active = False
        handler.allow_insecure_localhost = True
        handler.client_address = ("192.0.2.10", 12345)
        self.assertFalse(handler.certificate_ui_available())

        handler.client_address = ("127.0.0.1", 12345)
        self.assertTrue(handler.certificate_ui_available())


class TestDataDirOverrideTests(unittest.TestCase):
    """FORTIOS_TEST_DATA_DIR (used only by the isolated E2E fixture) must redirect /data/* to
    the override directory while leaving /app/* on the real ROOT, and must stay just as
    traversal-safe as the default (unset) case.
    """

    def setUp(self):
        import importlib
        import os
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        (Path(self._tmp.name) / "fortios-data.generated.json").write_text("{}")
        self._orig_env = os.environ.get("FORTIOS_TEST_DATA_DIR")
        os.environ["FORTIOS_TEST_DATA_DIR"] = self._tmp.name
        importlib.reload(fs)

    def tearDown(self):
        import importlib
        import os

        if self._orig_env is None:
            os.environ.pop("FORTIOS_TEST_DATA_DIR", None)
        else:
            os.environ["FORTIOS_TEST_DATA_DIR"] = self._orig_env
        importlib.reload(fs)  # restore the module to its default (unset) state for other tests
        self._tmp.cleanup()

    def test_data_requests_resolve_against_the_override_dir(self):
        self.assertTrue(is_served("/data/fortios-data.generated.json"))
        self.assertEqual(
            translate("/data/fortios-data.generated.json"),
            str(Path(self._tmp.name).resolve() / "fortios-data.generated.json"),
        )

    def test_app_requests_still_resolve_against_the_real_root_when_overridden(self):
        self.assertTrue(is_served("/index.html"))
        self.assertEqual(translate("/index.html"), str(fs.ROOT / "app" / "index.html"))

    def test_traversal_out_of_the_override_dir_is_still_denied(self):
        self.assertFalse(is_served("/data/../scripts/fortios_server.py"))
        self.assertFalse(is_served("/data/%2e%2e/scripts/fortios_server.py"))


if __name__ == "__main__":
    unittest.main()
