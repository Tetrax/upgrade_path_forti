"""Regression tests for docs.fortinet.com branch coverage (2026-09 regression).

Fortinet publishes a train's product page (`/product/fortigate/8.4`, `/product/forticlient/8.4`)
only once that train exists. `DEFAULT_DOCS_MAJOR_VERSIONS` starts with the newest trains, so a
branch nobody can open yet used to abort the whole scrape on its very first fetch: the FortiOS
and FortiClient/EMS sources went red and no version at all was collected, day after day.

A 404 on one branch is now "nothing published here yet, try the next train"; anything else
(timeout, 5xx, DNS) still fails the source, and a run where NO branch can be read must stay a
visible error — never a green "0 versions collected" scan.
"""

import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_watch as fw

FORIOS_80_PAGE = (
    '<a href="/document/fortigate/8.0.1/fortios-release-notes">8.0.1</a>'
    '<a href="/document/fortigate/8.0.0/fortios-release-notes">8.0.0</a>'
)
FORTICLIENT_74_PAGE = (
    '<a href="/document/forticlient/7.4.4/windows-release-notes">windows</a>'
    '<a href="/document/forticlient/7.4.4/macos-release-notes">macos</a>'
    '<a href="/document/forticlient/7.4.4/linux-release-notes">linux</a>'
    '<a href="/document/forticlient/7.4.4/ems-release-notes">ems</a>'
)
FORIOS_801_RELEASE_NOTES = (
    "<p>This guide provides release information for FortiOS 8.0.1 build 0245.</p>"
    "<p>FortiOS 8.0.1 supports the following models.</p>"
    "<p>FG-40F FG-60F</p><p>Previous</p>"
)


def _http_error(url, code):
    return urllib.error.HTTPError(url, code, "error", {}, None)


class DocsBranchDiscoveryTests(unittest.TestCase):
    def test_404_branch_is_skipped_and_later_branches_still_collected(self):
        def fake_fetch_text(url, timeout):
            if url.endswith("/product/fortigate/8.4"):
                raise _http_error(url, 404)
            if url.endswith("/product/fortigate/8.0"):
                return FORIOS_80_PAGE
            self.fail(f"unexpected fetch: {url}")

        with patch.object(fw, "fetch_text", side_effect=fake_fetch_text):
            versions, missing = fw.discover_docs_versions(("8.4", "8.0"), timeout=5)

        self.assertEqual(versions, ["8.0.0", "8.0.1"])
        self.assertEqual(missing, ["fortigate/8.4"])

    def test_all_branches_missing_is_an_error_not_an_empty_success(self):
        def fake_fetch_text(url, timeout):
            raise _http_error(url, 404)

        with (
            patch.object(fw, "fetch_text", side_effect=fake_fetch_text),
            self.assertRaisesRegex(ValueError, "Aucune branche FortiOS exploitable"),
        ):
            fw.discover_docs_versions(("8.4", "8.2"), timeout=5)

    def test_non_404_http_error_still_fails_the_source(self):
        def fake_fetch_text(url, timeout):
            raise _http_error(url, 503)

        with (
            patch.object(fw, "fetch_text", side_effect=fake_fetch_text),
            self.assertRaises(urllib.error.HTTPError),
        ):
            fw.discover_docs_versions(("8.4", "8.0"), timeout=5)

    def test_network_timeout_still_fails_the_source(self):
        def fake_fetch_text(url, timeout):
            raise TimeoutError("docs.fortinet.com unreachable")

        with (
            patch.object(fw, "fetch_text", side_effect=fake_fetch_text),
            self.assertRaises(TimeoutError),
        ):
            fw.discover_docs_versions(("8.4", "8.0"), timeout=5)

    def test_collect_docs_catalog_keeps_collecting_after_a_404_branch(self):
        def fake_fetch_text(url, timeout):
            if url.endswith("/product/fortigate/8.4"):
                raise _http_error(url, 404)
            if url.endswith("/product/fortigate/8.0"):
                return FORIOS_80_PAGE
            if url.endswith("/document/fortigate/8.0.1/fortios-release-notes"):
                return FORIOS_801_RELEASE_NOTES
            if url.endswith("/document/fortigate/8.0.0/fortios-release-notes"):
                return FORIOS_801_RELEASE_NOTES.replace("8.0.1", "8.0.0").replace("build 0245", "build 0167")
            self.fail(f"unexpected fetch: {url}")

        with patch.object(fw, "fetch_text", side_effect=fake_fetch_text):
            state, skipped = fw.collect_docs_catalog(("8.4", "8.0"), timeout=5)

        product = state["products"][0]
        self.assertEqual(product["id"], "fortigate-fortios")
        model_ids = {model["id"] for model in product["models"]}
        self.assertIn("FGT40F", model_ids)
        self.assertIn("FGT60F", model_ids)
        self.assertEqual(
            state["products"][0]["models"][0]["firmwares"][0]["build"], "0167"
        )
        self.assertEqual(skipped, ["fortigate/8.4 (page absente, HTTP 404)"])

    def test_forticlient_404_branch_is_skipped_and_later_branches_collected(self):
        def fake_fetch_text(url, timeout):
            if url.endswith(
                ("/product/forticlient/8.4", "/product/forticlient/8.2")
            ):
                raise _http_error(url, 404)
            if url.endswith("/product/forticlient/7.4"):
                return FORTICLIENT_74_PAGE
            self.fail(f"unexpected fetch: {url}")

        with patch.object(fw, "fetch_text", side_effect=fake_fetch_text):
            versions, missing = fw.discover_forticlient_versions(
                ("8.4", "8.2", "7.4"), "windows-release-notes", timeout=5
            )

        self.assertEqual(versions, ["7.4.4"])
        self.assertEqual(missing, ["forticlient/8.4", "forticlient/8.2"])

    def test_collect_forticlient_catalog_all_branches_missing_is_an_error(self):
        def fake_fetch_text(url, timeout):
            raise _http_error(url, 404)

        with (
            patch.object(fw, "fetch_text", side_effect=fake_fetch_text),
            self.assertRaisesRegex(ValueError, "Aucune branche FortiClient exploitable"),
        ):
            fw.collect_forticlient_catalog(("8.4", "8.2"), timeout=5)


class DocsSourceHealthTests(unittest.TestCase):
    """The health record of a run, not just the helper functions: a 404-prone first branch must
    leave the source green (data collected) and an all-404 run must leave it red."""

    def _run_main(self, tmp, fake_fetch_text, extra_args=()):
        base_path = Path(tmp) / "state.json"
        health_path = Path(tmp) / "health.json"
        report_path = Path(tmp) / "report.md"
        fw.write_json(base_path, fw.normalize_state({}))
        with (
            patch.object(fw, "fetch_text", side_effect=fake_fetch_text),
            patch.object(fw, "fetch_fortios_lifecycle", return_value={}),
            patch.object(fw, "fetch_fortios_version_maturity", return_value={}),
        ):
            exit_code = fw.main(
                [
                    "--docs-catalog",
                    "--docs-major-versions",
                    "8.4,8.0",
                    "--base",
                    str(base_path),
                    "--output",
                    str(base_path),
                    "--report",
                    str(report_path),
                    "--health-output",
                    str(health_path),
                    "--notification-settings-output",
                    str(Path(tmp) / "notification-settings.json"),
                    "--notify-history-output",
                    str(Path(tmp) / "notify-history.json"),
                    # Hermetic fixture: the repo's own data/official-path-requests.csv would
                    # otherwise trigger a real upgrade-path fetch whose hops land in the state
                    # this test asserts on.
                    "--official-paths-csv",
                    str(Path(tmp) / "no-official-paths.csv"),
                    "--timeout",
                    "5",
                    *extra_args,
                ]
            )
        return exit_code, fw.read_json(health_path, {}), fw.read_json(base_path, {})

    def test_first_branch_404_then_success_keeps_the_source_green(self):
        def fake_fetch_text(url, timeout):
            if url.endswith("/product/fortigate/8.4"):
                raise _http_error(url, 404)
            if url.endswith("/product/fortigate/8.0"):
                return FORIOS_80_PAGE
            if url.endswith("/document/fortigate/8.0.1/fortios-release-notes"):
                return FORIOS_801_RELEASE_NOTES
            if url.endswith("/document/fortigate/8.0.0/fortios-release-notes"):
                return FORIOS_801_RELEASE_NOTES.replace("8.0.1", "8.0.0").replace("build 0245", "build 0167")
            self.fail(f"unexpected fetch: {url}")

        with tempfile.TemporaryDirectory() as tmp:
            exit_code, health, state = self._run_main(tmp, fake_fetch_text)

        self.assertEqual(exit_code, 0)
        record = health["sources"][fw.SOURCE_FORTIOS_DOCS]
        self.assertEqual(record["status"], fw.HEALTH_STATUS_OK)
        self.assertGreater(record["itemsCollected"], 0)
        self.assertEqual(health["sources"][fw.SOURCE_DAILY_RUN]["status"], fw.HEALTH_STATUS_OK)
        self.assertEqual(state["products"][0]["id"], "fortigate-fortios")

    def test_all_branches_404_is_red_and_preserves_the_existing_catalog(self):
        def fake_fetch_text(url, timeout):
            raise _http_error(url, 404)

        with tempfile.TemporaryDirectory() as tmp:
            base_path = Path(tmp) / "state.json"
            existing = fw.normalize_state({})
            fw.upsert_firmware(
                existing,
                fw.Firmware(
                    product=fw.DEFAULT_PRODUCT_ID, model="FGT60F", version="7.0.0"
                ),
            )
            fw.write_json(base_path, existing)
            health_path = Path(tmp) / "health.json"
            with (
                patch.object(fw, "fetch_text", side_effect=fake_fetch_text),
                patch.object(fw, "fetch_fortios_lifecycle", return_value={}),
                patch.object(fw, "fetch_fortios_version_maturity", return_value={}),
            ):
                exit_code = fw.main(
                    [
                        "--docs-catalog",
                        "--docs-major-versions",
                        "8.4,8.2",
                        "--base",
                        str(base_path),
                        "--output",
                        str(base_path),
                        "--report",
                        str(Path(tmp) / "report.md"),
                        "--health-output",
                        str(health_path),
                        "--notification-settings-output",
                        str(Path(tmp) / "notification-settings.json"),
                        "--notify-history-output",
                        str(Path(tmp) / "notify-history.json"),
                        # Hermetic fixture: the repo's own data/official-path-requests.csv would
                        # otherwise trigger a real upgrade-path fetch whose hops land in the
                        # state this test asserts on.
                        "--official-paths-csv",
                        str(Path(tmp) / "no-official-paths.csv"),
                        "--timeout",
                        "5",
                    ]
                )
            final_state = fw.read_json(base_path, {})
            health = fw.read_json(health_path, {})

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            health["sources"][fw.SOURCE_FORTIOS_DOCS]["status"], fw.HEALTH_STATUS_ERROR
        )
        # The version already in the catalog survives a run that collected nothing.
        model = final_state["products"][0]["models"][0]
        self.assertEqual([f["version"] for f in model["firmwares"]], ["7.0.0"])


if __name__ == "__main__":
    unittest.main()
