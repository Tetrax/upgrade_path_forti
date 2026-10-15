"""PSIRT history completeness: every advisory of the tracked products, not only the RSS window.

Audit of 2026-10-15 against the per-product PSIRT listing: 318 advisories for the tracked
products, 37 in the catalogue. The 281 missing ones held 235 CVEs (13 critical). The listing is
reachable again, so a weekly backfill imports them; this file covers what made that import
incomplete or unsafe:

- legacy advisories (<= FG-IR-23) without CSAF, whose CVRF enumerates exact versions;
- CSAF shapes the parser refused: "X.Y.Z and above", a note after "all versions", the
  "FortiOS-6K7K" / lowercase "cloud" variants, empty known_affected on untracked products;
- the backfill itself: RSS-window ids left to the notifying runs, empty listing = failure,
  history record kept in cveCoverage, weekly scheduler job without KEV read.
"""

from __future__ import annotations

import datetime as dt
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import container_scheduler as scheduler
import fortios_notify as fn
import fortios_watch as fw
import scheduled_refresh as refresh
from test_csaf_applicability import make_csaf_document, make_vulnerability
from test_psirt_unresolvable import legacy_cvrf, legacy_page


class LegacyCvrfTests(unittest.TestCase):
    def test_exact_versions_become_per_branch_ranges_with_gaps_excluded(self) -> None:
        raw = legacy_cvrf(
            "FG-IR-23-424",
            "FortiOS 7.0.0", "FortiOS 7.0.1", "FortiOS 7.0.3", "FortiOS 7.2.4",
            "FortiProxy 7.2.0", "FortiClientWindows 6.4.2",
            cve="CVE-2023-46717",
        )
        [entry] = fw.parse_legacy_cvrf_document("FG-IR-23-424", raw)
        self.assertEqual(entry["id"], "CVE-2023-46717")
        self.assertEqual(entry["severity"], "high")
        self.assertEqual(entry["cvssScore"], 7.5)
        self.assertEqual((entry["publishedAt"], entry["updatedAt"]), ("2022-04-01", "2026-08-27"))
        by_branch = {(item["product"], item["branch"]): item for item in entry["affected"]}
        self.assertEqual(
            by_branch[(fw.DEFAULT_PRODUCT_ID, "7.0")],
            {"product": fw.DEFAULT_PRODUCT_ID, "models": [], "branch": "7.0",
             "from": "7.0.0", "to": "7.0.3", "excluded": ["7.0.2"]},
        )
        self.assertEqual(by_branch[(fw.DEFAULT_PRODUCT_ID, "7.2")]["from"], "7.2.4")
        self.assertEqual(by_branch[(fw.FORTICLIENT_PRODUCT_ID, "6.4")]["models"], ["windows"])
        self.assertEqual(len(entry["affected"]), 3)  # FortiProxy is not tracked

    def test_one_vulnerability_with_two_cves_yields_both(self) -> None:
        raw = legacy_cvrf("FG-IR-23-015", "FortiOS 7.2.4").replace(
            "<cvrf:CVE>CVE-2022-0778</cvrf:CVE>",
            "<cvrf:CVE>CVE-2023-33306</cvrf:CVE><cvrf:CVE>CVE-2023-33307</cvrf:CVE>",
        )
        entries = fw.parse_legacy_cvrf_document("FG-IR-23-015", raw)
        self.assertEqual([entry["id"] for entry in entries], ["CVE-2023-33306", "CVE-2023-33307"])

    def test_a_vulnerability_without_known_affected_keeps_the_advisory_unresolved(self) -> None:
        raw = legacy_cvrf("FG-IR-23-015", "FortiOS 7.2.4").replace(
            "</cvrf:cvrfdoc>",
            '<Vulnerability Ordinal="2"><cvrf:CVE>CVE-2023-33307</cvrf:CVE></Vulnerability></cvrf:cvrfdoc>',
        )
        with self.assertRaises(fw.CsafUnavailableError):
            fw.parse_legacy_cvrf_document("FG-IR-23-015", raw)

    def test_train_level_or_untracked_only_stays_unavailable(self) -> None:
        for products in (("FortiOS 7.6",), ("FortiOS 7.6.0", "FortiOS 7.4"), ("FortiProxy 7.2.0",), ()):
            raw = legacy_cvrf("FG-IR-22-059", *products)
            with self.subTest(products=products), self.assertRaises(fw.CsafUnavailableError):
                fw.parse_legacy_cvrf_document("FG-IR-22-059", raw)

    def test_malformed_or_foreign_export_is_a_failure(self) -> None:
        cases = {
            "not xml": "<html>challenge",
            "foreign id": legacy_cvrf("FG-IR-22-001", "FortiOS 7.0.1"),
            "unknown product ref": legacy_cvrf("FG-IR-22-059", "FortiOS 7.0.1").replace(
                "<ProductID>P0</ProductID>", "<ProductID>P9</ProductID>"
            ),
        }
        for label, raw in cases.items():
            with self.subTest(case=label), self.assertRaises(fw.CsafResolutionError) as caught:
                fw.parse_legacy_cvrf_document("FG-IR-22-059", raw)
            self.assertNotIsInstance(caught.exception, fw.CsafUnavailableError)

    def test_collector_reads_the_cvrf_of_a_legacy_page(self) -> None:
        responses = {
            "https://fortiguard.fortinet.com/psirt/FG-IR-22-036": legacy_page("FG-IR-22-036"),
            "https://fortiguard.fortinet.com/psirt/cvrf/FG-IR-22-036": legacy_cvrf(
                "FG-IR-22-036", "FortiOS 6.2.0", "FortiOS 6.2.1"
            ),
        }
        validators = []

        def fetch_text(url, timeout, redirect_validator=None):
            validators.append(redirect_validator)
            return responses[url]

        with mock.patch.object(fw, "fetch_text", fetch_text):
            [entry] = fw.collect_cve_entries_for_advisory("FG-IR-22-036", timeout=5)
        self.assertEqual(entry["affected"][0]["to"], "6.2.1")
        self.assertEqual(validators, [fw._psirt_page_redirect_allowed] * 2)


class CsafShapeTests(unittest.TestCase):
    def test_and_above_is_a_half_open_range(self) -> None:
        self.assertEqual(
            fw.parse_csaf_version_clause("7.0.6 and above"),
            {"branch": "7.0", "from": "7.0.6", "to": None},
        )
        self.assertIsNone(fw.parse_csaf_version_clause("7.0 and above"))

    def test_a_note_is_dropped_after_a_whole_train_claim_only(self) -> None:
        self.assertEqual(
            fw.parse_csaf_version_clause("6.0 all versions (need to be authenticated)"),
            {"branch": "6.0", "from": None, "to": None},
        )
        self.assertIsNone(fw.parse_csaf_version_clause("7.0.6 (see note)"))

    def test_chassis_and_cloud_variants_are_other_products(self) -> None:
        self.assertIsNone(fw.split_csaf_product_value("FortiOS-6K7K 7.0.10"))
        self.assertIsNone(fw.split_csaf_product_value("FortiManager cloud 7.0 all versions"))
        self.assertEqual(fw.split_csaf_product_value("FortiOS-7.4.4"), ("FortiOS", "-7.4.4"))

    def test_empty_known_affected_about_untracked_products_is_skipped(self) -> None:
        untracked = make_vulnerability("CVE-2024-48886", not_affected=("FortiSASE/ 24.4 all versions",))
        untracked["product_status"]["known_affected"] = []
        tracked = make_vulnerability("CVE-2024-48886", affected=("FortiOS >=7.4.0|<=7.4.4",))
        doc = make_csaf_document("FG-IR-24-221", vulns=[untracked, tracked])
        fw.validate_csaf_document("FG-IR-24-221", doc)
        [entry] = fw.parse_csaf_document("FG-IR-24-221", doc)
        self.assertEqual(entry["affected"][0]["to"], "7.4.4")

    def test_any_other_status_naming_a_tracked_product_keeps_it_invalid(self) -> None:
        vuln = make_vulnerability("CVE-2024-48886", not_affected=("FortiSASE/ 24.4 all versions",))
        vuln["product_status"].update(known_affected=[], under_investigation=["FortiOS 7.6 all versions"])
        doc = make_csaf_document("FG-IR-24-221", vulns=[vuln])
        with self.assertRaises(fw.CsafResolutionError):
            fw.validate_csaf_document("FG-IR-24-221", doc)

    def test_empty_known_affected_stays_invalid_when_it_names_a_tracked_product(self) -> None:
        for statements in (("FortiOS/ 7.6 all versions",), ()):
            vuln = make_vulnerability("CVE-2024-48886", not_affected=statements)
            vuln["product_status"]["known_affected"] = []
            doc = make_csaf_document("FG-IR-24-221", vulns=[vuln])
            with self.subTest(statements=statements), self.assertRaises(fw.CsafResolutionError):
                fw.validate_csaf_document("FG-IR-24-221", doc)


class BackfillDiscoveryTests(unittest.TestCase):
    def test_known_ids_are_left_out_and_listing_is_reported(self) -> None:
        listings = {name: ["FG-IR-26-182", "FG-IR-22-036"] for name in fw.CVE_LISTING_PRODUCT_FILTERS}
        listings["FortiOS"] = ["FG-IR-26-182", "FG-IR-24-015", "FG-IR-22-036"]
        fetched: list[list[str]] = []
        listed: list[str] = []
        with mock.patch.object(
            fw, "discover_advisory_ids_from_listing", lambda name, pages, timeout: listings[name]
        ), mock.patch.object(
            fw, "fetch_cve_entries_for_advisories",
            lambda ids, timeout, *, reasons=None: (fetched.append(list(ids)), ({}, []))[1],
        ):
            fw.collect_cve_catalog({"FG-IR-24-015"}, 5, backfill=True, listed=listed)
        self.assertEqual(fetched, [["FG-IR-26-182", "FG-IR-22-036"]])
        self.assertEqual(listed, ["FG-IR-26-182", "FG-IR-24-015", "FG-IR-22-036"])

    def test_an_empty_product_listing_fails_the_backfill(self) -> None:
        with mock.patch.object(
            fw, "discover_advisory_ids_from_listing",
            lambda name, pages, timeout: [] if name == "FortiClientEMS" else ["FG-IR-24-015"],
        ), self.assertRaises(fw.CsafResolutionError):
            fw.collect_cve_catalog(set(), 5, backfill=True, listed=[])


class HistoryRecordTests(unittest.TestCase):
    def test_rss_continuity_keeps_the_history_record(self) -> None:
        history = {"checkedAt": "2026-10-15T18:00:00Z", "listedAdvisories": 318, "unresolved": []}
        coverage, _gap = fw.update_cve_coverage(
            {"rssSeenIds": ["FG-IR-26-182"], "history": history}, ["FG-IR-26-182"], "2026-10-16T05:00:00Z"
        )
        self.assertEqual(coverage["history"], history)

    def run_backfill(self, skipped: dict[str, str], results: dict):
        def collect(*_args, reasons=None, listed=None, **_kwargs):
            reasons.update(skipped)
            listed.extend(["FG-IR-22-059", "FG-IR-23-424", "FG-IR-26-182"])
            return dict(results), list(skipped)

        with tempfile.TemporaryDirectory() as tmp:
            base_path = Path(tmp) / "state.json"
            fw.write_json(
                base_path,
                {**fw.normalize_state({}), "cveCoverage": {"rssSeenIds": ["FG-IR-26-182"], "gaps": []}},
            )
            health_path = Path(tmp) / "health.json"
            with mock.patch.object(fw, "collect_cve_catalog", collect), mock.patch.object(
                fw, "fetch_cve_entries_for_advisories",
                lambda ids, _t, *, reasons=None: ({}, list(ids)),
            ), mock.patch.object(fw, "fetch_psirt_versions", lambda *a, **k: set()), mock.patch.object(
                fw.time, "sleep", lambda _s: None
            ):
                exit_code = fw.main([
                    "--cve-backfill",
                    "--base", str(base_path), "--output", str(base_path),
                    "--report", str(Path(tmp) / "report.md"), "--health-output", str(health_path),
                ])
            self.assertEqual(exit_code, 0)
            catalogue = fw.read_json(base_path, {})
            sources = fw.read_json(health_path, {})["sources"]
            # The weekly check has its own source: the daily RSS record and summary are untouched.
            self.assertNotIn(fw.SOURCE_CVE_PSIRT, sources)
            self.assertNotIn(fw.SOURCE_DAILY_RUN, sources)
            return catalogue, sources[fw.SOURCE_CVE_HISTORY]

    def test_backfill_records_the_check_and_what_stayed_unresolved(self) -> None:
        catalogue, record = self.run_backfill({"FG-IR-22-059": fw.SKIP_REASON_NO_CSAF}, {"FG-IR-23-424": []})
        history = catalogue["cveCoverage"]["history"]
        self.assertEqual(history["listedAdvisories"], 3)
        self.assertEqual(history["failed"], 0)  # a legacy no-CSAF advisory is not a failure
        self.assertEqual(history["unresolved"], [{"id": "FG-IR-22-059", "reason": "sans export CSAF"}])
        self.assertEqual(catalogue["cveCoverage"]["rssSeenIds"], ["FG-IR-26-182"])  # untouched
        self.assertEqual(record["status"], fw.HEALTH_STATUS_OK)

    def test_a_failed_read_makes_the_check_incomplete(self) -> None:
        catalogue, record = self.run_backfill({"FG-IR-24-221": fw.SKIP_REASON_INVALID}, {"FG-IR-23-424": []})
        self.assertEqual(catalogue["cveCoverage"]["history"]["failed"], 1)
        self.assertEqual(record["status"], fw.HEALTH_STATUS_WARNING)

    def test_weekly_pass_left_with_only_legacy_advisories_is_not_an_outage(self) -> None:
        _catalogue, record = self.run_backfill({"FG-IR-22-059": fw.SKIP_REASON_NO_CSAF}, {})
        self.assertEqual(record["status"], fw.HEALTH_STATUS_OK)


IMPORTED_CVE = {
    "id": "CVE-2023-46717", "advisoryId": "FG-IR-23-424", "title": "Improper authentication",
    "severity": "high", "cvssScore": 7.5,
    "url": "https://fortiguard.fortinet.com/psirt/FG-IR-23-424",
    "publishedAt": "2024-02-22", "updatedAt": "2024-06-19",
    "affected": [{"product": fw.DEFAULT_PRODUCT_ID, "models": [], "branch": "7.0",
                  "from": "7.0.0", "to": "7.0.12"}],
}


class BackfillCrashSilenceTests(unittest.TestCase):
    """The weekly backfill can be killed by any redeploy: one dying right after its catalogue
    commit, before the checkpoint advance, must not make the next normal pass notify history."""

    def run_pass(self, tmp: Path, flags: list[str], results: dict) -> None:
        def collect(*_args, reasons=None, listed=None, **_kwargs):
            if listed is not None:
                listed.append("FG-IR-23-424")
            return {key: [dict(entry) for entry in value] for key, value in results.items()}, []

        with mock.patch.object(fw, "collect_cve_catalog", collect), mock.patch.object(
            fw, "fetch_psirt_versions", lambda *a, **k: set()
        ):
            fw.main([
                *flags,
                "--base", str(tmp / "state.json"), "--output", str(tmp / "state.json"),
                "--report", str(tmp / "report.md"), "--health-output", str(tmp / "health.json"),
                "--official-paths-csv", str(tmp / "none.csv"),
                "--advisories-csv", str(tmp / "none-advisories.csv"),
                "--upgrade-exports", str(tmp / "no-exports"),
                "--notify-history-output", str(tmp / "history.json"),
                "--notification-settings-output", str(tmp / "notification-settings.json"),
                "--cve-retry-delays-seconds", "",
            ])

    def replayed_keys(self, *, stage) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            fw.write_json(tmp / "state.json", fw.normalize_state({}))
            payload = fn._default_notification_settings_payload()
            payload["enabled"] = True
            payload["recipients"] = ["ops@example.com"]
            fn.save_notification_settings(tmp / "notification-settings.json", payload)
            fn.ensure_checkpoint(
                tmp / "history.json", {"versionsByProduct": {}, "cvesById": {}, "health": {}}
            )
            real_commit = fw.commit_collected_state

            def commit_then_die(*args, **kwargs):
                real_commit(*args, **kwargs)
                raise KeyboardInterrupt()

            with mock.patch.object(fw, "commit_collected_state", side_effect=commit_then_die), mock.patch.object(
                fn, "stage_pending_cve_baseline", stage
            ), self.assertRaises(KeyboardInterrupt):
                self.run_pass(tmp, ["--cve-backfill"], {"FG-IR-23-424": [IMPORTED_CVE]})
            self.assertIn(
                "CVE-2023-46717", {c["id"] for c in fw.read_json(tmp / "state.json", {})["cves"]}
            )
            self.run_pass(tmp, ["--cve-catalog"], {})
            state = fn.load_notify_state(tmp / "history.json")
            return [
                key
                for key in [entry.get("dedupKey") for entry in state["outbox"]] + list(state["sentKeys"])
                if key and "CVE-2023-46717" in key
            ]

    def setup_state(self, tmp: Path, *, catalogue_cves=(), checkpoint_cves=None) -> None:
        fw.write_json(tmp / "state.json", {**fw.normalize_state({}), "cves": list(catalogue_cves)})
        payload = fn._default_notification_settings_payload()
        payload["enabled"] = True
        payload["recipients"] = ["ops@example.com"]
        fn.save_notification_settings(tmp / "notification-settings.json", payload)
        fn.ensure_checkpoint(
            tmp / "history.json",
            {"versionsByProduct": {}, "cvesById": dict(checkpoint_cves or {}), "health": {}},
        )

    def queued_keys(self, tmp: Path) -> list[str]:
        state = fn.load_notify_state(tmp / "history.json")
        return [entry.get("dedupKey") for entry in state["outbox"]] + list(state["sentKeys"])

    def test_a_recent_advisory_imported_by_the_backfill_still_notifies(self) -> None:
        recent = dict(IMPORTED_CVE, id="CVE-2026-55555", advisoryId="FG-IR-26-190",
                      publishedAt=dt.date.today().isoformat())
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            self.setup_state(tmp)
            self.run_pass(tmp, ["--cve-backfill"], {"FG-IR-26-190": [recent], "FG-IR-23-424": [IMPORTED_CVE]})
            checkpoint = fn.load_notify_state(tmp / "history.json")["checkpoint"]["cvesById"]
            self.assertIn("CVE-2023-46717", checkpoint)
            self.assertNotIn("CVE-2026-55555", checkpoint)
            self.assertNotIn("kev", checkpoint["CVE-2023-46717"])  # unknown KEV baseline
            self.assertEqual(self.queued_keys(tmp), [])
            self.run_pass(tmp, ["--cve-catalog"], {})
            self.assertEqual(self.queued_keys(tmp), ["new-cve|psirt|CVE-2026-55555|high"])

    def test_the_backfill_never_absorbs_a_novelty_it_did_not_import(self) -> None:
        # A normal pass committed this CVE, then died before its notification work.
        pending = dict(IMPORTED_CVE, id="CVE-2026-44444", advisoryId="FG-IR-26-180",
                       publishedAt=dt.date.today().isoformat(), severity="critical", cvssScore=9.8)
        known = dict(IMPORTED_CVE, id="CVE-2026-33333", advisoryId="FG-IR-26-170")
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            self.setup_state(
                tmp, catalogue_cves=[pending, known],
                checkpoint_cves={"CVE-2026-33333": {**known, "kev": False}},
            )
            self.run_pass(tmp, ["--cve-backfill"], {"FG-IR-23-424": [IMPORTED_CVE]})
            checkpoint = fn.load_notify_state(tmp / "history.json")["checkpoint"]["cvesById"]
            self.assertNotIn("CVE-2026-44444", checkpoint)
            self.assertIs(checkpoint["CVE-2026-33333"]["kev"], False)  # KEV baseline kept
            self.run_pass(tmp, ["--cve-catalog"], {})
            self.assertEqual(self.queued_keys(tmp), ["new-cve|psirt|CVE-2026-44444|critical"])

    def test_crash_after_the_commit_stays_silent(self) -> None:
        self.assertEqual(self.replayed_keys(stage=fn.stage_pending_cve_baseline), [])

    def test_canary_without_the_durable_intent_the_history_is_replayed(self) -> None:
        self.assertEqual(
            self.replayed_keys(stage=lambda *_a, **_k: 0), ["new-cve|psirt|CVE-2023-46717|high"]
        )


class WeeklySchedulerTests(unittest.TestCase):
    PARIS = ZoneInfo("Europe/Paris")

    def test_history_check_runs_on_sunday_at_0600(self) -> None:
        saturday_evening = dt.datetime(2026, 10, 17, 20, 0, tzinfo=self.PARIS)
        scheduled, job = scheduler.next_job(saturday_evening)
        self.assertEqual(job, "cve-history")
        self.assertEqual((scheduled.weekday(), scheduled.hour, scheduled.minute), (6, 6, 0))
        monday = dt.datetime(2026, 10, 19, 7, 30, tzinfo=self.PARIS)
        self.assertEqual(scheduler.next_job(monday)[1], "recovery")

    def test_history_job_is_dispatched(self) -> None:
        sunday = dt.datetime(2026, 10, 18, 6, 0, tzinfo=self.PARIS)
        with mock.patch.object(scheduler, "run_cve_history_refresh", return_value=0) as history:
            self.assertEqual(scheduler.run_scheduled_job("cve-history", now_fn=lambda: sunday), 0)
        history.assert_called_once_with()

    def test_a_history_check_overrunning_0745_runs_the_recovery_right_after(self) -> None:
        now_values = iter([
            dt.datetime(2026, 10, 18, 6, 0, tzinfo=self.PARIS),
            dt.datetime(2026, 10, 18, 7, 50, tzinfo=self.PARIS),
        ])
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            scheduler, "run_cve_history_refresh", return_value=0
        ), mock.patch.object(scheduler, "run_recovery", return_value=0) as recovery:
            scheduler.run_scheduled_job(
                "cve-history", now_fn=lambda: next(now_values), marker_path=Path(tmp) / "r.lock"
            )
        recovery.assert_called_once_with(ensure_full_today=True)

    def test_history_refresh_is_a_silent_backfill_without_kev(self) -> None:
        calls = []

        def runner(command, cwd, check):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(refresh.run_cve_history_refresh(root=Path(tmp), runner=runner, python="py"), 0)
        self.assertEqual(
            calls,
            [["py", "scripts/fortios_watch.py", "--base", "data/fortios-data.generated.json", "--cve-backfill"]],
        )

    def test_never_checked_until_a_history_record_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "data").mkdir()
            self.assertTrue(refresh.cve_history_never_checked(root))
            fw.write_json(root / "data" / "fortios-data.generated.json", {"cveCoverage": {"history": {}}})
            self.assertFalse(refresh.cve_history_never_checked(root))


if __name__ == "__main__":
    unittest.main()
