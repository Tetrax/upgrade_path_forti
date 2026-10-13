"""CISA KEV enrichment (exploited CVEs) and PSIRT RSS continuity (cveCoverage).

Covers the feed parsing, the catalogue flags, the notification transition rules (a KEV listing
is notified once, never replayed from an unknown baseline) and the RSS gap detection, unit by
unit and through the real collection path with every network call mocked.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import fortios_email_render as render
import fortios_notify as notify
import fortios_watch as fw

from tests.test_security_notifications import PRODUCT_SELECTIONS, cve, settings_payload

FMG = [PRODUCT_SELECTIONS["fortimanager"]]
LISTED = {"dateAdded": "2026-10-01", "ransomware": False}


def kev_document(entries: list[dict[str, Any]], *, padding: int = fw.KEV_MIN_ENTRIES) -> dict:
    filler = [
        {"cveID": f"CVE-2020-{10000 + index}", "vendorProject": "Other", "dateAdded": "2020-01-01"}
        for index in range(padding)
    ]
    return {"title": "CISA KEV", "vulnerabilities": [*entries, *filler]}


class KevFeedTests(unittest.TestCase):
    def test_only_fortinet_entries_are_kept_with_normalized_fields(self) -> None:
        listed = fw.parse_cisa_kev(
            kev_document(
                [
                    {
                        "cveID": "cve-2026-104286",
                        "vendorProject": "Fortinet",
                        "dateAdded": "2026-10-01",
                        "knownRansomwareCampaignUse": "Known",
                    },
                    {"cveID": "CVE-2026-1111", "vendorProject": "fortinet", "dateAdded": "bad"},
                    {"cveID": "not-a-cve", "vendorProject": "Fortinet"},
                    "garbage",
                ]
            )
        )
        self.assertEqual(
            listed,
            {
                "CVE-2026-104286": {"dateAdded": "2026-10-01", "ransomware": True},
                "CVE-2026-1111": {"dateAdded": None, "ransomware": False},
            },
        )

    def test_a_short_or_malformed_document_is_refused(self) -> None:
        with self.assertRaises(fw.KevFeedError):
            fw.parse_cisa_kev(kev_document([], padding=3))
        for payload in (None, [], {"vulnerabilities": "x"}):
            with self.subTest(payload=payload), self.assertRaises(fw.KevFeedError):
                fw.parse_cisa_kev(payload)

    def test_annotations_mark_listed_and_checked_cves(self) -> None:
        state = fw.normalize_state(
            {"cves": [cve("CVE-2026-1", "medium", FMG), cve("CVE-2026-2", "high", FMG)]}
        )
        self.assertEqual(fw.apply_kev_annotations(state, {"CVE-2026-1": LISTED}), 1)
        self.assertEqual(state["cves"][0]["kev"], LISTED)
        self.assertIs(state["cves"][1]["kev"], False)

    def test_a_csaf_refetch_keeps_the_flag_and_is_not_an_update(self) -> None:
        state = fw.normalize_state({"cves": [{**cve("CVE-2026-1", "medium", FMG), "kev": LISTED}]})
        self.assertFalse(fw.upsert_cve(state, cve("CVE-2026-1", "medium", FMG)))
        self.assertEqual(state["cves"][0]["kev"], LISTED)
        self.assertTrue(fw.upsert_cve(state, cve("CVE-2026-1", "high", FMG)))
        self.assertEqual(state["cves"][0]["kev"], LISTED)

    def test_catalogue_without_coverage_keeps_its_historical_shape(self) -> None:
        self.assertNotIn("cveCoverage", fw.normalize_state({}))
        self.assertEqual(
            fw.normalize_state({"cveCoverage": {"continuousSince": "x"}})["cveCoverage"],
            {"continuousSince": "x"},
        )


class CoverageTests(unittest.TestCase):
    def test_first_observation_starts_continuity_without_gap(self) -> None:
        coverage, gap = fw.update_cve_coverage(None, ["FG-IR-26-2", "FG-IR-26-1"], "T1")
        self.assertFalse(gap)
        self.assertEqual(coverage["continuousSince"], "T1")
        self.assertEqual(coverage["rssSeenIds"], ["FG-IR-26-1", "FG-IR-26-2"])
        self.assertEqual(coverage["gaps"], [])

    def test_overlapping_windows_keep_continuity(self) -> None:
        first, _ = fw.update_cve_coverage(None, ["A", "B"], "T1")
        second, gap = fw.update_cve_coverage(first, ["B", "C"], "T2")
        self.assertFalse(gap)
        self.assertEqual(second["continuousSince"], "T1")
        self.assertEqual(second["lastCheckAt"], "T2")

    def test_disjoint_windows_record_a_gap_and_restart_continuity(self) -> None:
        first, _ = fw.update_cve_coverage(None, ["A", "B"], "T1")
        second, gap = fw.update_cve_coverage(first, ["C", "D"], "T2")
        self.assertTrue(gap)
        self.assertEqual(second["continuousSince"], "T2")
        self.assertEqual(second["gaps"], [{"detectedAt": "T2", "previousCheckAt": "T1"}])

    def test_gap_history_is_bounded_and_malformed_records_are_tolerated(self) -> None:
        coverage: Any = {"rssSeenIds": "bad", "gaps": "bad", "continuousSince": 3}
        coverage, gap = fw.update_cve_coverage(coverage, ["A"], "T0")
        self.assertFalse(gap)
        for index in range(fw.CVE_COVERAGE_MAX_GAPS + 5):
            coverage, gap = fw.update_cve_coverage(coverage, [f"X{index}"], f"T{index + 1}")
            self.assertTrue(gap)
        self.assertEqual(len(coverage["gaps"]), fw.CVE_COVERAGE_MAX_GAPS)


class KevEventTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = notify.validate_notification_settings(settings_payload())

    def entry(self, cve_id: str = "CVE-2026-1", severity: str = "medium", **extra: Any) -> dict:
        return {**cve(cve_id, severity, FMG), **extra}

    def test_checked_then_listed_notifies_once_whatever_the_threshold(self) -> None:
        events = notify.derive_kev_events(
            {"CVE-2026-1": self.entry(kev=False)},
            {"CVE-2026-1": self.entry(kev=LISTED)},
            self.settings,
        )
        self.assertEqual([event.dedup_key for event in events], ["cve-kev|cisa|CVE-2026-1|listed"])
        self.assertEqual(events[0].details["change"], "kev-listed")
        self.assertEqual(events[0].details["kev"], LISTED)

    def test_unknown_baseline_or_already_listed_is_silent(self) -> None:
        for before in (self.entry(), self.entry(kev=LISTED)):
            with self.subTest(before=before.get("kev", "absent")):
                self.assertEqual(
                    notify.derive_kev_events(
                        {"CVE-2026-1": before},
                        {"CVE-2026-1": self.entry(kev=LISTED)},
                        self.settings,
                    ),
                    [],
                )

    def test_removal_and_unlisted_are_silent(self) -> None:
        self.assertEqual(
            notify.derive_kev_events(
                {"CVE-2026-1": self.entry(kev=LISTED)},
                {"CVE-2026-1": self.entry(kev=False)},
                self.settings,
            ),
            [],
        )

    def test_new_listed_cve_is_notified_unless_its_new_cve_event_carries_it(self) -> None:
        after = {"CVE-2026-1": self.entry(kev=LISTED)}
        self.assertEqual(len(notify.derive_kev_events({}, after, self.settings)), 1)
        self.assertEqual(
            notify.derive_kev_events(
                {}, after, self.settings, already_notified_ids={"CVE-2026-1"}
            ),
            [],
        )

    def test_unselected_product_is_silent(self) -> None:
        settings = notify.validate_notification_settings(
            settings_payload(selected={"fortigate-fortios"})
        )
        self.assertEqual(
            notify.derive_kev_events(
                {"CVE-2026-1": self.entry(kev=False)},
                {"CVE-2026-1": self.entry(kev=LISTED)},
                settings,
            ),
            [],
        )

    def test_revalidation_drops_a_listing_the_durable_state_already_absorbed(self) -> None:
        events = notify.derive_kev_events(
            {"CVE-2026-1": self.entry(kev=False)},
            {"CVE-2026-1": self.entry(kev=LISTED)},
            self.settings,
        )
        absorbed = {"cvesById": {"CVE-2026-1": self.entry(kev=LISTED)}}
        pending = {"cvesById": {"CVE-2026-1": self.entry(kev=False)}}
        self.assertEqual(notify._revalidate_cve_events_against_checkpoint(events, absorbed), [])
        self.assertEqual(
            notify._revalidate_cve_events_against_checkpoint(events, pending), events
        )

    def test_email_names_the_exploitation_only_when_listed(self) -> None:
        kev_events = notify.derive_kev_events(
            {"CVE-2026-1": self.entry(kev=False)},
            {"CVE-2026-1": self.entry(kev={"dateAdded": "2026-10-01", "ransomware": True})},
            self.settings,
        )
        subject, text_body, html_body = notify.compose_email(
            kev_events, app_url="https://upgrade.example/", run_timestamp="2026-10-13T07:00:00Z"
        )
        self.assertEqual(subject, "[FortiUpgrade] 1 vulnérabilité exploitée activement — 1 Medium")
        self.assertIn("Exploitation active confirmée (CISA KEV, ajoutée le 1 octobre 2026)", text_body)
        self.assertIn("rançongiciel", text_body)
        self.assertIn("désormais exploitée activement", html_body)

        plain = notify.derive_new_cve_events([self.entry("CVE-2026-9", "high")], self.settings)
        _, plain_text, plain_html = notify.compose_email(
            plain, app_url="https://upgrade.example/", run_timestamp="2026-10-13T07:00:00Z"
        )
        self.assertNotIn("CISA KEV", plain_text)
        self.assertNotIn("CISA KEV", plain_html)
        self.assertEqual(render._kev_text({"kev": False}), "")


class CollectionPathTests(unittest.TestCase):
    """The real fortios_watch.main() path: KEV flags, notification once, RSS gap health."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.root = root
        self.base = root / "state.json"
        self.health = root / "health.json"
        self.history = root / "notify-history.json"
        self.settings = root / "notification-settings.json"
        self.catalog_cves = [cve("CVE-2026-1", "medium", FMG), cve("CVE-2026-2", "medium", FMG)]
        fw.write_json(self.base, fw.normalize_state({"cves": self.catalog_cves}))
        notify.save_notification_settings(self.settings, settings_payload(selected={"fortimanager"}))
        # A notification state that predates KEV: checkpoint entries without the flag.
        notify.ensure_checkpoint(
            self.history,
            {
                "versionsByProduct": {},
                "cvesById": {item["id"]: item for item in self.catalog_cves},
                "health": {},
            },
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_collection(
        self, *, kev: Any, rss: tuple[str, ...] = ("FG-IR-26-001",)
    ) -> MagicMock:
        client = MagicMock()
        client.__enter__ = MagicMock(return_value=client)
        client.__exit__ = MagicMock(return_value=False)
        results = {advisory: [] for advisory in rss}
        results["FG-IR-26-001"] = [dict(item) for item in self.catalog_cves]
        kev_patch = (
            patch.object(fw, "fetch_cisa_kev", side_effect=kev)
            if isinstance(kev, Exception)
            else patch.object(fw, "fetch_cisa_kev", return_value=kev)
        )
        with (
            patch.dict(
                os.environ,
                {"FORTIOS_SMTP_HOST": "smtp.example.com", "FORTIOS_SMTP_FROM": "fu@example.com"},
                clear=True,
            ),
            patch.object(fw, "collect_cve_catalog", return_value=(results, [])),
            patch.object(fw, "fetch_psirt_versions", return_value=set()),
            kev_patch,
            patch("smtplib.SMTP", return_value=client),
        ):
            exit_code = fw.main(
                [
                    "--cve-catalog",
                    "--kev-catalog",
                    "--base", str(self.base),
                    "--output", str(self.base),
                    "--report", str(self.root / "report.md"),
                    "--health-output", str(self.health),
                    "--notify-history-output", str(self.history),
                    "--notification-settings-output", str(self.settings),
                    "--official-paths-csv", str(self.root / "none.csv"),
                    "--advisories-csv", str(self.root / "none-advisories.csv"),
                    "--upgrade-exports", str(self.root / "none-exports"),
                ]
            )
        self.assertEqual(exit_code, 0)
        return client

    def catalog(self) -> dict[str, Any]:
        return json.loads(self.base.read_text(encoding="utf-8"))

    def sources(self) -> dict[str, Any]:
        return json.loads(self.health.read_text(encoding="utf-8"))["sources"]

    def test_first_kev_read_is_silent_then_a_new_listing_is_sent_exactly_once(self) -> None:
        first = self.run_collection(kev={"CVE-2026-1": LISTED})
        first.send_message.assert_not_called()
        flags = {item["id"]: item["kev"] for item in self.catalog()["cves"]}
        self.assertEqual(flags, {"CVE-2026-1": LISTED, "CVE-2026-2": False})
        self.assertEqual(self.sources()["cisa-kev"]["status"], "ok")

        second = self.run_collection(kev={"CVE-2026-1": LISTED, "CVE-2026-2": LISTED})
        second.send_message.assert_called_once()
        message = second.send_message.call_args.args[0]
        self.assertIn("exploitée activement", message["Subject"])
        body = message.get_body(preferencelist=("plain",)).get_content()
        self.assertIn("CVE-2026-2", body)
        self.assertNotIn("CVE-2026-1", body)
        state = notify.load_notify_state(self.history)
        self.assertIn("cve-kev|cisa|CVE-2026-2|listed", state["sentKeys"])
        self.assertEqual(state["outbox"], [])

        third = self.run_collection(kev={"CVE-2026-1": LISTED, "CVE-2026-2": LISTED})
        third.send_message.assert_not_called()

    def test_kev_outage_keeps_the_flags_and_spares_the_psirt_source(self) -> None:
        self.run_collection(kev={"CVE-2026-1": LISTED})
        self.run_collection(kev=fw.KevFeedError("catalogue CISA KEV anormalement court"))
        flags = {item["id"]: item["kev"] for item in self.catalog()["cves"]}
        self.assertEqual(flags, {"CVE-2026-1": LISTED, "CVE-2026-2": False})
        self.assertEqual(self.sources()["cisa-kev"]["status"], "error")
        self.assertEqual(self.sources()["cve-psirt"]["status"], "ok")

    def test_disjoint_rss_windows_raise_a_gap_warning_and_record_it(self) -> None:
        self.run_collection(kev={}, rss=("FG-IR-26-001",))
        self.assertEqual(self.sources()["cve-psirt"]["status"], "ok")
        self.assertEqual(self.catalog()["cveCoverage"]["gaps"], [])

        self.run_collection(kev={}, rss=("FG-IR-26-001", "FG-IR-26-002"))
        self.assertEqual(self.sources()["cve-psirt"]["status"], "ok")
        self.assertEqual(self.catalog()["cveCoverage"]["gaps"], [])

        # The previous collection saw a window that shares nothing with the next one (the feed
        # moved by more than its whole size in between).
        catalog = self.catalog()
        catalog["cveCoverage"]["rssSeenIds"] = ["FG-IR-25-999"]
        fw.write_json(self.base, catalog)

        self.run_collection(kev={}, rss=("FG-IR-26-001",))
        source = self.sources()["cve-psirt"]
        self.assertEqual(source["status"], "warning")
        self.assertIn("trou possible dans le flux rss psirt", source["lastError"].lower())
        coverage = self.catalog()["cveCoverage"]
        self.assertEqual(len(coverage["gaps"]), 1)
        self.assertEqual(coverage["continuousSince"], coverage["gaps"][0]["detectedAt"])

    def test_a_cve_added_while_kev_is_down_is_still_notified_when_listed(self) -> None:
        self.run_collection(kev={"CVE-2026-1": LISTED})
        self.catalog_cves.append(cve("CVE-2026-3", "medium", FMG))
        quiet = self.run_collection(kev=fw.KevFeedError("indisponible"))
        quiet.send_message.assert_not_called()
        self.assertNotIn(
            "kev", next(c for c in self.catalog()["cves"] if c["id"] == "CVE-2026-3")
        )
        listed = self.run_collection(kev={"CVE-2026-1": LISTED, "CVE-2026-3": LISTED})
        listed.send_message.assert_called_once()
        body = listed.send_message.call_args.args[0].get_body(preferencelist=("plain",)).get_content()
        self.assertIn("CVE-2026-3", body)

class ReviewRegressionTests(unittest.TestCase):
    """Paths found in review that silently lost a KEV notification or duplicated a CVE."""

    def setUp(self) -> None:
        self.settings = notify.validate_notification_settings(settings_payload())

    def test_a_consumed_reconciliation_keeps_the_durable_kev_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify-history.json"
            checked = {**cve("CVE-2026-1", "medium", FMG), "kev": False}
            notify.ensure_checkpoint(
                path, {"versionsByProduct": {}, "cvesById": {"CVE-2026-1": checked}, "health": {}}
            )
            corrected = {**cve("CVE-2026-1", "medium", FMG), "title": "Corrigé"}
            notify.stage_pending_cve_baseline(path, {"CVE-2026-1": corrected})
            self.assertEqual(
                notify.consume_pending_cve_baseline(path, {"CVE-2026-1": corrected}), (1, 0)
            )
            durable = notify.load_notify_state(path)["checkpoint"]["cvesById"]["CVE-2026-1"]
        self.assertEqual(durable["title"], "Corrigé")
        self.assertIs(durable["kev"], False)
        events = notify.derive_kev_events(
            {"CVE-2026-1": durable},
            {"CVE-2026-1": {**corrected, "kev": LISTED}},
            self.settings,
        )
        self.assertEqual(len(events), 1)

    def test_durable_kev_merge_never_forges_a_baseline(self) -> None:
        merged = notify.with_durable_kev(
            {"CVE-2026-1": {"id": "CVE-2026-1", "kev": LISTED}, "CVE-2026-2": {"id": "CVE-2026-2"}},
            {"CVE-2026-2": {"id": "CVE-2026-2", "kev": False}},
        )
        self.assertNotIn("kev", merged["CVE-2026-1"])
        self.assertIs(merged["CVE-2026-2"]["kev"], False)

    def test_an_escalation_carrying_the_flag_is_the_only_section_for_its_cve(self) -> None:
        before = {"CVE-2026-1": {**cve("CVE-2026-1", "medium", FMG), "kev": False}}
        after = {"CVE-2026-1": {**cve("CVE-2026-1", "high", FMG), "kev": LISTED}}
        escalations = notify.derive_cve_modification_events(before, after, self.settings)
        self.assertEqual(escalations[0].details["kev"], LISTED)
        self.assertEqual(
            notify.derive_kev_events(
                before, after, self.settings, already_notified_ids={"CVE-2026-1"}
            ),
            [],
        )

    def test_a_document_without_fortinet_entries_is_refused(self) -> None:
        with self.assertRaises(fw.KevFeedError):
            fw.parse_cisa_kev(kev_document([]))

    def test_a_listing_is_definitive_so_a_degraded_feed_cannot_replay_it(self) -> None:
        state = fw.normalize_state({"cves": [{**cve("CVE-2026-1", "medium", FMG), "kev": LISTED}]})
        self.assertEqual(fw.apply_kev_annotations(state, {"CVE-2026-9": LISTED}), 1)
        self.assertEqual(state["cves"][0]["kev"], LISTED)

    def test_recovery_retries_a_failed_kev_read_with_its_cve_pass(self) -> None:
        import scheduled_refresh as refresh

        plan = refresh.build_retry_plan(
            {"sources": {"cisa-kev": {"status": "error", "consecutiveFailures": 1}}}
        )
        self.assertIn("--cve-catalog", plan.catalog_args)
        self.assertIn("--kev-catalog", plan.catalog_args)
        psirt_plan = refresh.build_retry_plan(
            {"sources": {"cve-psirt": {"status": "error", "consecutiveFailures": 1}}}
        )
        self.assertIn("--kev-catalog", psirt_plan.catalog_args)

    def test_coverage_is_chained_on_the_record_on_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            earlier_gap = {"detectedAt": "T1", "previousCheckAt": "T0"}
            fw.write_json(
                path,
                fw.normalize_state(
                    {"cveCoverage": {"rssSeenIds": ["A"], "gaps": [earlier_gap],
                                     "continuousSince": "T1", "lastCheckAt": "T1"}}
                ),
            )
            stale_snapshot = fw.normalize_state({})
            final = fw.commit_collected_state(path, stale_snapshot, [], [], {}, rss_ids=["A", "B"])
        self.assertEqual(final["cveCoverage"]["gaps"], [earlier_gap])
        self.assertEqual(final["cveCoverage"]["continuousSince"], "T1")


if __name__ == "__main__":
    unittest.main()
