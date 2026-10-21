"""Recovery of the CVEs the PSIRT collection never brought (weekly --cve-backfill --cve-crosscheck).

Audit of 2026-10-20: 90 NVD CVEs reached a catalogued version without being in the catalogue,
nearly all from FG-IR-16 to FG-IR-21 advisories the per-product PSIRT listing no longer shows and
that Fortinet never exported exactly. Each is traced to its advisory through the FG-IR link of
Fortinet's CVE record; an exact export is imported as is, otherwise Fortinet's other statements
(structured CVE.org record, advisory page) must agree with NVD on a catalogued version. What NVD
alone states is still never shown.
"""

from __future__ import annotations

import datetime as dt
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
sys.path.insert(0, str(ROOT))

import fortios_notify as notify
import fortios_watch as fw

from tests.test_cve_crosscheck import (
    catalogue,
    cpe,
    le,
    nvd_cve,
    nvd_pages,
    product,
    rng,
)
from tests.test_security_notifications import cve, settings_payload


def record(cve_id: str, advisory_ids: list[str], *affected: dict, score: float | None = None, severity: str = "") -> dict:
    cna: dict[str, Any] = {
        "affected": list(affected),
        "references": [{"url": f"https://fortiguard.com/psirt/{advisory_id}"} for advisory_id in advisory_ids],
    }
    if score is not None:
        cna["metrics"] = [{"format": "CVSS", "cvssV3_1": {"baseScore": score, "baseSeverity": severity}}]
    return {"cveMetadata": {"cveId": cve_id}, "containers": {"cna": cna}}


def page(
    advisory_id: str,
    cve_ids: list[str],
    *,
    affected: str = "",
    title: str = "Heap overflow in sslvpnd",
    published: str = "Jul 5, 2020",
    severity: str = "High",
    cvss: str = "7.5",
) -> str:
    buttons = "".join(
        f'<button type="button" class="fg-green cve-button" data-cveid="{cve_id}">{cve_id}</button>' for cve_id in cve_ids
    )
    return f"""<html><section><h1 class="title" style="word-break: unset !important;">{title}</h1></section>
<div class="detail-item"><h2 class="h3">Affected Products</h2>{affected}</div>
<div class="detail-item"><h2 class="h3">Solutions</h2><p>Please upgrade.</p></div>
<table lang="en" class="table table-responsive table-borderless meta">
<tr><td>IR Number</td><td>{advisory_id}</td></tr>
<tr><td>Published Date</td><td>{published}</td></tr>
<tr><td>Severity</td><td><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> {severity} </td></tr>
<tr><td>CVSSv3 Score</td><td><a target="_blank" href=" https://nvd.nist.gov/x">{cvss}</a></td></tr>
<tr><td>CVE ID</td><td>{buttons}</td></tr>
</table></html>"""


def nvd_of(*items: dict) -> dict[str, dict[str, Any]]:
    return fw.parse_nvd_fortinet(nvd_pages(*items))


VERSIONS = [("fortigate-fortios", None, version) for version in ("6.2.4", "7.0.2", "7.2.11")]


class AttributionTests(unittest.TestCase):
    def test_advisory_ids_come_from_fortiguard_links_only(self) -> None:
        doc = record("CVE-2024-1001", [])
        doc["containers"]["cna"]["references"] = [
            {"url": "https://fortiguard.com/advisory/FG-IR-19-223"},
            {"url": "http://fortiguard.fortinet.com/psirt/fg-ir-19-223"},
            {"url": "https://www.fortiguard.com/psirt/FG-IR-20-014"},
            {"url": "https://evil.example/psirt/FG-IR-21-001"},
            {"url": "https://fortiguard.com/psirt/FG-IR-21-002-extra"},
            {"url": "http://www.securityfocus.com/bid/94480"},
        ]
        self.assertEqual(fw.cve_org_advisory_ids(doc), ["FG-IR-19-223", "FG-IR-20-014"])
        self.assertEqual(fw.cve_org_advisory_ids(None), [])

    def test_page_meta_is_read_from_the_sidebar(self) -> None:
        meta = fw.parse_psirt_page_meta(page("FG-IR-20-131", ["CVE-2021-26110"], published="Dec 7, 2021", cvss="7.8"))
        self.assertEqual(
            meta,
            {
                "advisoryId": "FG-IR-20-131",
                "title": "Heap overflow in sslvpnd",
                "publishedAt": "2021-12-07",
                "severity": "high",
                "cvssScore": 7.8,
                "cveIds": ["CVE-2021-26110"],
            },
        )
        self.assertIsNone(fw.parse_psirt_page_meta("<html><title>Just a moment...</title></html>"))


class CompleteReadTests(unittest.TestCase):
    """A page or a record read as the only statement of a CVE's versions must be read in full."""

    def test_a_prose_line_in_another_wording_makes_the_page_unreadable(self) -> None:
        prose = page(
            "FG-IR-20-131",
            ["CVE-2024-1001"],
            affected="<p>FortiOS version 7.0.0</p><p>FortiOS versions 6.4.6 and below.</p><p>FortiOS 5.6 all versions</p>",
        )
        self.assertIsNone(fw.parse_psirt_page_affected(prose, complete=True))
        # As a mere widening (PR #50) each row read is still a true Fortinet statement.
        self.assertEqual(len(fw.parse_psirt_page_affected(prose)), 2)
        fortigate = page("FG-IR-21-018", ["CVE-2024-1001"], affected="<p>FortiGate version 6.4.2 to 6.4.4.</p>")
        self.assertIsNone(fw.parse_psirt_page_affected(fortigate, complete=True))
        proxy_only = page("FG-IR-21-019", ["CVE-2024-1001"], affected="<p>FortiOS 7.0.0 through 7.0.5</p><p>FortiProxy 2.0.1 and below.</p>")
        self.assertEqual(
            fw.parse_psirt_page_affected(proxy_only, complete=True), [rng("7.0", "7.0.0", "7.0.5")]
        )
        # A tracked product named anywhere in a line not read: the read is not complete.
        note = page(
            "FG-IR-21-043",
            ["CVE-2024-1001"],
            affected="<p>FortiManager version 6.4.4</p><p>Please note that FortiManager version 6.4.3 and below are NOT impacted.</p>",
        )
        self.assertIsNone(fw.parse_psirt_page_affected(note, complete=True))

    def test_a_narrower_table_row_makes_the_page_unreadable(self) -> None:
        table = page(
            "FG-IR-24-001",
            ["CVE-2024-1001"],
            affected=(
                "<table><tr><th>Version</th><th>Affected</th></tr>"
                "<tr><td>FortiOS 7.4</td><td>7.4.0 through 7.4.3</td></tr>"
                "<tr><td>FortiOS (only FGT_VM64) 7.2</td><td>7.2.0 through 7.2.6</td></tr></table>"
            ),
        )
        self.assertIsNone(fw.parse_psirt_page_affected(table, complete=True))
        self.assertEqual(fw.parse_psirt_page_affected(table), [rng("7.4", "7.4.0", "7.4.3")])
        for label in ("FortiOS 7.2 (only FGT_VM64)", "FortiGate 7.2", "FortiClient Windows 7.2"):
            other = table.replace("FortiOS (only FGT_VM64) 7.2", label)
            self.assertIsNone(fw.parse_psirt_page_affected(other, complete=True), label)
        cloud = table.replace("FortiOS (only FGT_VM64) 7.2", "FortiManager Cloud 7.2")
        self.assertEqual(fw.parse_psirt_page_affected(cloud, complete=True), [rng("7.4", "7.4.0", "7.4.3")])

    def test_a_record_mixing_ranges_and_free_text_is_unstructured(self) -> None:
        mixed = record(
            "CVE-2024-1001",
            [],
            product("FortiOS", le("7.0.0", "7.0.5"), {"version": "6.4 all versions", "status": "affected"}),
        )
        self.assertEqual(fw.parse_cve_org_record(mixed)[0], "confirmed")
        self.assertEqual(fw.parse_cve_org_record(mixed, complete=True), ("unstructured", []))


class RecoveredEntryTests(unittest.TestCase):
    def nvd(self, *matches: dict) -> dict[str, Any]:
        return nvd_of(nvd_cve("CVE-2020-1001", *matches))["CVE-2020-1001"]

    def test_fortinet_ranges_agreeing_with_nvd_make_an_entry(self) -> None:
        entry = fw.recovered_cve_entry(
            "FG-IR-20-082",
            "CVE-2020-1001",
            record("CVE-2020-1001", ["FG-IR-20-082"], product("FortiOS", le("6.2.0", "6.2.4"), le("7.0.0", "7.0.2")), score=5.4, severity="MEDIUM"),
            page("FG-IR-20-082", ["CVE-2020-1001", "CVE-2020-1002"], published="Sep 24, 2020"),
            self.nvd(cpe("fortios", versionStartIncluding="6.2.0", versionEndIncluding="6.2.4")),
            VERSIONS,
        )
        self.assertEqual(
            entry,
            {
                "id": "CVE-2020-1001",
                "advisoryId": "FG-IR-20-082",
                "title": "Heap overflow in sslvpnd",
                "severity": "medium",
                "cvssScore": 5.4,
                "url": "https://fortiguard.fortinet.com/psirt/FG-IR-20-082",
                "publishedAt": "2020-09-24",
                "updatedAt": "2020-09-24",
                # Fortinet's ranges are shown, 7.0 included, though NVD only states 6.2.
                "affected": [rng("6.2", "6.2.0", "6.2.4", source="cve-org"), rng("7.0", "7.0.0", "7.0.2", source="cve-org")],
                "recovered": True,
            },
        )

    def test_no_shared_catalogued_version_means_no_entry(self) -> None:
        cve_record = record("CVE-2020-1001", ["FG-IR-20-082"], product("FortiOS", le("7.0.0", "7.0.2")), score=5.4)
        self.assertIsNone(
            fw.recovered_cve_entry(
                "FG-IR-20-082", "CVE-2020-1001", cve_record, page("FG-IR-20-082", ["CVE-2020-1001"]),
                self.nvd(cpe("fortios", version="7.2.11")), VERSIONS,
            )
        )
        # A product NVD does not name is not taken from CVE.org alone.
        self.assertIsNone(
            fw.recovered_cve_entry(
                "FG-IR-20-082", "CVE-2020-1001", cve_record, page("FG-IR-20-082", ["CVE-2020-1001"]),
                self.nvd(cpe("fortianalyzer", version="7.0.2")), VERSIONS,
            )
        )

    def test_the_page_must_be_the_advisory_and_list_the_cve(self) -> None:
        cve_record = record("CVE-2020-1001", ["FG-IR-20-082"], product("FortiOS", le("6.2.0", "6.2.4")), score=5.4)
        nvd = self.nvd(cpe("fortios", version="6.2.4"))
        for raw in (
            page("FG-IR-20-083", ["CVE-2020-1001"]),
            page("FG-IR-20-082", ["CVE-2020-1009"]),
            page("FG-IR-20-082", ["CVE-2020-1001"], published="sometime"),
            "<html>anti-bot</html>",
        ):
            self.assertIsNone(fw.recovered_cve_entry("FG-IR-20-082", "CVE-2020-1001", cve_record, raw, nvd, VERSIONS))

    def test_the_page_table_and_severity_serve_only_a_single_cve_advisory(self) -> None:
        free_text = record("CVE-2020-1001", ["FG-IR-21-179"], product("Fortinet FortiOS, FortiProxy", {"version": "6.2.4 and below", "status": "affected"}))
        affected = "<p>FortiOS version 6.2.0 through 6.2.4</p><p>FortiOS 7.0 all versions</p>"
        nvd = self.nvd(cpe("fortios", versionStartIncluding="6.2.0", versionEndIncluding="6.2.4"))
        alone = fw.recovered_cve_entry(
            "FG-IR-21-179", "CVE-2020-1001", free_text,
            page("FG-IR-21-179", ["CVE-2020-1001"], affected=affected, severity="Medium", cvss="6.7"), nvd, VERSIONS,
        )
        self.assertEqual(alone["affected"], [rng("6.2", "6.2.0", "6.2.4", source="psirt-page"), rng("7.0", None, None, source="psirt-page")])
        self.assertEqual((alone["severity"], alone["cvssScore"]), ("medium", 6.7))
        shared = page("FG-IR-21-179", ["CVE-2020-1001", "CVE-2020-1002"], affected=affected)
        self.assertIsNone(fw.recovered_cve_entry("FG-IR-21-179", "CVE-2020-1001", free_text, shared, nvd, VERSIONS))

    def test_a_partial_statement_is_never_the_only_source(self) -> None:
        partial = page(
            "FG-IR-20-131",
            ["CVE-2020-1001"],
            affected="<p>FortiOS version 7.0.0</p><p>FortiOS versions 6.2.9 and below.</p>",
        )
        self.assertIsNone(
            fw.recovered_cve_entry(
                "FG-IR-20-131", "CVE-2020-1001", record("CVE-2020-1001", ["FG-IR-20-131"]), partial,
                self.nvd(cpe("fortios", version="6.2.4")), VERSIONS,
            )
        )


class RecoverMissingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = catalogue("6.2.4", "7.0.2", "7.2.11")
        self.state["cves"] = [{**cve("CVE-2026-1", "high", [rng("7.2", "7.2.0", "7.2.11")]), "advisoryId": "FG-IR-26-001"}]
        self.nvd = nvd_of(
            nvd_cve("CVE-2026-1", cpe("fortios", version="7.2.11")),
            nvd_cve("CVE-2020-1001", cpe("fortios", version="6.2.4")),
            nvd_cve("CVE-2020-1002", cpe("fortios", version="5.6.0")),  # no catalogued version
        )
        self.records = {
            "CVE-2020-1001": record("CVE-2020-1001", ["FG-IR-20-082"], product("FortiOS", le("6.2.0", "6.2.4")), score=5.4),
        }
        self.pages = {"FG-IR-20-082": page("FG-IR-20-082", ["CVE-2020-1001"])}

    def recover(self, *, collect: Any = None, known: set[str] | None = None, **kwargs: Any) -> tuple:
        def fetch_record(cve_id: str, _timeout: int) -> Any:
            value = self.records[cve_id]
            if isinstance(value, Exception):
                raise value
            return value

        def fetch_page(advisory_id: str, _timeout: int) -> str:
            value = self.pages[advisory_id]
            if isinstance(value, Exception):
                raise value
            return value

        def no_export(advisory_id: str, _timeout: int) -> list:
            raise fw.CsafUnavailableError(advisory_id)

        with patch.object(fw.time, "sleep"):
            return fw.recover_missing_cves(
                self.state, self.nvd, known if known is not None else {"FG-IR-26-001"}, 5,
                fetch_record=fetch_record, fetch_page=fetch_page, collect_advisory=collect or no_export, **kwargs,
            )

    def test_an_advisory_without_exact_export_gives_the_agreeing_cve(self) -> None:
        results, records, problems = self.recover()
        self.assertEqual(list(results), ["FG-IR-20-082"])
        self.assertEqual([entry["id"] for entry in results["FG-IR-20-082"]], ["CVE-2020-1001"])
        self.assertTrue(results["FG-IR-20-082"][0]["recovered"])
        self.assertEqual(set(records), {"CVE-2020-1001"})
        self.assertEqual(problems, [])

    def test_an_exact_export_is_imported_whole_like_a_backfill(self) -> None:
        exported = [cve("CVE-2020-1001", "medium", [rng("6.2", "6.2.0", "6.2.4")]), cve("CVE-2020-1003", "low", [rng("6.2", "6.2.3", "6.2.4")])]
        results, _records, _problems = self.recover(collect=lambda _advisory_id, _timeout: exported)
        self.assertEqual(results, {"FG-IR-20-082": exported})
        # A confirmed empty export gives nothing, and the page is not read instead.
        self.pages["FG-IR-20-082"] = AssertionError("page read")
        self.assertEqual(self.recover(collect=lambda _advisory_id, _timeout: []), ({}, {"CVE-2020-1001": self.records["CVE-2020-1001"]}, []))

    def test_a_known_or_ambiguous_advisory_is_left_alone(self) -> None:
        collect = MagicMock(return_value=[])
        # Replacing a known advisory with one CVE would drop its other CVEs.
        self.assertEqual(self.recover(collect=collect, known={"FG-IR-26-001", "FG-IR-20-082"})[::2], ({}, []))
        self.records["CVE-2020-1001"] = record("CVE-2020-1001", ["FG-IR-20-082", "FG-IR-20-083"], product("FortiOS", le("6.2.0", "6.2.4")))
        self.assertEqual(self.recover(collect=collect)[::2], ({}, []))
        collect.assert_not_called()

    def test_an_advisory_known_only_by_recovery_is_tried_again_and_kept_whole(self) -> None:
        """An earlier pass recovered CVE-2020-1004 of FG-IR-20-082 but could not read
        CVE-2020-1001: this pass adds it, and keeps CVE-2020-1004."""
        earlier = {
            **cve("CVE-2020-1004", "medium", [rng("6.2", "6.2.0", "6.2.4", source="cve-org")]),
            "advisoryId": "FG-IR-20-082", "recovered": True, "kev": False,
        }
        self.state["cves"].append(earlier)
        self.pages["FG-IR-20-082"] = page("FG-IR-20-082", ["CVE-2020-1001", "CVE-2020-1004"])
        results, _records, problems = self.recover(known={"FG-IR-26-001", "FG-IR-20-082"})
        self.assertEqual(problems, [])
        self.assertEqual([entry["id"] for entry in results["FG-IR-20-082"]], ["CVE-2020-1001", "CVE-2020-1004"])
        self.assertEqual(results["FG-IR-20-082"][1], earlier)
        # Not when the advisory also holds a CVE from an exact export.
        self.state["cves"][-1] = {**earlier, "recovered": False}
        self.assertEqual(self.recover(known={"FG-IR-26-001", "FG-IR-20-082"})[0], {})

    def test_read_failures_are_problems_never_results(self) -> None:
        self.records["CVE-2020-1001"] = TimeoutError("cveawg")
        results, _records, problems = self.recover()
        self.assertEqual((results, problems), ({}, ["CVE-2020-1001 (fiche CVE.org, TimeoutError)"]))
        self.records["CVE-2020-1001"] = record("CVE-2020-1001", ["FG-IR-20-082"], product("FortiOS", le("6.2.0", "6.2.4")), score=5.4)

        def link_missing(advisory_id: str, _timeout: int) -> list:
            raise fw.CsafLinkMissingError(advisory_id)

        results, _records, problems = self.recover(collect=link_missing)
        self.assertEqual((results, problems), ({}, ["FG-IR-20-082 (page sans lien CSAF)"]))
        self.pages["FG-IR-20-082"] = OSError("reset")
        results, _records, problems = self.recover()
        self.assertEqual((results, problems), ({}, ["FG-IR-20-082 (page PSIRT, OSError)"]))

    def test_candidates_are_bounded(self) -> None:
        def never(*_args: Any) -> Any:
            raise AssertionError("read beyond the limit")

        self.assertEqual(
            fw.recover_missing_cves(self.state, self.nvd, set(), 5, fetch_record=never, limit=0), ({}, {}, [])
        )


class WeeklyPassTests(unittest.TestCase):
    """The real fortios_watch.main() path: weekly backfill with --cve-crosscheck, then a normal pass."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.base = self.root / "state.json"
        self.health = self.root / "health.json"
        self.history = self.root / "notify-history.json"
        self.settings = self.root / "notification-settings.json"
        self.known = [{**cve("CVE-2026-1", "high", [rng("7.2", "7.2.0", "7.2.11")]), "publishedAt": "2026-01-05"}]
        state = catalogue("6.2.4", "7.0.2", "7.2.11")
        state["cves"] = self.known
        fw.write_json(self.base, state)
        notify.save_notification_settings(self.settings, settings_payload(selected={"fortigate-fortios"}))
        notify.ensure_checkpoint(
            self.history,
            {
                "versionsByProduct": {product_id: sorted(versions) for product_id, versions in fw.versions_by_product(state).items()},
                "cvesById": {item["id"]: item for item in self.known},
                "health": {},
            },
        )
        self.nvd = nvd_of(
            nvd_cve("CVE-2026-1", cpe("fortios", version="7.2.11")),
            nvd_cve("CVE-2020-1001", cpe("fortios", version="6.2.4")),
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_pass(self, flags: list[str], *, published: str = "Jul 5, 2020") -> MagicMock:
        client = MagicMock()
        client.__enter__ = MagicMock(return_value=client)
        client.__exit__ = MagicMock(return_value=False)
        cve_record = record("CVE-2020-1001", ["FG-IR-20-082"], product("FortiOS", le("6.2.0", "6.2.4")), score=8.1, severity="HIGH")
        with (
            patch.dict(os.environ, {"FORTIOS_SMTP_HOST": "smtp.example.com", "FORTIOS_SMTP_FROM": "fu@example.com"}, clear=True),
            patch.object(fw, "collect_cve_catalog", return_value=({}, [])),
            patch.object(fw, "fetch_psirt_versions", return_value=set()),
            patch.object(fw, "fetch_cve_org_record", return_value=cve_record),
            patch.object(fw, "fetch_nvd_fortinet", return_value=self.nvd),
            patch.object(fw, "collect_cve_entries_for_advisory", side_effect=fw.CsafUnavailableError("FG-IR-20-082")),
            patch.object(fw, "_fetch_psirt_page", return_value=page("FG-IR-20-082", ["CVE-2020-1001"], published=published)),
            patch.object(fw.time, "sleep"),
            patch("smtplib.SMTP", return_value=client),
        ):
            exit_code = fw.main(
                [
                    *flags,
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

    def catalog_cves(self) -> dict[str, Any]:
        return {item["id"]: item for item in json.loads(self.base.read_text(encoding="utf-8"))["cves"]}

    def test_history_is_recovered_silently(self) -> None:
        client = self.run_pass(["--cve-backfill", "--cve-crosscheck"])
        client.send_message.assert_not_called()
        recovered = self.catalog_cves()["CVE-2020-1001"]
        self.assertTrue(recovered["recovered"])
        self.assertEqual(recovered["affected"], [rng("6.2", "6.2.0", "6.2.4", source="cve-org")])
        self.assertEqual((recovered["cveOrg"], recovered["nvd"]), ("confirmed", "confirmed"))
        catalog = json.loads(self.base.read_text(encoding="utf-8"))
        self.assertEqual(catalog["cveCoverage"]["crossCheck"]["missingCount"], 0)
        source = json.loads(self.health.read_text(encoding="utf-8"))["sources"]["cve-crosscheck"]
        self.assertEqual((source["status"], source["itemsCollected"]), ("ok", 1))
        state = notify.load_notify_state(self.history)
        self.assertIn("CVE-2020-1001", state["checkpoint"]["cvesById"])
        self.assertEqual(state["outbox"], [])
        # The next normal pass has nothing to report about it.
        self.run_pass(["--cve-catalog", "--cve-crosscheck"]).send_message.assert_not_called()

    def test_a_recent_recovered_cve_stays_notifiable(self) -> None:
        recent = (dt.datetime.now(dt.UTC) - dt.timedelta(days=5)).strftime("%b %d, %Y")
        self.run_pass(["--cve-backfill", "--cve-crosscheck"], published=recent).send_message.assert_not_called()
        self.assertIn("CVE-2020-1001", self.catalog_cves())
        self.assertNotIn("CVE-2020-1001", notify.load_notify_state(self.history)["checkpoint"]["cvesById"])
        client = self.run_pass(["--cve-catalog"], published=recent)
        client.send_message.assert_called_once()
        body = client.send_message.call_args.args[0].get_body(preferencelist=("plain",)).get_content()
        self.assertIn("CVE-2020-1001", body)

    def test_only_the_weekly_pass_recovers(self) -> None:
        # Never with --cve-reconcile-existing either: it silences all it stages, a recent CVE included.
        with patch.object(fw, "recover_missing_cves", MagicMock(return_value=({}, {}, []))) as recover:
            self.run_pass(["--cve-catalog", "--cve-crosscheck"])
            self.run_pass(["--cve-catalog", "--cve-reconcile-existing", "--cve-crosscheck"])
            self.run_pass(["--cve-backfill", "--cve-reconcile-existing", "--cve-crosscheck"])
            recover.assert_not_called()
            self.run_pass(["--cve-backfill", "--cve-crosscheck"])
            recover.assert_called_once()
        self.assertNotIn("CVE-2020-1001", self.catalog_cves())
        source = json.loads(self.health.read_text(encoding="utf-8"))["sources"]["cve-crosscheck"]
        self.assertEqual(source["status"], "ok")


if __name__ == "__main__":
    unittest.main()
