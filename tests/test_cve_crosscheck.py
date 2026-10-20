"""Cross-check of the PSIRT CVE data with CVE.org and NVD (--cve-crosscheck).

Audit of 2026-10-20 (331 CVEs, version by version, against the catalogue's real versions):
- CVE.org, Fortinet's own CNA record published through another channel than its CSAF, filled
  real PSIRT gaps (CVE-2024-26013: no FortiOS range in the CSAF at all; CVE-2026-71408: CSAF and
  page list only the maintained trains). It widens what is shown, like the advisory page.
- NVD, an independent analysis, agreed on 85 % of the versions, but two thirds of what it alone
  reported came from ranges spanning several trains. It confirms and feeds the coverage report;
  a version NVD alone reports is never shown (decision of 2026-10-20).
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

import fortios_notify as notify
import fortios_watch as fw

from tests.test_security_notifications import PRODUCT_SELECTIONS, cve, settings_payload

FOS = PRODUCT_SELECTIONS["fortigate-fortios"]


def rng(branch: str, start: str | None, end: str | None, product: str = "fortigate-fortios", **extra: Any) -> dict:
    models = ["ems"] if product == "forticlient-ems" else []
    return {"product": product, "models": extra.pop("models", models), "branch": branch, "from": start, "to": end, **extra}


def cve_org(*affected: dict) -> dict:
    return {"cveMetadata": {"cveId": "CVE-X"}, "containers": {"cna": {"affected": list(affected)}}}


def product(name: str, *versions: dict) -> dict:
    return {"vendor": "Fortinet", "product": name, "defaultStatus": "unaffected", "versions": list(versions)}


def le(start: str, end: str) -> dict:
    return {"version": start, "lessThanOrEqual": end, "status": "affected", "versionType": "semver"}


def nvd_cve(cve_id: str, *matches: dict, severity: str = "HIGH", published: str = "2024-05-01T00:00:00") -> dict:
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseSeverity": severity}}]},
            "configurations": [{"nodes": [{"cpeMatch": list(matches)}]}],
        }
    }


def cpe(product_name: str, *, version: str = "*", target: str = "*", **bounds: str) -> dict:
    return {
        "vulnerable": True,
        "criteria": f"cpe:2.3:o:fortinet:{product_name}:{version}:*:*:*:*:{target}:*:*",
        **bounds,
    }


def nvd_pages(*items: dict, total: int | None = None) -> list[dict]:
    filler = [{"cve": {"id": f"CVE-2000-{index}", "configurations": []}} for index in range(fw.NVD_MIN_FORTINET_CVES)]
    vulnerabilities = [*items, *filler]
    return [{"totalResults": total if total is not None else len(vulnerabilities), "vulnerabilities": vulnerabilities}]


def catalogue(*fortios_versions: str) -> dict:
    return fw.normalize_state(
        {
            "products": [
                {
                    "id": "fortigate-fortios",
                    "models": [{"id": "FGT60F", "firmwares": [{"version": version} for version in fortios_versions]}],
                }
            ]
        }
    )


class CveOrgParsingTests(unittest.TestCase):
    def test_structured_ranges_of_tracked_products(self) -> None:
        status, ranges = fw.parse_cve_org_record(
            cve_org(
                product("FortiOS", le("7.0.0", "7.0.17"), le("6.4.0", "6.4.16")),
                product("Fortinet FortiManager", {"version": "7.4.2", "status": "affected"}),
                product("FortiClientMac", {"version": "7.0.0", "lessThan": "7.0.10", "status": "affected"}),
                product("FortiProxy", le("7.4.0", "7.4.3")),
                product("FortiManager Cloud", le("7.4.1", "7.4.4")),
            )
        )
        self.assertEqual(status, "confirmed")
        self.assertEqual(
            ranges,
            [
                rng("7.0", "7.0.0", "7.0.9", product="forticlient", models=["macos"]),
                rng("6.4", "6.4.0", "6.4.16"),
                rng("7.0", "7.0.0", "7.0.17"),
                rng("7.4", "7.4.2", "7.4.2", product="fortimanager"),
            ],
        )

    def test_free_text_and_cross_train_entries_are_never_interpreted(self) -> None:
        free_text = cve_org(
            product("Fortinet FortiOS, FortiProxy", {"version": "FortiOS 6.0.10 and below, 6.2.2 and below", "status": "affected"})
        )
        self.assertEqual(fw.parse_cve_org_record(free_text), ("unstructured", []))
        cross_train = cve_org(product("FortiOS", le("6.4.0", "7.0.16")))
        self.assertEqual(fw.parse_cve_org_record(cross_train), ("unstructured", []))
        before_a_train = cve_org(product("FortiOS", {"version": "7.2.0", "lessThan": "7.4.0", "status": "affected"}))
        self.assertEqual(fw.parse_cve_org_record(before_a_train), ("unstructured", []))

    def test_untracked_or_missing_records_are_absent(self) -> None:
        self.assertEqual(fw.parse_cve_org_record(None), ("absent", []))
        self.assertEqual(fw.parse_cve_org_record({"error": "CVE_RECORD_DNE"}), ("absent", []))
        self.assertEqual(fw.parse_cve_org_record(cve_org(product("FortiWeb", le("7.6.0", "7.6.1")))), ("absent", []))
        unaffected = cve_org(product("FortiOS", {"version": "7.6.0", "status": "unaffected"}))
        self.assertEqual(fw.parse_cve_org_record(unaffected), ("absent", []))

    def test_record_fetch_treats_404_as_no_record(self) -> None:
        error = urllib.error.HTTPError("https://cveawg.mitre.org/api/cve/CVE-1", 404, "Not Found", None, None)
        with patch.object(fw, "read_url_with_retry", side_effect=error):
            self.assertIsNone(fw.fetch_cve_org_record("CVE-1", 5))
        outage = urllib.error.HTTPError("https://cveawg.mitre.org/api/cve/CVE-1", 503, "Unavailable", None, None)
        with patch.object(fw, "read_url_with_retry", side_effect=outage), self.assertRaises(urllib.error.HTTPError):
            fw.fetch_cve_org_record("CVE-1", 5)


class CveOrgWideningTests(unittest.TestCase):
    def test_a_train_missing_from_psirt_is_added_from_cve_org(self) -> None:
        # CVE-2026-71408: PSIRT lists the maintained trains only, CVE.org also 7.0 and 6.4.
        entry = cve("CVE-2026-71408", "medium", [rng("7.2", None, None), rng("7.6", "7.6.0", "7.6.6")])
        records = {"CVE-2026-71408": cve_org(product("FortiOS", le("7.6.0", "7.6.6"), le("7.2.0", "7.2.13"), le("7.0.0", "7.0.19")))}
        failed = fw.apply_cve_org_crosscheck([entry], 5, fetch=lambda cve_id, _timeout: records[cve_id])
        self.assertEqual(failed, [])
        self.assertEqual(entry["cveOrg"], "confirmed")
        self.assertEqual(
            entry["affected"],
            [rng("7.0", "7.0.0", "7.0.19", source="cve-org"), rng("7.2", None, None), rng("7.6", "7.6.0", "7.6.6")],
        )

    def test_a_product_psirt_does_not_name_needs_nvd_too(self) -> None:
        fmg = rng("7.2", "7.2.0", "7.2.3", product="fortimanager")
        records = {
            # CVE-2023-42791: FortiAnalyzer only in the structured record, not in NVD.
            "CVE-2023-42791": cve_org(
                product("FortiManager", le("7.2.0", "7.2.3")), product("FortiAnalyzer", le("7.2.0", "7.2.3"))
            ),
            # CVE-2024-26013: no FortiOS range in the CSAF, FortiOS in CVE.org and NVD.
            "CVE-2024-26013": cve_org(product("FortiOS", le("7.2.0", "7.2.7"))),
        }
        nvd = {
            "CVE-2023-42791": {"claims": [{"product": "fortimanager", "platform": None}]},
            "CVE-2024-26013": {"claims": [{"product": "fortigate-fortios", "platform": None}]},
        }
        lone_product = cve("CVE-2023-42791", "high", [fmg])
        confirmed_product = cve("CVE-2024-26013", "high", [fmg])
        fw.apply_cve_org_crosscheck(
            [lone_product, confirmed_product],
            5,
            fetch=lambda cve_id, _timeout: records[cve_id],
            second_opinion=fw.nvd_second_opinion(nvd, {}),
        )
        self.assertEqual(lone_product["affected"], [fmg])
        # Its FortiManager ranges are already shown: the record still confirms a shown product.
        self.assertEqual(lone_product["cveOrg"], "confirmed")
        only_other_product = cve("CVE-2023-42791", "high", [rng("7.2", "7.2.0", "7.2.3")])
        records["CVE-2023-42791"] = cve_org(product("FortiAnalyzer", le("7.2.0", "7.2.3")))
        fw.apply_cve_org_crosscheck(
            [only_other_product], 5, fetch=lambda cve_id, _timeout: records[cve_id],
            second_opinion=fw.nvd_second_opinion(nvd, {}),
        )
        self.assertEqual(only_other_product["cveOrg"], "absent")
        self.assertEqual(confirmed_product["affected"], [rng("7.2", "7.2.0", "7.2.7", source="cve-org"), fmg])

    def test_forticlient_platforms_are_distinct_products(self) -> None:
        windows = rng("7.0", "7.0.0", "7.0.9", product="forticlient", models=["windows"])
        mac_record = cve_org(product("FortiClientMac", le("7.0.0", "7.0.9")), product("FortiClientWindows", le("7.0.0", "7.0.9")))
        entry = cve("CVE-1", "medium", [windows])
        fw.apply_cve_org_crosscheck([entry], 5, fetch=lambda *_: mac_record, second_opinion=lambda _id: set())
        self.assertEqual(entry["affected"], [windows])
        any_platform = {("forticlient", None)}  # NVD CPE without target platform
        entry = cve("CVE-1", "medium", [windows])
        fw.apply_cve_org_crosscheck([entry], 5, fetch=lambda *_: mac_record, second_opinion=lambda _id: any_platform)
        self.assertIn(rng("7.0", "7.0.0", "7.0.9", product="forticlient", models=["macos"], source="cve-org"), entry["affected"])

    def test_without_nvd_a_product_addition_is_kept_only_if_already_shown(self) -> None:
        previous = cve("CVE-2024-26013", "high", [rng("7.2", "7.2.0", "7.2.7", source="cve-org")])
        opinion = fw.nvd_second_opinion(None, {"CVE-2024-26013": previous})
        self.assertEqual(opinion("CVE-2024-26013"), {("fortigate-fortios", None)})
        self.assertEqual(opinion("CVE-2023-42791"), set())

    def test_an_unreachable_record_keeps_what_the_catalogue_held(self) -> None:
        previous = cve("CVE-1", "high", [rng("7.2", "7.2.0", "7.2.4"), rng("7.0", "7.0.0", "7.0.9", source="cve-org")])
        previous["cveOrg"] = "confirmed"
        fresh = cve("CVE-1", "high", [rng("7.2", "7.2.0", "7.2.4")])

        def outage(_cve_id: str, _timeout: int) -> Any:
            raise TimeoutError("cveawg")

        self.assertEqual(fw.apply_cve_org_crosscheck([fresh], 5, fetch=outage), ["CVE-1"])
        self.assertNotIn("cveOrg", fresh)
        fw.restore_cve_org_crosscheck(fresh, previous)
        self.assertEqual(fresh["cveOrg"], "confirmed")
        self.assertEqual(fresh["affected"], sorted(previous["affected"], key=fw._csaf_range_sort_key))
        never_checked = cve("CVE-2", "high", [rng("7.2", "7.2.0", "7.2.4")])
        fw.restore_cve_org_crosscheck(never_checked, None)
        self.assertNotIn("cveOrg", never_checked)


class NvdTests(unittest.TestCase):
    def test_only_tracked_products_and_platforms_are_kept(self) -> None:
        tracked = fw.parse_nvd_fortinet(
            nvd_pages(
                nvd_cve("CVE-1", cpe("fortios", versionStartIncluding="7.2.0", versionEndExcluding="7.2.12")),
                nvd_cve("CVE-2", cpe("forticlient", target="windows", version="7.0.3"), cpe("forticlient", target="iphone_os")),
                nvd_cve("CVE-3", cpe("fortiproxy", versionEndIncluding="7.4.3")),
            )
        )
        self.assertEqual(set(tracked), {"CVE-1", "CVE-2"})
        self.assertEqual(tracked["CVE-1"]["severity"], "high")
        self.assertEqual(
            tracked["CVE-2"]["claims"], [{"product": "forticlient", "platform": "windows", "version": "7.0.3"}]
        )

    def test_a_short_or_partial_answer_is_refused(self) -> None:
        with self.assertRaises(fw.NvdFeedError):
            fw.parse_nvd_fortinet([{"totalResults": 12, "vulnerabilities": []}])
        with self.assertRaises(fw.NvdFeedError):
            fw.parse_nvd_fortinet(nvd_pages(total=5000))

    def test_marks_and_report_against_the_catalogue_versions(self) -> None:
        state = catalogue("6.4.15", "7.0.17", "7.2.11", "7.2.12")
        state["cves"] = [
            cve("CVE-SHOWN", "high", [rng("7.2", "7.2.0", "7.2.11")]),
            cve("CVE-NOT-IN-NVD", "high", [rng("7.2", "7.2.0", "7.2.11")]),
        ]
        nvd = fw.parse_nvd_fortinet(
            nvd_pages(
                # Agrees on 7.2 and also claims 7.0: reported, never shown.
                nvd_cve(
                    "CVE-SHOWN",
                    cpe("fortios", versionStartIncluding="7.2.0", versionEndExcluding="7.2.12"),
                    cpe("fortios", versionStartIncluding="7.0.0", versionEndIncluding="7.0.17"),
                    # Spans 6.4 -> 7.0, or bounded on one side only, or not at all: too coarse to
                    # point at versions, only counted.
                    cpe("fortios", versionStartIncluding="6.4.0", versionEndIncluding="7.0.16"),
                    cpe("fortios", versionEndIncluding="6.4.15"),
                    cpe("fortios", versionStartIncluding="7.0.0"),
                    cpe("fortios"),
                ),
                nvd_cve("CVE-MISSING", cpe("fortios", version="7.2.12"), severity="CRITICAL"),
                nvd_cve("CVE-OTHER-VERSIONS", cpe("fortios", version="5.6.3")),
            )
        )
        report = fw.apply_nvd_crosscheck(state, nvd, "2026-10-20T06:00:00Z")
        marks = {item["id"]: item["nvd"] for item in state["cves"]}
        self.assertEqual(marks, {"CVE-SHOWN": "confirmed", "CVE-NOT-IN-NVD": "absent"})
        self.assertEqual(
            report,
            {
                "checkedAt": "2026-10-20T06:00:00Z",
                "nvdOnlyCount": 1,
                "nvdOnly": [{"id": "CVE-SHOWN", "versionCount": 1, "versions": ["fortigate-fortios 7.0.17"]}],
                "missingCount": 1,
                "missing": [
                    {"id": "CVE-MISSING", "published": "2024-05-01", "severity": "critical", "products": ["fortigate-fortios"]}
                ],
                "crossTrainIgnored": 4,
            },
        )
        # Nothing NVD alone says is shown.
        self.assertEqual(state["cves"][0]["affected"], [rng("7.2", "7.2.0", "7.2.11")])


class StorageTests(unittest.TestCase):
    def test_an_entry_refetched_without_nvd_keeps_its_mark(self) -> None:
        state = {"cves": [{**cve("CVE-1", "high", [rng("7.2", "7.2.0", "7.2.4")]), "nvd": "confirmed"}]}
        self.assertFalse(fw.upsert_cve(state, cve("CVE-1", "high", [rng("7.2", "7.2.0", "7.2.4")])))
        self.assertEqual(state["cves"][0]["nvd"], "confirmed")

    def test_the_rss_record_keeps_the_crosscheck_report(self) -> None:
        coverage, _ = fw.update_cve_coverage({"rssSeenIds": ["A"], "crossCheck": {"missingCount": 3}}, ["A"], "now")
        self.assertEqual(coverage["crossCheck"], {"missingCount": 3})


class CollectionPathTests(unittest.TestCase):
    """The real fortios_watch.main() path with --cve-crosscheck."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.base = self.root / "state.json"
        self.health = self.root / "health.json"
        self.history = self.root / "notify-history.json"
        self.settings = self.root / "notification-settings.json"
        self.catalog_cves = [cve("CVE-2026-1", "high", [rng("7.2", "7.2.0", "7.2.11")])]
        state = catalogue("7.0.17", "7.2.11")
        state["cves"] = self.catalog_cves
        fw.write_json(self.base, state)
        notify.save_notification_settings(self.settings, settings_payload(selected={"fortigate-fortios"}))
        notify.ensure_checkpoint(
            self.history,
            {
                "versionsByProduct": {
                    product_id: sorted(versions) for product_id, versions in fw.versions_by_product(state).items()
                },
                "cvesById": {item["id"]: item for item in self.catalog_cves},
                "health": {},
            },
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_collection(self, *, cve_org_record: Any, nvd: Any) -> MagicMock:
        client = MagicMock()
        client.__enter__ = MagicMock(return_value=client)
        client.__exit__ = MagicMock(return_value=False)
        results = {"FG-IR-26-001": [json.loads(json.dumps(item)) for item in self.catalog_cves]}
        cve_org_patch = (
            patch.object(fw, "fetch_cve_org_record", side_effect=cve_org_record)
            if isinstance(cve_org_record, Exception)
            else patch.object(fw, "fetch_cve_org_record", return_value=cve_org_record)
        )
        nvd_patch = (
            patch.object(fw, "fetch_nvd_fortinet", side_effect=nvd)
            if isinstance(nvd, Exception)
            else patch.object(fw, "fetch_nvd_fortinet", return_value=nvd)
        )
        with (
            patch.dict(
                os.environ, {"FORTIOS_SMTP_HOST": "smtp.example.com", "FORTIOS_SMTP_FROM": "fu@example.com"}, clear=True
            ),
            patch.object(fw, "collect_cve_catalog", return_value=(results, [])),
            patch.object(fw, "fetch_psirt_versions", return_value=set()),
            cve_org_patch,
            nvd_patch,
            patch("smtplib.SMTP", return_value=client),
        ):
            exit_code = fw.main(
                [
                    "--cve-catalog",
                    "--cve-crosscheck",
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

    def source(self) -> dict[str, Any]:
        return json.loads(self.health.read_text(encoding="utf-8"))["sources"]["cve-crosscheck"]

    def test_widening_marks_and_report_are_committed_silently(self) -> None:
        record = cve_org(product("FortiOS", le("7.2.0", "7.2.11"), le("7.0.0", "7.0.17")))
        nvd = fw.parse_nvd_fortinet(
            nvd_pages(
                nvd_cve("CVE-2026-1", cpe("fortios", versionStartIncluding="7.2.0", versionEndIncluding="7.2.11")),
                nvd_cve("CVE-2026-9", cpe("fortios", version="7.0.17")),
            )
        )
        client = self.run_collection(cve_org_record=record, nvd=nvd)
        client.send_message.assert_not_called()
        item = self.catalog()["cves"][0]
        self.assertEqual(item["cveOrg"], "confirmed")
        self.assertEqual(item["nvd"], "confirmed")
        self.assertIn(rng("7.0", "7.0.0", "7.0.17", source="cve-org"), item["affected"])
        report = self.catalog()["cveCoverage"]["crossCheck"]
        self.assertEqual((report["nvdOnlyCount"], report["missingCount"]), (0, 1))
        self.assertEqual(report["missing"][0]["id"], "CVE-2026-9")
        self.assertEqual(self.source()["status"], "ok")
        self.assertEqual(notify.load_notify_state(self.history)["outbox"], [])

    def test_outages_keep_what_the_catalogue_holds_and_spare_psirt(self) -> None:
        record = cve_org(product("FortiOS", le("7.2.0", "7.2.11"), le("7.0.0", "7.0.17")))
        nvd = fw.parse_nvd_fortinet(
            nvd_pages(nvd_cve("CVE-2026-1", cpe("fortios", versionStartIncluding="7.2.0", versionEndIncluding="7.2.11")))
        )
        self.run_collection(cve_org_record=record, nvd=nvd)
        before = self.catalog()
        client = self.run_collection(
            cve_org_record=TimeoutError("cveawg"), nvd=fw.NvdFeedError("liste NVD Fortinet incomplète")
        )
        client.send_message.assert_not_called()
        after = self.catalog()
        self.assertEqual(after["cves"], before["cves"])
        self.assertEqual(after["cveCoverage"]["crossCheck"], before["cveCoverage"]["crossCheck"])
        self.assertEqual(self.source()["status"], "warning")
        self.assertIn("NVD indisponible", self.source()["lastError"])
        self.assertIn("1 fiche(s) CVE.org non lue(s)", self.source()["lastError"])
        psirt = json.loads(self.health.read_text(encoding="utf-8"))["sources"]["cve-psirt"]
        self.assertEqual(psirt["status"], "ok")

    def test_a_crosscheck_failure_never_reaches_psirt_nor_the_silence_intent(self) -> None:
        """A weekly backfill whose cross-check breaks mid-way still stages and commits the PSIRT
        results exactly as collected, and only the cross-check source reports it."""
        imported = cve("CVE-2019-1", "high", [rng("6.2", "6.2.0", "6.2.4")])
        imported["advisoryId"] = "FG-IR-19-001"
        imported["publishedAt"] = "2019-06-01"
        record = cve_org(product("FortiOS", le("6.2.0", "6.2.4"), le("6.0.0", "6.0.9")))
        nvd = fw.parse_nvd_fortinet(nvd_pages(nvd_cve("CVE-2019-1", cpe("fortios", version="6.2.4"))))

        def broken(*_args: Any, **_kwargs: Any) -> int:
            raise KeyError("branch")

        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(fw, "collect_cve_catalog", return_value=({"FG-IR-19-001": [json.loads(json.dumps(imported))]}, [])),
            patch.object(fw, "fetch_psirt_versions", return_value=set()),
            patch.object(fw, "fetch_cve_org_record", return_value=record),
            patch.object(fw, "fetch_nvd_fortinet", return_value=nvd),
            patch.object(fw, "merge_psirt_page_ranges", side_effect=broken),
            patch.object(notify, "stage_pending_cve_baseline", wraps=notify.stage_pending_cve_baseline) as staged,
        ):
            exit_code = fw.main(
                [
                    "--cve-backfill",
                    "--cve-crosscheck",
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
        staged.assert_called_once()
        self.assertIn("CVE-2019-1", staged.call_args.args[1])
        committed = {item["id"]: item for item in self.catalog()["cves"]}
        self.assertEqual(committed["CVE-2019-1"]["affected"], imported["affected"])
        self.assertNotIn("cveOrg", committed["CVE-2019-1"])
        sources = json.loads(self.health.read_text(encoding="utf-8"))["sources"]
        self.assertEqual(sources["cve-psirt-history"]["status"], "ok")
        self.assertEqual(sources["cve-crosscheck"]["status"], "warning")
        self.assertIn("contre-vérification interrompue (KeyError", sources["cve-crosscheck"]["lastError"])
        self.assertIn("CVE-2019-1", notify.load_notify_state(self.history)["checkpoint"]["cvesById"])

    def test_without_the_flag_nothing_is_fetched(self) -> None:
        with (
            patch.object(fw, "fetch_cve_org_record", side_effect=AssertionError("CVE.org fetched")),
            patch.object(fw, "fetch_nvd_fortinet", side_effect=AssertionError("NVD fetched")),
            patch.object(fw, "collect_cve_catalog", return_value=({"FG-IR-26-001": list(self.catalog_cves)}, [])),
            patch.object(fw, "fetch_psirt_versions", return_value=set()),
            patch.dict(os.environ, {}, clear=True),
        ):
            exit_code = fw.main(
                [
                    "--cve-catalog",
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
        self.assertNotIn("cveOrg", self.catalog()["cves"][0])


if __name__ == "__main__":
    unittest.main()
