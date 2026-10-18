"""PSIRT advisories that cannot be read the normal way, and why they were skipped.

Observed in production (2026-10-15): three advisories failed every single run, so the CVE
source stayed orange and each pass waited ~20 min on retries that could never succeed.

- FG-IR-26-144: a valid CSAF export naming only FortiSOAR, published without any
  ``vulnerabilities`` section — a confirmed "nothing tracked here", not a failure.
- FG-IR-20-005, FG-IR-22-059: older advisories whose genuine page only links the legacy CVRF
  export, never a CSAF one — a permanent state, reported but neither retried nor alarming.

An anti-bot page (neither link) and a CSAF naming a tracked product without vulnerabilities
stay real failures: previous data preserved, source orange, retried.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fortios_watch as fw
from test_csaf_applicability import make_advisory_page, make_csaf_document


def product_tree(*names: str) -> dict:
    return {
        "branches": [
            {
                "category": "vendor",
                "name": "Fortinet PSIRT",
                "branches": [
                    {
                        "category": "product",
                        "name": name,
                        "branches": [
                            {
                                "category": "product_version",
                                "name": f"{name}/1.0.0",
                                "product": {"product_id": f"{name} 1.0.0", "name": name},
                            }
                        ],
                    }
                    for name in names
                ],
            }
        ]
    }


def csaf_without_vulnerabilities(advisory_id: str, *names: str) -> dict:
    doc = make_csaf_document(advisory_id)
    doc.pop("vulnerabilities")
    doc["product_tree"] = product_tree(*names)
    return doc


def legacy_cvrf(advisory_id: str, *products: str, cve: str = "CVE-2022-0778") -> str:
    """A pre-CSAF CVRF export: each product one exact version, all "Known Affected"."""
    tree = "".join(
        f'<FullProductName ProductID="P{index}">{name}</FullProductName>'
        for index, name in enumerate(products)
    )
    refs = "".join(f"<ProductID>P{index}</ProductID>" for index in range(len(products)))
    statuses = (
        f'<ProductStatuses><Status Type="Known Affected">{refs}</Status></ProductStatuses>'
        if products
        else ""
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<cvrf:cvrfdoc xmlns:cvrf="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf">'
        "<cvrf:DocumentTitle>Legacy advisory</cvrf:DocumentTitle>"
        "<cvrf:DocumentTracking><cvrf:Identification>"
        f"<cvrf:ID>{advisory_id}</cvrf:ID></cvrf:Identification>"
        "<cvrf:InitialReleaseDate>2022-04-01T00:00:00</cvrf:InitialReleaseDate>"
        "<cvrf:CurrentReleaseDate>2026-08-27T00:00:00</cvrf:CurrentReleaseDate>"
        "</cvrf:DocumentTracking>"
        f'<ProductTree><Branch Name="Fortinet" Type="Vendor">{tree}</Branch></ProductTree>'
        f'<Vulnerability Ordinal="1"><cvrf:CVE>{cve}</cvrf:CVE>{statuses}'
        "<CVSSScoreSets><ScoreSetV3><BaseScoreV3>7.5</BaseScoreV3></ScoreSetV3></CVSSScoreSets>"
        "</Vulnerability></cvrf:cvrfdoc>"
    )


def legacy_page(advisory_id: str) -> str:
    return (
        "<html><body><table><tr><td>Download</td><td>"
        f'<p><a href="/psirt/cvrf/{advisory_id}">CVRF</a></p>'
        "</td></tr></table></body></html>"
    )


class CsafWithoutVulnerabilitiesTests(unittest.TestCase):
    def test_untracked_only_export_is_a_confirmed_empty_result(self) -> None:
        doc = csaf_without_vulnerabilities("FG-IR-26-144", "FortiSOAR on-premise")
        fw.validate_csaf_document("FG-IR-26-144", doc)
        self.assertEqual(fw.parse_csaf_document("FG-IR-26-144", doc), [])

    def test_tracked_product_without_vulnerabilities_stays_invalid(self) -> None:
        for names in (("FortiOS",), ("FortiSOAR on-premise", "FortiClientEMS")):
            doc = csaf_without_vulnerabilities("FG-IR-26-144", *names)
            with self.subTest(names=names), self.assertRaises(fw.CsafResolutionError):
                fw.validate_csaf_document("FG-IR-26-144", doc)

    def test_empty_or_uninterpretable_product_tree_stays_invalid(self) -> None:
        for names in ((), ("Linux kernel",)):
            doc = csaf_without_vulnerabilities("FG-IR-26-144", *names)
            with self.subTest(names=names), self.assertRaises(fw.CsafResolutionError):
                fw.validate_csaf_document("FG-IR-26-144", doc)

    def test_explicit_null_vulnerabilities_stays_invalid(self) -> None:
        doc = csaf_without_vulnerabilities("FG-IR-26-144", "FortiSOAR on-premise")
        doc["vulnerabilities"] = None
        with self.assertRaises(fw.CsafResolutionError):
            fw.validate_csaf_document("FG-IR-26-144", doc)

    def test_foreign_document_is_still_refused_first(self) -> None:
        doc = csaf_without_vulnerabilities("FG-IR-26-999", "FortiSOAR on-premise")
        with self.assertRaises(fw.CsafResolutionError):
            fw.validate_csaf_document("FG-IR-26-144", doc)


class SkipReasonTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_fetch_text = fw.fetch_text
        self._orig_sleep = fw.time.sleep
        fw.time.sleep = lambda _seconds: None
        csaf_url = "https://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-26-144.json"
        bad_url = "https://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-26-145.json"
        self.responses: dict[str, object] = {
            "https://fortiguard.fortinet.com/psirt/FG-IR-26-144": make_advisory_page(
                "FG-IR-26-144", csaf_url
            ),
            csaf_url: json.dumps(
                csaf_without_vulnerabilities("FG-IR-26-144", "FortiSOAR on-premise")
            ),
            "https://fortiguard.fortinet.com/psirt/FG-IR-26-145": make_advisory_page(
                "FG-IR-26-145", bad_url
            ),
            bad_url: json.dumps(csaf_without_vulnerabilities("FG-IR-26-145", "FortiOS")),
            "https://fortiguard.fortinet.com/psirt/FG-IR-22-059": legacy_page("FG-IR-22-059"),
            # Like the real one: the CVRF names no product at all, so nothing can be read.
            "https://fortiguard.fortinet.com/psirt/cvrf/FG-IR-22-059": legacy_cvrf("FG-IR-22-059"),
            "https://fortiguard.fortinet.com/psirt/FG-IR-26-146": "<html>challenge</html>",
            "https://fortiguard.fortinet.com/psirt/FG-IR-26-147": fw.urllib.error.URLError("down"),
        }

        def fetch_text(url: str, timeout: int, redirect_validator=None) -> str:
            response = self.responses[url]
            if isinstance(response, Exception):
                raise response
            return response

        fw.fetch_text = fetch_text

    def tearDown(self) -> None:
        fw.fetch_text = self._orig_fetch_text
        fw.time.sleep = self._orig_sleep

    def test_legacy_page_without_csaf_is_unavailable_not_a_failure(self) -> None:
        with self.assertRaises(fw.CsafUnavailableError):
            fw.collect_cve_entries_for_advisory("FG-IR-22-059", timeout=5)

    def test_unvalidated_csaf_link_on_a_genuine_page_stays_a_failure(self) -> None:
        # Fortinet moving its file store must not turn every advisory into "no CSAF" (green).
        self.responses["https://fortiguard.fortinet.com/psirt/FG-IR-22-059"] = (
            legacy_page("FG-IR-22-059")
            + '<a href="/psirt/csaf/FG-IR-22-059?csaf_url=https://elsewhere.example/x.json">CSAF</a>'
        )
        reasons: dict[str, str] = {}
        _results, skipped = fw.fetch_cve_entries_for_advisories(
            ["FG-IR-22-059"], timeout=5, reasons=reasons
        )
        self.assertEqual(skipped, ["FG-IR-22-059"])
        self.assertEqual(reasons, {"FG-IR-22-059": fw.SKIP_REASON_NO_LINK})

    def test_recent_page_without_csaf_is_a_retryable_failure(self) -> None:
        # Modern pages also link their CVRF export: a recent advisory whose CSAF is not out yet
        # must stay orange and retried, never be filed as a legacy "no CSAF" advisory.
        self.responses["https://fortiguard.fortinet.com/psirt/FG-IR-26-148"] = legacy_page(
            "FG-IR-26-148"
        )
        reasons: dict[str, str] = {}
        _results, skipped = fw.fetch_cve_entries_for_advisories(
            ["FG-IR-26-148"], timeout=5, reasons=reasons
        )
        self.assertEqual(skipped, ["FG-IR-26-148"])
        self.assertEqual(reasons, {"FG-IR-26-148": fw.SKIP_REASON_NO_LINK})

    def test_legacy_cutoff_follows_the_advisory_number(self) -> None:
        self.assertTrue(fw.is_legacy_advisory_id("FG-IR-20-005"))
        self.assertTrue(fw.is_legacy_advisory_id("FG-IR-23-494"))
        self.assertFalse(fw.is_legacy_advisory_id("FG-IR-24-001"))
        self.assertFalse(fw.is_legacy_advisory_id("not-an-id"))

    def test_anti_bot_page_is_still_a_retryable_failure(self) -> None:
        with self.assertRaises(fw.CsafResolutionError) as caught:
            fw.collect_cve_entries_for_advisory("FG-IR-26-146", timeout=5)
        self.assertIsInstance(caught.exception, fw.CsafLinkMissingError)

    def test_each_skipped_advisory_records_its_reason(self) -> None:
        reasons = {"FG-IR-26-144": "stale"}
        results, skipped = fw.fetch_cve_entries_for_advisories(
            ["FG-IR-26-144", "FG-IR-26-145", "FG-IR-22-059", "FG-IR-26-146", "FG-IR-26-147"],
            timeout=5,
            reasons=reasons,
        )
        self.assertEqual(results, {"FG-IR-26-144": []})
        self.assertEqual(skipped, ["FG-IR-26-145", "FG-IR-22-059", "FG-IR-26-146", "FG-IR-26-147"])
        self.assertEqual(
            reasons,
            {
                "FG-IR-26-145": fw.SKIP_REASON_INVALID,
                "FG-IR-22-059": fw.SKIP_REASON_NO_CSAF,
                "FG-IR-26-146": fw.SKIP_REASON_NO_LINK,
                "FG-IR-26-147": fw.SKIP_REASON_NETWORK,
            },
        )

    def test_format_groups_ids_by_reason(self) -> None:
        reasons = {
            "FG-IR-26-145": fw.SKIP_REASON_INVALID,
            "FG-IR-26-146": fw.SKIP_REASON_NETWORK,
            "FG-IR-26-147": fw.SKIP_REASON_NETWORK,
        }
        self.assertEqual(
            fw.format_skipped_advisories(["FG-IR-26-145", "FG-IR-26-146", "FG-IR-26-147"], reasons),
            "FG-IR-26-145 (CSAF invalide), FG-IR-26-146, FG-IR-26-147 (réseau)",
        )


class MainRetryAndHealthTests(unittest.TestCase):
    """The scheduled pass: no-CSAF advisories are neither retried nor alarming."""

    def run_cve_pass(self, skipped: dict[str, str], still_failing: set[str]):
        sleeps: list[float] = []
        retried: list[list[str]] = []

        def collect(*_args, reasons=None, **_kwargs):
            reasons.update(skipped)
            return {"FG-IR-26-150": []}, list(skipped)

        def refetch(advisory_ids, _timeout, *, reasons=None):
            retried.append(list(advisory_ids))
            for advisory_id in advisory_ids:
                if advisory_id not in still_failing:
                    reasons.pop(advisory_id, None)
            return (
                {i: [] for i in advisory_ids if i not in still_failing},
                [i for i in advisory_ids if i in still_failing],
            )

        with tempfile.TemporaryDirectory() as tmp:
            base_path = Path(tmp) / "state.json"
            fw.write_json(base_path, fw.normalize_state({}))
            health_path = Path(tmp) / "health.json"
            report_path = Path(tmp) / "report.md"
            with mock.patch.object(fw, "collect_cve_catalog", collect), mock.patch.object(
                fw, "fetch_cve_entries_for_advisories", refetch
            ), mock.patch.object(fw, "fetch_psirt_versions", lambda *a, **k: set()), mock.patch.object(
                fw.time, "sleep", sleeps.append
            ):
                exit_code = fw.main([
                    "--cve-catalog",
                    "--cve-retry-delays-seconds", "300,900",
                    "--base", str(base_path), "--output", str(base_path),
                    "--report", str(report_path), "--health-output", str(health_path),
                ])
            self.assertEqual(exit_code, 0)
            record = fw.read_json(health_path, {})["sources"][fw.SOURCE_CVE_PSIRT]
            return record, sleeps, retried, report_path.read_text(encoding="utf-8")

    def test_only_no_csaf_advisories_left_means_ok_without_any_wait(self) -> None:
        record, sleeps, retried, report = self.run_cve_pass(
            {"FG-IR-20-005": fw.SKIP_REASON_NO_CSAF, "FG-IR-22-059": fw.SKIP_REASON_NO_CSAF},
            still_failing=set(),
        )
        self.assertEqual(record["status"], fw.HEALTH_STATUS_OK)
        self.assertIsNone(record["lastError"])
        self.assertEqual(sleeps, [])
        self.assertEqual(retried, [])
        self.assertIn(
            "Advisories sans export CSAF (non analysées, à vérifier sur la page PSIRT) : "
            "FG-IR-20-005, FG-IR-22-059",
            report,
        )
        self.assertIn("Advisories PSIRT non résolues : aucune", report)

    def test_real_failures_are_retried_alone_and_named_with_their_reason(self) -> None:
        record, sleeps, retried, report = self.run_cve_pass(
            {
                "FG-IR-22-059": fw.SKIP_REASON_NO_CSAF,
                "FG-IR-26-145": fw.SKIP_REASON_INVALID,
                "FG-IR-26-147": fw.SKIP_REASON_NETWORK,
            },
            still_failing={"FG-IR-26-145"},
        )
        self.assertEqual(sleeps, [300, 900])
        self.assertEqual(retried, [["FG-IR-26-145", "FG-IR-26-147"], ["FG-IR-26-145"]])
        self.assertEqual(record["status"], fw.HEALTH_STATUS_WARNING)
        self.assertEqual(
            record["lastError"], "1 advisorie(s) PSIRT non résolue(s) : FG-IR-26-145 (CSAF invalide)"
        )
        self.assertIn("Advisories PSIRT non résolues : FG-IR-26-145 (CSAF invalide)", report)
        self.assertIn("à vérifier sur la page PSIRT) : FG-IR-22-059", report)

    def test_nothing_resolved_names_every_skip_with_its_reason(self) -> None:
        def collect(*_args, reasons=None, **_kwargs):
            reasons.update({"FG-IR-22-059": fw.SKIP_REASON_NO_CSAF, "FG-IR-26-147": fw.SKIP_REASON_NETWORK})
            return {}, ["FG-IR-22-059", "FG-IR-26-147"]

        with tempfile.TemporaryDirectory() as tmp:
            base_path = Path(tmp) / "state.json"
            fw.write_json(base_path, fw.normalize_state({}))
            health_path = Path(tmp) / "health.json"
            with mock.patch.object(fw, "collect_cve_catalog", collect), mock.patch.object(
                fw, "fetch_cve_entries_for_advisories", lambda ids, _t, *, reasons=None: ({}, list(ids))
            ), mock.patch.object(fw, "fetch_psirt_versions", lambda *a, **k: set()), mock.patch.object(
                fw.time, "sleep", lambda _s: None
            ):
                fw.main([
                    "--cve-catalog",
                    "--base", str(base_path), "--output", str(base_path),
                    "--report", str(Path(tmp) / "report.md"), "--health-output", str(health_path),
                ])
            record = fw.read_json(health_path, {})["sources"][fw.SOURCE_CVE_PSIRT]
        self.assertEqual(record["status"], fw.HEALTH_STATUS_ERROR)
        self.assertEqual(
            record["lastError"],
            "2 advisorie(s) PSIRT non résolue(s), aucune résolue : "
            "FG-IR-22-059 (sans export CSAF), FG-IR-26-147 (réseau)",
        )


if __name__ == "__main__":
    unittest.main()
