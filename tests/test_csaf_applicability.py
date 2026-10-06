"""CSAF applicability tests for scripts/fortios_watch.py's CVE collector.

Covers the fix for the FG-IR-26-174 class of false positives: the previous collector read
Fortinet's coarse CVRF feed, whose branch-level "Known Affected" entries (no bounds) were
applied to *every* version of a train — it flagged FortiOS 7.2/7.4/8.0 as affected while the
official CSAF export restricts the impact to >=7.6.1|<=7.6.6. The collector now reads the CSAF
export as its single authoritative source, validates it before use, exploits its exact ranges
and exclusions, and treats anything unresolved as "keep previous data + diagnostic" — never as
an empty result.

Real frozen documents live in tests/fixtures/psirt/ (see CORPUS.md there); the synthetic
documents in this file cover shapes and failure modes the corpus does not exhibit.
"""

from __future__ import annotations

import http.server
import json
import sys
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_watch as fw

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "psirt"

# Real CSAF file-store URLs, as advertised by each advisory page when the fixtures were
# captured (see CORPUS.md). They embed a slugified title, hence the mapping here.
FIXTURE_CSAF_URLS = {
    "FG-IR-26-154": "https://filestore.fortinet.com/fortiguard/psirt/csaf_buffer-overread-in-authd-and-wad-daemon_fg-ir-26-154.json",
    "FG-IR-26-162": "https://filestore.fortinet.com/fortiguard/psirt/csaf_ui-dos-attack_fg-ir-26-162.json",
    "FG-IR-26-165": "https://filestore.fortinet.com/fortiguard/psirt/csaf_arbitrary-process-termination-from-exposed-minifilter-communication-port_fg-ir-26-165.json",
    "FG-IR-26-171": "https://filestore.fortinet.com/fortiguard/psirt/csaf_workflow-session-email-approval-process-bypass_fg-ir-26-171.json",
    "FG-IR-26-172": "https://filestore.fortinet.com/fortiguard/psirt/csaf_uncontrolled-resource-consumption-in-snmp_fg-ir-26-172.json",
    "FG-IR-26-173": "https://filestore.fortinet.com/fortiguard/psirt/csaf_null-pointer-dereference-in-log-report_fg-ir-26-173.json",
    "FG-IR-26-174": "https://filestore.fortinet.com/fortiguard/psirt/csaf_ztna-portal-improper-certificate-validation_fg-ir-26-174.json",
}


def load_csaf(advisory_id: str) -> dict:
    return json.loads(
        (FIXTURES / f"{advisory_id}.csaf.json").read_text(encoding="utf-8")
    )


def load_advisory_html(advisory_id: str) -> str:
    return (FIXTURES / f"{advisory_id}.advisory.html").read_text(encoding="utf-8")


def make_csaf_document(
    advisory_id: str = "FG-IR-26-001",
    *,
    title: str = "Synthetic advisory",
    vulns: list[dict] | None = None,
    **document_overrides: object,
) -> dict:
    document: dict = {
        "title": title,
        "csaf_version": "2.0",
        "publisher": {
            "name": "Fortinet PSIRT",
            "namespace": "https://fortiguard.fortinet.com/psirt",
        },
        "tracking": {
            "id": advisory_id,
            "initial_release_date": "2026-08-12T00:00:00",
            "current_release_date": "2026-08-19T00:00:00",
        },
    }
    document.update(document_overrides)
    return {
        "document": document,
        "product_tree": {"branches": []},
        "vulnerabilities": vulns or [],
    }


def make_vulnerability(
    cve: str = "CVE-2026-00001",
    *,
    affected: tuple = (),
    not_affected: tuple = (),
    fixed: tuple = (),
    score: float = 8.8,
    severity: str = "HIGH",
) -> dict:
    status: dict[str, list[str]] = {}
    if affected:
        status["known_affected"] = list(affected)
    if not_affected:
        status["known_not_affected"] = list(not_affected)
    if fixed:
        status["fixed"] = list(fixed)
    return {
        "cve": cve,
        "scores": [{"cvss_v3": {"baseScore": score, "baseSeverity": severity}}],
        "product_status": status,
    }


def make_advisory_page(advisory_id: str, csaf_url: str) -> str:
    return (
        "<html><body><table><tr><td>Download</td><td>"
        f'<p><a href="/psirt/csaf/{advisory_id}?csaf_url={csaf_url}">CSAF</a></p>'
        "</td></tr></table></body></html>"
    )


class CsafVersionClauseTests(unittest.TestCase):
    def test_bounded_range(self) -> None:
        self.assertEqual(
            fw.parse_csaf_version_clause(" >=7.6.1|<=7.6.6"),
            {"branch": "7.6", "from": "7.6.1", "to": "7.6.6"},
        )

    def test_half_open_ranges(self) -> None:
        self.assertEqual(
            fw.parse_csaf_version_clause(" >=7.6.1"),
            {"branch": "7.6", "from": "7.6.1", "to": None},
        )
        self.assertEqual(
            fw.parse_csaf_version_clause(" <=7.6.6"),
            {"branch": "7.6", "from": None, "to": "7.6.6"},
        )

    def test_all_versions(self) -> None:
        self.assertEqual(
            fw.parse_csaf_version_clause("/ 7.2 all versions"),
            {"branch": "7.2", "from": None, "to": None},
        )

    def test_exact_and_dashed_versions(self) -> None:
        self.assertEqual(
            fw.parse_csaf_version_clause("-7.6.7"),
            {"branch": "7.6", "from": "7.6.7", "to": "7.6.7"},
        )
        self.assertEqual(
            fw.parse_csaf_version_clause(" 7.6.7"),
            {"branch": "7.6", "from": "7.6.7", "to": "7.6.7"},
        )

    def test_upcoming_version(self) -> None:
        self.assertEqual(
            fw.parse_csaf_version_clause("upcoming  7.6.7"),
            {"branch": "7.6", "from": "7.6.7", "to": "7.6.7"},
        )

    def test_unrecognized_shapes_return_none(self) -> None:
        for value in ("", "version 7.6.1", ">=7.4.10|<=7.6.2", ">=7.6.6|<=7.6.1", "all versions"):
            with self.subTest(value=value):
                self.assertIsNone(fw.parse_csaf_version_clause(value))

    def test_partially_recognized_clauses_are_refused(self) -> None:
        """The whole clause must be one of the documented shapes: a bound embedded in unknown
        or contradictory text must never be partially consumed — that used to turn
        ">=7.6.1|<7.6.7" into a lower bound with NO upper bound (a weaker claim than the
        document actually makes)."""
        for value in (
            ">=7.6.1|<7.6.7",
            ">=7.6.1 extra",
            "junk <=7.6.6",
            "version >=7.6.1",
            ">=7.6.1|<=7.6.6 (see note)",
            "<7.6.7",
            "<=7.6.6|>=7.6.1",
        ):
            with self.subTest(value=value):
                self.assertIsNone(fw.parse_csaf_version_clause(value))

    def test_whitespace_around_markers_is_still_accepted(self) -> None:
        self.assertEqual(
            fw.parse_csaf_version_clause(" >= 7.6.1 | <= 7.6.6 "),
            {"branch": "7.6", "from": "7.6.1", "to": "7.6.6"},
        )


class CsafProductValueTests(unittest.TestCase):
    def test_tracked_products_are_split(self) -> None:
        self.assertEqual(
            fw.split_csaf_product_value("FortiOS >=7.6.1|<=7.6.6"),
            ("FortiOS", " >=7.6.1|<=7.6.6"),
        )
        self.assertEqual(
            fw.split_csaf_product_value("FortiClientWindows 7.2 all versions"),
            ("FortiClientWindows", " 7.2 all versions"),
        )
        self.assertEqual(
            fw.split_csaf_product_value("FortiClientEMS 7.0 all versions"),
            ("FortiClientEMS", " 7.0 all versions"),
        )

    def test_untracked_products_are_ignored(self) -> None:
        for value in (
            "FortiWeb 7.4 all versions",
            "FortiMail >=7.0.0|<=7.0.5",
            "FortiADC 7.1 all versions",
        ):
            with self.subTest(value=value):
                self.assertIsNone(fw.split_csaf_product_value(value))

    def test_cloud_variants_of_tracked_products_are_a_different_product(self) -> None:
        """"FortiManager Cloud 7.2 all versions" is the cloud service, not on-prem FortiManager —
        treating it as FortiManager would suspend every advisory that lists it."""
        for value in (
            "FortiManager Cloud 7.2 all versions",
            "FortiManager Cloud-upcoming  7.4.11",
            "FortiManager Cloud-7.6.5",
        ):
            with self.subTest(value=value):
                self.assertIsNone(fw.split_csaf_product_value(value))

    def test_unresolved_or_null_values_are_refused(self) -> None:
        """A value that names no recognizable Fortinet product is uninterpretable data, not an
        untracked product: silently ignoring it is what let a partially-invalid export look
        like a confirmed "no longer affected" and delete the stored entries."""
        for value in (None, 7, ["FortiOS 7.6.1"], "", "   ", "CSAFPID-0001", "product-1"):
            with self.subTest(value=value), self.assertRaises(fw.CsafResolutionError):
                fw.split_csaf_product_value(value)

    def test_recognizable_untracked_fortinet_lines_stay_out_of_scope(self) -> None:
        for value in (
            "FortiPAM 1.9.0",
            "FortiProxy 7.0 all versions",
            "FortiWeb some future syntax",
        ):
            with self.subTest(value=value):
                self.assertIsNone(fw.split_csaf_product_value(value))


class RealCorpusParsingTests(unittest.TestCase):
    """Parse the frozen real exports and assert the exact official ranges."""

    def test_fg_ir_26_174_yields_only_the_official_7_6_range(self) -> None:
        entries = fw.parse_csaf_document("FG-IR-26-174", load_csaf("FG-IR-26-174"))
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["id"], "CVE-2026-84393")
        self.assertEqual(entry["severity"], "high")
        self.assertEqual(entry["cvssScore"], 7.3)
        self.assertEqual(entry["title"], "ZTNA Portal Improper Certificate Validation")
        self.assertEqual(entry["advisoryId"], "FG-IR-26-174")
        self.assertEqual(entry["publishedAt"], "2026-09-08")
        self.assertEqual(
            entry["url"], "https://fortiguard.fortinet.com/psirt/FG-IR-26-174"
        )
        self.assertEqual(
            entry["affected"],
            [
                {
                    "product": "fortigate-fortios",
                    "models": [],
                    "branch": "7.6",
                    "from": "7.6.1",
                    "to": "7.6.6",
                }
            ],
        )

    def test_fg_ir_26_165_forticlient_windows_platform(self) -> None:
        entries = fw.parse_csaf_document("FG-IR-26-165", load_csaf("FG-IR-26-165"))
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["id"], "CVE-2026-84386")
        self.assertEqual(
            entries[0]["affected"],
            [
                {
                    "product": "forticlient",
                    "models": ["windows"],
                    "branch": "7.2",
                    "from": None,
                    "to": None,
                },
                {
                    "product": "forticlient",
                    "models": ["windows"],
                    "branch": "7.4",
                    "from": "7.4.0",
                    "to": "7.4.7",
                },
            ],
        )

    def test_fg_ir_26_171_fortimanager_ignores_the_cloud_variant(self) -> None:
        entries = fw.parse_csaf_document("FG-IR-26-171", load_csaf("FG-IR-26-171"))
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["id"], "CVE-2026-22575")
        self.assertEqual(
            entries[0]["affected"],
            [
                {
                    "product": "fortimanager",
                    "models": [],
                    "branch": "7.2",
                    "from": None,
                    "to": None,
                },
                {
                    "product": "fortimanager",
                    "models": [],
                    "branch": "7.4",
                    "from": "7.4.0",
                    "to": "7.4.10",
                },
                {
                    "product": "fortimanager",
                    "models": [],
                    "branch": "7.6",
                    "from": "7.6.0",
                    "to": "7.6.4",
                },
            ],
        )

    def test_fg_ir_26_172_fortianalyzer_precise_range(self) -> None:
        entries = fw.parse_csaf_document("FG-IR-26-172", load_csaf("FG-IR-26-172"))
        self.assertEqual(
            entries[0]["affected"],
            [
                {
                    "product": "fortianalyzer",
                    "models": [],
                    "branch": "7.6",
                    "from": "7.6.3",
                    "to": "7.6.6",
                }
            ],
        )

    def test_fg_ir_26_162_mixes_all_versions_and_bounded_ranges(self) -> None:
        entries = fw.parse_csaf_document("FG-IR-26-162", load_csaf("FG-IR-26-162"))
        self.assertEqual(
            entries[0]["affected"],
            [
                {
                    "product": "fortigate-fortios",
                    "models": [],
                    "branch": "7.2",
                    "from": None,
                    "to": None,
                },
                {
                    "product": "fortigate-fortios",
                    "models": [],
                    "branch": "7.4",
                    "from": None,
                    "to": None,
                },
                {
                    "product": "fortigate-fortios",
                    "models": [],
                    "branch": "7.6",
                    "from": "7.6.0",
                    "to": "7.6.6",
                },
            ],
        )

    def test_fg_ir_26_154_merges_multiple_cves(self) -> None:
        entries = fw.parse_csaf_document("FG-IR-26-154", load_csaf("FG-IR-26-154"))
        self.assertEqual(
            sorted(entry["id"] for entry in entries),
            ["CVE-2025-43892", "CVE-2026-59840"],
        )
        for entry in entries:
            self.assertEqual(
                [range_["branch"] for range_ in entry["affected"]],
                ["6.4", "7.0", "7.2", "7.4", "7.6"],
            )

    def test_fg_ir_26_173_unaffected_branches_never_become_affected(self) -> None:
        entries = fw.parse_csaf_document("FG-IR-26-173", load_csaf("FG-IR-26-173"))
        self.assertEqual(
            [range_["branch"] for range_ in entries[0]["affected"]],
            ["7.2", "7.4"],
        )

    def test_real_advisory_page_advertises_its_own_csaf_url(self) -> None:
        self.assertEqual(
            fw.discover_csaf_url("FG-IR-26-174", load_advisory_html("FG-IR-26-174")),
            FIXTURE_CSAF_URLS["FG-IR-26-174"],
        )


class CsafExclusionTests(unittest.TestCase):
    def test_exact_exclusion_inside_an_all_versions_range(self) -> None:
        doc = make_csaf_document(
            vulns=[
                make_vulnerability(
                    affected=("FortiOS 7.2 all versions",),
                    not_affected=("FortiOS-7.2.9",),
                )
            ]
        )
        entries = fw.parse_csaf_document("FG-IR-26-001", doc)
        self.assertEqual(
            entries[0]["affected"],
            [
                {
                    "product": "fortigate-fortios",
                    "models": [],
                    "branch": "7.2",
                    "from": None,
                    "to": None,
                    "excluded": ["7.2.9"],
                }
            ],
        )

    def test_exact_exclusion_inside_a_bounded_range(self) -> None:
        doc = make_csaf_document(
            vulns=[
                make_vulnerability(
                    affected=("FortiOS >=7.6.1|<=7.6.6",),
                    not_affected=("FortiOS-7.6.3",),
                )
            ]
        )
        entries = fw.parse_csaf_document("FG-IR-26-001", doc)
        self.assertEqual(entries[0]["affected"][0]["excluded"], ["7.6.3"])

    def test_fixed_versions_are_treated_as_exclusions(self) -> None:
        doc = make_csaf_document(
            vulns=[
                make_vulnerability(
                    affected=("FortiOS 7.2 all versions",),
                    fixed=("FortiOS-7.2.9",),
                )
            ]
        )
        entries = fw.parse_csaf_document("FG-IR-26-001", doc)
        self.assertEqual(entries[0]["affected"][0]["excluded"], ["7.2.9"])

    def test_exclusion_outside_the_range_is_dropped(self) -> None:
        """FG-IR-26-174 lists FortiOS-7.6.7 as not affected, just above its <=7.6.6 bound."""
        doc = make_csaf_document(
            vulns=[
                make_vulnerability(
                    affected=("FortiOS >=7.6.1|<=7.6.6",),
                    not_affected=("FortiOS-7.6.7",),
                )
            ]
        )
        entries = fw.parse_csaf_document("FG-IR-26-001", doc)
        self.assertNotIn("excluded", entries[0]["affected"][0])

    def test_exclusions_for_branches_without_affected_entries_are_unused(self) -> None:
        doc = make_csaf_document(
            vulns=[
                make_vulnerability(
                    affected=("FortiOS >=7.6.1|<=7.6.6",),
                    not_affected=(
                        "FortiOS/ 7.2 all versions",
                        "FortiOS/ 7.4 all versions",
                        "FortiOS/ 8.0 all versions",
                    ),
                )
            ]
        )
        entries = fw.parse_csaf_document("FG-IR-26-001", doc)
        self.assertEqual(len(entries[0]["affected"]), 1)

    def test_fully_unaffected_and_affected_for_the_same_train_is_a_contradiction(self) -> None:
        doc = make_csaf_document(
            vulns=[
                make_vulnerability(
                    affected=("FortiOS 7.2 all versions",),
                    not_affected=("FortiOS/ 7.2 all versions",),
                )
            ]
        )
        with self.assertRaises(fw.CsafResolutionError):
            fw.parse_csaf_document("FG-IR-26-001", doc)

    def test_unusable_exclusion_range_suspends_the_advisory(self) -> None:
        doc = make_csaf_document(
            vulns=[
                make_vulnerability(
                    affected=("FortiOS 7.2 all versions",),
                    not_affected=("FortiOS >=7.2.0|<=7.2.5",),
                )
            ]
        )
        with self.assertRaises(fw.CsafResolutionError):
            fw.parse_csaf_document("FG-IR-26-001", doc)


class CsafUnknownShapeTests(unittest.TestCase):
    def test_unknown_affected_shape_for_a_tracked_product_raises(self) -> None:
        doc = make_csaf_document(
            vulns=[make_vulnerability(affected=("FortiOS version seven point six",))]
        )
        with self.assertRaises(fw.CsafResolutionError):
            fw.parse_csaf_document("FG-IR-26-001", doc)

    def test_unknown_shapes_for_untracked_products_are_ignored(self) -> None:
        doc = make_csaf_document(
            vulns=[
                make_vulnerability(
                    affected=("FortiWeb some future syntax",),
                    not_affected=("FortiMail even weirder",),
                )
            ]
        )
        self.assertEqual(fw.parse_csaf_document("FG-IR-26-001", doc), [])

    def test_non_list_status_values_raise(self) -> None:
        doc = make_csaf_document(vulns=[make_vulnerability()])
        doc["vulnerabilities"][0]["product_status"]["known_affected"] = "FortiOS 7.2 all versions"
        with self.assertRaises(fw.CsafResolutionError):
            fw.parse_csaf_document("FG-IR-26-001", doc)

    def test_non_object_product_status_raises(self) -> None:
        doc = make_csaf_document(vulns=[make_vulnerability()])
        doc["vulnerabilities"][0]["product_status"] = ["not", "an", "object"]
        with self.assertRaises(fw.CsafResolutionError):
            fw.parse_csaf_document("FG-IR-26-001", doc)

    def test_vulnerability_without_tracked_products_is_a_definitive_empty_list(self) -> None:
        doc = make_csaf_document(
            vulns=[make_vulnerability(affected=("FortiWeb 7.4 all versions",))]
        )
        self.assertEqual(fw.parse_csaf_document("FG-IR-26-001", doc), [])


class CsafDocumentValidationTests(unittest.TestCase):
    def test_valid_document_passes(self) -> None:
        doc = make_csaf_document()
        self.assertIs(fw.validate_csaf_document("FG-IR-26-001", doc), doc)

    def test_mismatched_tracking_id_is_refused(self) -> None:
        doc = make_csaf_document("FG-IR-26-002")
        with self.assertRaises(fw.CsafResolutionError):
            fw.validate_csaf_document("FG-IR-26-001", doc)

    def test_unexpected_csaf_version_is_refused(self) -> None:
        doc = make_csaf_document(csaf_version="1.2")
        with self.assertRaises(fw.CsafResolutionError):
            fw.validate_csaf_document("FG-IR-26-001", doc)

    def test_foreign_publisher_is_refused(self) -> None:
        doc = make_csaf_document(publisher={"name": "Someone Else"})
        with self.assertRaises(fw.CsafResolutionError):
            fw.validate_csaf_document("FG-IR-26-001", doc)

    def test_non_object_and_missing_sections_are_refused(self) -> None:
        for doc in ("<html>challenge</html>", {}, {"document": "x"}, {"document": {}, "vulnerabilities": []}):
            with self.subTest(doc=doc), self.assertRaises(fw.CsafResolutionError):
                fw.validate_csaf_document("FG-IR-26-001", doc)

    def test_non_list_vulnerabilities_are_refused(self) -> None:
        doc = make_csaf_document()
        doc["vulnerabilities"] = {"not": "a list"}
        with self.assertRaises(fw.CsafResolutionError):
            fw.validate_csaf_document("FG-IR-26-001", doc)

    def test_partially_invalid_vulnerabilities_are_refused(self) -> None:
        """Identity checks alone are not enough: a document whose vulnerability entries or
        status lists are malformed must be refused before it can be read as "no CVEs"."""
        element_not_object = make_csaf_document()
        element_not_object["vulnerabilities"] = ["junk"]
        without_cve = make_csaf_document(vulns=[make_vulnerability()])
        without_cve["vulnerabilities"][0].pop("cve")
        no_product_status = make_csaf_document(
            vulns=[make_vulnerability(affected=("FortiOS 7.2 all versions",))]
        )
        no_product_status["vulnerabilities"][0]["product_status"] = None
        empty_known_affected = make_csaf_document(vulns=[make_vulnerability()])
        empty_known_affected["vulnerabilities"][0]["product_status"] = {
            "known_affected": []
        }
        for label, doc in (
            ("element not object", element_not_object),
            ("no cve", without_cve),
            ("no product_status", no_product_status),
            ("empty known_affected", empty_known_affected),
        ):
            with self.subTest(case=label), self.assertRaises(fw.CsafResolutionError):
                fw.validate_csaf_document("FG-IR-26-001", doc)


class CsafUrlDiscoveryTests(unittest.TestCase):
    def test_relay_link_is_accepted_and_unwrapped(self) -> None:
        html = make_advisory_page(
            "FG-IR-26-001", "https://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-26-001.json"
        )
        self.assertEqual(
            fw.discover_csaf_url("FG-IR-26-001", html),
            "https://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-26-001.json",
        )

    def test_html_escaped_ampersand_is_unescaped(self) -> None:
        html = (
            '<a href="/psirt/csaf/FG-IR-26-001?x=1&amp;csaf_url='
            'https://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-26-001.json">CSAF</a>'
        )
        self.assertEqual(
            fw.discover_csaf_url("FG-IR-26-001", html),
            "https://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-26-001.json",
        )

    def test_direct_file_store_link_is_accepted(self) -> None:
        html = (
            '<a href="https://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-26-001.json">'
            "CSAF</a>"
        )
        self.assertEqual(
            fw.discover_csaf_url("FG-IR-26-001", html),
            "https://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-26-001.json",
        )

    def test_unexpected_destinations_are_refused(self) -> None:
        refused = {
            "http": "http://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-26-001.json",
            "other host": "https://evil.example.com/fortiguard/psirt/csaf_x_fg-ir-26-001.json",
            "other path": "https://filestore.fortinet.com/other/csaf_x_fg-ir-26-001.json",
            "not json": "https://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-26-001.txt",
            "credentials": "https://user:pass@filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-26-001.json",
            "fragment": "https://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-26-001.json%23f",
        }
        for label, target in refused.items():
            with self.subTest(label=label):
                html = make_advisory_page("FG-IR-26-001", target)
                self.assertIsNone(fw.discover_csaf_url("FG-IR-26-001", html))

    def test_anti_bot_or_legacy_page_without_link_returns_none(self) -> None:
        for html in (
            "<html><body>Access denied (captcha)</body></html>",
            '<a href="/psirt/cvrf/FG-IR-22-059">CVRF</a>',  # legacy advisory: CVRF only
        ):
            with self.subTest(html=html[:30]):
                self.assertIsNone(fw.discover_csaf_url("FG-IR-22-059", html))

    def test_link_for_a_different_advisory_is_not_used(self) -> None:
        html = make_advisory_page(
            "FG-IR-26-002", "https://filestore.fortinet.com/fortiguard/psirt/csaf_y_fg-ir-26-002.json"
        )
        self.assertIsNone(fw.discover_csaf_url("FG-IR-26-001", html))


class CollectCveEntriesForAdvisoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_fetch_text = fw.fetch_text

    def tearDown(self) -> None:
        fw.fetch_text = self._orig_fetch_text

    def _install_transport(self, responses: dict[str, str | Exception]) -> list[str]:
        calls: list[str] = []

        def fetch_text(
            url: str, timeout: int, redirect_validator=None
        ) -> str:
            calls.append(url)
            response = responses.get(url)
            if response is None:
                raise AssertionError(f"unexpected fetch: {url}")
            if isinstance(response, Exception):
                raise response
            return response

        fw.fetch_text = fetch_text
        return calls

    def test_success_walks_page_then_csaf_and_returns_the_precise_entry(self) -> None:
        advisory_id = "FG-IR-26-174"
        csaf_url = FIXTURE_CSAF_URLS[advisory_id]
        calls = self._install_transport(
            {
                f"https://fortiguard.fortinet.com/psirt/{advisory_id}": load_advisory_html(
                    advisory_id
                ),
                csaf_url: json.dumps(load_csaf(advisory_id)),
            }
        )
        entries = fw.collect_cve_entries_for_advisory(advisory_id, timeout=5)
        self.assertEqual(
            calls,
            [
                f"https://fortiguard.fortinet.com/psirt/{advisory_id}",
                csaf_url,
            ],
        )
        self.assertEqual(entries[0]["id"], "CVE-2026-84393")
        self.assertEqual(entries[0]["affected"][0]["from"], "7.6.1")

    def test_all_corpus_bulletins_resolve_from_their_advisory_id(self) -> None:
        """Every frozen bulletin must be reachable through the normal discovery path
        (advisory id -> page -> CSAF), never through a hand-fed URL."""
        for advisory_id, csaf_url in sorted(FIXTURE_CSAF_URLS.items()):
            with self.subTest(advisory_id=advisory_id):
                self._install_transport(
                    {
                        f"https://fortiguard.fortinet.com/psirt/{advisory_id}": make_advisory_page(
                            advisory_id, csaf_url
                        ),
                        csaf_url: json.dumps(load_csaf(advisory_id)),
                    }
                )
                entries = fw.collect_cve_entries_for_advisory(advisory_id, timeout=5)
                self.assertTrue(all(entry["id"] for entry in entries))

    def test_anti_bot_page_without_link_raises_instead_of_returning_empty(self) -> None:
        self._install_transport(
            {
                "https://fortiguard.fortinet.com/psirt/FG-IR-26-001": "<html>challenge</html>",
            }
        )
        with self.assertRaises(fw.CsafResolutionError):
            fw.collect_cve_entries_for_advisory("FG-IR-26-001", timeout=5)

    def test_invalid_json_raises(self) -> None:
        csaf_url = "https://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-26-001.json"
        self._install_transport(
            {
                "https://fortiguard.fortinet.com/psirt/FG-IR-26-001": make_advisory_page(
                    "FG-IR-26-001", csaf_url
                ),
                csaf_url: "<html>not json</html>",
            }
        )
        with self.assertRaises(json.JSONDecodeError):
            fw.collect_cve_entries_for_advisory("FG-IR-26-001", timeout=5)

    def test_identity_mismatch_raises(self) -> None:
        csaf_url = "https://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-26-001.json"
        self._install_transport(
            {
                "https://fortiguard.fortinet.com/psirt/FG-IR-26-001": make_advisory_page(
                    "FG-IR-26-001", csaf_url
                ),
                csaf_url: json.dumps(make_csaf_document("FG-IR-26-999")),
            }
        )
        with self.assertRaises(fw.CsafResolutionError):
            fw.collect_cve_entries_for_advisory("FG-IR-26-001", timeout=5)

    def test_validated_empty_export_is_a_definitive_empty_list(self) -> None:
        csaf_url = "https://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-26-001.json"
        self._install_transport(
            {
                "https://fortiguard.fortinet.com/psirt/FG-IR-26-001": make_advisory_page(
                    "FG-IR-26-001", csaf_url
                ),
                csaf_url: json.dumps(make_csaf_document("FG-IR-26-001")),
            }
        )
        self.assertEqual(fw.collect_cve_entries_for_advisory("FG-IR-26-001", timeout=5), [])

    def test_network_failure_is_propagated_for_the_batch_wrapper_to_record(self) -> None:
        self._install_transport(
            {
                "https://fortiguard.fortinet.com/psirt/FG-IR-26-001": urllib.error.URLError(
                    "PSIRT unreachable"
                ),
            }
        )
        with self.assertRaises(urllib.error.URLError):
            fw.collect_cve_entries_for_advisory("FG-IR-26-001", timeout=5)


class BatchWrapperSkipTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_fetch_text = fw.fetch_text

    def tearDown(self) -> None:
        fw.fetch_text = self._orig_fetch_text

    def test_unresolved_advisories_are_skipped_and_never_treated_as_empty(self) -> None:
        ok_url = "https://filestore.fortinet.com/fortiguard/psirt/csaf_ok_fg-ir-26-002.json"
        responses: dict[str, str | Exception] = {
            "https://fortiguard.fortinet.com/psirt/FG-IR-26-001": "<html>challenge</html>",
            "https://fortiguard.fortinet.com/psirt/FG-IR-26-002": make_advisory_page(
                "FG-IR-26-002", ok_url
            ),
            ok_url: json.dumps(
                make_csaf_document(
                    "FG-IR-26-002",
                    vulns=[make_vulnerability(affected=("FortiOS >=7.6.1|<=7.6.6",))],
                )
            ),
        }

        def fetch_text(
            url: str, timeout: int, redirect_validator=None
        ) -> str:
            response = responses.get(url)
            if response is None:
                raise AssertionError(f"unexpected fetch: {url}")
            if isinstance(response, Exception):
                raise response
            return response

        fw.fetch_text = fetch_text
        results, skipped = fw.fetch_cve_entries_for_advisories(
            ["FG-IR-26-001", "FG-IR-26-002"], timeout=5
        )
        self.assertEqual(skipped, ["FG-IR-26-001"])
        self.assertNotIn("FG-IR-26-001", results)
        self.assertEqual([entry["id"] for entry in results["FG-IR-26-002"]], ["CVE-2026-00001"])


class CsafInvalidDataTests(unittest.TestCase):
    """A partially invalid document must suspend the advisory (previous CVE data preserved)
    instead of being read as a confirmed empty/partial result that deletes stored entries."""

    def test_non_object_vulnerability_element_is_refused(self) -> None:
        doc = make_csaf_document(
            vulns=[make_vulnerability(affected=("FortiOS 7.2 all versions",))]
        )
        doc["vulnerabilities"].append("junk")
        with self.assertRaises(fw.CsafResolutionError):
            fw.parse_csaf_document("FG-IR-26-001", doc)

    def test_missing_or_null_product_status_is_refused(self) -> None:
        for label in ("missing", "null"):
            vuln = make_vulnerability(affected=("FortiOS 7.2 all versions",))
            if label == "missing":
                vuln.pop("product_status")
            else:
                vuln["product_status"] = None
            with self.subTest(case=label), self.assertRaises(fw.CsafResolutionError):
                fw.parse_csaf_document("FG-IR-26-001", make_csaf_document(vulns=[vuln]))

    def test_null_or_empty_known_affected_is_refused(self) -> None:
        for status in ({"known_affected": None}, {"known_affected": []}, {}):
            vuln = make_vulnerability(affected=("FortiOS 7.2 all versions",))
            vuln["product_status"] = status
            with self.subTest(status=status), self.assertRaises(fw.CsafResolutionError):
                fw.parse_csaf_document("FG-IR-26-001", make_csaf_document(vulns=[vuln]))

    def test_null_or_opaque_product_value_is_refused(self) -> None:
        for value in (None, "CSAFPID-0001"):
            vuln = make_vulnerability(affected=(value,))
            with self.subTest(value=value), self.assertRaises(fw.CsafResolutionError):
                fw.parse_csaf_document("FG-IR-26-001", make_csaf_document(vulns=[vuln]))

    def test_vulnerability_without_cve_identifier_is_refused(self) -> None:
        vuln = make_vulnerability(affected=("FortiOS 7.2 all versions",))
        vuln.pop("cve")
        with self.assertRaises(fw.CsafResolutionError):
            fw.parse_csaf_document("FG-IR-26-001", make_csaf_document(vulns=[vuln]))

    def test_untracked_products_only_still_is_a_definitive_empty_result(self) -> None:
        """The legitimate retraction path is preserved: a fully-readable export that names
        only untracked products really has nothing for us — empty, not suspended."""
        doc = make_csaf_document(
            vulns=[
                make_vulnerability(
                    affected=(
                        "FortiWeb 7.4 all versions",
                        "FortiPAM 1.9.0",
                        "FortiProxy >=7.4.0|<=7.4.13",
                    )
                )
            ]
        )
        self.assertEqual(fw.parse_csaf_document("FG-IR-26-001", doc), [])


class FortiClientPlatformScopeTests(unittest.TestCase):
    """Affected-ness and exclusions are scoped per product AND platform: Windows/macOS/Linux
    share the `forticlient` product id, so a product+branch-only key would cross-contaminate."""

    def test_mac_exclusion_does_not_leak_into_windows(self) -> None:
        doc = make_csaf_document(
            vulns=[
                make_vulnerability(
                    affected=(
                        "FortiClientWindows 7.2 all versions",
                        "FortiClientMac 7.2 all versions",
                    ),
                    fixed=("FortiClientMac-7.2.9",),
                )
            ]
        )
        entry = fw.parse_csaf_document("FG-IR-26-001", doc)[0]
        by_model = {tuple(range_["models"]): range_ for range_ in entry["affected"]}
        self.assertEqual(by_model[("windows",)].get("excluded"), None)
        self.assertEqual(by_model[("macos",)]["excluded"], ["7.2.9"])
        self.assertEqual(by_model[("macos",)]["product"], "forticlient")

    def test_mac_whole_branch_not_affected_does_not_suspend_a_windows_bulletin(self) -> None:
        doc = make_csaf_document(
            vulns=[
                make_vulnerability(
                    affected=("FortiClientWindows 7.2 all versions",),
                    not_affected=(
                        "FortiClientMac/ 7.2 all versions",
                        "FortiClientLinux/ 7.2 all versions",
                    ),
                )
            ]
        )
        entry = fw.parse_csaf_document("FG-IR-26-001", doc)[0]
        self.assertEqual(
            entry["affected"],
            [
                {
                    "product": "forticlient",
                    "models": ["windows"],
                    "branch": "7.2",
                    "from": None,
                    "to": None,
                }
            ],
        )

    def test_three_platforms_keep_separate_exclusions(self) -> None:
        doc = make_csaf_document(
            vulns=[
                make_vulnerability(
                    affected=(
                        "FortiClientWindows 7.2 all versions",
                        "FortiClientMac 7.2 all versions",
                        "FortiClientLinux 7.2 all versions",
                    ),
                    fixed=("FortiClientWindows-7.2.9", "FortiClientLinux-7.2.9"),
                )
            ]
        )
        entry = fw.parse_csaf_document("FG-IR-26-001", doc)[0]
        by_model = {tuple(range_["models"]): range_ for range_ in entry["affected"]}
        self.assertEqual(by_model[("windows",)]["excluded"], ["7.2.9"])
        self.assertEqual(by_model[("macos",)].get("excluded"), None)
        self.assertEqual(by_model[("linux",)]["excluded"], ["7.2.9"])

    def test_same_platform_whole_branch_contradiction_still_suspends(self) -> None:
        doc = make_csaf_document(
            vulns=[
                make_vulnerability(
                    affected=("FortiClientWindows 7.2 all versions",),
                    not_affected=("FortiClientWindows/ 7.2 all versions",),
                )
            ]
        )
        with self.assertRaises(fw.CsafResolutionError):
            fw.parse_csaf_document("FG-IR-26-001", doc)


class RedirectValidationTests(unittest.TestCase):
    """Redirect destinations are re-validated before any connection is opened — for the
    advisory page fetch *and* the CSAF download. The validator functions are pure, and the
    mechanism itself is exercised against inert local HTTP servers only."""

    def test_psirt_page_redirect_rules(self) -> None:
        allowed = fw._psirt_page_redirect_allowed
        self.assertTrue(allowed("https://fortiguard.fortinet.com/psirt/FG-IR-26-174"))
        for refused in (
            "http://fortiguard.fortinet.com/psirt/FG-IR-26-174",
            "https://evil.example.com/psirt/FG-IR-26-174",
            "https://fortiguard.fortinet.com:8443/psirt/FG-IR-26-174",
            "https://user:pass@fortiguard.fortinet.com/psirt/FG-IR-26-174",
            "https://fortiguard.fortinet.com/other/FG-IR-26-174",
            "https://127.0.0.1/psirt/FG-IR-26-174",
        ):
            with self.subTest(candidate=refused):
                self.assertFalse(allowed(refused))

    def test_csaf_redirect_rules(self) -> None:
        allowed = fw._csaf_redirect_allowed
        self.assertTrue(
            allowed(
                "https://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-26-001.json"
            )
        )
        for refused in (
            "http://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-26-001.json",
            "https://evil.example.com/fortiguard/psirt/csaf_x_fg-ir-26-001.json",
            "https://filestore.fortinet.com/other/csaf_x_fg-ir-26-001.json",
            "https://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-26-001.txt",
            "https://127.0.0.1/fortiguard/psirt/csaf_x_fg-ir-26-001.json",
        ):
            with self.subTest(candidate=refused):
                self.assertFalse(allowed(refused))

    def _serve(self, handler_class) -> http.server.ThreadingHTTPServer:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server

    def test_redirect_is_refused_before_any_connection_to_the_target(self) -> None:
        target_hits: list[str] = []
        target_port_holder: list[int] = []

        class TargetHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                target_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"SECRET")

            def log_message(self, format, *args):  # keep test output clean
                pass

        target_server = self._serve(TargetHandler)
        target_port_holder.append(target_server.server_address[1])

        class SourceHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header(
                    "Location",
                    f"http://127.0.0.1:{target_port_holder[0]}/secret",
                )
                self.end_headers()

            def log_message(self, format, *args):  # keep test output clean
                pass

        source_server = self._serve(SourceHandler)
        try:
            source_port = source_server.server_address[1]
            with self.assertRaises(fw.UnsafeRedirectError):
                fw.read_url_with_retry(
                    urllib.request.Request(f"http://127.0.0.1:{source_port}/redirect"),
                    timeout=5,
                    retries=1,
                    redirect_validator=lambda candidate: candidate.startswith(
                        f"http://127.0.0.1:{source_port}/"
                    ),
                )
            self.assertEqual(
                target_hits, [], "no request may ever reach the refused destination"
            )
        finally:
            source_server.shutdown()
            target_server.shutdown()
            source_server.server_close()
            target_server.server_close()

    def test_allowed_redirect_is_followed(self) -> None:
        port_holder: list[int] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header(
                        "Location",
                        f"http://127.0.0.1:{port_holder[0]}/final",
                    )
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"OK")

            def log_message(self, format, *args):  # keep test output clean
                pass

        server = self._serve(Handler)
        port_holder.append(server.server_address[1])
        try:
            port = port_holder[0]
            body = fw.read_url_with_retry(
                urllib.request.Request(f"http://127.0.0.1:{port}/redirect"),
                timeout=5,
                retries=1,
                redirect_validator=lambda candidate: urllib.parse.urlsplit(
                    candidate
                ).port
                == port,
            )
            self.assertEqual(body, b"OK")
        finally:
            server.shutdown()
            server.server_close()

    def test_collect_validates_redirects_on_page_and_csaf_fetches(self) -> None:
        advisory_id = "FG-IR-26-174"
        csaf_url = FIXTURE_CSAF_URLS[advisory_id]
        calls: list[tuple[str, object]] = []
        original = fw.read_url_with_retry

        def fake_read(request, timeout, retries=3, redirect_validator=None):
            calls.append((request.full_url, redirect_validator))
            if request.full_url == f"https://fortiguard.fortinet.com/psirt/{advisory_id}":
                return make_advisory_page(advisory_id, csaf_url).encode("utf-8")
            if request.full_url == csaf_url:
                return json.dumps(load_csaf(advisory_id)).encode("utf-8")
            raise AssertionError(f"unexpected fetch: {request.full_url}")

        fw.read_url_with_retry = fake_read
        try:
            entries = fw.collect_cve_entries_for_advisory(advisory_id, timeout=5)
        finally:
            fw.read_url_with_retry = original

        self.assertEqual(entries[0]["id"], "CVE-2026-84393")
        self.assertEqual(len(calls), 2)
        self.assertIs(calls[0][1], fw._psirt_page_redirect_allowed)
        self.assertIs(calls[1][1], fw._csaf_redirect_allowed)


if __name__ == "__main__":
    unittest.main()
