"""Cross-check of an advisory's CSAF/CVRF export against its public PSIRT page.

Audit of 2026-10-18 (all 317 advisories of the catalogue, version for version): 308 agreed. Three
exports were narrower than their own page, so the tool did not show a CVE the page announces:

- FG-IR-26-123: CSAF lists FortiOS 7.2-7.6 only, the page also 6.0-7.0;
- FG-IR-18-292: CSAF names FortiAnalyzer/FortiManager only, the page also FortiOS 5.6-6.2;
- FG-IR-24-463: CSAF lost the "Cloud" label, so FortiManager 7.2.8/7.4.5 read "not affected"
  while the page lists them for on-prem.

The page now widens the export (a version is shown as soon as either says so), except that a
page "all versions" claim never overrides the export on a train the export describes.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fortios_notify as fn
import fortios_watch as fw
from test_csaf_applicability import make_csaf_document, make_vulnerability
from test_psirt_unresolvable import legacy_cvrf


def affected_table(*rows: tuple[str, str]) -> str:
    body = "".join(f"<tr><td>{label}</td><td>{affected}</td><td>-</td></tr>" for label, affected in rows)
    return (
        "<table><thead><tr><th>Version</th><th>Affected</th><th>Solution</th></tr></thead>"
        f"<tbody>{body}</tbody></table>"
    )


def page(*rows: tuple[str, str], link: str = "") -> str:
    return f"<html><body><h1>Advisory</h1>{affected_table(*rows)}{link}</body></html>"


def entry(*ranges: dict, cve: str = "CVE-2026-00001") -> dict:
    return {"id": cve, "advisoryId": "FG-IR-26-001", "severity": "high", "affected": [dict(r) for r in ranges]}


def fos(branch: str, start: str | None, end: str | None, **extra: object) -> dict:
    return {"product": "fortigate-fortios", "models": [], "branch": branch, "from": start, "to": end, **extra}


def fmg(branch: str, start: str | None, end: str | None, **extra: object) -> dict:
    return {"product": "fortimanager", "models": [], "branch": branch, "from": start, "to": end, **extra}


class PageParsingTests(unittest.TestCase):
    def test_table_rows_of_tracked_products(self) -> None:
        raw = page(
            ("FortiOS 8.0", "Not affected"),
            ("FortiOS 7.6", "7.6.0 through 7.6.3"),
            ("FortiOS 7.2", "7.2 through 7.2.11"),
            ("FortiOS 6.0", "6.0 all versions (Need to be authenticated to provoke a crash)"),
            ("FortiOS 7.0", "7.0.6 and above"),
            ("FortiManager 7.4", "7.4.2"),
            ("FortiClientMac 7.0", "7.0.0 though 7.0.9"),
            ("FortiClientEMS 7.2", "7.2 all versions"),
        )
        self.assertEqual(
            fw.parse_psirt_page_affected(raw),
            [
                {"product": "forticlient", "models": ["macos"], "branch": "7.0", "from": "7.0.0", "to": "7.0.9"},
                {"product": "forticlient-ems", "models": ["ems"], "branch": "7.2", "from": None, "to": None},
                {"product": "fortigate-fortios", "models": [], "branch": "6.0", "from": None, "to": None},
                {"product": "fortigate-fortios", "models": [], "branch": "7.0", "from": "7.0.6", "to": None},
                {"product": "fortigate-fortios", "models": [], "branch": "7.2", "from": "7.2.0", "to": "7.2.11"},
                {"product": "fortigate-fortios", "models": [], "branch": "7.6", "from": "7.6.0", "to": "7.6.3"},
                {"product": "fortimanager", "models": [], "branch": "7.4", "from": "7.4.2", "to": "7.4.2"},
            ],
        )

    def test_qualified_labels_and_cloud_cells_are_other_products(self) -> None:
        raw = page(
            ("FortiOS (only FGT_VM64) 7.4", "7.4.0 through 7.4.1"),
            ("FortiOS-6K7K 7.0", "7.0.10"),
            ("FortiManager Cloud 7.2", "7.2.2 through 7.2.7"),
            ("FortiManager 7.4", "Cloud 7.4.1 through 7.4.2"),
            ("FortiProxy 7.4", "7.4.0 through 7.4.1"),
        )
        self.assertEqual(fw.parse_psirt_page_affected(raw), [])

    def test_unrecognized_wording_for_a_tracked_product_distrusts_the_whole_page(self) -> None:
        raw = page(("FortiOS 7.6", "7.6.0 through 7.6.3"), ("FortiOS 7.4", "7.4.8 and below"))
        self.assertIsNone(fw.parse_psirt_page_affected(raw))
        cross_train = page(("FortiOS 7.4", "7.2.0 through 7.4.1"))
        self.assertIsNone(fw.parse_psirt_page_affected(cross_train))

    def test_a_note_after_a_bound_is_not_trusted(self) -> None:
        # "(only FGT_VM64)" narrows the claim: reading it as a plain range would widen it.
        self.assertIsNone(fw.parse_psirt_page_affected(page(("FortiOS 7.4", "7.4.0 through 7.4.3 (only FGT_VM64)"))))
        self.assertEqual(
            fw.parse_psirt_page_affected(page(("FortiOS 6.0", "6.0 all versions (special note below)"))),
            [fos("6.0", None, None)],
        )

    def test_page_without_affected_section_is_not_readable(self) -> None:
        self.assertIsNone(fw.parse_psirt_page_affected("<html><body>Just a moment...</body></html>"))

    def test_legacy_affected_products_block(self) -> None:
        raw = (
            "<html><body><h3>Affected Products</h3>"
            "<p>FortiOS 7.2 all versions are not affected</p>"
            "<p>FortiOS version 7.0.0 through 7.0.5</p>"
            "<p>FortiOS 6.2 all versions</p>"
            "<p>FortiOS version 6.4.3</p>"
            "<p>FortiProxy version 7.0.0 through 7.0.4</p>"
            "<h3>Solutions</h3><p>FortiOS 9.9 all versions</p></body></html>"
        )
        self.assertEqual(
            fw.parse_psirt_page_affected(raw),
            [fos("6.2", None, None), fos("6.4", "6.4.3", "6.4.3"), fos("7.0", "7.0.0", "7.0.5")],
        )


class MergeTests(unittest.TestCase):
    def test_train_missing_from_the_export_is_added_from_the_page(self) -> None:
        # FG-IR-26-123: the CSAF stops at 7.2, the page goes down to 6.0.
        item = entry(fos("7.2", "7.2.0", "7.2.11"))
        added = fw.merge_psirt_page_ranges(
            item, [fos("6.0", None, None), fos("7.0", "7.0.0", "7.0.17"), fos("7.2", "7.2.0", "7.2.11")]
        )
        self.assertEqual(added, 2)
        self.assertEqual(
            item["affected"],
            [
                fos("6.0", None, None, source="psirt-page"),
                fos("7.0", "7.0.0", "7.0.17", source="psirt-page"),
                fos("7.2", "7.2.0", "7.2.11"),
            ],
        )

    def test_page_all_versions_never_overrides_the_export_on_a_described_train(self) -> None:
        # FG-IR-22-255: the CSAF declares 6.2.13 fixed, the page still says "6.2 all versions";
        # a CVRF enumerating 6.2.0-6.2.17 is likewise more precise than "all versions".
        fixed = entry(fos("6.2", None, None, excluded=["6.2.13"]))
        self.assertEqual(fw.merge_psirt_page_ranges(fixed, [fos("6.2", None, None)]), 0)
        enumerated = entry(fos("6.2", "6.2.0", "6.2.17"))
        self.assertEqual(fw.merge_psirt_page_ranges(enumerated, [fos("6.2", None, None)]), 0)

    def test_bounded_page_claim_wins_over_an_export_exclusion(self) -> None:
        # FG-IR-24-463: Cloud rows lost their name in the CSAF, so on-prem 7.2.8 reads excluded.
        item = entry(fmg("7.2", "7.2.1", "7.2.8", excluded=["7.2.8"]), fmg("7.2", "7.2.2", "7.2.7"))
        self.assertEqual(fw.merge_psirt_page_ranges(item, [fmg("7.2", "7.2.1", "7.2.8")]), 1)
        self.assertIn(fmg("7.2", "7.2.1", "7.2.8", source="psirt-page"), item["affected"])

    def test_bounded_claim_already_covered_adds_nothing(self) -> None:
        item = entry(fos("7.4", "7.4.0", "7.4.9"), fos("7.0", None, None))
        before = json.loads(json.dumps(item))
        self.assertEqual(
            fw.merge_psirt_page_ranges(item, [fos("7.4", "7.4.0", "7.4.9"), fos("7.0", "7.0.0", "7.0.17")]),
            0,
        )
        self.assertEqual(item, before)

    def test_merge_is_idempotent(self) -> None:
        item = entry(fmg("7.2", "7.2.1", "7.2.8", excluded=["7.2.8"]))
        page_ranges = [fmg("7.2", "7.2.1", "7.2.8"), fmg("7.0", None, None)]
        fw.merge_psirt_page_ranges(item, page_ranges)
        once = json.loads(json.dumps(item))
        self.assertEqual(fw.merge_psirt_page_ranges(item, page_ranges), 0)
        self.assertEqual(item, once)

    def test_platforms_are_kept_apart(self) -> None:
        mac = {"product": "forticlient", "models": ["macos"], "branch": "7.0", "from": None, "to": None}
        windows = {**mac, "models": ["windows"]}
        item = entry(mac)
        self.assertEqual(fw.merge_psirt_page_ranges(item, [windows]), 1)


class ApplyTests(unittest.TestCase):
    def test_multi_cve_advisory_is_left_to_its_export(self) -> None:
        entries = [entry(fos("7.2", "7.2.0", "7.2.1"), cve="CVE-1"), entry(fmg("7.4", "7.4.0", "7.4.2"), cve="CVE-2")]
        before = json.loads(json.dumps(entries))
        result = fw.apply_psirt_page_crosscheck(
            "FG-IR-26-001", entries, page(("FortiOS 6.4", "6.4 all versions")), {"CVE-1", "CVE-2"}
        )
        self.assertEqual(result, before)

    def test_a_second_cve_about_untracked_products_only_also_blocks_the_page(self) -> None:
        # The export keeps only CVE-1 (CVE-2 names FortiProxy alone): the page rows may be CVE-2's.
        entries = [entry(fos("7.2", "7.2.0", "7.2.1"), cve="CVE-1")]
        before = json.loads(json.dumps(entries))
        result = fw.apply_psirt_page_crosscheck(
            "FG-IR-26-001", entries, page(("FortiOS 6.4", "6.4 all versions")), {"CVE-1", "CVE-2"}
        )
        self.assertEqual(result, before)

    def test_a_surprise_while_reading_the_page_keeps_the_export(self) -> None:
        entries = [entry(fos("7.2", "7.2.0", "7.2.1"), cve="CVE-1")]
        before = json.loads(json.dumps(entries))
        original = fw.merge_psirt_page_ranges

        def broken(*_args: object) -> int:
            raise KeyError("product")

        fw.merge_psirt_page_ranges = broken
        try:
            result = fw.apply_psirt_page_crosscheck(
                "FG-IR-26-001", entries, page(("FortiOS 6.4", "6.4 all versions")), {"CVE-1"}
            )
        finally:
            fw.merge_psirt_page_ranges = original
        self.assertEqual(result, before)
        self.assertEqual(entries, before)

    def test_unreadable_page_leaves_the_export_untouched(self) -> None:
        entries = [entry(fos("7.2", "7.2.0", "7.2.1"))]
        before = json.loads(json.dumps(entries))
        result = fw.apply_psirt_page_crosscheck(
            "FG-IR-26-001", entries, page(("FortiOS 6.4", "6.4.x and below")), {"CVE-2026-00001"}
        )
        self.assertEqual(result, before)


class CollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_fetch_text = fw.fetch_text

    def tearDown(self) -> None:
        fw.fetch_text = self._orig_fetch_text

    def _install(self, responses: dict[str, str]) -> None:
        def fetch_text(url: str, timeout: int, redirect_validator=None) -> str:
            if url not in responses:
                raise AssertionError(f"unexpected fetch: {url}")
            return responses[url]

        fw.fetch_text = fetch_text

    def test_csaf_path_is_widened_by_the_page(self) -> None:
        advisory_id = "FG-IR-26-123"
        csaf_url = "https://filestore.fortinet.com/fortiguard/psirt/csaf_capwap_fg-ir-26-123.json"
        doc = make_csaf_document(
            advisory_id,
            vulns=[make_vulnerability("CVE-2025-53844", affected=("FortiOS >=7.2.0|<=7.2.11",))],
        )
        link = f'<a href="/psirt/csaf/{advisory_id}?csaf_url={csaf_url}">CSAF</a>'
        self._install(
            {
                f"https://fortiguard.fortinet.com/psirt/{advisory_id}": page(
                    ("FortiOS 7.2", "7.2.0 through 7.2.11"), ("FortiOS 7.0", "7.0.0 through 7.0.17"), link=link
                ),
                csaf_url: json.dumps(doc),
            }
        )
        entries = fw.collect_cve_entries_for_advisory(advisory_id, timeout=5)
        self.assertEqual(
            entries[0]["affected"],
            [fos("7.0", "7.0.0", "7.0.17", source="psirt-page"), fos("7.2", "7.2.0", "7.2.11")],
        )

    def _csaf_responses(self, advisory_id: str, page_html_rows: tuple, doc: dict) -> dict[str, str]:
        csaf_url = f"https://filestore.fortinet.com/fortiguard/psirt/csaf_x_{advisory_id.lower()}.json"
        link = f'<a href="/psirt/csaf/{advisory_id}?csaf_url={csaf_url}">CSAF</a>'
        return {
            f"https://fortiguard.fortinet.com/psirt/{advisory_id}": page(*page_html_rows, link=link),
            csaf_url: json.dumps(doc),
        }

    def test_unreadable_page_on_the_full_path_keeps_the_export(self) -> None:
        advisory_id = "FG-IR-26-200"
        doc = make_csaf_document(
            advisory_id, vulns=[make_vulnerability("CVE-2026-20000", affected=("FortiOS >=7.2.0|<=7.2.11",))]
        )
        self._install(self._csaf_responses(advisory_id, (("FortiOS 7.0", "7.0.17 and below"),), doc))
        entries = fw.collect_cve_entries_for_advisory(advisory_id, timeout=5)
        self.assertEqual(entries[0]["affected"], [fos("7.2", "7.2.0", "7.2.11")])

    def test_two_csaf_cves_one_about_an_untracked_product_keep_the_export(self) -> None:
        advisory_id = "FG-IR-26-201"
        doc = make_csaf_document(
            advisory_id,
            vulns=[
                make_vulnerability("CVE-2026-20001", affected=("FortiOS >=7.2.0|<=7.2.11",)),
                make_vulnerability("CVE-2026-20002", affected=("FortiProxy >=7.0.0|<=7.0.9",)),
            ],
        )
        self._install(self._csaf_responses(advisory_id, (("FortiOS 7.0", "7.0 all versions"),), doc))
        entries = fw.collect_cve_entries_for_advisory(advisory_id, timeout=5)
        self.assertEqual([item["id"] for item in entries], ["CVE-2026-20001"])
        self.assertEqual(entries[0]["affected"], [fos("7.2", "7.2.0", "7.2.11")])

    def test_a_second_reconciliation_changes_nothing(self) -> None:
        advisory_id = "FG-IR-24-463"
        doc = make_csaf_document(
            advisory_id,
            vulns=[
                make_vulnerability(
                    "CVE-2024-50566",
                    affected=("FortiManager >=7.2.2|<=7.2.7", "FortiManager >=7.2.1|<=7.2.8"),
                    not_affected=("FortiManager-7.2.8", "FortiManager-7.2.9"),
                )
            ],
        )
        self._install(self._csaf_responses(advisory_id, (("FortiManager 7.2", "7.2.1 through 7.2.8"),), doc))
        state: dict = {"cves": []}
        first = fw.replace_cves_for_advisory(state, advisory_id, fw.collect_cve_entries_for_advisory(advisory_id, timeout=5))
        self.assertEqual((first.added, first.updated, first.removed), (1, 0, 0))
        self.assertIn(fmg("7.2", "7.2.1", "7.2.8", source="psirt-page"), state["cves"][0]["affected"])
        second = fw.replace_cves_for_advisory(state, advisory_id, fw.collect_cve_entries_for_advisory(advisory_id, timeout=5))
        self.assertEqual((second.added, second.updated, second.removed), (0, 0, 0))

    def test_legacy_cvrf_path_is_widened_by_the_page(self) -> None:
        # FG-IR-18-292 shape: the export names FortiManager only, the page also FortiOS.
        advisory_id = "FG-IR-18-292"
        legacy_rows = (
            "<html><body><h3>Affected Products</h3>"
            "<p>FortiManager version 6.4.0</p><p>FortiOS version 6.2.0 through 6.2.15</p>"
            f'<h3>Solutions</h3><a href="/psirt/cvrf/{advisory_id}">CVRF</a></body></html>'
        )
        self._install(
            {
                f"https://fortiguard.fortinet.com/psirt/{advisory_id}": legacy_rows,
                f"https://fortiguard.fortinet.com/psirt/cvrf/{advisory_id}": legacy_cvrf(
                    advisory_id, "FortiManager 6.4.0", cve="CVE-2022-22305"
                ),
            }
        )
        entries = fw.collect_cve_entries_for_advisory(advisory_id, timeout=5)
        self.assertEqual(
            entries[0]["affected"],
            [fos("6.2", "6.2.0", "6.2.15", source="psirt-page"), fmg("6.4", "6.4.0", "6.4.0")],
        )


class NotificationTests(unittest.TestCase):
    def test_a_new_cve_lists_the_page_ranges_without_any_extra_event(self) -> None:
        item = entry(fos("7.2", "7.2.0", "7.2.11"), cve="CVE-2025-53844")
        fw.merge_psirt_page_ranges(item, [fos("7.0", "7.0.0", "7.0.17")])
        events = fn.derive_new_cve_events([item])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].dedup_key, "new-cve|psirt|CVE-2025-53844|high")

    def test_page_ranges_on_a_known_cve_are_not_news(self) -> None:
        before = entry(fos("7.2", "7.2.0", "7.2.11"), cve="CVE-2025-53844")
        after = json.loads(json.dumps(before))
        fw.merge_psirt_page_ranges(after, [fos("7.0", "7.0.0", "7.0.17")])
        self.assertNotEqual(before, after)
        self.assertEqual(
            fn.derive_cve_modification_events({before["id"]: before}, {after["id"]: after}), []
        )


if __name__ == "__main__":
    unittest.main()
