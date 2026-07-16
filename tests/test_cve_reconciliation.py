"""Covers scripts/fortios_watch.py's CVE removal/reconciliation logic.

Before this fix, the daily CVE collector only ever upserted (added/updated) entries, so a CVE
Fortinet later removed from an advisory (reattributed away from our tracked products, or
corrected off entirely) lingered in state["cves"] forever. The fix distinguishes a definitive,
successfully-parsed CSAF result (replace everything for that advisory, dropping anything no
longer present) from an unresolved one — no CSAF url found, or a network/parse failure — which
must leave existing data completely untouched.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_watch as fw  # noqa: E402


def make_csaf_doc(cve_ids: list[str]) -> dict:
    return {
        "document": {
            "title": "Test advisory",
            "tracking": {
                "initial_release_date": "2026-01-01T00:00:00Z",
                "current_release_date": "2026-01-01T00:00:00Z",
            },
        },
        "vulnerabilities": [
            {
                "cve": cve_id,
                "scores": [{"cvss_v3": {"baseSeverity": "high", "baseScore": 7.5}}],
                "product_status": {"known_affected": ["FortiOS >=7.6.0 <=7.6.4"]},
            }
            for cve_id in cve_ids
        ],
    }


class CollectCveEntriesForAdvisoryTests(unittest.TestCase):
    def setUp(self):
        self._orig_fetch_csaf_url = fw.fetch_csaf_url
        self._orig_fetch_text = fw.fetch_text

    def tearDown(self):
        fw.fetch_csaf_url = self._orig_fetch_csaf_url
        fw.fetch_text = self._orig_fetch_text

    def test_returns_none_when_no_csaf_url_found(self):
        fw.fetch_csaf_url = lambda advisory_id, timeout: None
        result = fw.collect_cve_entries_for_advisory("FG-IR-99-999", timeout=5)
        self.assertIsNone(result, "an unresolved CSAF lookup must be None, never an empty list")

    def test_returns_definitive_list_when_csaf_parses_successfully(self):
        fw.fetch_csaf_url = lambda advisory_id, timeout: "https://example/csaf.json"
        doc = make_csaf_doc(["CVE-2026-00001"])
        fw.fetch_text = lambda url, timeout: __import__("json").dumps(doc)
        result = fw.collect_cve_entries_for_advisory("FG-IR-26-001", timeout=5)
        self.assertIsNotNone(result)
        self.assertEqual([entry["id"] for entry in result], ["CVE-2026-00001"])

    def test_returns_definitive_empty_list_when_no_cves_apply_anymore(self):
        """A successfully-parsed CSAF doc with zero CVEs relevant to tracked products is still a
        DEFINITIVE result (empty, not None) — the advisory really has nothing for us anymore."""
        fw.fetch_csaf_url = lambda advisory_id, timeout: "https://example/csaf.json"
        fw.fetch_text = lambda url, timeout: __import__("json").dumps({"document": {}, "vulnerabilities": []})
        result = fw.collect_cve_entries_for_advisory("FG-IR-26-002", timeout=5)
        self.assertEqual(result, [])


class ReplaceCvesForAdvisoryTests(unittest.TestCase):
    def test_removes_cve_no_longer_returned(self):
        state = fw.normalize_state({"cves": [
            {"id": "CVE-2026-00001", "advisoryId": "FG-IR-26-001", "title": "old"},
            {"id": "CVE-2026-00002", "advisoryId": "FG-IR-26-001", "title": "old"},
            {"id": "CVE-2026-99999", "advisoryId": "FG-IR-26-999", "title": "unrelated advisory"},
        ]})
        # Fresh, successful re-fetch only returns CVE-2026-00001 now.
        stats = fw.replace_cves_for_advisory(state, "FG-IR-26-001", [
            {"id": "CVE-2026-00001", "advisoryId": "FG-IR-26-001", "title": "refreshed"},
        ])
        ids = sorted(item["id"] for item in state["cves"])
        self.assertEqual(ids, ["CVE-2026-00001", "CVE-2026-99999"], "CVE-2026-00002 must be removed")
        self.assertEqual(stats.removed, 1)
        self.assertEqual(stats.updated, 1)  # CVE-2026-00001 already existed, its title changed
        self.assertEqual(stats.added, 0)
        # An unrelated advisory's CVEs must never be touched.
        unrelated = next(item for item in state["cves"] if item["id"] == "CVE-2026-99999")
        self.assertEqual(unrelated["title"], "unrelated advisory")

    def test_empty_new_entries_removes_all_of_that_advisorys_cves(self):
        state = fw.normalize_state({"cves": [
            {"id": "CVE-2026-00001", "advisoryId": "FG-IR-26-001", "title": "old"},
        ]})
        fw.replace_cves_for_advisory(state, "FG-IR-26-001", [])
        self.assertEqual(state["cves"], [])

    def test_no_change_reports_zero(self):
        state = fw.normalize_state({"cves": [
            {"id": "CVE-2026-00001", "advisoryId": "FG-IR-26-001", "title": "same"},
        ]})
        stats = fw.replace_cves_for_advisory(state, "FG-IR-26-001", [
            {"id": "CVE-2026-00001", "advisoryId": "FG-IR-26-001", "title": "same"},
        ])
        self.assertEqual(stats, fw.CveReconciliationStats(added=0, updated=0, removed=0))

    def test_pure_removal_is_not_counted_as_an_addition(self):
        """Codex's exact concern: a removal must never inflate the "added" counter."""
        state = fw.normalize_state({"cves": [
            {"id": "CVE-KEEP", "advisoryId": "FG-IR-26-001", "title": "keep, unchanged"},
            {"id": "CVE-STALE", "advisoryId": "FG-IR-26-001", "title": "no longer returned"},
        ]})
        stats = fw.replace_cves_for_advisory(state, "FG-IR-26-001", [
            {"id": "CVE-KEEP", "advisoryId": "FG-IR-26-001", "title": "keep, unchanged"},
        ])
        self.assertEqual(stats.removed, 1)
        self.assertEqual(stats.added, 0)
        self.assertEqual(stats.updated, 0)

    def test_genuinely_new_cve_is_counted_as_added(self):
        state = fw.normalize_state({"cves": []})
        stats = fw.replace_cves_for_advisory(state, "FG-IR-26-001", [
            {"id": "CVE-NEW", "advisoryId": "FG-IR-26-001", "title": "brand new"},
        ])
        self.assertEqual(stats.added, 1)
        self.assertEqual(stats.updated, 0)
        self.assertEqual(stats.removed, 0)


class CollectCveCatalogReconciliationTests(unittest.TestCase):
    """End-to-end-ish: collect_cve_catalog()'s output correctly separates resolved advisories
    (to reconcile) from skipped ones (to leave untouched), matching how main() consumes it."""

    def setUp(self):
        self._orig_rss = fw.discover_advisory_ids_from_rss
        self._orig_fetch_csaf_url = fw.fetch_csaf_url
        self._orig_fetch_text = fw.fetch_text

    def tearDown(self):
        fw.discover_advisory_ids_from_rss = self._orig_rss
        fw.fetch_csaf_url = self._orig_fetch_csaf_url
        fw.fetch_text = self._orig_fetch_text

    def test_stale_cve_removed_after_successful_refetch_returns_fewer(self):
        state = fw.normalize_state({"cves": [
            {"id": "CVE-2026-00001", "advisoryId": "FG-IR-26-001", "title": "old"},
            {"id": "CVE-2026-00002", "advisoryId": "FG-IR-26-001", "title": "old, now removed by Fortinet"},
        ]})
        fw.discover_advisory_ids_from_rss = lambda timeout: ["FG-IR-26-001"]
        fw.fetch_csaf_url = lambda advisory_id, timeout: "https://example/csaf.json"
        doc = make_csaf_doc(["CVE-2026-00001"])  # CVE-2026-00002 no longer in the CSAF doc
        fw.fetch_text = lambda url, timeout: __import__("json").dumps(doc)

        cve_results, skipped = fw.collect_cve_catalog(
            existing_advisory_ids={"FG-IR-26-001"}, timeout=5, backfill=False,
        )
        self.assertEqual(skipped, [])
        for advisory_id, entries in cve_results.items():
            fw.replace_cves_for_advisory(state, advisory_id, entries)

        ids = [item["id"] for item in state["cves"]]
        self.assertEqual(ids, ["CVE-2026-00001"], "CVE-2026-00002 must be removed after a successful re-fetch")

    def test_cves_preserved_after_simulated_network_failure(self):
        state = fw.normalize_state({"cves": [
            {"id": "CVE-2026-00001", "advisoryId": "FG-IR-26-001", "title": "old"},
            {"id": "CVE-2026-00002", "advisoryId": "FG-IR-26-001", "title": "old"},
        ]})
        fw.discover_advisory_ids_from_rss = lambda timeout: ["FG-IR-26-001"]

        def raise_network_error(advisory_id, timeout):
            raise TimeoutError("PSIRT unreachable")

        fw.fetch_csaf_url = raise_network_error

        cve_results, skipped = fw.collect_cve_catalog(
            existing_advisory_ids={"FG-IR-26-001"}, timeout=5, backfill=False,
        )
        self.assertEqual(skipped, ["FG-IR-26-001"])
        self.assertEqual(cve_results, {}, "a failed advisory must not appear as a resolved result")

        # main()'s loop only reconciles advisory_ids present in cve_results -- FG-IR-26-001 isn't,
        # so state["cves"] must stay exactly as it was.
        for advisory_id, entries in cve_results.items():
            fw.replace_cves_for_advisory(state, advisory_id, entries)

        ids = sorted(item["id"] for item in state["cves"])
        self.assertEqual(ids, ["CVE-2026-00001", "CVE-2026-00002"], "nothing must be lost on a network failure")


class MainCommitSequenceCveReconciliationTests(unittest.TestCase):
    """Reproduces main()'s actual end-to-end commit sequence, not just replace_cves_for_advisory()
    in isolation — that's exactly what let the first fix pass its own test while still shipping
    the resurrection bug: reconciling only the in-memory `state` working copy is not enough,
    because the final commit re-reads the file fresh and merge_state()'s CVE merge is a keyed
    union that never removes anything absent from the incoming side. The removal only actually
    sticks if the same reconciliation is re-applied on `final_state` after that merge.
    """

    def test_stale_cve_does_not_reappear_after_the_full_commit_sequence(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "state.json"
            fw.write_json(output_path, fw.normalize_state({"cves": [
                {"id": "CVE-KEEP", "advisoryId": "FG-IR-26-001", "title": "keep"},
                {"id": "CVE-STALE", "advisoryId": "FG-IR-26-001", "title": "removed by Fortinet"},
            ]}))

            # 1. main() reads its working-copy snapshot at the top of the run.
            state = fw.normalize_state(fw.read_json(output_path, {}))

            # 2. A definitive CSAF re-fetch for FG-IR-26-001 now only returns CVE-KEEP.
            cve_results_by_advisory = {
                "FG-IR-26-001": [{"id": "CVE-KEEP", "advisoryId": "FG-IR-26-001", "title": "keep"}],
            }

            # 3. Reconcile the working copy (this is what the previous fix stopped at).
            for advisory_id, entries in cve_results_by_advisory.items():
                fw.replace_cves_for_advisory(state, advisory_id, entries)
            self.assertEqual(
                sorted(item["id"] for item in state["cves"]), ["CVE-KEEP"],
                "sanity check: the working copy itself must already be clean",
            )

            # 4-6. The actual final commit sequence from main(): re-read fresh, bulk-merge
            # everything except advisories/paths/compatibilities, then re-apply the CVE
            # reconciliation on final_state -- the step that was missing.
            with fw.cross_process_lock(output_path):
                latest_from_disk = fw.normalize_state(fw.read_json(output_path, {}))
                state_for_bulk_merge = {**state, "advisories": [], "paths": [], "compatibilities": []}
                final_state = fw.merge_state(latest_from_disk, state_for_bulk_merge)
                for advisory_id, entries in cve_results_by_advisory.items():
                    fw.replace_cves_for_advisory(final_state, advisory_id, entries)
                fw.write_json(output_path, final_state)

            # 7. CVE-STALE must not have reappeared.
            result = fw.normalize_state(fw.read_json(output_path, {}))
            ids = sorted(item["id"] for item in result["cves"])
            self.assertEqual(ids, ["CVE-KEEP"], "CVE-STALE must not resurrect during the final merge")


if __name__ == "__main__":
    unittest.main()
