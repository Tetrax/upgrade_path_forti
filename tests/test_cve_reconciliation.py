"""Covers scripts/fortios_watch.py's CVE removal/reconciliation logic.

Before this fix, the daily CVE collector only ever upserted (added/updated) entries, so a CVE
Fortinet later removed from an advisory (reattributed away from our tracked products, or
corrected off entirely) lingered in state["cves"] forever. The fix distinguishes a definitive,
successfully-parsed CVRF result (replace everything for that advisory, dropping anything no
longer present) from an unresolved one — a network/parse failure — which
must leave existing data completely untouched.
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_watch as fw


def make_cvrf_xml(cve_ids: list[str] | None = None) -> str:
    cve_ids = ["CVE-2026-71407"] if cve_ids is None else cve_ids
    vulnerabilities = "\n".join(
        f"""  <Vulnerability Ordinal="{index}">
    <Title>Stack buffer overflow in WAD</Title>
    <cvrf:CVE>{cve_id}</cvrf:CVE>
    <ProductStatuses>
      <Status Type="Known Affected">
        <ProductID>FortiOS-FortiOS 7.6</ProductID>
        <ProductID>FortiOS-7.6.4</ProductID>
      </Status>
    </ProductStatuses>
    <CVSSScoreSets>
      <ScoreSetV3>
        <BaseScoreV3>8.8</BaseScoreV3>
      </ScoreSetV3>
    </CVSSScoreSets>
  </Vulnerability>"""
        for index, cve_id in enumerate(cve_ids, 1)
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<cvrf:cvrfdoc xmlns:cvrf="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf">
  <cvrf:DocumentTitle>Stack buffer overflow in WAD</cvrf:DocumentTitle>
  <cvrf:DocumentTracking>
    <cvrf:InitialReleaseDate>2026-08-12T00:00:00</cvrf:InitialReleaseDate>
    <cvrf:CurrentReleaseDate>2026-08-19T00:00:00</cvrf:CurrentReleaseDate>
  </cvrf:DocumentTracking>
{vulnerabilities}
</cvrf:cvrfdoc>
"""


class CollectCveEntriesForAdvisoryTests(unittest.TestCase):
    def setUp(self):
        self._orig_fetch_cvrf_document = fw.fetch_cvrf_document
        self._orig_fetch_text = fw.fetch_text

    def tearDown(self):
        fw.fetch_cvrf_document = self._orig_fetch_cvrf_document
        fw.fetch_text = self._orig_fetch_text

    def test_network_failure_is_propagated_for_the_batch_wrapper_to_record(self):
        fw.fetch_cvrf_document = lambda advisory_id, timeout: (_ for _ in ()).throw(
            TimeoutError("PSIRT unreachable")
        )
        with self.assertRaises(TimeoutError):
            fw.collect_cve_entries_for_advisory("FG-IR-99-999", timeout=5)

    def test_returns_definitive_list_when_cvrf_parses_successfully(self):
        fw.fetch_cvrf_document = lambda advisory_id, timeout: make_cvrf_xml(
            ["CVE-2026-00001"]
        )
        result = fw.collect_cve_entries_for_advisory("FG-IR-26-001", timeout=5)
        self.assertEqual([entry["id"] for entry in result], ["CVE-2026-00001"])

    def test_returns_definitive_empty_list_when_no_cves_apply_anymore(self):
        """A successfully-parsed CVRF doc with zero CVEs relevant to tracked products is still a
        DEFINITIVE result (empty, not None) — the advisory really has nothing for us anymore."""
        fw.fetch_cvrf_document = lambda advisory_id, timeout: make_cvrf_xml([])
        result = fw.collect_cve_entries_for_advisory("FG-IR-26-002", timeout=5)
        self.assertEqual(result, [])

    def test_reads_public_cvrf_export_without_fetching_challenged_html_page(self):
        calls = []

        def fetch_text(url, timeout):
            calls.append(url)
            return make_cvrf_xml()

        fw.fetch_text = fetch_text
        result = fw.collect_cve_entries_for_advisory("FG-IR-26-161", timeout=5)

        self.assertEqual(
            calls,
            ["https://fortiguard.fortinet.com/psirt/cvrf/FG-IR-26-161"],
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], "CVE-2026-71407")
        self.assertEqual(result[0]["severity"], "high")
        self.assertEqual(result[0]["cvssScore"], 8.8)
        self.assertEqual(
            result[0]["affected"],
            [
                {
                    "product": "fortigate-fortios",
                    "models": [],
                    "branch": "7.6",
                    "from": None,
                    "to": None,
                },
                {
                    "product": "fortigate-fortios",
                    "models": [],
                    "branch": "7.6",
                    "from": "7.6.4",
                    "to": "7.6.4",
                },
            ],
        )


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
        self._orig_fetch_cvrf_document = fw.fetch_cvrf_document
        self._orig_fetch_text = fw.fetch_text

    def tearDown(self):
        fw.discover_advisory_ids_from_rss = self._orig_rss
        fw.fetch_cvrf_document = self._orig_fetch_cvrf_document
        fw.fetch_text = self._orig_fetch_text

    def test_stale_cve_removed_after_successful_refetch_returns_fewer(self):
        state = fw.normalize_state({"cves": [
            {"id": "CVE-2026-00001", "advisoryId": "FG-IR-26-001", "title": "old"},
            {"id": "CVE-2026-00002", "advisoryId": "FG-IR-26-001", "title": "old, now removed by Fortinet"},
        ]})
        fw.discover_advisory_ids_from_rss = lambda timeout: ["FG-IR-26-001"]
        fw.fetch_cvrf_document = lambda advisory_id, timeout: make_cvrf_xml(
            ["CVE-2026-00001"]
        )  # CVE-2026-00002 no longer in the CVRF document

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

        fw.fetch_cvrf_document = raise_network_error

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

            # 2. A definitive CVRF re-fetch for FG-IR-26-001 now only returns CVE-KEEP.
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


class CveRetryAfterDelayIntegrationTests(unittest.TestCase):
    """Covers the retry-after-a-real-delay added on top of collect_cve_catalog(): a single
    advisory failing out of ~50 fetched daily is almost always a transient PSIRT hiccup (rate
    limiting, brief outage) that clears up within minutes, not a real reason to flag the whole
    day's run as a warning. main() retries the still-skipped ids after each delay in
    --cve-retry-delays-seconds (default "300,900" -- 5 min then 15 min), stopping early once
    nothing is left to retry. Deliberately bounded, not "retry forever until green": an advisory
    can be legitimately CVRF-less (indistinguishable here from a real failure), and hammering an
    already-struggling PSIRT harder only makes rate limiting worse, not better."""

    def setUp(self):
        self._orig_rss = fw.discover_advisory_ids_from_rss
        self._orig_fetch_cvrf_document = fw.fetch_cvrf_document
        self._orig_fetch_text = fw.fetch_text
        self._orig_psirt_versions = fw.fetch_psirt_versions
        self._orig_sleep = fw.time.sleep
        fw.fetch_psirt_versions = lambda *a, **k: set()
        self.sleep_calls: list[float] = []
        fw.time.sleep = lambda seconds: self.sleep_calls.append(seconds)

    def tearDown(self):
        fw.discover_advisory_ids_from_rss = self._orig_rss
        fw.fetch_cvrf_document = self._orig_fetch_cvrf_document
        fw.fetch_text = self._orig_fetch_text
        fw.fetch_psirt_versions = self._orig_psirt_versions
        fw.time.sleep = self._orig_sleep

    def _run_main(self, tmp: Path, base_path: Path, health_path: Path, extra_args: list[str]) -> int:
        return fw.main([
            "--cve-catalog", *extra_args,
            "--base", str(base_path), "--output", str(base_path),
            "--report", str(tmp / "report.md"), "--health-output", str(health_path),
            "--official-paths-csv", str(tmp / "no-official-paths.csv"),
            "--advisories-csv", str(tmp / "no-advisories.csv"),
            "--upgrade-exports", str(tmp / "no-upgrade-exports"),
        ])

    def _install_fakes(self, flaky_advisory_id: str, fail_times: int = 1):
        """FG-IR-26-002 always succeeds; `flaky_advisory_id` fails its first `fail_times`
        fetch_cvrf_document calls (simulated network error) then succeeds on every subsequent one.
        `fail_times=math.inf`-like large int simulates an advisory that never recovers."""
        call_counts: dict[str, int] = {}

        def fetch_cvrf_document(advisory_id, timeout):
            call_counts[advisory_id] = call_counts.get(advisory_id, 0) + 1
            if advisory_id == flaky_advisory_id and call_counts[advisory_id] <= fail_times:
                raise TimeoutError("PSIRT unreachable")
            return make_cvrf_xml([f"CVE-{advisory_id}"])

        fw.fetch_cvrf_document = fetch_cvrf_document
        return call_counts

    def test_advisory_that_fails_once_then_succeeds_on_first_retry_ends_up_green(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            base_path = tmp / "state.json"
            health_path = tmp / "health.json"
            fw.write_json(base_path, fw.normalize_state({}))
            fw.discover_advisory_ids_from_rss = lambda timeout: ["FG-IR-26-001", "FG-IR-26-002"]
            call_counts = self._install_fakes("FG-IR-26-001", fail_times=1)

            exit_code = self._run_main(tmp, base_path, health_path, [])
            self.assertEqual(exit_code, 0)

            self.assertEqual(call_counts["FG-IR-26-001"], 2, "must stop retrying as soon as it recovers")
            self.assertEqual(self.sleep_calls.count(300), 1, "must wait the first configured delay")
            self.assertEqual(self.sleep_calls.count(900), 0, "must not need the second delay once recovered")

            health = fw.read_json(health_path, {})
            source = health["sources"][fw.SOURCE_CVE_PSIRT]
            self.assertEqual(source["status"], fw.HEALTH_STATUS_OK)
            self.assertIsNone(source.get("lastError"))

            state = fw.read_json(base_path, {})
            ids = sorted(item["id"] for item in state["cves"])
            self.assertEqual(ids, ["CVE-FG-IR-26-001", "CVE-FG-IR-26-002"], "the recovered advisory's CVE must land")

    def test_advisory_that_recovers_only_on_the_second_retry_still_ends_up_green(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            base_path = tmp / "state.json"
            health_path = tmp / "health.json"
            fw.write_json(base_path, fw.normalize_state({}))
            fw.discover_advisory_ids_from_rss = lambda timeout: ["FG-IR-26-001", "FG-IR-26-002"]
            call_counts = self._install_fakes("FG-IR-26-001", fail_times=2)

            exit_code = self._run_main(tmp, base_path, health_path, [])
            self.assertEqual(exit_code, 0)

            self.assertEqual(call_counts["FG-IR-26-001"], 3, "initial attempt + both retries")
            self.assertEqual(self.sleep_calls.count(300), 1)
            self.assertEqual(self.sleep_calls.count(900), 1, "the second, longer delay must have been used too")

            health = fw.read_json(health_path, {})
            self.assertEqual(health["sources"][fw.SOURCE_CVE_PSIRT]["status"], fw.HEALTH_STATUS_OK)

    def test_advisory_still_failing_after_every_retry_stays_a_warning_and_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            base_path = tmp / "state.json"
            health_path = tmp / "health.json"
            fw.write_json(base_path, fw.normalize_state({}))
            fw.discover_advisory_ids_from_rss = lambda timeout: ["FG-IR-26-001", "FG-IR-26-002"]
            call_counts = self._install_fakes("FG-IR-26-001", fail_times=999)

            exit_code = self._run_main(tmp, base_path, health_path, [])
            self.assertEqual(exit_code, 0)

            self.assertEqual(
                call_counts["FG-IR-26-001"], 3,
                "must give up after the initial attempt plus exactly the two configured retries, never loop forever",
            )
            self.assertEqual(self.sleep_calls.count(300), 1)
            self.assertEqual(self.sleep_calls.count(900), 1)

            health = fw.read_json(health_path, {})
            source = health["sources"][fw.SOURCE_CVE_PSIRT]
            self.assertEqual(source["status"], fw.HEALTH_STATUS_WARNING)
            self.assertIn("1 advisorie", source["lastError"])

    def test_empty_delays_disables_the_retry_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            base_path = tmp / "state.json"
            health_path = tmp / "health.json"
            fw.write_json(base_path, fw.normalize_state({}))
            fw.discover_advisory_ids_from_rss = lambda timeout: ["FG-IR-26-001", "FG-IR-26-002"]
            call_counts = self._install_fakes("FG-IR-26-001", fail_times=1)

            exit_code = self._run_main(tmp, base_path, health_path, ["--cve-retry-delays-seconds", ""])
            self.assertEqual(exit_code, 0)

            self.assertEqual(call_counts["FG-IR-26-001"], 1, "no retry attempt should happen")
            self.assertNotIn(300, self.sleep_calls)
            self.assertNotIn(900, self.sleep_calls)

            health = fw.read_json(health_path, {})
            source = health["sources"][fw.SOURCE_CVE_PSIRT]
            self.assertEqual(source["status"], fw.HEALTH_STATUS_WARNING)


if __name__ == "__main__":
    unittest.main()
