"""Covers scripts/fortios_watch.py's CVE removal/reconciliation logic (CSAF era).

History worth keeping: the original collector only ever upserted (added/updated) entries, so a
CVE Fortinet later removed from an advisory (reattributed away from our tracked products, or
corrected off entirely) lingered in state["cves"] forever. The fix distinguishes a definitive,
successfully-parsed result (replace everything for that advisory, dropping anything no longer
present) from an unresolved one — a network/parse failure — which must leave existing data
completely untouched. The collector now reads Fortinet's CSAF export instead of the coarse CVRF
feed (exact ranges/exclusions; see test_csaf_applicability.py for the applicability side).

This file also covers the maintenance pass (--cve-reconcile-existing) that re-fetches every
advisory already in the catalogue — including ones the RSS window no longer covers — and proves,
through the real pipeline plus the real notification engine, that a reconciliation neither
replays historical notifications nor breaks the checkpoint/persistence invariants.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_notify as fn
import fortios_watch as fw

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "psirt"
LIVE_CATALOG_COPY = FIXTURES / "catalog-live-2026-10-04.json"
# The real file-store URL advertised by the frozen FG-IR-26-174 advisory page.
FG_IR_26_174_CSAF_URL = (
    "https://filestore.fortinet.com/fortiguard/psirt/"
    "csaf_ztna-portal-improper-certificate-validation_fg-ir-26-174.json"
)


def csaf_url_for(advisory_id: str) -> str:
    return (
        "https://filestore.fortinet.com/fortiguard/psirt/"
        f"csaf_test_{advisory_id.lower()}.json"
    )


def make_advisory_page(advisory_id: str, csaf_url: str | None = None) -> str:
    csaf_url = csaf_url or csaf_url_for(advisory_id)
    return (
        "<html><body>"
        f'<a href="/psirt/csaf/{advisory_id}?csaf_url={csaf_url}">CSAF</a>'
        "</body></html>"
    )


def make_csaf_document(
    advisory_id: str = "FG-IR-26-001",
    *,
    cve_ids: tuple[str, ...] = ("CVE-2026-71407",),
    affected: tuple[str, ...] = ("FortiOS >=7.6.1|<=7.6.6",),
    title: str = "Stack buffer overflow in WAD",
) -> dict:
    return {
        "document": {
            "title": title,
            "csaf_version": "2.0",
            "publisher": {"name": "Fortinet PSIRT"},
            "tracking": {
                "id": advisory_id,
                "initial_release_date": "2026-08-12T00:00:00",
                "current_release_date": "2026-08-19T00:00:00",
            },
        },
        "product_tree": {"branches": []},
        "vulnerabilities": [
            {
                "cve": cve_id,
                "scores": [{"cvss_v3": {"baseScore": 8.8, "baseSeverity": "HIGH"}}],
                "product_status": {"known_affected": list(affected)},
            }
            for cve_id in cve_ids
        ],
    }


class FakeTransport:
    """Inert PSIRT transport: serves frozen pages/CSAF JSON, records every URL fetched."""

    def __init__(self) -> None:
        self.pages: dict[str, str | Exception] = {}
        self.documents: dict[str, dict | str | Exception] = {}
        self.csaf_urls: dict[str, str] = {}
        self.calls: list[str] = []
        self.default_error: Exception | None = None

    def add_advisory(
        self,
        advisory_id: str,
        document: dict | None = None,
        *,
        page: str | None = None,
        csaf_url: str | None = None,
    ) -> None:
        self.csaf_urls[advisory_id] = csaf_url or csaf_url_for(advisory_id)
        self.pages[advisory_id] = (
            page
            if page is not None
            else make_advisory_page(advisory_id, self.csaf_urls[advisory_id])
        )
        self.documents[advisory_id] = (
            document if document is not None else make_csaf_document(advisory_id)
        )

    def fail_page(self, advisory_id: str, error: Exception) -> None:
        self.pages[advisory_id] = error

    def __call__(self, url: str, timeout: int) -> str:
        self.calls.append(url)
        for advisory_id, page in self.pages.items():
            if url == f"{fw.PSIRT_BASE_URL}/psirt/{advisory_id}":
                if isinstance(page, Exception):
                    raise page
                return page
        for advisory_id, document in self.documents.items():
            if url == self.csaf_urls.get(advisory_id, csaf_url_for(advisory_id)):
                if isinstance(document, Exception):
                    raise document
                if isinstance(document, str):
                    return document
                return json.dumps(document)
        if self.default_error is not None:
            raise self.default_error
        raise AssertionError(f"unexpected fetch: {url}")


class CollectCveEntriesForAdvisoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_fetch_text = fw.fetch_text

    def tearDown(self) -> None:
        fw.fetch_text = self._orig_fetch_text

    def test_network_failure_is_propagated_for_the_batch_wrapper_to_record(self) -> None:
        transport = FakeTransport()
        transport.fail_page("FG-IR-99-999", TimeoutError("PSIRT unreachable"))
        fw.fetch_text = transport
        with self.assertRaises(TimeoutError):
            fw.collect_cve_entries_for_advisory("FG-IR-99-999", timeout=5)

    def test_returns_definitive_list_when_csaf_parses_successfully(self) -> None:
        transport = FakeTransport()
        transport.add_advisory("FG-IR-26-001")
        fw.fetch_text = transport
        result = fw.collect_cve_entries_for_advisory("FG-IR-26-001", timeout=5)
        self.assertEqual([entry["id"] for entry in result], ["CVE-2026-71407"])

    def test_returns_definitive_empty_list_when_no_cves_apply_anymore(self) -> None:
        """A validated CSAF export with zero CVEs relevant to tracked products is still a
        DEFINITIVE result (empty, not None) — the advisory really has nothing for us anymore."""
        transport = FakeTransport()
        transport.add_advisory(
            "FG-IR-26-002",
            make_csaf_document("FG-IR-26-002", cve_ids=(), affected=()),
        )
        fw.fetch_text = transport
        result = fw.collect_cve_entries_for_advisory("FG-IR-26-002", timeout=5)
        self.assertEqual(result, [])

    def test_reads_the_csaf_export_through_the_advisory_page(self) -> None:
        transport = FakeTransport()
        transport.add_advisory("FG-IR-26-161")
        fw.fetch_text = transport
        result = fw.collect_cve_entries_for_advisory("FG-IR-26-161", timeout=5)

        self.assertEqual(
            transport.calls,
            [
                "https://fortiguard.fortinet.com/psirt/FG-IR-26-161",
                csaf_url_for("FG-IR-26-161"),
            ],
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
                    "from": "7.6.1",
                    "to": "7.6.6",
                },
            ],
        )


class ReplaceCvesForAdvisoryTests(unittest.TestCase):
    def test_removes_cve_no_longer_returned(self) -> None:
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

    def test_empty_new_entries_removes_all_of_that_advisorys_cves(self) -> None:
        state = fw.normalize_state({"cves": [
            {"id": "CVE-2026-00001", "advisoryId": "FG-IR-26-001", "title": "old"},
        ]})
        fw.replace_cves_for_advisory(state, "FG-IR-26-001", [])
        self.assertEqual(state["cves"], [])

    def test_no_change_reports_zero(self) -> None:
        state = fw.normalize_state({"cves": [
            {"id": "CVE-2026-00001", "advisoryId": "FG-IR-26-001", "title": "same"},
        ]})
        stats = fw.replace_cves_for_advisory(state, "FG-IR-26-001", [
            {"id": "CVE-2026-00001", "advisoryId": "FG-IR-26-001", "title": "same"},
        ])
        self.assertEqual(stats, fw.CveReconciliationStats(added=0, updated=0, removed=0))

    def test_pure_removal_is_not_counted_as_an_addition(self) -> None:
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

    def test_genuinely_new_cve_is_counted_as_added(self) -> None:
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

    def setUp(self) -> None:
        self._orig_rss = fw.discover_advisory_ids_from_rss
        self._orig_fetch_text = fw.fetch_text

    def tearDown(self) -> None:
        fw.discover_advisory_ids_from_rss = self._orig_rss
        fw.fetch_text = self._orig_fetch_text

    def test_stale_cve_removed_after_successful_refetch_returns_fewer(self) -> None:
        state = fw.normalize_state({"cves": [
            {"id": "CVE-2026-00001", "advisoryId": "FG-IR-26-001", "title": "old"},
            {"id": "CVE-2026-00002", "advisoryId": "FG-IR-26-001", "title": "old, now removed by Fortinet"},
        ]})
        transport = FakeTransport()
        transport.add_advisory(
            "FG-IR-26-001", make_csaf_document("FG-IR-26-001", cve_ids=("CVE-2026-00001",))
        )
        fw.fetch_text = transport
        fw.discover_advisory_ids_from_rss = lambda timeout: ["FG-IR-26-001"]

        cve_results, skipped = fw.collect_cve_catalog(
            existing_advisory_ids={"FG-IR-26-001"}, timeout=5, backfill=False,
        )
        self.assertEqual(skipped, [])
        for advisory_id, entries in cve_results.items():
            fw.replace_cves_for_advisory(state, advisory_id, entries)

        ids = [item["id"] for item in state["cves"]]
        self.assertEqual(ids, ["CVE-2026-00001"], "CVE-2026-00002 must be removed after a successful re-fetch")

    def test_cves_preserved_after_simulated_network_failure(self) -> None:
        state = fw.normalize_state({"cves": [
            {"id": "CVE-2026-00001", "advisoryId": "FG-IR-26-001", "title": "old"},
            {"id": "CVE-2026-00002", "advisoryId": "FG-IR-26-001", "title": "old"},
        ]})
        transport = FakeTransport()
        transport.fail_page("FG-IR-26-001", TimeoutError("PSIRT unreachable"))
        fw.fetch_text = transport
        fw.discover_advisory_ids_from_rss = lambda timeout: ["FG-IR-26-001"]

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

    def test_reconcile_existing_also_refetches_advisories_outside_the_rss_window(self) -> None:
        transport = FakeTransport()
        transport.add_advisory("FG-IR-26-001")
        transport.add_advisory(
            "FG-IR-26-002", make_csaf_document("FG-IR-26-002", cve_ids=("CVE-2026-00002",))
        )
        fw.fetch_text = transport
        fw.discover_advisory_ids_from_rss = lambda timeout: ["FG-IR-26-001"]

        # Without the maintenance flag, the out-of-window advisory is never looked at.
        results, _skipped = fw.collect_cve_catalog(
            existing_advisory_ids={"FG-IR-26-002"}, timeout=5, backfill=False,
        )
        self.assertEqual(sorted(results), ["FG-IR-26-001"])
        self.assertNotIn("FG-IR-26-002", results)

        transport.calls.clear()
        results, _skipped = fw.collect_cve_catalog(
            existing_advisory_ids={"FG-IR-26-002"}, timeout=5, backfill=False,
            reconcile_existing=True,
        )
        self.assertEqual(sorted(results), ["FG-IR-26-001", "FG-IR-26-002"])
        self.assertIn(
            "https://fortiguard.fortinet.com/psirt/FG-IR-26-002", transport.calls
        )


class MainCommitSequenceCveReconciliationTests(unittest.TestCase):
    """Reproduces main()'s actual end-to-end commit sequence, not just replace_cves_for_advisory()
    in isolation — that's exactly what let the first fix pass its own test while still shipping
    the resurrection bug: reconciling only the in-memory `state` working copy is not enough,
    because the final commit re-reads the file fresh and merge_state()'s CVE merge is a keyed
    union that never removes anything absent from the incoming side. The removal only actually
    sticks if the same reconciliation is re-applied on `final_state` after that merge.
    """

    def test_stale_cve_does_not_reappear_after_the_full_commit_sequence(self) -> None:
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


class CveReconciliationPipelineTests(unittest.TestCase):
    """Runs the real main() pipeline against a copy of the real production catalogue (trimmed
    fixture, all 33 real CVEs kept), with the frozen FG-IR-26-174 documents served by an inert
    transport, and the real notification engine in the loop.

    Proves, in one place: the false-positive ranges are corrected; every other catalogue section
    is preserved; advisories skipped on failure keep their previous data; the pass is idempotent
    and restartable; and neither the reconciliation nor its re-run replays any notification
    (sentKeys/outbox untouched, checkpoint advanced with the corrected entry)."""

    def setUp(self) -> None:
        self._orig_fetch_text = fw.fetch_text
        self._orig_rss = fw.discover_advisory_ids_from_rss
        self._orig_psirt_versions = fw.fetch_psirt_versions
        self._orig_lifecycle = fw.fetch_fortios_lifecycle
        self._orig_sleep = fw.time.sleep
        fw.fetch_psirt_versions = lambda timeout: set()
        fw.fetch_fortios_lifecycle = lambda timeout: {}
        fw.discover_advisory_ids_from_rss = lambda timeout: []
        fw.time.sleep = lambda seconds: None

    def tearDown(self) -> None:
        fw.fetch_text = self._orig_fetch_text
        fw.discover_advisory_ids_from_rss = self._orig_rss
        fw.fetch_psirt_versions = self._orig_psirt_versions
        fw.fetch_fortios_lifecycle = self._orig_lifecycle
        fw.time.sleep = self._orig_sleep

    def _run(self, tmp: Path, state_path: Path, health_path: Path, history_path: Path) -> int:
        return fw.main([
            "--cve-catalog", "--cve-reconcile-existing",
            "--base", str(state_path), "--output", str(state_path),
            "--report", str(tmp / "report.md"), "--health-output", str(health_path),
            "--official-paths-csv", str(tmp / "no-official-paths.csv"),
            "--advisories-csv", str(tmp / "no-advisories.csv"),
            "--upgrade-exports", str(tmp / "no-upgrade-exports"),
            "--notify-history-output", str(history_path),
            "--notification-settings-output", str(tmp / "notification-settings.json"),
            "--cve-retry-delays-seconds", "",
            "--timeout", "5",
        ])

    def _make_transport(self) -> FakeTransport:
        transport = FakeTransport()
        transport.add_advisory(
            "FG-IR-26-174",
            json.loads((FIXTURES / "FG-IR-26-174.csaf.json").read_text(encoding="utf-8")),
            page=(FIXTURES / "FG-IR-26-174.advisory.html").read_text(encoding="utf-8"),
            csaf_url=FG_IR_26_174_CSAF_URL,
        )
        # Every other advisory referenced by the catalogue fails with a clean network error:
        # skipped, preserved, never emptied.
        transport.default_error = urllib.error.URLError("not served in this test")
        return transport

    def test_reconciliation_fixes_the_false_positive_without_replay_or_data_loss(self) -> None:
        fixture = json.loads(LIVE_CATALOG_COPY.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            state_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            fw.write_json(state_path, fixture)

            coarse_entry = next(c for c in fixture["cves"] if c["id"] == "CVE-2026-84393")
            fn.ensure_checkpoint(history_path, {
                "versionsByProduct": {},
                "cvesById": {"CVE-2026-84393": coarse_entry},
                "health": {},
            })
            seeded = fn.load_notify_state(history_path)
            seeded["sentKeys"]["new-cve|psirt|CVE-2026-84393|high"] = "2026-09-08T00:00:00Z"
            fw.write_json(history_path, seeded)

            transport = self._make_transport()
            fw.fetch_text = transport
            exit_code = self._run(tmp, state_path, health_path, history_path)
            self.assertEqual(exit_code, 0)

            after = json.loads(state_path.read_text(encoding="utf-8"))

            # 1. The false-positive entry now carries exactly the official CSAF range.
            fixed = next(c for c in after["cves"] if c["id"] == "CVE-2026-84393")
            self.assertEqual(
                fixed["affected"],
                [{
                    "product": "fortigate-fortios",
                    "models": [],
                    "branch": "7.6",
                    "from": "7.6.1",
                    "to": "7.6.6",
                }],
            )
            self.assertEqual(fixed["severity"], "high")
            self.assertEqual(fixed["cvssScore"], 7.3)

            # 2. Every other section is preserved; the other 32 CVEs keep their previous data
            #    (their advisories were skipped on this run, never emptied).
            self.assertEqual(
                [c for c in after["cves"] if c["id"] != "CVE-2026-84393"],
                [c for c in fixture["cves"] if c["id"] != "CVE-2026-84393"],
            )
            for section in ("products", "paths", "advisories", "compatibilities"):
                self.assertEqual(after.get(section), fixture.get(section), section)

            # 3. No notification replay: the real engine's baseline advanced to the corrected
            #    entry while sentKeys/outbox were left strictly untouched.
            notify_state = fn.load_notify_state(history_path)
            self.assertEqual(
                sorted(notify_state["sentKeys"]),
                ["new-cve|psirt|CVE-2026-84393|high"],
            )
            self.assertEqual(notify_state["outbox"], [])
            checkpoint_entry = notify_state["checkpoint"]["cvesById"]["CVE-2026-84393"]
            self.assertEqual(checkpoint_entry["affected"], fixed["affected"])

            # 4. Idempotence/restart safety: re-running on the already-reconciled catalogue
            #    changes nothing (only generatedAt moves) and still replays nothing.
            transport.calls.clear()
            exit_code = self._run(tmp, state_path, health_path, history_path)
            self.assertEqual(exit_code, 0)
            after_second = json.loads(state_path.read_text(encoding="utf-8"))
            after_second["generatedAt"] = after["generatedAt"]
            self.assertEqual(after_second, after)
            notify_state_2 = fn.load_notify_state(history_path)
            self.assertEqual(notify_state_2["sentKeys"], notify_state["sentKeys"])
            self.assertEqual(notify_state_2["outbox"], [])
            # The checkpoint's health snapshot legitimately moves between runs (timestamps and
            # durations); the diff baselines themselves must not.
            self.assertEqual(
                notify_state_2["checkpoint"]["cvesById"],
                notify_state["checkpoint"]["cvesById"],
            )
            self.assertEqual(
                notify_state_2["checkpoint"]["versionsByProduct"],
                notify_state["checkpoint"]["versionsByProduct"],
            )

    def test_interrupted_run_leaves_the_catalogue_untouched_and_a_later_run_converges(self) -> None:
        fixture = json.loads(LIVE_CATALOG_COPY.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            state_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            fw.write_json(state_path, fixture)
            before_bytes = state_path.read_text(encoding="utf-8")

            # First attempt: the advisory page loads but the CSAF download dies mid-run.
            transport = self._make_transport()
            transport.documents["FG-IR-26-174"] = urllib.error.URLError("connection reset")
            fw.fetch_text = transport
            exit_code = self._run(tmp, state_path, health_path, history_path)
            self.assertEqual(exit_code, 0)
            interrupted = json.loads(state_path.read_text(encoding="utf-8"))
            before = json.loads(before_bytes)
            self.assertEqual(
                {**interrupted, "generatedAt": before["generatedAt"]},
                before,
                "an interrupted collection must leave the catalogue data untouched",
            )

            # A later run with the transport back up converges on the corrected entry.
            fw.fetch_text = self._make_transport()
            exit_code = self._run(tmp, state_path, health_path, history_path)
            self.assertEqual(exit_code, 0)
            after = json.loads(state_path.read_text(encoding="utf-8"))
            fixed = next(c for c in after["cves"] if c["id"] == "CVE-2026-84393")
            self.assertEqual(fixed["affected"][0]["from"], "7.6.1")

    def test_range_only_change_never_produces_a_notification_event(self) -> None:
        """Real engine functions: correcting ranges (severity unchanged) derives nothing; a
        genuine severity escalation still does — the guard against a vacuous assertion."""
        fixture = json.loads(LIVE_CATALOG_COPY.read_text(encoding="utf-8"))
        coarse = next(c for c in fixture["cves"] if c["id"] == "CVE-2026-84393")
        fixed = dict(coarse)
        fixed["affected"] = [{
            "product": "fortigate-fortios",
            "models": [],
            "branch": "7.6",
            "from": "7.6.1",
            "to": "7.6.6",
        }]
        events = fn.derive_cve_modification_events(
            {"CVE-2026-84393": coarse}, {"CVE-2026-84393": fixed}
        )
        self.assertEqual(events, [])

        escalated = dict(fixed)
        escalated["severity"] = "critical"
        events = fn.derive_cve_modification_events(
            {"CVE-2026-84393": coarse}, {"CVE-2026-84393": escalated}
        )
        self.assertEqual(len(events), 1)


if __name__ == "__main__":
    unittest.main()
