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

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

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

    def __call__(self, url: str, timeout: int, redirect_validator=None) -> str:
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


def _mock_smtp_client():
    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    return client


# SMTP bootstrap for the pipeline tests that enable notifications: the functional settings come
# from the saved notification-settings.json, the non-secret SMTP infrastructure from the
# environment (the same bootstrap path real deployments use), and sends go to a mock client.
NOTIFY_ENV = {
    "FORTIOS_EMAIL_ENABLED": "true",
    "FORTIOS_SMTP_HOST": "smtp.example.com",
    "FORTIOS_SMTP_FROM": "fortios@example.com",
    "FORTIOS_SMTP_TO": "ops@example.com",
}

PENDING_EVENT_KEY = "new-cve|psirt|CVE-2020-00001|high"
# The dedup key of the CVRF-era severity escalation the maintenance pass repairs (CVE-2026-84393
# low -> high): if a repair ever replays as a notification, this is the key it replays under.
CVE_ESCALATION_REPLAY_KEY = "cve-severity|psirt|CVE-2026-84393|low-to-high"


def full_cve_baseline(fixture: dict) -> dict[str, dict]:
    """The CVE map a completed NORMAL (or backfill) notification pass leaves as its baseline.

    A normal run — and a backfill — advances the checkpoint's cvesById to the whole catalogue it
    just committed, so a realistic checkpoint knows every stored CVE id. Seeding a test catalogue
    whose checkpoint only knew the single CVE under test would model an unrealistically lagging
    baseline: a later run would legitimately derive all the other stored ids as new. A maintenance
    pass is different by design: it only ever absorbs its own confirmed corrections (see the
    concurrency tests at the end of CveReconciliationPipelineTests).
    """
    return {c["id"]: c for c in fixture["cves"] if c.get("id")}


def _pending_event() -> dict:
    """A legitimate event already sitting in the outbox before the maintenance pass runs."""
    return {
        "category": "DAILY",
        "dedupKey": PENDING_EVENT_KEY,
        "summary": "CVE-2020-00001 — FortiGate / FortiOS (high)",
        "severity": "high",
        "details": {
            "kind": "cve",
            "id": "CVE-2020-00001",
            "severity": "high",
            "cvssScore": 8.8,
            "title": "legitimate pending event",
            "url": "https://fortiguard.fortinet.com/psirt/FG-IR-20-001",
            "affected": [],
            "productLabels": ["FortiGate / FortiOS"],
            "change": "new",
        },
        "queuedAt": "2026-10-01T00:00:00Z",
        "claimedBy": None,
        "claimedAt": None,
        "nextAttemptAt": None,
        "lastTransport": None,
        "lastErrorCode": None,
    }


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
        for failure in (
            TimeoutError("PSIRT unreachable"),
            fw.UnsafeRedirectError("redirection refusée : https://evil.example/"),
        ):
            with self.subTest(failure=type(failure).__name__):
                state = fw.normalize_state({"cves": [
                    {"id": "CVE-2026-00001", "advisoryId": "FG-IR-26-001", "title": "old"},
                    {"id": "CVE-2026-00002", "advisoryId": "FG-IR-26-001", "title": "old"},
                ]})
                transport = FakeTransport()
                transport.fail_page("FG-IR-26-001", failure)
                fw.fetch_text = transport
                fw.discover_advisory_ids_from_rss = lambda timeout: ["FG-IR-26-001"]

                cve_results, skipped = fw.collect_cve_catalog(
                    existing_advisory_ids={"FG-IR-26-001"}, timeout=5, backfill=False,
                )
                self.assertEqual(skipped, ["FG-IR-26-001"])
                self.assertEqual(cve_results, {}, "a failed advisory must not appear as a resolved result")

                # main()'s loop only reconciles advisory_ids present in cve_results -- FG-IR-26-001
                # isn't, so state["cves"] must stay exactly as it was.
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
    """Reproduces main()'s actual end-to-end commit sequence through the real
    commit_collected_state() helper, not just replace_cves_for_advisory() in isolation — that's
    exactly what let the first fix pass its own test while still shipping the resurrection bug.
    CVEs are never bulk-merged from a run's snapshot: only this run's definitive per-advisory
    results are applied, so a stale snapshot cannot undo a concurrent repair or removal.
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

            # 4. The actual final commit sequence from main(), through the real helper.
            fw.commit_collected_state(output_path, state, [], [], cve_results_by_advisory)

            # 5. CVE-STALE must not have reappeared.
            result = fw.normalize_state(fw.read_json(output_path, {}))
            ids = sorted(item["id"] for item in result["cves"])
            self.assertEqual(ids, ["CVE-KEEP"], "CVE-STALE must not resurrect during the final merge")

    def test_stale_snapshot_cannot_undo_a_concurrent_reconciliation(self) -> None:
        """The precise interleaving from the review: run A reads the catalogue, then collects
        slowly; run B (--cve-reconcile-existing) repairs an advisory outside A's fetch scope and
        commits; A then commits its own fresh result for another advisory, with no new probative
        result for B's advisory. A's stale snapshot must not overwrite B's correction, and B's
        removal must stick — while A's own fresh result still lands."""
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "state.json"
            fw.write_json(output_path, fw.normalize_state({"cves": [
                {"id": "CVE-FRESH", "advisoryId": "FG-IR-A", "title": "old, A will re-fetch it"},
                {"id": "CVE-CORRECTED", "advisoryId": "FG-IR-B", "title": "coarse ranges (old collector)"},
                {"id": "CVE-RETRACTED", "advisoryId": "FG-IR-B", "title": "gone from the new export"},
            ]}))

            # Both runs start from the same pre-collection snapshot.
            snapshot_a = fw.normalize_state(fw.read_json(output_path, {}))
            snapshot_b = fw.normalize_state(fw.read_json(output_path, {}))

            # Run B repairs FG-IR-B: corrected entry, retracted entry removed.
            corrected = {"id": "CVE-CORRECTED", "advisoryId": "FG-IR-B", "title": "corrected ranges"}
            fw.commit_collected_state(output_path, snapshot_b, [], [], {"FG-IR-B": [corrected]})

            # Run A only has a fresh result for FG-IR-A; its snapshot still carries the old
            # coarse/retracted entries for FG-IR-B.
            fresh = {"id": "CVE-FRESH", "advisoryId": "FG-IR-A", "title": "refreshed"}
            fw.commit_collected_state(output_path, snapshot_a, [], [], {"FG-IR-A": [fresh]})

            result = fw.normalize_state(fw.read_json(output_path, {}))
            by_id = {item["id"]: item for item in result["cves"]}
            self.assertEqual(by_id["CVE-CORRECTED"]["title"], "corrected ranges")
            self.assertNotIn(
                "CVE-RETRACTED", by_id, "a concurrent retraction must not be undone by a stale snapshot"
            )
            self.assertEqual(by_id["CVE-FRESH"]["title"], "refreshed")


class CveReconciliationPipelineTests(unittest.TestCase):
    """Runs the real main() pipeline against a copy of the real production catalogue (trimmed
    fixture, all 33 real CVEs kept), with the frozen FG-IR-26-174 documents served by an inert
    transport, and the real notification engine in the loop.

    Proves, in one place: the false-positive ranges are corrected; every other catalogue section
    is preserved; advisories skipped on failure keep their previous data; the pass is idempotent
    and restartable; and neither the reconciliation nor its re-run replays any notification
    (sentKeys/outbox untouched, checkpoint advanced with the corrected entry). The four
    concurrency tests at the end pin the cross-run coordination boundary: durable notify state
    always wins over an in-flight run's stale capture — an unobserved intent is never erased, a
    consumed baseline stays opposable to a collection already started, a completed advance is
    never regressed, and the pass never absorbs a concurrent novelty it did not resolve."""

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

    def _run(
        self,
        tmp: Path,
        state_path: Path,
        health_path: Path,
        history_path: Path,
        *,
        reconcile: bool = True,
    ) -> int:
        flags = ["--cve-catalog"]
        if reconcile:
            flags.append("--cve-reconcile-existing")
        return fw.main([
            *flags,
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

    def _enable_notifications(self, tmp: Path) -> None:
        """Persist the functional configuration with the CVE category enabled (SMTP infra comes
        from the environment bootstrap; sends are mocked in the tests)."""
        payload = fn._default_notification_settings_payload()
        payload["enabled"] = True
        payload["recipients"] = ["ops@example.com"]
        fn.save_notification_settings(tmp / "notification-settings.json", payload)

    def _catalog_with_low_severity_false_positive(self) -> dict:
        """The frozen production catalogue, with the CVRF-era false positive downgraded to
        `low`: the CSAF repair is then also a severity escalation, so it WOULD notify if the
        maintenance pass weren't silent (see the canaries in the tests below)."""
        fixture = json.loads(LIVE_CATALOG_COPY.read_text(encoding="utf-8"))
        for index, cve in enumerate(fixture["cves"]):
            if cve["id"] == "CVE-2026-84393":
                fixture["cves"][index] = dict(cve, severity="low")
        return fixture

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

    def test_reconcile_with_notifications_enabled_is_silent_and_preserves_pending_outbox(self) -> None:
        """With the CVE category ENABLED and a legitimate event already pending, a maintenance
        reconciliation repairs history without deriving any event, delivers exactly the pending
        one, and still advances the checkpoint to the corrected entry."""
        fixture = self._catalog_with_low_severity_false_positive()
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            state_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            fw.write_json(state_path, fixture)
            self._enable_notifications(tmp)

            coarse = next(c for c in fixture["cves"] if c["id"] == "CVE-2026-84393")
            fn.ensure_checkpoint(history_path, {
                "versionsByProduct": {},
                "cvesById": full_cve_baseline(fixture),
                "health": {},
            })
            seeded = fn.load_notify_state(history_path)
            seeded["outbox"].append(_pending_event())
            fw.write_json(history_path, seeded)

            corrected = fw.parse_csaf_document(
                "FG-IR-26-174",
                json.loads((FIXTURES / "FG-IR-26-174.csaf.json").read_text(encoding="utf-8")),
            )[0]
            canary = fn.derive_cve_modification_events(
                {"CVE-2026-84393": coarse}, {"CVE-2026-84393": corrected}
            )
            self.assertEqual(
                len(canary), 1,
                "canary: the severity correction would notify if the maintenance pass weren't silent",
            )

            transport = self._make_transport()
            fw.fetch_text = transport
            client = _mock_smtp_client()
            with patch.dict(os.environ, NOTIFY_ENV, clear=False), patch(
                "smtplib.SMTP", return_value=client
            ):
                exit_code = self._run(tmp, state_path, health_path, history_path)
            self.assertEqual(exit_code, 0)

            after = json.loads(state_path.read_text(encoding="utf-8"))
            fixed = next(c for c in after["cves"] if c["id"] == "CVE-2026-84393")
            self.assertEqual(fixed["severity"], "high")
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

            notify_state = fn.load_notify_state(history_path)
            self.assertEqual(
                notify_state["outbox"], [],
                "the pending legitimate event must be delivered, nothing else left behind",
            )
            self.assertEqual(
                list(notify_state["sentKeys"]),
                [PENDING_EVENT_KEY],
                "maintenance must never (re)notify historical CVEs: only the pre-existing "
                "legitimate event may be sent",
            )
            self.assertEqual(
                client.send_message.call_count, 1,
                "exactly the pre-existing pending event is sent",
            )
            checkpoint_entry = notify_state["checkpoint"]["cvesById"]["CVE-2026-84393"]
            self.assertEqual(checkpoint_entry["severity"], "high")
            self.assertEqual(checkpoint_entry["affected"], fixed["affected"])

    def test_interrupted_maintenance_cannot_replay_history_on_the_next_normal_run(self) -> None:
        """The crash window: a reconcile pass commits its corrections, then dies between the
        catalogue commit and the notification block. A later NORMAL run must derive no
        historical event, and a genuinely new advisory after that must still notify normally."""
        fixture = self._catalog_with_low_severity_false_positive()
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            state_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            fw.write_json(state_path, fixture)
            self._enable_notifications(tmp)

            coarse = next(c for c in fixture["cves"] if c["id"] == "CVE-2026-84393")
            fn.ensure_checkpoint(history_path, {
                "versionsByProduct": {},
                "cvesById": full_cve_baseline(fixture),
                "health": {},
            })

            transport = self._make_transport()
            transport.add_advisory(
                "FG-IR-26-154",
                json.loads((FIXTURES / "FG-IR-26-154.csaf.json").read_text(encoding="utf-8")),
            )
            fw.fetch_text = transport

            original_load_email_config = fn.load_email_config

            def interrupted(*args, **kwargs):
                raise KeyboardInterrupt()

            # Run 1: the maintenance pass commits the catalogue (including CVE-2026-59840, the
            # real CVE absent from the old export), then dies before any notification work.
            fn.load_email_config = interrupted
            try:
                with self.assertRaises(KeyboardInterrupt):
                    self._run(tmp, state_path, health_path, history_path)
            finally:
                fn.load_email_config = original_load_email_config

            after_first = json.loads(state_path.read_text(encoding="utf-8"))
            ids = {c["id"] for c in after_first["cves"]}
            self.assertIn("CVE-2026-59840", ids, "the historical CVE absent from the old export must be committed")
            self.assertIn("CVE-2025-43892", ids)
            first_state = fn.load_notify_state(history_path)
            self.assertEqual(first_state["outbox"], [])
            self.assertEqual(first_state["sentKeys"], {})
            self.assertEqual(
                first_state["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"], "high"
            )
            self.assertIn(
                "CVE-2026-59840",
                first_state["checkpoint"]["cvesById"],
                "the CVE-baseline consumption must already cover the committed historical entries",
            )
            checkpoint_entry = first_state["checkpoint"]["cvesById"]["CVE-2026-84393"]
            self.assertEqual(
                len(fn.derive_cve_modification_events(
                    {"CVE-2026-84393": coarse}, {"CVE-2026-84393": checkpoint_entry}
                )),
                1,
                "canary: with the old baseline, the next run would notify this escalation",
            )

            # Run 2: a normal run must not replay any of it.
            fw.fetch_text = self._make_transport()
            client2 = _mock_smtp_client()
            with patch.dict(os.environ, NOTIFY_ENV, clear=False), patch(
                "smtplib.SMTP", return_value=client2
            ):
                exit_code = self._run(
                    tmp, state_path, health_path, history_path, reconcile=False
                )
            self.assertEqual(exit_code, 0)
            second_state = fn.load_notify_state(history_path)
            self.assertEqual(client2.send_message.call_count, 0, "the resume run must not replay history")
            self.assertEqual(second_state["outbox"], [])
            self.assertEqual(second_state["sentKeys"], {})

            # Run 3: a genuinely new advisory still notifies normally.
            transport3 = FakeTransport()
            transport3.add_advisory(
                "FG-IR-26-999",
                make_csaf_document("FG-IR-26-999", cve_ids=("CVE-2026-99999",)),
            )
            transport3.default_error = urllib.error.URLError("not served in this test")
            fw.fetch_text = transport3
            fw.discover_advisory_ids_from_rss = lambda timeout: ["FG-IR-26-999"]
            client3 = _mock_smtp_client()
            with patch.dict(os.environ, NOTIFY_ENV, clear=False), patch(
                "smtplib.SMTP", return_value=client3
            ):
                exit_code = self._run(
                    tmp, state_path, health_path, history_path, reconcile=False
                )
            self.assertEqual(exit_code, 0)
            third_state = fn.load_notify_state(history_path)
            self.assertIn("new-cve|psirt|CVE-2026-99999|high", third_state["sentKeys"])
            self.assertEqual(third_state["outbox"], [])
            self.assertEqual(client3.send_message.call_count, 1)

    def test_crash_right_after_the_catalogue_commit_is_silent_on_a_normal_resume(self) -> None:
        """B3's exact boundary: the maintenance pass persists the corrected catalogue and dies
        BEFORE any notification bookkeeping (no baseline advance, no notification block).

        RED half — the same on-disk situation with the staged intent dropped, exactly the state
        the pre-fix code left at this boundary — replays the corrected CVE as a notification.
        GREEN half — with the durable intent in place — the normal resume absorbs the correction
        silently, delivers only the pre-existing legitimate event, and a genuinely new advisory
        after that still notifies normally. Repeated resumes stay silent.
        """
        fixture = self._catalog_with_low_severity_false_positive()
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            state_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            fw.write_json(state_path, fixture)
            self._enable_notifications(tmp)
            settings_bytes = (tmp / "notification-settings.json").read_text(encoding="utf-8")

            fn.ensure_checkpoint(history_path, {
                "versionsByProduct": {},
                "cvesById": full_cve_baseline(fixture),
                "health": {},
            })
            seeded = fn.load_notify_state(history_path)
            seeded["outbox"].append(_pending_event())
            fw.write_json(history_path, seeded)

            transport = self._make_transport()
            transport.add_advisory(
                "FG-IR-26-154",
                json.loads((FIXTURES / "FG-IR-26-154.csaf.json").read_text(encoding="utf-8")),
            )
            fw.fetch_text = transport

            real_commit = fw.commit_collected_state

            def commit_then_die(*args, **kwargs):
                real_commit(*args, **kwargs)
                raise KeyboardInterrupt()

            # Run 1: the maintenance pass commits the corrected catalogue, then dies immediately
            # after the real commit returns — before the baseline consumption, before the
            # notification block (the reviewer's probe shape, now a permanent regression test).
            with patch.object(
                fw, "commit_collected_state", side_effect=commit_then_die
            ), self.assertRaises(KeyboardInterrupt):
                self._run(tmp, state_path, health_path, history_path)

            after_first = json.loads(state_path.read_text(encoding="utf-8"))
            fixed = next(c for c in after_first["cves"] if c["id"] == "CVE-2026-84393")
            self.assertEqual(fixed["severity"], "high")
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
            self.assertIn("CVE-2026-59840", {c["id"] for c in after_first["cves"]})

            first_state = fn.load_notify_state(history_path)
            staged = first_state.get(fn.PENDING_CVE_BASELINE_KEY) or {}
            self.assertIn(
                "CVE-2026-84393", staged,
                "the durability intent must already be on disk before the catalogue commit",
            )
            self.assertIn("CVE-2026-59840", staged)
            self.assertEqual(
                first_state["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"], "low",
                "sanity: the baseline was NOT advanced — this IS the crash window",
            )
            self.assertEqual(
                [entry["dedupKey"] for entry in first_state["outbox"]],
                [PENDING_EVENT_KEY],
                "the legitimate pending event must survive the crashed pass untouched",
            )
            self.assertEqual(
                len(fn.derive_cve_modification_events(
                    {"CVE-2026-84393": first_state["checkpoint"]["cvesById"]["CVE-2026-84393"]},
                    {"CVE-2026-84393": fixed},
                )),
                1,
                "canary: without the durable intent, the resume would replay this escalation",
            )

            # RED half: drop the staged intent from a copy of the same on-disk situation — the
            # exact state the pre-fix code left at this boundary — and watch the replay happen.
            red_tmp = Path(tmp_str) / "red-copy"
            shutil.copytree(tmp, red_tmp)
            red_state_path = red_tmp / "state.json"
            red_health_path = red_tmp / "health.json"
            red_history_path = red_tmp / "notify-history.json"
            red_state = fn.load_notify_state(red_history_path)
            red_state.pop(fn.PENDING_CVE_BASELINE_KEY, None)
            fw.write_json(red_history_path, red_state)
            client_red = _mock_smtp_client()
            with patch.dict(os.environ, NOTIFY_ENV, clear=False), patch(
                "smtplib.SMTP", return_value=client_red
            ):
                exit_code = self._run(
                    red_tmp, red_state_path, red_health_path, red_history_path, reconcile=False
                )
            self.assertEqual(exit_code, 0)
            red_after = fn.load_notify_state(red_history_path)
            self.assertEqual(client_red.send_message.call_count, 1)
            self.assertTrue(
                [key for key in red_after["sentKeys"] if "CVE-2026-84393" in key],
                "RED: without the durable intent the resume replays the corrected CVE",
            )

            # GREEN half: same crash, same resume — with the durable intent actually in place.
            client = _mock_smtp_client()
            with patch.dict(os.environ, NOTIFY_ENV, clear=False), patch(
                "smtplib.SMTP", return_value=client
            ):
                exit_code = self._run(
                    tmp, state_path, health_path, history_path, reconcile=False
                )
            self.assertEqual(exit_code, 0)
            resumed = fn.load_notify_state(history_path)
            self.assertEqual(
                list(resumed["sentKeys"]),
                [PENDING_EVENT_KEY],
                "the resume may deliver the pre-existing legitimate event and nothing else",
            )
            self.assertEqual(client.send_message.call_count, 1)
            self.assertEqual(resumed["outbox"], [])
            self.assertNotIn(fn.PENDING_CVE_BASELINE_KEY, resumed)
            self.assertEqual(
                resumed["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"], "high"
            )

            # Repeated resume: still silent, still nothing staged.
            client_again = _mock_smtp_client()
            with patch.dict(os.environ, NOTIFY_ENV, clear=False), patch(
                "smtplib.SMTP", return_value=client_again
            ):
                exit_code = self._run(
                    tmp, state_path, health_path, history_path, reconcile=False
                )
            self.assertEqual(exit_code, 0)
            self.assertEqual(client_again.send_message.call_count, 0)
            again = fn.load_notify_state(history_path)
            self.assertEqual(list(again["sentKeys"]), [PENDING_EVENT_KEY])
            self.assertNotIn(fn.PENDING_CVE_BASELINE_KEY, again)

            # A genuinely new advisory after the resume still notifies normally.
            transport3 = FakeTransport()
            transport3.add_advisory(
                "FG-IR-26-999",
                make_csaf_document("FG-IR-26-999", cve_ids=("CVE-2026-99999",)),
            )
            transport3.default_error = urllib.error.URLError("not served in this test")
            fw.fetch_text = transport3
            fw.discover_advisory_ids_from_rss = lambda timeout: ["FG-IR-26-999"]
            client3 = _mock_smtp_client()
            with patch.dict(os.environ, NOTIFY_ENV, clear=False), patch(
                "smtplib.SMTP", return_value=client3
            ):
                exit_code = self._run(
                    tmp, state_path, health_path, history_path, reconcile=False
                )
            self.assertEqual(exit_code, 0)
            final_state = fn.load_notify_state(history_path)
            self.assertIn("new-cve|psirt|CVE-2026-99999|high", final_state["sentKeys"])
            self.assertEqual(client3.send_message.call_count, 1)

            # None of the runs rewrote the functional preferences.
            self.assertEqual(
                (tmp / "notification-settings.json").read_text(encoding="utf-8"),
                settings_bytes,
            )

    def test_crash_at_the_intent_boundary_leaves_history_untouched_until_a_later_pass(
        self,
    ) -> None:
        """Boundary right BEFORE the intent is persisted: the pass dies while trying to write it,
        so nothing was staged and the catalogue was not committed either. A later maintenance
        pass completes normally, silently."""
        fixture = self._catalog_with_low_severity_false_positive()
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            state_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            fw.write_json(state_path, fixture)
            before_bytes = state_path.read_text(encoding="utf-8")
            self._enable_notifications(tmp)
            fn.ensure_checkpoint(history_path, {
                "versionsByProduct": {},
                "cvesById": full_cve_baseline(fixture),
                "health": {},
            })
            fw.fetch_text = self._make_transport()

            def die(*args, **kwargs):
                raise KeyboardInterrupt()

            with patch.object(
                fn, "stage_pending_cve_baseline", side_effect=die
            ), self.assertRaises(KeyboardInterrupt):
                self._run(tmp, state_path, health_path, history_path)

            # Neither the catalogue nor the notification state was touched.
            self.assertEqual(state_path.read_text(encoding="utf-8"), before_bytes)
            self.assertNotIn(
                fn.PENDING_CVE_BASELINE_KEY, fn.load_notify_state(history_path)
            )

            # A later pass completes: corrected catalogue, staged intent consumed, no email.
            client = _mock_smtp_client()
            with patch.dict(os.environ, NOTIFY_ENV, clear=False), patch(
                "smtplib.SMTP", return_value=client
            ):
                exit_code = self._run(tmp, state_path, health_path, history_path)
            self.assertEqual(exit_code, 0)
            after = json.loads(state_path.read_text(encoding="utf-8"))
            fixed = next(c for c in after["cves"] if c["id"] == "CVE-2026-84393")
            self.assertEqual(fixed["severity"], "high")
            final_state = fn.load_notify_state(history_path)
            self.assertEqual(final_state["sentKeys"], {})
            self.assertEqual(final_state["outbox"], [])
            self.assertEqual(client.send_message.call_count, 0)
            self.assertNotIn(fn.PENDING_CVE_BASELINE_KEY, final_state)

    def test_intent_without_the_commit_keeps_the_old_baseline_and_never_replays(self) -> None:
        """Boundary right AFTER the intent, BEFORE the catalogue commit: the staged corrections
        are not in the catalogue, so no run may advance the baseline to them (diffing an old,
        coarser entry against an already-corrected baseline is the replay in the opposite
        direction). The unapplied entries stay staged until the pass is retried."""
        fixture = self._catalog_with_low_severity_false_positive()
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            state_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            fw.write_json(state_path, fixture)
            self._enable_notifications(tmp)
            fn.ensure_checkpoint(history_path, {
                "versionsByProduct": {},
                "cvesById": full_cve_baseline(fixture),
                "health": {},
            })
            fw.fetch_text = self._make_transport()

            def die(*args, **kwargs):
                raise KeyboardInterrupt()

            with patch.object(
                fw, "commit_collected_state", side_effect=die
            ), self.assertRaises(KeyboardInterrupt):
                self._run(tmp, state_path, health_path, history_path)

            after_first = json.loads(state_path.read_text(encoding="utf-8"))
            fixed = next(c for c in after_first["cves"] if c["id"] == "CVE-2026-84393")
            self.assertEqual(fixed["severity"], "low", "the catalogue commit never happened")
            self.assertNotIn("CVE-2026-59840", {c["id"] for c in after_first["cves"]})
            first_state = fn.load_notify_state(history_path)
            self.assertIn(
                "CVE-2026-84393", first_state.get(fn.PENDING_CVE_BASELINE_KEY) or {},
                "the intent was staged before the crashed commit",
            )

            # A normal resume must not replay anything, and must not apply the uncommitted
            # correction: the old baseline stays exactly where it was.
            client = _mock_smtp_client()
            with patch.dict(os.environ, NOTIFY_ENV, clear=False), patch(
                "smtplib.SMTP", return_value=client
            ):
                exit_code = self._run(
                    tmp, state_path, health_path, history_path, reconcile=False
                )
            self.assertEqual(exit_code, 0)
            self.assertEqual(client.send_message.call_count, 0)
            resumed = fn.load_notify_state(history_path)
            self.assertEqual(resumed["sentKeys"], {})
            self.assertEqual(
                resumed["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"], "low",
                "an uncommitted correction must never be advanced into the baseline",
            )
            self.assertIn(
                "CVE-2026-84393", resumed.get(fn.PENDING_CVE_BASELINE_KEY) or {},
                "the unapplied entries must stay staged for the retried pass",
            )

            # Retrying the maintenance pass completes the correction, still silently.
            client2 = _mock_smtp_client()
            with patch.dict(os.environ, NOTIFY_ENV, clear=False), patch(
                "smtplib.SMTP", return_value=client2
            ):
                exit_code = self._run(tmp, state_path, health_path, history_path)
            self.assertEqual(exit_code, 0)
            after = json.loads(state_path.read_text(encoding="utf-8"))
            fixed = next(c for c in after["cves"] if c["id"] == "CVE-2026-84393")
            self.assertEqual(fixed["severity"], "high")
            final_state = fn.load_notify_state(history_path)
            self.assertEqual(final_state["sentKeys"], {})
            self.assertEqual(final_state["outbox"], [])
            self.assertEqual(client2.send_message.call_count, 0)
            self.assertNotIn(fn.PENDING_CVE_BASELINE_KEY, final_state)

    def test_unwritable_intent_aborts_the_maintenance_commit_fail_closed(self) -> None:
        """Write-failure boundary: if the durable intent cannot be written, the pass must NOT
        commit corrections nothing would keep silent. The run still completes, reports the abort
        on stderr and in the health state, and a later (working) pass completes normally."""
        fixture = self._catalog_with_low_severity_false_positive()
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            state_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            fw.write_json(state_path, fixture)
            self._enable_notifications(tmp)
            fn.ensure_checkpoint(history_path, {
                "versionsByProduct": {},
                "cvesById": full_cve_baseline(fixture),
                "health": {},
            })
            fw.fetch_text = self._make_transport()

            stderr = io.StringIO()
            with patch.object(
                fn, "stage_pending_cve_baseline", side_effect=OSError("read-only filesystem")
            ), contextlib.redirect_stderr(stderr):
                exit_code = self._run(tmp, state_path, health_path, history_path)
            self.assertEqual(exit_code, 0)
            self.assertIn("abandonn", stderr.getvalue())
            self.assertIn("non enregistrable", stderr.getvalue())

            after = json.loads(state_path.read_text(encoding="utf-8"))
            fixed = next(c for c in after["cves"] if c["id"] == "CVE-2026-84393")
            self.assertEqual(
                fixed["severity"], "low",
                "corrections that nothing could keep silent must not be committed",
            )
            self.assertNotIn("CVE-2026-59840", {c["id"] for c in after["cves"]})
            self.assertNotIn(
                fn.PENDING_CVE_BASELINE_KEY, fn.load_notify_state(history_path)
            )
            health = fw.read_health_state(health_path).get("sources", {})
            self.assertEqual(health.get("cve-psirt", {}).get("status"), "error")

            # The next pass, with the intent writable again, completes the correction silently.
            client = _mock_smtp_client()
            with patch.dict(os.environ, NOTIFY_ENV, clear=False), patch(
                "smtplib.SMTP", return_value=client
            ):
                exit_code = self._run(tmp, state_path, health_path, history_path)
            self.assertEqual(exit_code, 0)
            after = json.loads(state_path.read_text(encoding="utf-8"))
            fixed = next(c for c in after["cves"] if c["id"] == "CVE-2026-84393")
            self.assertEqual(fixed["severity"], "high")
            final_state = fn.load_notify_state(history_path)
            self.assertEqual(final_state["sentKeys"], {})
            self.assertEqual(client.send_message.call_count, 0)

    def test_normal_run_started_before_a_completed_maintenance_must_not_replay(self) -> None:
        """B3 review case 1 — a consumed historical baseline stays opposable to runs already in
        flight.

        A normal collection bootstraps its checkpoint (CVE-2026-84393 still `low`) and starts
        collecting; DURING that collection a complete maintenance pass runs to the end: corrected
        catalogue, intent consumed, baseline advanced to `high`, no email. The normal run then
        resumes with no advisory result of its own and merges the corrected catalogue. Deriving
        against its stale start-up checkpoint would replay the low->high repair as a notification
        (key `cve-severity|psirt|CVE-2026-84393|low-to-high`); the derivation must use the
        checkpoint as it actually stands once the run reaches its notification block.
        """
        fixture = self._catalog_with_low_severity_false_positive()
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            state_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            fw.write_json(state_path, fixture)
            self._enable_notifications(tmp)
            fn.ensure_checkpoint(history_path, {
                "versionsByProduct": {},
                "cvesById": full_cve_baseline(fixture),
                "health": {},
            })
            fw.fetch_text = self._make_transport()

            real_collect = fw.collect_cve_catalog
            client = _mock_smtp_client()

            def run_full_maintenance_then_resume_without_results(*args, **kwargs):
                with patch.object(fw, "collect_cve_catalog", real_collect):
                    self.assertEqual(
                        self._run(tmp, state_path, health_path, history_path, reconcile=True), 0
                    )
                after_b = fn.load_notify_state(history_path)
                self.assertEqual(after_b["sentKeys"], {}, "a complete maintenance pass is silent")
                self.assertNotIn(fn.PENDING_CVE_BASELINE_KEY, after_b)
                self.assertEqual(
                    after_b["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"], "high"
                )
                # A resumes with no advisory result of its own.
                return {}, []

            with patch.dict(os.environ, NOTIFY_ENV, clear=False), patch(
                "smtplib.SMTP", return_value=client
            ), patch(
                "socket.socket.connect",
                side_effect=AssertionError("external network forbidden"),
            ), patch(
                "socket.create_connection",
                side_effect=AssertionError("external network forbidden"),
            ), patch.object(
                fw,
                "collect_cve_catalog",
                side_effect=run_full_maintenance_then_resume_without_results,
            ):
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )

            after_a = fn.load_notify_state(history_path)
            self.assertNotIn(
                CVE_ESCALATION_REPLAY_KEY,
                after_a["sentKeys"],
                "a run already in flight must not replay a baseline consumed by a completed pass",
            )
            self.assertEqual(client.send_message.call_count, 0)
            self.assertEqual(
                after_a["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"], "high"
            )

    def test_old_normal_committer_must_not_erase_the_staged_maintenance_intent(self) -> None:
        """B3 review case 2 — an unobserved intent is never erased by a commit.

        A (normal collection) reads the notify state — no intent yet — and later reaches its
        final commit. Exactly then, B stages the durable intent, commits the corrected catalogue
        and dies before consuming it. A's commit must keep B's intent untouched (A never observed
        it), and the next normal run must still resolve it against the corrected catalogue: no
        low->high replay, durable silence.
        """
        fixture = self._catalog_with_low_severity_false_positive()
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            state_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            fw.write_json(state_path, fixture)
            self._enable_notifications(tmp)
            fn.ensure_checkpoint(history_path, {
                "versionsByProduct": {},
                "cvesById": full_cve_baseline(fixture),
                "health": {},
            })
            fw.fetch_text = self._make_transport()

            real_catalog_commit = fw.commit_collected_state
            real_notify_commit = fn.commit_events_with_checkpoint
            client = _mock_smtp_client()

            def commit_b_catalog_then_die(*args, **kwargs):
                real_catalog_commit(*args, **kwargs)
                raise KeyboardInterrupt("maintenance pass died after its catalogue commit")

            def run_maintenance_then_interpose(*args, **kwargs):
                with patch.object(
                    fw, "commit_collected_state", side_effect=commit_b_catalog_then_die
                ), self.assertRaises(KeyboardInterrupt):
                    self._run(tmp, state_path, health_path, history_path, reconcile=True)
                staged = fn.load_notify_state(history_path)
                self.assertIn(
                    "CVE-2026-84393",
                    staged.get(fn.PENDING_CVE_BASELINE_KEY) or {},
                    "sanity: the durable intent must exist when A's commit runs",
                )
                # A's ordinary final commit must not remove an intent it never resolved.
                return real_notify_commit(*args, **kwargs)

            with patch.dict(os.environ, NOTIFY_ENV, clear=False), patch(
                "smtplib.SMTP", return_value=client
            ), patch(
                "socket.socket.connect",
                side_effect=AssertionError("external network forbidden"),
            ), patch(
                "socket.create_connection",
                side_effect=AssertionError("external network forbidden"),
            ):
                with patch.object(
                    fn, "commit_events_with_checkpoint", side_effect=run_maintenance_then_interpose
                ):
                    self.assertEqual(
                        self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                    )

                after_a = fn.load_notify_state(history_path)
                self.assertIn(
                    "CVE-2026-84393",
                    after_a.get(fn.PENDING_CVE_BASELINE_KEY) or {},
                    "an unrelated committer erased the only durable silence intent",
                )
                self.assertEqual(client.send_message.call_count, 0)

                # A fresh normal run reads the catalogue B had already repaired and resolves the
                # surviving intent silently.
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                resumed = fn.load_notify_state(history_path)
                self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, resumed["sentKeys"])
                self.assertEqual(client.send_message.call_count, 0)
                self.assertNotIn(fn.PENDING_CVE_BASELINE_KEY, resumed)
                self.assertEqual(
                    resumed["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"], "high"
                )

                # Repeated resumes stay silent.
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                again = fn.load_notify_state(history_path)
                self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, again["sentKeys"])
                self.assertEqual(client.send_message.call_count, 0)

    def test_maintenance_must_not_absorb_a_concurrent_legitimate_new_cve(self) -> None:
        """B3 review case 3 — silence covers the pass's own corrections, never a concurrent
        novelty.

        While the maintenance pass is collecting, a concurrent normal run adds a genuinely new
        advisory (FG-IR-26-999 / CVE-2026-99999, High) and dies right after its real catalogue
        commit, before any notification work. The maintenance pass merges that catalogue (keeping
        the new CVE) but must not advance the CVE baseline over an entry it never resolved: the
        next normal run has to recover and deliver new-cve|psirt|CVE-2026-99999|high exactly
        once, while the pre-existing legitimate outbox event is preserved and delivered.
        """
        fixture = self._catalog_with_low_severity_false_positive()
        new_cve = "CVE-2026-99999"
        expected_key = f"new-cve|psirt|{new_cve}|high"
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            state_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            fw.write_json(state_path, fixture)
            self._enable_notifications(tmp)
            fn.ensure_checkpoint(history_path, {
                "versionsByProduct": {},
                "cvesById": full_cve_baseline(fixture),
                "health": {},
            })
            seeded = fn.load_notify_state(history_path)
            seeded["outbox"].append(_pending_event())
            fw.write_json(history_path, seeded)
            fw.fetch_text = self._make_transport()

            real_collect = fw.collect_cve_catalog
            real_catalog_commit = fw.commit_collected_state
            client = _mock_smtp_client()

            def commit_normal_then_die(*args, **kwargs):
                real_catalog_commit(*args, **kwargs)
                raise KeyboardInterrupt("normal collection died before notification")

            def collect_maintenance_with_concurrent_new_cve(*args, **kwargs):
                maintenance_results = real_collect(*args, **kwargs)
                # Meanwhile a normal run adds the new advisory and crashes after its commit.
                concurrent_transport = FakeTransport()
                concurrent_transport.add_advisory(
                    "FG-IR-26-999",
                    make_csaf_document("FG-IR-26-999", cve_ids=(new_cve,)),
                )
                with patch.object(fw, "collect_cve_catalog", real_collect), patch.object(
                    fw, "fetch_text", concurrent_transport
                ), patch.object(
                    fw, "discover_advisory_ids_from_rss", return_value=["FG-IR-26-999"]
                ), patch.object(
                    fw, "commit_collected_state", side_effect=commit_normal_then_die
                ), self.assertRaises(KeyboardInterrupt):
                    self._run(tmp, state_path, health_path, history_path, reconcile=False)
                crashed = fn.load_notify_state(history_path)
                self.assertNotIn(new_cve, crashed["checkpoint"]["cvesById"])
                self.assertIn(
                    new_cve, {item["id"] for item in fw.read_json(state_path, {})["cves"]}
                )
                return maintenance_results

            with patch.dict(os.environ, NOTIFY_ENV, clear=False), patch(
                "smtplib.SMTP", return_value=client
            ), patch(
                "socket.socket.connect",
                side_effect=AssertionError("external network forbidden"),
            ), patch(
                "socket.create_connection",
                side_effect=AssertionError("external network forbidden"),
            ):
                with patch.object(
                    fw,
                    "collect_cve_catalog",
                    side_effect=collect_maintenance_with_concurrent_new_cve,
                ):
                    self.assertEqual(
                        self._run(tmp, state_path, health_path, history_path, reconcile=True), 0
                    )

                after_maintenance = fn.load_notify_state(history_path)
                self.assertNotIn(
                    new_cve,
                    after_maintenance["checkpoint"]["cvesById"],
                    "the maintenance pass absorbed a concurrent novelty it never resolved",
                )
                self.assertEqual(
                    after_maintenance["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"],
                    "high",
                    "the pass's own corrections are still absorbed silently",
                )
                self.assertEqual(sorted(after_maintenance["sentKeys"]), [PENDING_EVENT_KEY])
                self.assertEqual(after_maintenance["outbox"], [])
                self.assertEqual(client.send_message.call_count, 1)

                # The next normal run still recovers the legitimate new CVE, exactly once.
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                resumed = fn.load_notify_state(history_path)
                self.assertIn(expected_key, resumed["sentKeys"])
                self.assertEqual(client.send_message.call_count, 2)
                self.assertIn(new_cve, resumed["checkpoint"]["cvesById"])
                self.assertEqual(resumed["outbox"], [])

                # Repeated resume: no duplicate email.
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                again = fn.load_notify_state(history_path)
                self.assertIn(expected_key, again["sentKeys"])
                self.assertEqual(client.send_message.call_count, 2)

    def test_stale_normal_committer_must_not_regress_the_notify_checkpoint(self) -> None:
        """B3 review, completing boundary — the final commit is conditioned on durable state.

        A (normal) commits its catalogue (still coarse), then B completes fully — corrections
        committed, intent consumed, baseline advanced to `high` — before A reaches its own final
        notification commit. A must not write its stale `low` baseline back over B's advance, or
        the next normal run would replay low->high with no durable intent left to stop it.
        """
        fixture = self._catalog_with_low_severity_false_positive()
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            state_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            fw.write_json(state_path, fixture)
            self._enable_notifications(tmp)
            fn.ensure_checkpoint(history_path, {
                "versionsByProduct": {},
                "cvesById": full_cve_baseline(fixture),
                "health": {},
            })
            fw.fetch_text = self._make_transport()

            real_collect = fw.collect_cve_catalog
            real_notify_commit = fn.commit_events_with_checkpoint
            client = _mock_smtp_client()

            def finish_maintenance_then_commit(*args, **kwargs):
                with patch.object(fw, "collect_cve_catalog", real_collect), patch.object(
                    fn, "commit_events_with_checkpoint", real_notify_commit
                ):
                    self.assertEqual(
                        self._run(tmp, state_path, health_path, history_path, reconcile=True), 0
                    )
                after_b = fn.load_notify_state(history_path)
                self.assertEqual(
                    after_b["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"], "high"
                )
                self.assertEqual(after_b["sentKeys"], {})
                return real_notify_commit(*args, **kwargs)

            with patch.dict(os.environ, NOTIFY_ENV, clear=False), patch(
                "smtplib.SMTP", return_value=client
            ), patch(
                "socket.socket.connect",
                side_effect=AssertionError("external network forbidden"),
            ), patch(
                "socket.create_connection",
                side_effect=AssertionError("external network forbidden"),
            ), patch.object(
                fn, "commit_events_with_checkpoint", side_effect=finish_maintenance_then_commit
            ):
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )

            after_a = fn.load_notify_state(history_path)
            self.assertEqual(
                after_a["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"],
                "high",
                "a completed maintenance advance must survive the stale final commit",
            )
            self.assertNotIn(fn.PENDING_CVE_BASELINE_KEY, after_a)
            self.assertEqual(client.send_message.call_count, 0)

            # A fresh normal run: catalogue and checkpoint already agree, nothing to replay.
            self.assertEqual(
                self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
            )
            resumed = fn.load_notify_state(history_path)
            self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, resumed["sentKeys"])
            self.assertEqual(client.send_message.call_count, 0)


class PendingCveBaselineMechanicsTests(unittest.TestCase):
    """Unit coverage of the durable-intent primitives: staging merge, severity-projected
    resolution, idempotent consumption, write-failure safety and the round-trip guarantees every
    other notify-state writer relies on."""

    def _state_with_checkpoint(self, cves: dict) -> dict:
        state = fn._empty_notify_state()
        state["checkpoint"] = {"versionsByProduct": {}, "cvesById": cves, "health": {}}
        return state

    def test_staging_write_failure_leaves_the_existing_state_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            path = Path(tmp_str) / "notify-history.json"
            fw.write_json(
                path,
                self._state_with_checkpoint(
                    {"CVE-OLD": {"id": "CVE-OLD", "severity": "high"}}
                ),
            )
            before = path.read_text(encoding="utf-8")
            with patch.object(
                fn, "write_json", side_effect=OSError("read-only file system")
            ), self.assertRaises(OSError):
                fn.stage_pending_cve_baseline(
                    path, {"CVE-NEW": {"id": "CVE-NEW", "severity": "high"}}
                )
            self.assertEqual(path.read_text(encoding="utf-8"), before)

    def test_staging_merges_over_a_leftover_intent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            path = Path(tmp_str) / "notify-history.json"
            fw.write_json(
                path,
                self._state_with_checkpoint(
                    {"CVE-A": {"id": "CVE-A", "severity": "high"}}
                ),
            )
            fn.stage_pending_cve_baseline(
                path, {"CVE-A": {"id": "CVE-A", "severity": "medium"}}
            )
            fn.stage_pending_cve_baseline(
                path,
                {
                    "CVE-A": {"id": "CVE-A", "severity": "low"},
                    "CVE-B": {"id": "CVE-B", "severity": "high"},
                },
            )
            pending = fn.load_notify_state(path)[fn.PENDING_CVE_BASELINE_KEY]
            self.assertEqual(sorted(pending), ["CVE-A", "CVE-B"])
            self.assertEqual(
                pending["CVE-A"]["severity"], "low", "fresher results win per CVE id"
            )

    def test_consume_is_idempotent_and_keeps_unconfirmed_entries_staged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            path = Path(tmp_str) / "notify-history.json"
            fw.write_json(
                path,
                self._state_with_checkpoint(
                    {"CVE-A": {"id": "CVE-A", "severity": "low"}}
                ),
            )
            fn.stage_pending_cve_baseline(
                path,
                {
                    "CVE-A": {"id": "CVE-A", "severity": "high"},
                    "CVE-B": {"id": "CVE-B", "severity": "high"},
                },
            )
            catalog_partial = {"CVE-A": {"id": "CVE-A", "severity": "high"}}
            applied, remaining = fn.consume_pending_cve_baseline(path, catalog_partial)
            self.assertEqual((applied, remaining), (1, 1))
            state = fn.load_notify_state(path)
            self.assertEqual(
                state["checkpoint"]["cvesById"]["CVE-A"]["severity"], "high"
            )
            self.assertEqual(sorted(state[fn.PENDING_CVE_BASELINE_KEY]), ["CVE-B"])

            # Idempotent: a second consumer on the same catalogue finds nothing new to apply.
            self.assertEqual(
                fn.consume_pending_cve_baseline(path, catalog_partial), (0, 1)
            )

            # The leftover correction lands later: it resolves then.
            applied, remaining = fn.consume_pending_cve_baseline(
                path,
                {
                    "CVE-A": {"id": "CVE-A", "severity": "high"},
                    "CVE-B": {"id": "CVE-B", "severity": "high"},
                },
            )
            self.assertEqual((applied, remaining), (1, 0))
            state = fn.load_notify_state(path)
            self.assertIn("CVE-B", state["checkpoint"]["cvesById"])
            self.assertNotIn(fn.PENDING_CVE_BASELINE_KEY, state)

    def test_unconfirmed_entries_are_never_advanced_into_the_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            path = Path(tmp_str) / "notify-history.json"
            fw.write_json(
                path,
                self._state_with_checkpoint(
                    {"CVE-A": {"id": "CVE-A", "severity": "high"}}
                ),
            )
            fn.stage_pending_cve_baseline(
                path,
                {
                    "CVE-A": {"id": "CVE-A", "severity": "medium"},
                    "CVE-MISSING": {"id": "CVE-MISSING", "severity": "high"},
                },
            )
            # The catalogue still carries the old HIGH entry (correction not committed) and has
            # no idea about CVE-MISSING: neither may be advanced into the baseline.
            applied, remaining = fn.consume_pending_cve_baseline(
                path, {"CVE-A": {"id": "CVE-A", "severity": "high"}}
            )
            self.assertEqual((applied, remaining), (0, 2))
            state = fn.load_notify_state(path)
            self.assertEqual(
                state["checkpoint"]["cvesById"]["CVE-A"]["severity"], "high"
            )
            self.assertEqual(sorted(state[fn.PENDING_CVE_BASELINE_KEY]), ["CVE-A", "CVE-MISSING"])

            # Once the catalogue actually reaches the corrected severity, it applies.
            applied, remaining = fn.consume_pending_cve_baseline(
                path,
                {
                    "CVE-A": {"id": "CVE-A", "severity": "medium"},
                    "CVE-MISSING": {"id": "CVE-MISSING", "severity": "high"},
                },
            )
            self.assertEqual((applied, remaining), (2, 0))
            state = fn.load_notify_state(path)
            self.assertNotIn(fn.PENDING_CVE_BASELINE_KEY, state)

    def test_malformed_pending_is_rejected_without_touching_the_file(self) -> None:
        for bad in ([], "nope", 42, {"CVE-A": "not-a-dict"}, {"": {"severity": "high"}}):
            with self.subTest(bad=repr(bad)), tempfile.TemporaryDirectory() as tmp_str:
                path = Path(tmp_str) / "notify-history.json"
                payload = self._state_with_checkpoint({})
                payload[fn.PENDING_CVE_BASELINE_KEY] = bad
                fw.write_json(path, payload)
                before = path.read_text(encoding="utf-8")
                with self.assertRaises(fn.NotifyStateError):
                    fn.load_notify_state(path)
                with self.assertRaises(fn.NotifyStateError):
                    fn.stage_pending_cve_baseline(
                        path, {"CVE-A": {"id": "CVE-A", "severity": "high"}}
                    )
                self.assertEqual(path.read_text(encoding="utf-8"), before)

    def test_states_without_the_key_round_trip_through_unrelated_writers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            path = Path(tmp_str) / "notify-history.json"
            fw.write_json(
                path,
                self._state_with_checkpoint(
                    {"CVE-A": {"id": "CVE-A", "severity": "high"}}
                ),
            )
            self.assertNotIn(fn.PENDING_CVE_BASELINE_KEY, fn.load_notify_state(path))
            # An unrelated writer (claim bookkeeping) must not invent the key...
            fn.enqueue_and_claim(path, [], claimant="run-1")
            raw = json.loads(path.read_text(encoding="utf-8"))
            self.assertNotIn(fn.PENDING_CVE_BASELINE_KEY, raw)
            # ... and once an intent is outstanding, must not drop it either.
            fn.stage_pending_cve_baseline(
                path, {"CVE-NEW": {"id": "CVE-NEW", "severity": "high"}}
            )
            fn.enqueue_and_claim(path, [], claimant="run-2")
            raw = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(raw[fn.PENDING_CVE_BASELINE_KEY]["CVE-NEW"]["severity"], "high")

    def test_commit_events_with_checkpoint_preserves_an_outstanding_intent_by_default(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            path = Path(tmp_str) / "notify-history.json"
            fw.write_json(
                path, self._state_with_checkpoint({"CVE-OLD": {"id": "CVE-OLD", "severity": "high"}})
            )
            fn.stage_pending_cve_baseline(
                path, {"CVE-X": {"id": "CVE-X", "severity": "high"}}
            )
            checkpoint = {"versionsByProduct": {}, "cvesById": {}, "health": {}}
            # Default (sentinel): an unrelated committer leaves the staged intent alone.
            fn.commit_events_with_checkpoint(path, checkpoint, [], claimant="c1")
            self.assertIn("CVE-X", fn.load_notify_state(path)[fn.PENDING_CVE_BASELINE_KEY])
            # Bare None certifies no observation: it resolves nothing and never wipes the key.
            fn.commit_events_with_checkpoint(
                path, checkpoint, [], claimant="c1b", pending_cve_baseline=None
            )
            self.assertIn("CVE-X", fn.load_notify_state(path)[fn.PENDING_CVE_BASELINE_KEY])
            # Certified resolution: the entry the catalogue-derived caller observed and resolved
            # is retired by the same atomic write that advances the checkpoint.
            fn.commit_events_with_checkpoint(
                path,
                checkpoint,
                [],
                claimant="c2",
                pending_cve_baseline=fn.PendingCveBaselineResolution(
                    observed={"CVE-X": {"id": "CVE-X", "severity": "high"}},
                    remaining=None,
                ),
            )
            self.assertNotIn(fn.PENDING_CVE_BASELINE_KEY, fn.load_notify_state(path))
            # An intent the caller never observed is never dropped: the resolution above only
            # touches the ids it certifies.
            fn.stage_pending_cve_baseline(
                path, {"CVE-W": {"id": "CVE-W", "severity": "medium"}}
            )
            fn.commit_events_with_checkpoint(
                path,
                checkpoint,
                [],
                claimant="c2b",
                pending_cve_baseline=fn.PendingCveBaselineResolution(
                    observed={"CVE-X": {"id": "CVE-X", "severity": "high"}},
                    remaining=None,
                ),
            )
            self.assertEqual(
                sorted(fn.load_notify_state(path)[fn.PENDING_CVE_BASELINE_KEY]), ["CVE-W"]
            )
            # A value re-staged after the observation is never removed by that older resolution.
            fn.stage_pending_cve_baseline(path, {"CVE-W": {"id": "CVE-W", "severity": "high"}})
            fn.commit_events_with_checkpoint(
                path,
                checkpoint,
                [],
                claimant="c2c",
                pending_cve_baseline=fn.PendingCveBaselineResolution(
                    observed={"CVE-W": {"id": "CVE-W", "severity": "medium"}},
                    remaining=None,
                ),
            )
            pending = fn.load_notify_state(path)[fn.PENDING_CVE_BASELINE_KEY]
            self.assertEqual(pending["CVE-W"]["severity"], "high")
            # Explicit remaining: the still-unconfirmed entries are persisted by that same write.
            fn.commit_events_with_checkpoint(
                path,
                checkpoint,
                [],
                claimant="c3",
                pending_cve_baseline={"CVE-Z": {"id": "CVE-Z", "severity": "medium"}},
            )
            pending = fn.load_notify_state(path)[fn.PENDING_CVE_BASELINE_KEY]
            self.assertEqual(sorted(pending), ["CVE-W", "CVE-Z"])


if __name__ == "__main__":
    unittest.main()
