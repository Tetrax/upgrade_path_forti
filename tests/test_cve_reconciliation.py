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
import subprocess
import sys
import tempfile
import time
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


# --------------------------------------------------------------------------------------------
# Interprocess coordination probes: a REAL maintenance pipeline run as its own OS process,
# while this process holds the notification observation section of another real pipeline run.
# --------------------------------------------------------------------------------------------

# Bounded waits used by the interprocess tests. The "inside" delay gives the separate process a
# real chance to finish its advance while the observation section is held: a correct
# implementation keeps its checkpoint work blocked on the history lock for the whole window, so
# nothing timing-sensitive is being asserted -- only that the writer did NOT get through.
B_ATTEMPT_TIMEOUT_SECONDS = 15.0
B_INSIDE_DELAY_SECONDS = 2.0
B_PROCESS_TIMEOUT_SECONDS = 30.0


def _wait_for_marker(path: Path, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(0.02)
    return False


# The real `fortios_watch.main` maintenance pipeline (`--cve-catalog --cve-reconcile-existing`),
# run as a genuinely separate OS process against the shared scratch directory. Started by the
# parent test while that process holds the notification observation section; coordinates through
# marker files, then reports its outcome as JSON. Frozen public fixtures only, inert PSIRT
# transport, mocked SMTP, external network forbidden, no repository write. exec-based spawn
# (subprocess), so no open lock descriptor is ever inherited: the child takes its own flock on
# the notification history like any other writer.
INTERPROCESS_MAINTENANCE_RUNNER = r'''"""Real maintenance pipeline, as its own OS process, for the interprocess coordination tests."""
import json
import os
import sys
import time
import traceback
import urllib.error
from pathlib import Path
from unittest.mock import patch

repo_root = Path(sys.argv[1]).resolve()
scratch = Path(sys.argv[2]).resolve()
sys.path.insert(0, str(repo_root / "scripts"))
sys.path.insert(0, str(repo_root / "tests"))

import fortios_notify as fn  # noqa: E402
import fortios_watch as fw  # noqa: E402
import test_cve_reconciliation as fixture  # noqa: E402


def wait_for_marker(path, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(0.02)
    return False


def main():
    state_path = scratch / "state.json"
    health_path = scratch / "health.json"
    history_path = scratch / "notify-history.json"

    if not wait_for_marker(scratch / "a-in-observation", 15.0):
        return 2
    (scratch / "b-attempting").write_text("1", encoding="utf-8")

    transport = fixture.FakeTransport()
    transport.add_advisory(
        "FG-IR-26-174",
        json.loads(
            (fixture.FIXTURES / "FG-IR-26-174.csaf.json").read_text(encoding="utf-8")
        ),
        page=(fixture.FIXTURES / "FG-IR-26-174.advisory.html").read_text(
            encoding="utf-8"
        ),
        csaf_url=fixture.FG_IR_26_174_CSAF_URL,
    )
    transport.default_error = urllib.error.URLError("not served in this test")
    fw.fetch_text = transport
    fw.fetch_psirt_versions = lambda timeout: set()
    fw.fetch_fortios_lifecycle = lambda timeout: {}
    fw.discover_advisory_ids_from_rss = lambda timeout: []
    fw.time.sleep = lambda seconds: None

    client = fixture._mock_smtp_client()
    arguments = [
        "--cve-catalog",
        "--cve-reconcile-existing",
        "--base", str(state_path),
        "--output", str(state_path),
        "--report", str(scratch / "report-maintenance.md"),
        "--health-output", str(health_path),
        "--official-paths-csv", str(scratch / "no-official-paths-b.csv"),
        "--advisories-csv", str(scratch / "no-advisories-b.csv"),
        "--upgrade-exports", str(scratch / "no-upgrade-exports-b"),
        "--notify-history-output", str(history_path),
        "--notification-settings-output", str(scratch / "notification-settings.json"),
        "--cve-retry-delays-seconds", "",
        "--timeout", "5",
    ]
    with patch.dict(os.environ, fixture.NOTIFY_ENV, clear=False), patch(
        "smtplib.SMTP", return_value=client
    ), patch(
        "socket.socket.connect", side_effect=AssertionError("external network forbidden")
    ), patch(
        "socket.create_connection", side_effect=AssertionError("external network forbidden")
    ):
        exit_code = fw.main(arguments)

    state = fn.load_notify_state(history_path)
    checkpoint_cves = (state.get("checkpoint") or {}).get("cvesById") or {}
    (scratch / "b-done.json").write_text(
        json.dumps(
            {
                "exit": exit_code,
                "smtp_calls": client.send_message.call_count,
                "sent_keys": sorted(state["sentKeys"]),
                "outbox": [entry["dedupKey"] for entry in state["outbox"]],
                "pending": sorted(state.get(fn.PENDING_CVE_BASELINE_KEY) or {}),
                "severity_84393": (
                    checkpoint_cves.get("CVE-2026-84393") or {}
                ).get("severity"),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    try:
        runner_code = main()
    except BaseException:
        (scratch / "b-error").write_text(traceback.format_exc(), encoding="utf-8")
        raise SystemExit(3)
    raise SystemExit(runner_code)
'''


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
    (sentKeys/outbox untouched, checkpoint advanced with the corrected entry). The six
    concurrency tests at the end pin the cross-run coordination boundary: durable notify state
    always wins over an in-flight run's stale capture — an unobserved intent is never erased, a
    consumed baseline stays opposable to a collection already started, a completed advance is
    never regressed by an older catalogue image, the pass never absorbs a concurrent novelty it
    did not resolve, and events pre-derived from a stale capture are revalidated against the
    fresh durable state before any of them can enter the outbox. Two more review-367 regressions
    pin the remaining boundaries: a durable intent staged AFTER a run's observation still governs
    that run's commit (the catalogue-confirmed correction it describes never reaches the outbox),
    and a structurally invalid catalogue suspends the notification work — history untouched,
    cleaned diagnostic — instead of silently emptying a baseline."""

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

    def _spawn_interprocess_maintenance(self, tmp: Path) -> subprocess.Popen:
        """Start the real maintenance pipeline as a genuinely separate OS process.

        The runner is written to the test's own scratch directory and exec'd, so no open lock
        descriptor is inherited from this process: the child has to take its own flock on the
        notification history exactly like any other writer in production.
        """
        runner_path = tmp / "interprocess_maintenance_runner.py"
        runner_path.write_text(INTERPROCESS_MAINTENANCE_RUNNER, encoding="utf-8")
        repo_root = Path(fw.__file__).resolve().parents[1]
        return subprocess.Popen(
            [sys.executable, str(runner_path), str(repo_root), str(tmp)],
            cwd=str(repo_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _join_interprocess_maintenance(
        self, process: subprocess.Popen
    ) -> tuple[int, str, str]:
        """Wait for the separate maintenance runner, failing cleanly on hang or error."""
        try:
            stdout, stderr = process.communicate(timeout=B_PROCESS_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            self.fail(
                "the maintenance process never completed (deadlock?)\n"
                f"stdout:\n{stdout}\nstderr:\n{stderr}"
            )
        if process.returncode != 0:
            self.fail(
                f"the maintenance process failed (rc={process.returncode})\n"
                f"stdout:\n{stdout}\nstderr:\n{stderr}"
            )
        return process.returncode, stdout, stderr

    def _run_with_concurrent_maintenance_attempt(
        self,
        tmp: Path,
        state_path: Path,
        health_path: Path,
        history_path: Path,
    ) -> dict:
        """Run a real pipeline here, with a REAL maintenance process attempting its whole pass
        between the two reads of the notification observation.

        `fw.read_json` is instrumented: the first catalogue read after the notification block
        starts is the observation's catalogue read, so the moment it completes, a separate
        maintenance pipeline process is started and given a bounded window to finish its
        advance before this run reads the notify state. Under the lock-based observation the
        catalogue read happens with the history lock held, so the writer cannot get through
        during that window; before it, nothing stops it. Returns {process, completed_inside}.
        """
        real_config = fn.load_email_config
        real_read = fw.read_json
        armed = {"value": False}
        observation: dict = {}

        def arm_at_notification_block(*args, **kwargs):
            result = real_config(*args, **kwargs)
            armed["value"] = True
            return result

        def attempt_between_the_reads(path, default):
            result = real_read(path, default)
            if armed["value"] and path == state_path:
                armed["value"] = False
                (tmp / "a-in-observation").write_text("1", encoding="utf-8")
                observation["process"] = self._spawn_interprocess_maintenance(tmp)
                self.assertTrue(
                    _wait_for_marker(
                        tmp / "b-attempting", B_ATTEMPT_TIMEOUT_SECONDS
                    ),
                    "the maintenance process never signalled its attempt",
                )
                observation["completed_inside"] = _wait_for_marker(
                    tmp / "b-done.json", B_INSIDE_DELAY_SECONDS
                )
            return result

        with patch.object(
            fn, "load_email_config", side_effect=arm_at_notification_block
        ), patch.object(fw, "read_json", side_effect=attempt_between_the_reads):
            self.assertEqual(
                self._run(
                    tmp, state_path, health_path, history_path, reconcile=False
                ),
                0,
            )
        self.assertFalse(
            armed["value"], "the notification-block catalogue read was never observed"
        )
        return observation

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

    def test_completed_maintenance_between_catalog_and_fresh_checkpoint(self) -> None:
        """B3 review, remaining window 1 — the catalogue result and the baseline are one
        coordinated observation.

        A (normal, no advisory result of its own) commits its old catalogue first; B then
        completes a full maintenance pass — corrected catalogue, baseline advanced to `high`,
        intent consumed, zero SMTP — BEFORE A's notification block reads the fresh checkpoint.
        A must not write its stale `low` catalogue image back as the new baseline over B's
        already certified advance: an older catalogue image can never regress a freshly consumed
        correction, so both normal resumes stay silent with no historical replay.
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

            real_config = fn.load_email_config
            client = _mock_smtp_client()
            interposed = []

            def finish_b_before_a_reads_fresh_checkpoint(*args, **kwargs):
                interposed.append(True)
                # A has already committed its old catalogue, with no advisory result of its
                # own; B now completes through the REAL pipeline before A's fresh state read.
                with patch.object(fn, "load_email_config", real_config):
                    self.assertEqual(
                        self._run(tmp, state_path, health_path, history_path, reconcile=True), 0
                    )
                finished = fn.load_notify_state(history_path)
                self.assertEqual(
                    finished["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"],
                    "high",
                    "a complete maintenance pass absorbs its correction silently",
                )
                self.assertNotIn(fn.PENDING_CVE_BASELINE_KEY, finished)
                self.assertEqual(client.send_message.call_count, 0)
                return real_config(*args, **kwargs)

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
                    fn,
                    "load_email_config",
                    side_effect=finish_b_before_a_reads_fresh_checkpoint,
                ):
                    self.assertEqual(
                        self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                    )
                after_a = fn.load_notify_state(history_path)
                self.assertEqual(len(interposed), 1)
                self.assertEqual(
                    after_a["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"],
                    "high",
                    "an older catalogue image must never regress a freshly certified baseline",
                )

                # Both normal resumes stay silent: nothing was left to replay.
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                resumed = fn.load_notify_state(history_path)
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                repeated = fn.load_notify_state(history_path)

            self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, resumed["sentKeys"])
            self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, repeated["sentKeys"])
            self.assertEqual(client.send_message.call_count, 0)

    def test_events_derived_before_maintenance_are_revalidated_at_commit(self) -> None:
        """B3 review, remaining window 2 — the fresh durable state governs event validity at
        commit too.

        A (normal) refetches the corrected advisory, commits the `high` catalogue and derives the
        low->high transition from its baseline `low`. Just before A's commit actually runs, B
        completes the full maintenance pass silently (correction consumed, baseline `high`,
        nothing queued, zero SMTP). A's checkpoint write is already conditioned on the fresh
        durable state; its pre-derived event must be revalidated the same way — enqueuing it
        would email a correction that is already durably absorbed.
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

            real_commit = fn.commit_events_with_checkpoint
            client = _mock_smtp_client()
            derived = []

            def finish_b_before_a_commits(*args, **kwargs):
                derived.extend(event.dedup_key for event in args[2])
                self.assertIn(
                    CVE_ESCALATION_REPLAY_KEY,
                    derived,
                    "canary: A has derived the historical correction before its commit",
                )
                # B completes entirely before A's commit actually runs.
                with patch.object(fn, "commit_events_with_checkpoint", real_commit):
                    self.assertEqual(
                        self._run(tmp, state_path, health_path, history_path, reconcile=True), 0
                    )
                finished = fn.load_notify_state(history_path)
                self.assertEqual(
                    finished["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"], "high"
                )
                self.assertEqual(finished["outbox"], [])
                self.assertNotIn(fn.PENDING_CVE_BASELINE_KEY, finished)
                self.assertEqual(client.send_message.call_count, 0)
                return real_commit(*args, **kwargs)

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
                    fw, "discover_advisory_ids_from_rss", return_value=["FG-IR-26-174"]
                ), patch.object(
                    fn, "commit_events_with_checkpoint", side_effect=finish_b_before_a_commits
                ):
                    self.assertEqual(
                        self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                    )
                after_a = fn.load_notify_state(history_path)
                self.assertEqual(client.send_message.call_count, 0)
                self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, after_a["sentKeys"])

                # Two normal resumes: neither replays nor duplicates the consumed correction.
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                resumed = fn.load_notify_state(history_path)
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                repeated = fn.load_notify_state(history_path)

            self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, resumed["sentKeys"])
            self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, repeated["sentKeys"])
            self.assertEqual(client.send_message.call_count, 0)

    def test_concurrent_maintenance_cannot_advance_inside_the_notification_observation(
        self,
    ) -> None:
        """Final reliability pass — the catalogue result and the notify state are ONE
        observation, and that observation excludes concurrent writers.

        A real normal pipeline run (this process, real `main()`) reaches its notification
        observation section; while the section is held, the real maintenance pipeline runs as
        a separate OS process and attempts its whole pass between the observation's two reads.
        It must NOT be able to complete its advance inside the window (its checkpoint work is
        blocked on the very lock the observation holds); once the observation is released it
        completes silently — corrected catalogue, baseline `high`, no intent left, zero SMTP.
        Neither run regresses the other: the following normal resumes replay no historical
        low->high correction and send nothing.
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
            client = _mock_smtp_client()

            with patch.dict(os.environ, NOTIFY_ENV, clear=False), patch(
                "smtplib.SMTP", return_value=client
            ), patch(
                "socket.socket.connect",
                side_effect=AssertionError("external network forbidden"),
            ), patch(
                "socket.create_connection",
                side_effect=AssertionError("external network forbidden"),
            ):
                observation = self._run_with_concurrent_maintenance_attempt(
                    tmp, state_path, health_path, history_path
                )
                self._join_interprocess_maintenance(observation["process"])
                self.assertFalse(
                    observation["completed_inside"],
                    "a separate maintenance process completed its advance while the "
                    "notification observation was held",
                )

                # B completed silently once the observation was released.
                result = json.loads((tmp / "b-done.json").read_text(encoding="utf-8"))
                self.assertEqual(result["exit"], 0)
                self.assertEqual(result["smtp_calls"], 0)
                self.assertEqual(result["sent_keys"], [])
                self.assertEqual(result["outbox"], [])
                self.assertEqual(result["pending"], [])
                self.assertEqual(result["severity_84393"], "high")

                after_a = fn.load_notify_state(history_path)
                self.assertEqual(
                    after_a["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"],
                    "high",
                    "an in-flight catalogue image must never regress a certified advance",
                )
                self.assertEqual(after_a["outbox"], [])
                self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, after_a["sentKeys"])

                # Two normal resumes: neither replays the consumed historical correction.
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                resumed = fn.load_notify_state(history_path)
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                repeated = fn.load_notify_state(history_path)

            self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, resumed["sentKeys"])
            self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, repeated["sentKeys"])
            self.assertEqual(client.send_message.call_count, 0)
            self.assertEqual(
                repeated["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"], "high"
            )

    def test_disabled_run_cannot_regress_a_concurrent_advance_before_reactivation(
        self,
    ) -> None:
        """Final reliability pass — the disabled path writes conditioned on its observation.

        Every notification category is disabled, so the pipeline advances its baselines
        silently. While this run's observation section is held, the real maintenance pipeline
        (separate OS process) attempts its pass and completes only after the release. The
        disabled-state write must not push the stale catalogue image it observed back over the
        certified `high` advance — reactivating notifications then derives nothing and replays
        no historical correction.
        """
        fixture = self._catalog_with_low_severity_false_positive()
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            state_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            fw.write_json(state_path, fixture)
            disabled_payload = fn._default_notification_settings_payload()
            disabled_payload["recipients"] = ["ops@example.com"]
            fn.save_notification_settings(tmp / "notification-settings.json", disabled_payload)
            fn.ensure_checkpoint(history_path, {
                "versionsByProduct": {},
                "cvesById": full_cve_baseline(fixture),
                "health": {},
            })
            fw.fetch_text = self._make_transport()
            client = _mock_smtp_client()

            with patch.dict(os.environ, NOTIFY_ENV, clear=False), patch(
                "smtplib.SMTP", return_value=client
            ), patch(
                "socket.socket.connect",
                side_effect=AssertionError("external network forbidden"),
            ), patch(
                "socket.create_connection",
                side_effect=AssertionError("external network forbidden"),
            ):
                observation = self._run_with_concurrent_maintenance_attempt(
                    tmp, state_path, health_path, history_path
                )
                self._join_interprocess_maintenance(observation["process"])
                self.assertFalse(
                    observation["completed_inside"],
                    "a separate maintenance process completed its advance while the "
                    "notification observation was held",
                )

                after_a = fn.load_notify_state(history_path)
                self.assertEqual(
                    after_a["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"],
                    "high",
                    "a disabled run must not regress a concurrent certified advance",
                )
                self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, after_a["sentKeys"])
                self.assertEqual(client.send_message.call_count, 0)

                # Reactivation: the baseline already carries the correction, nothing to
                # derive, nothing to send, nothing to replay.
                self._enable_notifications(tmp)
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                resumed = fn.load_notify_state(history_path)
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                repeated = fn.load_notify_state(history_path)

            self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, resumed["sentKeys"])
            self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, repeated["sentKeys"])
            self.assertNotIn(fn.PENDING_CVE_BASELINE_KEY, repeated)
            self.assertEqual(client.send_message.call_count, 0)
            self.assertEqual(
                repeated["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"], "high"
            )

    def test_absent_durable_catalogue_suspends_notifications_without_resetting_state(
        self,
    ) -> None:
        """Final reliability pass — no silent fallback to this run's own stale `final_state`.

        The durable catalogue is externally removed at the exact moment the notification
        observation tries to read it. The notification work must be suspended with a cleaned
        diagnostic and the history kept byte-for-byte, never derived from the run's older
        in-flight image — which would notify the new CVE and advance the checkpoint from data
        the durable files do not back. The next run re-observes from scratch and delivers the
        novelty exactly once.
        """
        fixture = json.loads(LIVE_CATALOG_COPY.read_text(encoding="utf-8"))
        expected_key = "new-cve|psirt|CVE-2026-99999|high"
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
            transport = FakeTransport()
            transport.add_advisory(
                "FG-IR-26-999",
                make_csaf_document("FG-IR-26-999", cve_ids=("CVE-2026-99999",)),
            )
            transport.default_error = urllib.error.URLError("not served in this test")
            fw.fetch_text = transport
            before_bytes = history_path.read_bytes()

            real_config = fn.load_email_config
            real_read = fw.read_json
            removed_aside = tmp / "state.json.externally-removed"
            armed = {"value": False}
            interposed = {"count": 0}

            def arm_at_notification_block(*args, **kwargs):
                result = real_config(*args, **kwargs)
                if interposed["count"] == 0:
                    armed["value"] = True
                return result

            def absent_during_the_observation(path, default):
                if armed["value"] and path == state_path:
                    armed["value"] = False
                    interposed["count"] += 1
                    state_path.rename(removed_aside)
                    try:
                        return real_read(path, default)
                    finally:
                        removed_aside.rename(state_path)
                return real_read(path, default)

            client = _mock_smtp_client()
            stderr = io.StringIO()
            with patch.dict(os.environ, NOTIFY_ENV, clear=False), patch(
                "smtplib.SMTP", return_value=client
            ), patch(
                "socket.socket.connect",
                side_effect=AssertionError("external network forbidden"),
            ), patch(
                "socket.create_connection",
                side_effect=AssertionError("external network forbidden"),
            ), patch.object(
                fw, "discover_advisory_ids_from_rss", return_value=["FG-IR-26-999"]
            ), patch.object(
                fn, "load_email_config", side_effect=arm_at_notification_block
            ), patch.object(
                fw, "read_json", side_effect=absent_during_the_observation
            ):
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(
                        self._run(tmp, state_path, health_path, history_path, reconcile=False),
                        0,
                    )

                self.assertFalse(armed["value"])
                self.assertIn("notification email non envoyée", stderr.getvalue())
                # Suspended, not approximated: the history is byte-for-byte untouched and the
                # checkpoint does not absorb the novelty from an image nothing durable backs.
                self.assertEqual(history_path.read_bytes(), before_bytes)
                suspended = fn.load_notify_state(history_path)
                self.assertNotIn("CVE-2026-99999", suspended["checkpoint"]["cvesById"])
                self.assertEqual(suspended["sentKeys"], {})
                self.assertEqual(client.send_message.call_count, 0)
                catalog_cves = json.loads(state_path.read_text(encoding="utf-8"))["cves"]
                self.assertIn(
                    "CVE-2026-99999", {item["id"] for item in catalog_cves}
                )

                # The next run (durable catalogue present again) re-observes from scratch and
                # recovers the novelty exactly once.
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                recovered = fn.load_notify_state(history_path)
                self.assertIn(expected_key, recovered["sentKeys"])
                self.assertEqual(client.send_message.call_count, 1)
                self.assertIn("CVE-2026-99999", recovered["checkpoint"]["cvesById"])

                # Repeated resume: no duplicate email.
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                repeated = fn.load_notify_state(history_path)

            self.assertIn(expected_key, repeated["sentKeys"])
            self.assertEqual(client.send_message.call_count, 1)

    def _make_late_intent_interposer(
        self,
        tmp: Path,
        state_path: Path,
        health_path: Path,
        history_path: Path,
        client: MagicMock,
    ):
        """Side effect for fn.commit_events_with_checkpoint: before A's commit actually runs,
        B (the REAL maintenance pipeline) stages its durable intent, commits the corrected
        catalogue and dies right after that catalogue commit, before consuming the intent.

        A holds no history lock here (the interposed commit has not taken it yet), so B's
        real pass completes its staging and catalogue write; the SystemExit reproduces the
        interruption window. The returned list records whether the interposition fired.
        """
        real_notify_commit = fn.commit_events_with_checkpoint
        real_catalog_commit = fw.commit_collected_state
        interposed: list[bool] = []

        def interrupt_b_after_catalog(*args, **kwargs):
            real_catalog_commit(*args, **kwargs)
            raise SystemExit("simulated B interruption before consuming its durable intent")

        def b_runs_before_a_commits(*args, **kwargs):
            interposed.append(True)
            with patch.object(
                fn, "commit_events_with_checkpoint", real_notify_commit
            ), patch.object(
                fw, "commit_collected_state", side_effect=interrupt_b_after_catalog
            ), self.assertRaises(SystemExit):
                self._run(tmp, state_path, health_path, history_path, reconcile=True)
            staged = fn.load_notify_state(history_path)
            self.assertEqual(
                staged["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"],
                "low",
                "sanity: B dies before its own baseline advance",
            )
            self.assertEqual(
                staged[fn.PENDING_CVE_BASELINE_KEY]["CVE-2026-84393"]["severity"], "high"
            )
            durable_cve = next(
                item
                for item in fw.read_json(state_path, {})["cves"]
                if item["id"] == "CVE-2026-84393"
            )
            self.assertEqual(durable_cve["severity"], "high")
            self.assertEqual(client.send_message.call_count, 0)
            return real_notify_commit(*args, **kwargs)

        return b_runs_before_a_commits, interposed

    def test_late_durable_intent_silences_the_correction_it_describes(self) -> None:
        """Review 367 BLOCKING 1 — an intent staged after a run's observation still governs
        that run's commit.

        A (normal collection) refetches the corrected advisory, commits the `high` catalogue
        and derives the low->high transition while the durable state still carries no intent.
        Before A's final commit actually runs, B (the real maintenance pipeline) stages its
        durable intent, writes the corrected catalogue and is interrupted right after that
        catalogue commit, before consuming the intent. A's commit must treat the freshly
        durable, catalogue-confirmed intent as opposable: the historical correction it
        describes is dropped before it can enter the outbox — zero SMTP at the commit and
        across two normal resumes — while the intent itself is preserved (A never observed
        it) and retired by the first later run that actually observes and resolves it.
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
            client = _mock_smtp_client()
            interposer, interposed = self._make_late_intent_interposer(
                tmp, state_path, health_path, history_path, client
            )

            def interposer_with_canary(*args, **kwargs):
                self.assertIn(
                    CVE_ESCALATION_REPLAY_KEY,
                    [event.dedup_key for event in args[2]],
                    "canary: A derived the historical correction before its commit",
                )
                self.assertIsNone(kwargs["pending_cve_baseline"].observed)
                return interposer(*args, **kwargs)

            with patch.dict(os.environ, NOTIFY_ENV, clear=True), patch(
                "smtplib.SMTP", return_value=client
            ), patch(
                "socket.socket.connect",
                side_effect=AssertionError("external network forbidden"),
            ), patch(
                "socket.create_connection",
                side_effect=AssertionError("external network forbidden"),
            ), patch.object(
                fw, "discover_advisory_ids_from_rss", return_value=["FG-IR-26-174"]
            ), patch.object(
                fn, "commit_events_with_checkpoint", side_effect=interposer_with_canary
            ):
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )

                after_a = fn.load_notify_state(history_path)
                self.assertEqual(len(interposed), 1)
                self.assertEqual(
                    client.send_message.call_count,
                    0,
                    "a catalogue-confirmed late intent must silence the correction it describes",
                )
                self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, after_a["sentKeys"])
                self.assertEqual(
                    after_a["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"], "high"
                )
                self.assertIn(
                    "CVE-2026-84393",
                    after_a.get(fn.PENDING_CVE_BASELINE_KEY) or {},
                    "A never observed the late intent: its commit must not erase it",
                )

                # Two normal resumes: the first observes and resolves the surviving intent
                # silently, the second has nothing left to do. Neither replays anything.
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                resumed = fn.load_notify_state(history_path)

            self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, resumed["sentKeys"])
            self.assertNotIn(fn.PENDING_CVE_BASELINE_KEY, resumed)
            self.assertEqual(client.send_message.call_count, 0)

    def test_late_intent_does_not_silence_a_genuine_novelty(self) -> None:
        """Review 367, positive control — the late-intent neutralization is scoped.

        Same interleaving as the BLOCKING 1 regression, but the catalogue also carries a
        genuinely new High CVE (CVE-2026-99999) the checkpoint baseline has never seen. The
        catalogue-confirmed late intent for CVE-2026-84393 must silence only the correction
        it describes: the novelty is still notified exactly once — at A's commit — and never
        replayed or duplicated by the two following normal resumes.
        """
        fixture = self._catalog_with_low_severity_false_positive()
        novelty = {
            "id": "CVE-2026-99999",
            "advisoryId": "FG-IR-26-999",
            "title": "Synthetic novelty for the late-intent positive controls",
            "severity": "high",
            "cvssScore": 7.5,
            "url": "https://fortiguard.fortinet.com/psirt/FG-IR-26-999",
            "publishedAt": "2026-10-05",
            "updatedAt": "2026-10-05",
            "affected": [
                {
                    "product": "fortigate-fortios",
                    "models": [],
                    "branch": "7.6",
                    "from": None,
                    "to": None,
                }
            ],
        }
        expected_key = f"new-cve|psirt|{novelty['id']}|high"
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            state_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            baseline = full_cve_baseline(fixture)
            self.assertNotIn(novelty["id"], baseline)
            fixture["cves"].append(novelty)
            fw.write_json(state_path, fixture)
            self._enable_notifications(tmp)
            fn.ensure_checkpoint(history_path, {
                "versionsByProduct": {},
                "cvesById": baseline,
                "health": {},
            })
            fw.fetch_text = self._make_transport()
            client = _mock_smtp_client()
            interposer, interposed = self._make_late_intent_interposer(
                tmp, state_path, health_path, history_path, client
            )

            with patch.dict(os.environ, NOTIFY_ENV, clear=True), patch(
                "smtplib.SMTP", return_value=client
            ), patch(
                "socket.socket.connect",
                side_effect=AssertionError("external network forbidden"),
            ), patch(
                "socket.create_connection",
                side_effect=AssertionError("external network forbidden"),
            ), patch.object(
                fw, "discover_advisory_ids_from_rss", return_value=["FG-IR-26-174"]
            ), patch.object(
                fn, "commit_events_with_checkpoint", side_effect=interposer
            ):
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )

                after_a = fn.load_notify_state(history_path)
                self.assertEqual(len(interposed), 1)
                self.assertEqual(
                    client.send_message.call_count,
                    1,
                    "the genuine novelty must still be delivered",
                )
                self.assertIn(expected_key, after_a["sentKeys"])
                self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, after_a["sentKeys"])
                self.assertIn(novelty["id"], after_a["checkpoint"]["cvesById"])

                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                resumed = fn.load_notify_state(history_path)

            self.assertEqual(
                client.send_message.call_count, 1, "no replay and no duplicate on resumes"
            )
            self.assertIn(expected_key, resumed["sentKeys"])
            self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, resumed["sentKeys"])
            self.assertNotIn(fn.PENDING_CVE_BASELINE_KEY, resumed)

    def test_late_intent_does_not_silence_a_distinct_escalation(self) -> None:
        """Review 367, positive control — an escalation distinct from the intent still fires.

        Same interleaving, but the checkpoint baseline lags another CVE's real escalation
        (CVE-2026-22153 medium -> high) while the late intent only covers the
        CVE-2026-84393 low->high correction. The confirmed intent must neutralize only its
        own correction: the distinct escalation is delivered exactly once, never replayed,
        and the surviving intent is retired silently by the next run.
        """
        fixture = self._catalog_with_low_severity_false_positive()
        escalated_id = "CVE-2026-22153"
        expected_key = f"cve-severity|psirt|{escalated_id}|medium-to-high"
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            state_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            baseline = full_cve_baseline(fixture)
            escalated = baseline[escalated_id]
            self.assertEqual(escalated["severity"], "high")
            baseline[escalated_id] = dict(escalated, severity="medium")
            fw.write_json(state_path, fixture)
            self._enable_notifications(tmp)
            fn.ensure_checkpoint(history_path, {
                "versionsByProduct": {},
                "cvesById": baseline,
                "health": {},
            })
            fw.fetch_text = self._make_transport()
            client = _mock_smtp_client()
            interposer, interposed = self._make_late_intent_interposer(
                tmp, state_path, health_path, history_path, client
            )

            with patch.dict(os.environ, NOTIFY_ENV, clear=True), patch(
                "smtplib.SMTP", return_value=client
            ), patch(
                "socket.socket.connect",
                side_effect=AssertionError("external network forbidden"),
            ), patch(
                "socket.create_connection",
                side_effect=AssertionError("external network forbidden"),
            ), patch.object(
                fw, "discover_advisory_ids_from_rss", return_value=["FG-IR-26-174"]
            ), patch.object(
                fn, "commit_events_with_checkpoint", side_effect=interposer
            ):
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )

                after_a = fn.load_notify_state(history_path)
                self.assertEqual(len(interposed), 1)
                self.assertEqual(
                    client.send_message.call_count,
                    1,
                    "the escalation distinct from the intent must still be delivered",
                )
                self.assertIn(expected_key, after_a["sentKeys"])
                self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, after_a["sentKeys"])
                self.assertEqual(
                    after_a["checkpoint"]["cvesById"][escalated_id]["severity"], "high"
                )

                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                resumed = fn.load_notify_state(history_path)

            self.assertEqual(client.send_message.call_count, 1)
            self.assertIn(expected_key, resumed["sentKeys"])
            self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, resumed["sentKeys"])
            self.assertNotIn(fn.PENDING_CVE_BASELINE_KEY, resumed)

    def test_late_intent_with_disabled_notifications_stays_silent_across_reactivation(
        self,
    ) -> None:
        """Review 367 — the disabled path is verified too: a late intent never becomes a replay.

        Same interleaving with every notification category disabled: A's disabled commit
        advances the silent baselines while B's late intent stays staged; reactivating
        notifications resolves it silently — no historical send at any point, and no intent
        erased by a commit that never observed it.
        """
        fixture = self._catalog_with_low_severity_false_positive()
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            state_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            fw.write_json(state_path, fixture)
            disabled_payload = fn._default_notification_settings_payload()
            disabled_payload["recipients"] = ["ops@example.com"]
            fn.save_notification_settings(
                tmp / "notification-settings.json", disabled_payload
            )
            fn.ensure_checkpoint(history_path, {
                "versionsByProduct": {},
                "cvesById": full_cve_baseline(fixture),
                "health": {},
            })
            fw.fetch_text = self._make_transport()

            real_disabled_commit = fn.commit_disabled_notification_state
            real_notify_commit = fn.commit_events_with_checkpoint
            real_catalog_commit = fw.commit_collected_state
            client = _mock_smtp_client()
            interposed: list[bool] = []

            def interrupt_b_after_catalog(*args, **kwargs):
                real_catalog_commit(*args, **kwargs)
                raise SystemExit("simulated B interruption before consuming its durable intent")

            def b_runs_before_a_disabled_commit(*args, **kwargs):
                interposed.append(True)
                with patch.object(
                    fn, "commit_events_with_checkpoint", real_notify_commit
                ), patch.object(
                    fn, "commit_disabled_notification_state", real_disabled_commit
                ), patch.object(
                    fw, "commit_collected_state", side_effect=interrupt_b_after_catalog
                ), self.assertRaises(SystemExit):
                    self._run(tmp, state_path, health_path, history_path, reconcile=True)
                staged = fn.load_notify_state(history_path)
                self.assertEqual(
                    staged[fn.PENDING_CVE_BASELINE_KEY]["CVE-2026-84393"]["severity"], "high"
                )
                self.assertEqual(client.send_message.call_count, 0)
                return real_disabled_commit(*args, **kwargs)

            with patch.dict(os.environ, NOTIFY_ENV, clear=True), patch(
                "smtplib.SMTP", return_value=client
            ), patch(
                "socket.socket.connect",
                side_effect=AssertionError("external network forbidden"),
            ), patch(
                "socket.create_connection",
                side_effect=AssertionError("external network forbidden"),
            ), patch.object(
                fw, "discover_advisory_ids_from_rss", return_value=["FG-IR-26-174"]
            ), patch.object(
                fn,
                "commit_disabled_notification_state",
                side_effect=b_runs_before_a_disabled_commit,
            ):
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                disabled_after = fn.load_notify_state(history_path)
                self.assertEqual(len(interposed), 1)
                self.assertEqual(client.send_message.call_count, 0)
                self.assertEqual(
                    disabled_after["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"],
                    "high",
                )
                self.assertIn(
                    "CVE-2026-84393",
                    disabled_after.get(fn.PENDING_CVE_BASELINE_KEY) or {},
                    "the disabled path must not erase a late intent it never observed",
                )

                # Reactivation: the surviving intent resolves silently, nothing replays.
                self._enable_notifications(tmp)
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                resumed = fn.load_notify_state(history_path)

            self.assertEqual(client.send_message.call_count, 0)
            self.assertNotIn(CVE_ESCALATION_REPLAY_KEY, resumed["sentKeys"])
            self.assertNotIn(fn.PENDING_CVE_BASELINE_KEY, resumed)
            self.assertEqual(
                resumed["checkpoint"]["cvesById"]["CVE-2026-84393"]["severity"], "high"
            )

    def test_structurally_invalid_catalogue_suspends_notifications_without_touching_state(
        self,
    ) -> None:
        """Review 367 BLOCKING 2 — a structurally invalid catalogue must not become an empty
        baseline.

        The committed catalogue is intact except its `cves` field, replaced by an empty
        object at the exact moment the notification observation reads it: a wrong-typed
        collection must NOT be iterated as if it were empty (which would replace the 33-entry
        baseline with nothing and replay six historical events after restoration). The
        observation must reject it, suspend the notification work with a cleaned diagnostic
        and leave the history byte-for-byte untouched; the restored catalogue resumes with no
        replay.
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
            client = _mock_smtp_client()

            before_bytes = history_path.read_bytes()
            before_count = len(fn.load_notify_state(history_path)["checkpoint"]["cvesById"])
            self.assertEqual(before_count, len(fixture["cves"]))

            real_observe = fw.read_coherent_notification_observation

            def observe_invalid_cves_type(history, catalogue):
                # A CVE collection must be an array, not an object. Every other field stays
                # intact, so this is not an ambiguous intentionally empty catalogue.
                saved = catalogue.read_bytes()
                invalid = json.loads(saved)
                invalid["cves"] = {}
                catalogue.write_text(json.dumps(invalid), encoding="utf-8")
                try:
                    return real_observe(history, catalogue)
                finally:
                    catalogue.write_bytes(saved)

            stderr = io.StringIO()
            with patch.dict(os.environ, NOTIFY_ENV, clear=True), patch(
                "smtplib.SMTP", return_value=client
            ), patch(
                "socket.socket.connect",
                side_effect=AssertionError("external network forbidden"),
            ), patch(
                "socket.create_connection",
                side_effect=AssertionError("external network forbidden"),
            ), patch.object(
                fw,
                "read_coherent_notification_observation",
                side_effect=observe_invalid_cves_type,
            ):
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(
                        self._run(tmp, state_path, health_path, history_path, reconcile=False),
                        0,
                    )

                self.assertIn("notification email non envoyée", stderr.getvalue())
                self.assertEqual(
                    history_path.read_bytes(),
                    before_bytes,
                    "an invalid catalogue must suspend notifications without touching the "
                    "history",
                )
                suspended = fn.load_notify_state(history_path)
                self.assertEqual(len(suspended["checkpoint"]["cvesById"]), before_count)
                self.assertEqual(suspended["sentKeys"], {})
                self.assertEqual(client.send_message.call_count, 0)

                # Restored catalogue, normal resumes: nothing historical replays.
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                resumed = fn.load_notify_state(history_path)
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                repeated = fn.load_notify_state(history_path)

            self.assertEqual(client.send_message.call_count, 0)
            self.assertEqual(resumed["sentKeys"], {})
            self.assertEqual(repeated["sentKeys"], {})
            self.assertEqual(len(repeated["checkpoint"]["cvesById"]), before_count)

    def test_structurally_invalid_catalogue_suspends_the_disabled_path_too(self) -> None:
        """Review 367 BLOCKING 2 — the disabled path suspends on the same structural contract.

        With every category disabled, an invalid catalogue must not silently advance the
        baselines either: the history stays byte-for-byte until a valid catalogue returns,
        and reactivation then resumes normally with no historical replay.
        """
        fixture = self._catalog_with_low_severity_false_positive()
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            state_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            fw.write_json(state_path, fixture)
            disabled_payload = fn._default_notification_settings_payload()
            disabled_payload["recipients"] = ["ops@example.com"]
            fn.save_notification_settings(
                tmp / "notification-settings.json", disabled_payload
            )
            fn.ensure_checkpoint(history_path, {
                "versionsByProduct": {},
                "cvesById": full_cve_baseline(fixture),
                "health": {},
            })
            fw.fetch_text = self._make_transport()
            client = _mock_smtp_client()

            before_bytes = history_path.read_bytes()
            before_count = len(fn.load_notify_state(history_path)["checkpoint"]["cvesById"])

            real_observe = fw.read_coherent_notification_observation

            def observe_invalid_cves_type(history, catalogue):
                saved = catalogue.read_bytes()
                invalid = json.loads(saved)
                invalid["cves"] = {}
                catalogue.write_text(json.dumps(invalid), encoding="utf-8")
                try:
                    return real_observe(history, catalogue)
                finally:
                    catalogue.write_bytes(saved)

            stderr = io.StringIO()
            with patch.dict(os.environ, NOTIFY_ENV, clear=True), patch(
                "smtplib.SMTP", return_value=client
            ), patch(
                "socket.socket.connect",
                side_effect=AssertionError("external network forbidden"),
            ), patch(
                "socket.create_connection",
                side_effect=AssertionError("external network forbidden"),
            ), patch.object(
                fw,
                "read_coherent_notification_observation",
                side_effect=observe_invalid_cves_type,
            ):
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(
                        self._run(tmp, state_path, health_path, history_path, reconcile=False),
                        0,
                    )

                self.assertIn("notification email non envoyée", stderr.getvalue())
                self.assertEqual(
                    history_path.read_bytes(),
                    before_bytes,
                    "the disabled path must suspend instead of advancing baselines from an "
                    "invalid catalogue",
                )
                self.assertEqual(client.send_message.call_count, 0)

                # Reactivation on the restored catalogue: normal, silent, intact.
                self._enable_notifications(tmp)
                self.assertEqual(
                    self._run(tmp, state_path, health_path, history_path, reconcile=False), 0
                )
                resumed = fn.load_notify_state(history_path)

            self.assertEqual(client.send_message.call_count, 0)
            self.assertEqual(resumed["sentKeys"], {})
            self.assertEqual(len(resumed["checkpoint"]["cvesById"]), before_count)

    def test_genuinely_empty_cves_list_keeps_its_normal_meaning(self) -> None:
        """Review 367, positive control — a really empty `cves` list stays a valid collection.

        A catalogue whose `cves` field is a genuine empty list (every CVE legitimately gone)
        must not trip the structural validation: the notification pass runs normally, the
        CVE baseline advances to the empty set as usual and a legitimate pending event is
        still delivered — no suspension diagnostic anywhere.
        """
        fixture = self._catalog_with_low_severity_false_positive()
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            state_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            fw.write_json(state_path, dict(fixture, cves=[]))
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
            client = _mock_smtp_client()

            stderr = io.StringIO()
            with patch.dict(os.environ, NOTIFY_ENV, clear=True), patch(
                "smtplib.SMTP", return_value=client
            ), patch(
                "socket.socket.connect",
                side_effect=AssertionError("external network forbidden"),
            ), patch(
                "socket.create_connection",
                side_effect=AssertionError("external network forbidden"),
            ):
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(
                        self._run(tmp, state_path, health_path, history_path, reconcile=False),
                        0,
                    )

                self.assertNotIn("notification email non envoyée", stderr.getvalue())
                after = fn.load_notify_state(history_path)
                self.assertEqual(after["checkpoint"]["cvesById"], {})
                self.assertEqual(sorted(after["sentKeys"]), [PENDING_EVENT_KEY])
                self.assertEqual(after["outbox"], [])
                self.assertEqual(client.send_message.call_count, 1)


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

    def test_commit_revalidation_silences_only_the_exact_confirmed_correction(self) -> None:
        """The late-intent neutralization at commit is exact — same id AND same target severity.

        The freshly durable intent is resolved against the catalogue the commit is certifying
        and governs only the correction it actually describes. Every scenario starts from a
        checkpoint holding CVE-X at `low` and stages an intent of `high` for CVE-X:

        - event low -> high, catalogue certified `high`: dropped before the outbox;
        - event low -> critical, same intent: kept (a distinct escalation, not described by
          the intent, and the intent stays staged because the catalogue does not confirm it);
        - event low -> high, catalogue still `low`: kept (intent unconfirmed, stays staged);
        - event on another id the intent does not carry: kept;
        - a `new-cve` event for the confirmed correction's id: dropped as the same replay.
        """

        def _event(key: str) -> fn.NotificationEvent:
            return fn.NotificationEvent(category="DAILY", dedup_key=key, summary=key)

        def _commit(path, *, intent, proposed_cves, baseline_cves, events):
            fn.stage_pending_cve_baseline(path, intent)
            return fn.commit_events_with_checkpoint(
                path,
                {"versionsByProduct": {}, "cvesById": proposed_cves, "health": {}},
                events,
                claimant="late-intent-mechanics",
                pending_cve_baseline=None,
                derivation_checkpoint={
                    "versionsByProduct": {},
                    "cvesById": baseline_cves,
                    "health": {},
                },
            )

        low_x = {"id": "CVE-X", "severity": "low"}
        high_x = {"id": "CVE-X", "severity": "high"}
        critical_x = {"id": "CVE-X", "severity": "critical"}
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)

            def _fresh_path(name: str, checkpoint: dict) -> Path:
                path = tmp / f"{name}.json"
                fw.write_json(path, self._state_with_checkpoint(checkpoint))
                return path

            # Exact match: the catalogue certified `high`, the intent says `high` -> dropped.
            path = _fresh_path("exact", {"CVE-X": low_x})
            claimed = _commit(
                path,
                intent={"CVE-X": high_x},
                proposed_cves={"CVE-X": high_x},
                baseline_cves={"CVE-X": low_x},
                events=[_event("cve-severity|psirt|CVE-X|low-to-high")],
            )
            self.assertEqual(claimed, [])
            self.assertEqual(fn.load_notify_state(path)["outbox"], [])
            self.assertEqual(
                fn.load_notify_state(path)["checkpoint"]["cvesById"]["CVE-X"]["severity"],
                "high",
            )
            self.assertEqual(
                fn.load_notify_state(path)[fn.PENDING_CVE_BASELINE_KEY]["CVE-X"]["severity"],
                "high",
                "a commit that never observed the intent must not retire it",
            )

            # Distinct escalation on the same id: kept, and the unconfirmed intent stays staged.
            path = _fresh_path("escalation", {"CVE-X": low_x})
            claimed = _commit(
                path,
                intent={"CVE-X": high_x},
                proposed_cves={"CVE-X": critical_x},
                baseline_cves={"CVE-X": low_x},
                events=[_event("cve-severity|psirt|CVE-X|low-to-critical")],
            )
            self.assertEqual(
                [event.dedup_key for event in claimed],
                ["cve-severity|psirt|CVE-X|low-to-critical"],
            )
            self.assertEqual(
                fn.load_notify_state(path)[fn.PENDING_CVE_BASELINE_KEY]["CVE-X"]["severity"],
                "high",
            )

            # Unconfirmed intent: the catalogue has not reached it -> nothing is silenced.
            path = _fresh_path("unconfirmed", {"CVE-X": low_x})
            claimed = _commit(
                path,
                intent={"CVE-X": high_x},
                proposed_cves={"CVE-X": low_x},
                baseline_cves={"CVE-X": low_x},
                events=[_event("cve-severity|psirt|CVE-X|low-to-high")],
            )
            self.assertEqual(
                [event.dedup_key for event in claimed],
                ["cve-severity|psirt|CVE-X|low-to-high"],
            )
            self.assertEqual(
                fn.load_notify_state(path)[fn.PENDING_CVE_BASELINE_KEY]["CVE-X"]["severity"],
                "high",
            )

            # Another id: the intent never silences an id it does not carry.
            path = _fresh_path("other-id", {"CVE-Y": low_x})
            claimed = _commit(
                path,
                intent={"CVE-X": high_x},
                proposed_cves={"CVE-X": high_x, "CVE-Y": high_x},
                baseline_cves={"CVE-Y": low_x},
                events=[_event("cve-severity|psirt|CVE-Y|low-to-high")],
            )
            self.assertEqual(
                [event.dedup_key for event in claimed],
                ["cve-severity|psirt|CVE-Y|low-to-high"],
            )

            # New-CVE replay of the same confirmed correction: dropped as the same replay.
            path = _fresh_path("new-cve", {})
            claimed = _commit(
                path,
                intent={"CVE-X": high_x},
                proposed_cves={"CVE-X": high_x},
                baseline_cves={},
                events=[_event("new-cve|psirt|CVE-X|high")],
            )
            self.assertEqual(claimed, [])
            self.assertEqual(fn.load_notify_state(path)["outbox"], [])


if __name__ == "__main__":
    unittest.main()
