"""Covers scripts/fortios_notify.py's persistent outbox (claim/send/finalize lifecycle so an SMTP
failure never loses an event) and the EOL-crossing detector's bootstrap/transition state --
entirely with mocks and tmp files, no real network, SMTP server, or multiprocessing target
defined inside a test method (see test_health_state.py's _concurrent_write_worker for why that
matters under the "spawn" start method).
"""

import multiprocessing
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_notify as notify  # noqa: E402
import fortios_watch as fw  # noqa: E402


def _claim_worker(path, dedup_key, claimant_id, barrier, result_queue):
    """Module-level so it's picklable under the "spawn" multiprocessing start method."""
    barrier.wait()
    event = notify.NotificationEvent(category="DAILY", dedup_key=dedup_key, summary="x")
    claimed = notify.enqueue_and_claim(path, [event], claimant=claimant_id)
    result_queue.put((claimant_id, len(claimed)))


class OutboxLifecycleTests(unittest.TestCase):
    def test_new_event_is_enqueued_and_claimed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            event = notify.NotificationEvent(category="DAILY", dedup_key="k1", summary="x")
            claimed = notify.enqueue_and_claim(path, [event], claimant="run-A")
            self.assertEqual(claimed, [event])
            state = notify.load_notify_state(path)
            self.assertEqual(len(state["outbox"]), 1)
            self.assertEqual(state["outbox"][0]["claimedBy"], "run-A")

    def test_failed_send_then_retry_succeeds_next_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            event = notify.NotificationEvent(category="DAILY", dedup_key="k1", summary="x")

            # Run 1: claims the event, "sends" it (simulated failure), releases the claim.
            claimed = notify.enqueue_and_claim(path, [event], claimant="run-1")
            self.assertEqual(len(claimed), 1)
            notify.release_claim(path, "run-1")

            # Run 2: no NEW events this time, but the still-pending one must be reclaimed.
            claimed_again = notify.enqueue_and_claim(path, [], claimant="run-2")
            self.assertEqual([e.dedup_key for e in claimed_again], ["k1"])
            notify.finalize_sent_events(path, claimed_again)

            state = notify.load_notify_state(path)
            self.assertEqual(state["outbox"], [])
            self.assertIn("k1", state["sentKeys"])

    def test_repeated_failures_keep_event_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            event = notify.NotificationEvent(category="DAILY", dedup_key="k1", summary="x")
            notify.enqueue_and_claim(path, [event], claimant="run-1")
            notify.release_claim(path, "run-1")
            notify.enqueue_and_claim(path, [], claimant="run-2")
            notify.release_claim(path, "run-2")
            notify.enqueue_and_claim(path, [], claimant="run-3")
            notify.release_claim(path, "run-3")

            state = notify.load_notify_state(path)
            self.assertEqual(len(state["outbox"]), 1, "the event must survive multiple consecutive failures")
            self.assertNotIn("k1", state["sentKeys"])

    def test_no_duplicate_after_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            event = notify.NotificationEvent(category="DAILY", dedup_key="k1", summary="x")
            claimed = notify.enqueue_and_claim(path, [event], claimant="run-1")
            notify.finalize_sent_events(path, claimed)

            # The exact same event is "re-derived" on a later run (as if the diff logic produced
            # it again) -- it must not be re-queued since its dedup_key is already in sentKeys.
            claimed_again = notify.enqueue_and_claim(path, [event], claimant="run-2")
            self.assertEqual(claimed_again, [])
            state = notify.load_notify_state(path)
            self.assertEqual(state["outbox"], [])

    def test_stale_claim_can_be_reclaimed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            event = notify.NotificationEvent(category="DAILY", dedup_key="k1", summary="x")
            notify.enqueue_and_claim(path, [event], claimant="run-1", now="2026-07-17T07:00:00Z")
            # run-1 crashed before releasing its claim -- a much later run must be able to steal it.
            later = "2026-07-17T07:20:00Z"  # 1200s later, past CLAIM_STALE_SECONDS (600s)
            claimed = notify.enqueue_and_claim(path, [], claimant="run-2", now=later)
            self.assertEqual([e.dedup_key for e in claimed], ["k1"])

    def test_fresh_claim_is_not_stolen(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            event = notify.NotificationEvent(category="DAILY", dedup_key="k1", summary="x")
            notify.enqueue_and_claim(path, [event], claimant="run-1", now="2026-07-17T07:00:00Z")
            soon_after = "2026-07-17T07:01:00Z"  # 60s later, well under CLAIM_STALE_SECONDS
            claimed = notify.enqueue_and_claim(path, [], claimant="run-2", now=soon_after)
            self.assertEqual(claimed, [], "a fresh, still-live claim must not be stolen")

    def test_two_concurrent_collections_do_not_both_claim_the_same_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            barrier = multiprocessing.Barrier(2)
            result_queue = multiprocessing.Queue()
            p1 = multiprocessing.Process(target=_claim_worker, args=(path, "dup-key", "proc-A", barrier, result_queue))
            p2 = multiprocessing.Process(target=_claim_worker, args=(path, "dup-key", "proc-B", barrier, result_queue))
            p1.start()
            p2.start()
            p1.join(timeout=10)
            p2.join(timeout=10)

            results = [result_queue.get(timeout=2), result_queue.get(timeout=2)]
            claimed_counts = sorted(count for _, count in results)
            self.assertEqual(claimed_counts, [0, 1], "exactly one process must claim the event, the other must get nothing")

    def test_recovery_from_corrupt_outbox_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            path.write_text('{"outbox": "not-a-list", "sentKeys": {}}', encoding="utf-8")
            event = notify.NotificationEvent(category="DAILY", dedup_key="k1", summary="x")
            claimed = notify.enqueue_and_claim(path, [event], claimant="run-1")
            self.assertEqual(len(claimed), 1, "a corrupt state file must be treated as empty, not raise")

    def test_recovery_from_truncated_history_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            path.write_text('{"sentKeys": {"k0": "2026-07-01', encoding="utf-8")  # truncated mid-value
            state = notify.load_notify_state(path)
            self.assertEqual(state, {"sentKeys": {}, "outbox": [], "eolState": {}})
            archived = list(Path(tmp).glob("notify.json.corrupt-*"))
            self.assertEqual(len(archived), 1)

    def test_record_sent_events_is_still_the_public_name(self):
        """Backward-compat: existing callers/tests refer to this as record_sent_events()."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            event = notify.NotificationEvent(category="DAILY", dedup_key="k1", summary="x")
            notify.record_sent_events(path, [event])
            self.assertIn("k1", notify.load_notify_history(path))


class EolEventDerivationTests(unittest.TestCase):
    def test_first_activation_bootstraps_silently_even_for_already_past_eol_branches(self):
        """A branch already long past its support date must not immediately email on the very
        first run after this feature is turned on -- only the transition (not-EOL -> EOL) fires,
        and there's no "before" to transition from on a first sighting."""
        lifecycle = {"6.0": {"support": "2020-01-01"}}  # long past, relative to `now` below
        events, state = notify.derive_eol_events(lifecycle, {}, now="2026-07-17T07:00:00Z")
        self.assertEqual(events, [])
        self.assertEqual(state, {"6.0": True})

    def test_before_support_date_no_event(self):
        lifecycle = {"7.6": {"support": "2027-01-01"}}
        events, state = notify.derive_eol_events(lifecycle, {"7.6": False}, now="2026-07-17T07:00:00Z")
        self.assertEqual(events, [])
        self.assertEqual(state, {"7.6": False})

    def test_on_the_exact_support_date_no_event_yet(self):
        """The support date itself is still considered "supported that day" (strict less-than),
        consistent with classify_source_severity's own age comparisons elsewhere in this app."""
        lifecycle = {"7.6": {"support": "2026-07-17"}}
        events, state = notify.derive_eol_events(lifecycle, {"7.6": False}, now="2026-07-17T07:00:00Z")
        self.assertEqual(events, [])
        self.assertEqual(state, {"7.6": False})

    def test_the_day_after_support_date_fires_exactly_once(self):
        lifecycle = {"7.6": {"support": "2026-07-17"}}
        events, state = notify.derive_eol_events(lifecycle, {"7.6": False}, now="2026-07-18T07:00:00Z")
        self.assertEqual(len(events), 1)
        self.assertIn("7.6", events[0].summary)
        self.assertEqual(state, {"7.6": True})

        # A second run the following day, with the persisted state now up to date, must not refire.
        events_2, state_2 = notify.derive_eol_events(lifecycle, state, now="2026-07-19T07:00:00Z")
        self.assertEqual(events_2, [])
        self.assertEqual(state_2, {"7.6": True})

    def test_restart_after_several_days_without_a_collection_still_fires_once(self):
        """The tool didn't run for 5 days spanning the actual crossing -- eol_state still holds
        whatever was true the last time it genuinely ran, so the transition is still correctly
        observed (and only once) whenever the next collection finally happens, however late."""
        lifecycle = {"7.6": {"support": "2026-07-12"}}
        state_before_gap = {"7.6": False}  # last real check, a few days before the crossing
        events, state_after = notify.derive_eol_events(lifecycle, state_before_gap, now="2026-07-17T07:00:00Z")
        self.assertEqual(len(events), 1)
        self.assertEqual(state_after, {"7.6": True})

    def test_no_support_date_is_ignored(self):
        events, state = notify.derive_eol_events({"7.6": {"support": None}}, {}, now="2026-07-17T07:00:00Z")
        self.assertEqual(events, [])
        self.assertEqual(state, {})

    def test_save_and_reload_eol_state_round_trips(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            notify.save_eol_state(path, {"7.6": True, "7.4": False})
            state = notify.load_notify_state(path)
            self.assertEqual(state["eolState"], {"7.6": True, "7.4": False})


if __name__ == "__main__":
    unittest.main()
