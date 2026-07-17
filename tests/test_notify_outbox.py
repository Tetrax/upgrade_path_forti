"""Covers scripts/fortios_notify.py's persistent outbox (claim/send/finalize lifecycle so an SMTP
failure never loses an event) and the EOL-crossing detector's bootstrap/transition state --
entirely with mocks and tmp files, no real network, SMTP server, or multiprocessing target
defined inside a test method (see test_health_state.py's _concurrent_write_worker for why that
matters under the "spawn" start method).
"""

import json
import multiprocessing
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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


class NotifyStateDeepValidationTests(unittest.TestCase):
    """Regression: an outbox entry only needed a "dedupKey" key to pass validation, so
    {"outbox": [{"dedupKey": "k1"}]} was accepted, then raised KeyError('category') the moment
    enqueue_and_claim() tried to build a NotificationEvent from it -- with no self-healing path,
    since the bad entry would keep being re-read and re-crashing every single run.
    """

    def test_outbox_entry_missing_category_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            path.write_text(json.dumps({"sentKeys": {}, "outbox": [{"dedupKey": "k1"}], "eolState": {}}), encoding="utf-8")
            state = notify.load_notify_state(path)
            self.assertEqual(state, {"sentKeys": {}, "outbox": [], "eolState": {}})
            archived = list(Path(tmp).glob("notify.json.corrupt-*"))
            self.assertEqual(len(archived), 1)

    def test_outbox_entry_missing_summary_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            entry = {"category": "DAILY", "dedupKey": "k1", "queuedAt": "2026-07-17T07:00:00Z", "claimedBy": None, "claimedAt": None}
            path.write_text(json.dumps({"sentKeys": {}, "outbox": [entry], "eolState": {}}), encoding="utf-8")
            self.assertEqual(notify.load_notify_state(path)["outbox"], [])

    def test_outbox_entry_missing_claimed_by_key_is_rejected(self):
        """claimedBy/claimedAt must be PRESENT as keys (even if their value is null) -- not just
        absent-and-defaulted, since enqueue_and_claim()'s claim loop reads them unconditionally."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            entry = {"category": "DAILY", "dedupKey": "k1", "summary": "x", "queuedAt": "2026-07-17T07:00:00Z", "claimedAt": None}
            path.write_text(json.dumps({"sentKeys": {}, "outbox": [entry], "eolState": {}}), encoding="utf-8")
            self.assertEqual(notify.load_notify_state(path)["outbox"], [])

    def test_outbox_entry_with_wrong_type_category_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            entry = {
                "category": 123, "dedupKey": "k1", "summary": "x",
                "queuedAt": "2026-07-17T07:00:00Z", "claimedBy": None, "claimedAt": None,
            }
            path.write_text(json.dumps({"sentKeys": {}, "outbox": [entry], "eolState": {}}), encoding="utf-8")
            self.assertEqual(notify.load_notify_state(path)["outbox"], [])

    def test_outbox_entry_with_wrong_type_claimed_by_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            entry = {
                "category": "DAILY", "dedupKey": "k1", "summary": "x",
                "queuedAt": "2026-07-17T07:00:00Z", "claimedBy": 42, "claimedAt": None,
            }
            path.write_text(json.dumps({"sentKeys": {}, "outbox": [entry], "eolState": {}}), encoding="utf-8")
            self.assertEqual(notify.load_notify_state(path)["outbox"], [])

    def test_outbox_entry_with_empty_dedup_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            entry = {
                "category": "DAILY", "dedupKey": "", "summary": "x",
                "queuedAt": "2026-07-17T07:00:00Z", "claimedBy": None, "claimedAt": None,
            }
            path.write_text(json.dumps({"sentKeys": {}, "outbox": [entry], "eolState": {}}), encoding="utf-8")
            self.assertEqual(notify.load_notify_state(path)["outbox"], [])

    def test_a_fully_valid_outbox_entry_still_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            entry = {
                "category": "CRITICAL", "dedupKey": "new-cve|psirt|CVE-2026-1|critical", "summary": "x",
                "queuedAt": "2026-07-17T07:00:00Z", "claimedBy": "run-1", "claimedAt": "2026-07-17T07:00:00Z",
            }
            path.write_text(json.dumps({"sentKeys": {}, "outbox": [entry], "eolState": {}}), encoding="utf-8")
            state = notify.load_notify_state(path)
            self.assertEqual(len(state["outbox"]), 1)

    def test_eol_state_non_boolean_value_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            path.write_text(json.dumps({"sentKeys": {}, "outbox": [], "eolState": {"7.6": "true"}}), encoding="utf-8")
            self.assertEqual(notify.load_notify_state(path)["eolState"], {})

    def test_eol_state_int_value_is_rejected(self):
        """bool is a subclass of int, but the reverse isn't true -- 1/0 must not be accepted as
        stand-ins for True/False."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            path.write_text(json.dumps({"sentKeys": {}, "outbox": [], "eolState": {"7.6": 1}}), encoding="utf-8")
            self.assertEqual(notify.load_notify_state(path)["eolState"], {})

    def test_sent_keys_wrong_value_type_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            path.write_text(json.dumps({"sentKeys": {"k1": 12345}, "outbox": [], "eolState": {}}), encoding="utf-8")
            self.assertEqual(notify.load_notify_state(path)["sentKeys"], {})

    def test_sent_keys_wrong_top_level_type_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            path.write_text(json.dumps({"sentKeys": ["k1", "k2"], "outbox": [], "eolState": {}}), encoding="utf-8")
            self.assertEqual(notify.load_notify_state(path), {"sentKeys": {}, "outbox": [], "eolState": {}})

    def test_main_completes_despite_a_malformed_outbox_entry(self):
        """End-to-end: a notify-history file with a partial outbox entry must never crash main()
        or leave notifications permanently stuck -- it self-heals to an empty state instead.
        Email must be enabled for this run, otherwise main() never touches the notify-history
        file at all and the test would prove nothing.
        """
        with tempfile.TemporaryDirectory() as tmp:
            base_path = Path(tmp) / "state.json"
            fw.write_json(base_path, fw.normalize_state({}))
            history_path = Path(tmp) / "notify-history.json"
            history_path.write_text(json.dumps({"sentKeys": {}, "outbox": [{"dedupKey": "k1"}], "eolState": {}}), encoding="utf-8")

            env = {
                "FORTIOS_EMAIL_ENABLED": "true", "FORTIOS_SMTP_HOST": "smtp.example.com",
                "FORTIOS_SMTP_FROM": "fortios@example.com", "FORTIOS_SMTP_TO": "alice@example.com",
            }
            with patch.dict(os.environ, env, clear=False), patch("smtplib.SMTP", side_effect=ConnectionRefusedError("refused")):
                exit_code = fw.main([
                    "--skip-network",
                    "--base", str(base_path), "--output", str(base_path),
                    "--report", str(Path(tmp) / "report.md"), "--health-output", str(Path(tmp) / "health.json"),
                    "--notify-history-output", str(history_path),
                ])
            self.assertEqual(exit_code, 0)
            state = notify.load_notify_state(history_path)
            self.assertEqual(state["outbox"], [], "the malformed entry must be dropped, not crash the run")


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

    def test_commit_eol_transition_round_trips_state_with_no_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            notify.commit_eol_transition(path, {"7.6": True, "7.4": False}, [])
            state = notify.load_notify_state(path)
            self.assertEqual(state["eolState"], {"7.6": True, "7.4": False})
            self.assertEqual(state["outbox"], [])


class EolTransitionAtomicityTests(unittest.TestCase):
    """Regression: eolState used to be persisted (save_eol_state()) in a write separate from
    queuing the resulting event (via enqueue_and_claim()) -- a crash between the two would mark
    the branch as already handled while the event was never queued, permanently losing the
    notification (derive_eol_events() only fires on the False -> True transition of the exact
    persisted state, so it would never re-fire once eol_state already says True). See
    commit_eol_transition()'s docstring in fortios_notify.py.
    """

    def test_state_and_event_land_in_a_single_atomic_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            write_calls = []
            original_write_json = notify.write_json

            def counting_write_json(target_path, payload):
                write_calls.append(json.loads(json.dumps(payload)))  # deep snapshot
                return original_write_json(target_path, payload)

            event = notify.NotificationEvent(
                category="DAILY", dedup_key="support-eol|fortios|7.6|2026-07-17", summary="x",
            )
            with patch.object(notify, "write_json", side_effect=counting_write_json):
                notify.commit_eol_transition(path, {"7.6": True}, [event])

            self.assertEqual(len(write_calls), 1, "the state transition and its event must land in a single write")
            self.assertEqual(write_calls[0]["eolState"], {"7.6": True})
            self.assertEqual(len(write_calls[0]["outbox"]), 1)
            self.assertEqual(write_calls[0]["outbox"][0]["dedupKey"], "support-eol|fortios|7.6|2026-07-17")

    def test_no_partial_state_survives_a_crash_mid_commit(self):
        """Simulates the crash this fix targets: the write itself fails partway through (disk
        full, process killed) -- verify the ORIGINAL file (pre-transition) is what's left, never
        a half-applied state with eolState updated but the event missing. write_json() writes via
        temp-file + atomic rename (see fortios_watch.write_json()), so a failure during the dump
        must never corrupt or partially update the file already on disk.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            notify.write_json(path, {"sentKeys": {}, "outbox": [], "eolState": {"7.6": False}})

            event = notify.NotificationEvent(
                category="DAILY", dedup_key="support-eol|fortios|7.6|2026-07-17", summary="x",
            )
            with patch.object(notify, "write_json", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    notify.commit_eol_transition(path, {"7.6": True}, [event])

            # The file on disk must be exactly what it was before the failed commit -- neither
            # eolState nor the outbox may have been partially updated.
            state = notify.load_notify_state(path)
            self.assertEqual(state["eolState"], {"7.6": False}, "a failed commit must never leave eolState transitioned")
            self.assertEqual(state["outbox"], [], "a failed commit must never leave the event queued without its state")

    def test_restart_after_a_failed_commit_still_fires_the_event_next_time(self):
        """End-to-end: the first commit attempt fails entirely (simulating a crash) -- since
        nothing was persisted, the next run's derive_eol_events() still sees the pre-transition
        state and fires the event normally, and this time the commit succeeds."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            lifecycle = {"7.6": {"support": "2026-07-12"}}
            notify.commit_eol_transition(path, {"7.6": False}, [])  # last known-good state, before the crossing

            # Attempt 1: process dies mid-commit.
            with patch.object(notify, "write_json", side_effect=OSError("killed")):
                pre_state = notify.load_notify_state(path)
                events_1, eol_state_1 = notify.derive_eol_events(lifecycle, pre_state["eolState"], now="2026-07-17T07:00:00Z")
                self.assertEqual(len(events_1), 1)
                with self.assertRaises(OSError):
                    notify.commit_eol_transition(path, eol_state_1, events_1)

            # Restart: eolState on disk is untouched (still False), so the transition is detected again.
            state_after_crash = notify.load_notify_state(path)
            self.assertEqual(state_after_crash["eolState"], {"7.6": False})
            events_2, eol_state_2 = notify.derive_eol_events(lifecycle, state_after_crash["eolState"], now="2026-07-18T07:00:00Z")
            self.assertEqual(len(events_2), 1, "the event must still be detected after the failed attempt")
            notify.commit_eol_transition(path, eol_state_2, events_2)

            final_state = notify.load_notify_state(path)
            self.assertEqual(final_state["eolState"], {"7.6": True})
            self.assertEqual(len(final_state["outbox"]), 1)


if __name__ == "__main__":
    unittest.main()
