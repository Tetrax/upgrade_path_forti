"""Covers scripts/fortios_watch.py's health-state tracking (data/fortios-health.json).

Each source (fortios-docs, fortianalyzer, fortimanager, forticlient, forticlient-ems, cve-psirt,
fortios-lifecycle, compat-matrix, daily-run) gets a record tracking status, timing, item counts,
and consecutive-failure streaks, written to a file separate from the main catalog so a health
check never touches (or risks corrupting) the actual data.
"""

import multiprocessing
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_watch as fw  # noqa: E402


def _concurrent_write_worker(path, source_id, started_at, hold_seconds, barrier):
    """Module-level on purpose: multiprocessing's "spawn" start method (macOS and Windows
    defaults, and the only option left on Python 3.14) needs to locate the worker by its
    import path in the child process, which only works for a plain module-level function --
    one nested inside a test method has no such path and the child fails to start with it,
    even though "fork" (Linux's historical default) never cared. Defining it here instead of
    inside the test keeps the test meaningful on every platform without forcing a start method
    the test wouldn't otherwise run under in CI.
    """
    barrier.wait()
    with fw.cross_process_lock(path):
        state = fw.read_json(path, {"sources": {}})
        time.sleep(hold_seconds)  # widen the window a real race would need to slip through
        state.setdefault("sources", {})[source_id] = {"status": "ok", "lastAttemptAt": started_at}
        fw.write_json(path, state)


class ParseHealthTimestampTests(unittest.TestCase):
    """Regression: dt.datetime.fromisoformat() happily parses a timezone-naive string like
    "2026-07-17T07:00:00" (no "Z", no offset) into a naive datetime -- comparing that against the
    aware dt.datetime.now(dt.UTC) used everywhere else in this module raises
    "TypeError: can't compare offset-naive and offset-aware datetimes" deep inside
    classify_source_severity()/_merge_health_source(), which used to take main() down with it.
    parse_health_timestamp() must always return an aware UTC datetime, or raise ValueError
    (which every caller already handles) rather than ever handing back something naive.
    """

    def test_z_suffixed_timestamp_is_aware(self):
        parsed = fw.parse_health_timestamp("2026-07-17T07:00:00Z")
        self.assertIsNotNone(parsed.tzinfo)
        self.assertIsNotNone(parsed.utcoffset())
        self.assertEqual(parsed.utcoffset().total_seconds(), 0)

    def test_explicit_offset_timestamp_is_normalized_to_utc(self):
        parsed = fw.parse_health_timestamp("2026-07-17T09:00:00+02:00")
        self.assertIsNotNone(parsed.tzinfo)
        self.assertEqual(parsed.utcoffset().total_seconds(), 0)
        self.assertEqual(parsed.hour, 7, "09:00 +02:00 must normalize to 07:00 UTC")

    def test_naive_timestamp_is_rejected(self):
        with self.assertRaises(ValueError):
            fw.parse_health_timestamp("2026-07-17T07:00:00")

    def test_date_only_string_is_rejected(self):
        with self.assertRaises(ValueError):
            fw.parse_health_timestamp("2026-07-17")

    def test_merge_health_source_never_raises_typeerror_on_a_naive_existing_timestamp(self):
        """_merge_health_source()'s clobber-guard (existing["lastAttemptAt"] vs
        result.started_at) is the actual call site main() exercises on every run via
        record_health_results() -- a naive value reaching it used to raise
        "TypeError: can't compare offset-naive and offset-aware datetimes" since our own
        started_at is always aware. It now raises the much more benign, already-handled
        ValueError instead (never TypeError), and in the real read path this can't happen at all
        since read_health_state()'s validator rejects a naive timestamp before _merge_health_source()
        is ever called with it."""
        existing = {"status": fw.HEALTH_STATUS_OK, "lastAttemptAt": "2026-07-17T07:00:00"}
        result = fw.HealthSourceResult(status=fw.HEALTH_STATUS_OK, started_at="2026-07-17T12:00:00.000000Z", duration_seconds=1.0)
        try:
            fw._merge_health_source(existing, result)
        except TypeError as error:
            self.fail(f"_merge_health_source() must never raise TypeError, got {error!r}")
        except ValueError:
            pass  # acceptable: a naive timestamp is genuinely invalid data


class HealthResultMergeTests(unittest.TestCase):
    def test_first_successful_collection(self):
        result = fw.HealthSourceResult(
            status=fw.HEALTH_STATUS_OK, started_at="2026-07-16T07:15:00Z",
            duration_seconds=1.5, items_collected=42,
        )
        record = fw._merge_health_source({}, result)
        self.assertEqual(record["status"], fw.HEALTH_STATUS_OK)
        self.assertEqual(record["lastSuccessAt"], "2026-07-16T07:15:00Z")
        self.assertEqual(record["lastAttemptAt"], "2026-07-16T07:15:00Z")
        self.assertEqual(record["itemsCollected"], 42)
        self.assertEqual(record["consecutiveFailures"], 0)
        self.assertIsNone(record.get("lastError"))

    def test_failure_after_a_prior_success(self):
        existing = fw._merge_health_source({}, fw.HealthSourceResult(
            status=fw.HEALTH_STATUS_OK, started_at="2026-07-15T07:15:00Z", duration_seconds=1.0,
        ))
        failed = fw._merge_health_source(existing, fw.HealthSourceResult(
            status=fw.HEALTH_STATUS_ERROR, started_at="2026-07-16T07:15:00Z",
            duration_seconds=0.5, error="Connection timed out",
        ))
        self.assertEqual(failed["status"], fw.HEALTH_STATUS_ERROR)
        self.assertEqual(failed["lastErrorAt"], "2026-07-16T07:15:00Z")
        self.assertEqual(failed["lastError"], "Connection timed out")

    def test_last_success_at_preserved_after_failure(self):
        existing = fw._merge_health_source({}, fw.HealthSourceResult(
            status=fw.HEALTH_STATUS_OK, started_at="2026-07-15T07:15:00Z", duration_seconds=1.0,
        ))
        failed = fw._merge_health_source(existing, fw.HealthSourceResult(
            status=fw.HEALTH_STATUS_ERROR, started_at="2026-07-16T07:15:00Z", duration_seconds=0.5,
            error="boom",
        ))
        self.assertEqual(failed["lastSuccessAt"], "2026-07-15T07:15:00Z", "must never be cleared by a failure")

    def test_consecutive_failures_increment(self):
        record: dict = {}
        for day in range(1, 4):
            record = fw._merge_health_source(record, fw.HealthSourceResult(
                status=fw.HEALTH_STATUS_ERROR, started_at=f"2026-07-1{day}T07:15:00Z",
                duration_seconds=0.1, error="still down",
            ))
        self.assertEqual(record["consecutiveFailures"], 3)

    def test_consecutive_failures_reset_after_recovery(self):
        record: dict = {}
        for day in range(1, 4):
            record = fw._merge_health_source(record, fw.HealthSourceResult(
                status=fw.HEALTH_STATUS_ERROR, started_at=f"2026-07-1{day}T07:15:00Z",
                duration_seconds=0.1, error="still down",
            ))
        self.assertEqual(record["consecutiveFailures"], 3)
        recovered = fw._merge_health_source(record, fw.HealthSourceResult(
            status=fw.HEALTH_STATUS_OK, started_at="2026-07-14T07:15:00Z", duration_seconds=1.0,
        ))
        self.assertEqual(recovered["consecutiveFailures"], 0)
        self.assertEqual(recovered["status"], fw.HEALTH_STATUS_OK)

    def test_deliberately_skipped_source(self):
        existing = fw._merge_health_source({}, fw.HealthSourceResult(
            status=fw.HEALTH_STATUS_OK, started_at="2026-07-15T07:15:00Z", duration_seconds=1.0,
        ))
        skipped = fw._merge_health_source(existing, fw.HealthSourceResult(
            status=fw.HEALTH_STATUS_SKIPPED, started_at="2026-07-16T07:15:00Z", duration_seconds=0.0,
        ))
        self.assertEqual(skipped["status"], fw.HEALTH_STATUS_SKIPPED)
        self.assertEqual(skipped["consecutiveFailures"], 0, "a deliberate skip is not a failure")
        self.assertEqual(skipped["lastSuccessAt"], "2026-07-15T07:15:00Z", "must be left untouched")
        self.assertIsNone(skipped.get("lastError"))

    def test_older_run_never_clobbers_a_newer_result(self):
        newer = fw._merge_health_source({}, fw.HealthSourceResult(
            status=fw.HEALTH_STATUS_OK, started_at="2026-07-16T09:00:00Z", duration_seconds=1.0,
            items_collected=10,
        ))
        stale_write = fw._merge_health_source(newer, fw.HealthSourceResult(
            status=fw.HEALTH_STATUS_ERROR, started_at="2026-07-16T07:00:00Z", duration_seconds=0.1,
            error="a slow, older run finishing late",
        ))
        self.assertEqual(stale_write, newer, "an older attempt must never overwrite a newer result")

    def test_same_second_attempts_finishing_in_reverse_order_do_not_clobber(self):
        """Regression: utc_now() used to round lastAttemptAt/started_at down to the whole
        second, so two attempts beginning within the same second were indistinguishable by the
        clobber-guard above -- whichever one happened to *write* last would win, even if it had
        actually *started* first (i.e. was the stale one). Health timestamps now carry
        microsecond resolution (utc_now_precise()) specifically so this can't happen: B starts
        slightly after A within the same second but finishes (writes) first; A's write -- for an
        attempt that began before B -- must never overwrite B's already-recorded result.
        """
        state_after_b = fw._merge_health_source({}, fw.HealthSourceResult(
            status=fw.HEALTH_STATUS_OK, started_at="2026-07-16T07:15:00.400000Z", duration_seconds=0.1,
        ))
        state_after_a = fw._merge_health_source(state_after_b, fw.HealthSourceResult(
            status=fw.HEALTH_STATUS_ERROR, started_at="2026-07-16T07:15:00.100000Z", duration_seconds=5.0,
            error="a slower attempt that began before B, finishing after it",
        ))
        self.assertEqual(
            state_after_a, state_after_b,
            "an attempt that started earlier must never clobber a later one's result, even within the same second",
        )

    def test_legacy_whole_second_record_does_not_block_a_same_second_precise_update(self):
        """Regression: comparing lastAttemptAt as raw strings breaks the instant a
        microsecond-precision timestamp meets an older whole-second-precision one (pre-migration
        data) from the same wall-clock second -- '.' sorts before 'Z' in ASCII, so
        "...:00Z" > "...:00.500000Z" as plain strings even though .000000 is chronologically
        earlier than .500000. The comparison must parse both sides as datetimes instead.
        """
        existing = fw._merge_health_source({}, fw.HealthSourceResult(
            status=fw.HEALTH_STATUS_ERROR, started_at="2026-07-16T07:15:00Z", duration_seconds=1.0,
            error="an old, pre-migration whole-second record",
        ))
        updated = fw._merge_health_source(existing, fw.HealthSourceResult(
            status=fw.HEALTH_STATUS_OK, started_at="2026-07-16T07:15:00.500000Z", duration_seconds=1.0,
        ))
        self.assertEqual(updated["status"], fw.HEALTH_STATUS_OK, "a same-second, higher-precision update must not be rejected")

    def test_utc_now_precise_carries_microseconds(self):
        value = fw.utc_now_precise()
        self.assertRegex(value, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")

    def test_error_message_is_sanitized(self):
        record = fw._merge_health_source({}, fw.HealthSourceResult(
            status=fw.HEALTH_STATUS_ERROR, started_at="2026-07-16T07:15:00Z", duration_seconds=0.1,
            error="SMTP auth failed: password=hunter2 for user@example.com",
        ))
        self.assertNotIn("hunter2", record["lastError"])
        self.assertIn("[masqué]", record["lastError"])

    def test_warning_still_counts_as_a_success_but_stays_visibly_flagged(self):
        record = fw._merge_health_source({}, fw.HealthSourceResult(
            status=fw.HEALTH_STATUS_WARNING, started_at="2026-07-16T07:15:00Z",
            duration_seconds=1.0, items_collected=0, error="0 items collected, expected some",
        ))
        self.assertEqual(record["status"], fw.HEALTH_STATUS_WARNING)
        self.assertEqual(record["lastSuccessAt"], "2026-07-16T07:15:00Z", "the run did complete and produce data")
        self.assertEqual(record["consecutiveFailures"], 0)
        self.assertEqual(record["lastError"], "0 items collected, expected some")


class RecordHealthResultsIntegrationTests(unittest.TestCase):
    def test_atomic_write_leaves_no_partial_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            fw.record_health_results(path, {
                fw.SOURCE_FORTIOS_DOCS: fw.HealthSourceResult(
                    status=fw.HEALTH_STATUS_OK, started_at="2026-07-16T07:15:00Z",
                    duration_seconds=2.0, items_collected=100,
                ),
            })
            state = fw.read_json(path, None)
            self.assertIsNotNone(state)
            self.assertEqual(state["sources"][fw.SOURCE_FORTIOS_DOCS]["itemsCollected"], 100)
            # No leftover .tmp-* file from the atomic-rename write (the .lock sentinel file from
            # cross_process_lock() is expected to persist -- that's by design, not a leftover).
            leftover_tmp_files = [p for p in Path(tmp).iterdir() if ".tmp-" in p.name]
            self.assertEqual(leftover_tmp_files, [])

    def test_partial_execution_only_touches_recorded_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            fw.record_health_results(path, {
                fw.SOURCE_FORTIOS_DOCS: fw.HealthSourceResult(
                    status=fw.HEALTH_STATUS_OK, started_at="2026-07-15T07:15:00Z", duration_seconds=1.0,
                ),
                fw.SOURCE_CVE_PSIRT: fw.HealthSourceResult(
                    status=fw.HEALTH_STATUS_OK, started_at="2026-07-15T07:15:00Z", duration_seconds=1.0,
                ),
            })
            # A manual, partial run only touches fortios-docs this time.
            fw.record_health_results(path, {
                fw.SOURCE_FORTIOS_DOCS: fw.HealthSourceResult(
                    status=fw.HEALTH_STATUS_OK, started_at="2026-07-16T09:00:00Z",
                    duration_seconds=1.0, items_collected=5,
                ),
            })
            state = fw.read_json(path, {})
            self.assertEqual(state["sources"][fw.SOURCE_FORTIOS_DOCS]["lastAttemptAt"], "2026-07-16T09:00:00Z")
            self.assertEqual(
                state["sources"][fw.SOURCE_CVE_PSIRT]["lastAttemptAt"], "2026-07-15T07:15:00Z",
                "a source not touched by the partial run must be left exactly as it was",
            )

    def test_concurrent_updates_are_serialized(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            fw.write_json(path, {"sources": {}})
            barrier = multiprocessing.Barrier(2)
            p1 = multiprocessing.Process(target=_concurrent_write_worker, args=(path, "source-a", "t1", 0.3, barrier))
            p2 = multiprocessing.Process(target=_concurrent_write_worker, args=(path, "source-b", "t2", 0.3, barrier))
            p1.start()
            p2.start()
            p1.join(timeout=5)
            p2.join(timeout=5)

            state = fw.read_json(path, {})
            # Both writes must have landed -- if the lock didn't serialize them, one process's
            # read-modify-write could have clobbered the other's addition entirely.
            self.assertIn("source-a", state["sources"])
            self.assertIn("source-b", state["sources"])


class TolerantHealthReadTests(unittest.TestCase):
    """A corrupt data/fortios-health.json must never take the whole collection down with it --
    health tracking is diagnostic, not load-bearing (see read_health_state()/read_json_tolerant()
    in fortios_watch.py)."""

    def test_missing_file_returns_empty_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            self.assertEqual(fw.read_health_state(path), {"sources": {}})

    def test_truncated_json_is_treated_as_empty_and_archived(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text('{"sources": {"fortios-docs": {"status": "ok"', encoding="utf-8")
            state = fw.read_health_state(path)
            self.assertEqual(state, {"sources": {}})
            # The bad file must survive somewhere for diagnosis, not vanish or get clobbered blind.
            archived = list(Path(tmp).glob("health.json.corrupt-*"))
            self.assertEqual(len(archived), 1)
            self.assertIn("fortios-docs", archived[0].read_text(encoding="utf-8"))
            self.assertFalse(path.exists(), "the corrupt file must be moved aside, not left at the original path")

    def test_invalid_json_is_treated_as_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text("not json at all, just garbage \x00\x01", encoding="utf-8")
            self.assertEqual(fw.read_health_state(path), {"sources": {}})

    def test_wrong_top_level_type_is_treated_as_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text("[1, 2, 3]", encoding="utf-8")
            self.assertEqual(fw.read_health_state(path), {"sources": {}})

    def test_sources_wrong_type_is_treated_as_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text('{"sources": "not-a-dict"}', encoding="utf-8")
            self.assertEqual(fw.read_health_state(path), {"sources": {}})

    def test_source_record_wrong_type_is_treated_as_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text('{"sources": {"daily-run": "oops, a string not a record"}}', encoding="utf-8")
            self.assertEqual(fw.read_health_state(path), {"sources": {}})

    def test_invalid_timestamp_field_is_treated_as_empty(self):
        """Regression: parse_health_timestamp("not-a-date") raises ValueError, and used to
        propagate straight out of classify_source_severity()/_merge_health_source() the moment a
        record with a garbled lastAttemptAt was read -- validation must catch it up front."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text(
                '{"sources": {"daily-run": {"status": "ok", "lastAttemptAt": "not-a-date"}}}',
                encoding="utf-8",
            )
            self.assertEqual(fw.read_health_state(path), {"sources": {}})

    def test_invalid_last_success_at_is_treated_as_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text(
                '{"sources": {"daily-run": {"status": "ok", "lastSuccessAt": 12345}}}',
                encoding="utf-8",
            )
            self.assertEqual(fw.read_health_state(path), {"sources": {}})

    def test_unknown_status_value_is_treated_as_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text(
                '{"sources": {"daily-run": {"status": "totally-bogus"}}}',
                encoding="utf-8",
            )
            self.assertEqual(fw.read_health_state(path), {"sources": {}})

    def test_consecutive_failures_wrong_type_is_treated_as_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text(
                '{"sources": {"daily-run": {"status": "ok", "consecutiveFailures": "two"}}}',
                encoding="utf-8",
            )
            self.assertEqual(fw.read_health_state(path), {"sources": {}})

    def test_consecutive_failures_boolean_is_treated_as_empty(self):
        """bool is a subclass of int in Python -- a stray `true` here must not silently pass a
        naive isinstance(x, int) check."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text(
                '{"sources": {"daily-run": {"status": "ok", "consecutiveFailures": true}}}',
                encoding="utf-8",
            )
            self.assertEqual(fw.read_health_state(path), {"sources": {}})

    def test_items_collected_wrong_type_is_treated_as_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text(
                '{"sources": {"daily-run": {"status": "ok", "itemsCollected": "lots"}}}',
                encoding="utf-8",
            )
            self.assertEqual(fw.read_health_state(path), {"sources": {}})

    def test_duration_seconds_wrong_type_is_treated_as_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text(
                '{"sources": {"daily-run": {"status": "ok", "durationSeconds": "fast"}}}',
                encoding="utf-8",
            )
            self.assertEqual(fw.read_health_state(path), {"sources": {}})

    def test_last_error_wrong_type_is_treated_as_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text(
                '{"sources": {"daily-run": {"status": "error", "lastError": {"nested": "object"}}}}',
                encoding="utf-8",
            )
            self.assertEqual(fw.read_health_state(path), {"sources": {}})

    def test_a_fully_valid_record_still_passes(self):
        """Sanity check for the stricter validator: a normal, well-formed record must not be
        rejected."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text(
                '{"sources": {"daily-run": {'
                '"status": "ok", "lastAttemptAt": "2026-07-17T07:23:35.123456Z", '
                '"lastSuccessAt": "2026-07-17T07:23:35.123456Z", "consecutiveFailures": 0, '
                '"itemsCollected": 14584, "durationSeconds": 508.979, "lastError": null'
                '}}}',
                encoding="utf-8",
            )
            state = fw.read_health_state(path)
            self.assertEqual(state["sources"]["daily-run"]["itemsCollected"], 14584)

    def test_main_completes_despite_an_invalid_timestamp_in_the_health_file(self):
        """The literal bug report: a health file with a garbled lastAttemptAt used to raise
        ValueError inside main() (via read_health_state() -> classify checks downstream) and
        take the whole collection down with it."""
        with tempfile.TemporaryDirectory() as tmp:
            base_path = Path(tmp) / "state.json"
            fw.write_json(base_path, fw.normalize_state({}))
            health_path = Path(tmp) / "health.json"
            health_path.write_text(
                '{"sources": {"daily-run": {"status": "ok", "lastAttemptAt": "not-a-date"}}}',
                encoding="utf-8",
            )

            exit_code = fw.main([
                "--skip-network",
                "--base", str(base_path), "--output", str(base_path),
                "--report", str(Path(tmp) / "report.md"), "--health-output", str(health_path),
            ])
            self.assertEqual(exit_code, 0)
            health_state = fw.read_json(health_path, None)
            self.assertIsNotNone(health_state, "health tracking must self-heal with a fresh, valid file")

    def test_main_completes_despite_a_timezone_naive_timestamp_in_the_health_file(self):
        """Distinct from the "not-a-date" garbage case above: this timestamp IS a syntactically
        valid ISO 8601 string (fromisoformat() parses it without raising) -- it's just missing a
        timezone, which used to slip past the old validator (only checked "does it parse") and
        raise TypeError once compared against an aware datetime deep inside main()'s health
        bookkeeping."""
        with tempfile.TemporaryDirectory() as tmp:
            base_path = Path(tmp) / "state.json"
            fw.write_json(base_path, fw.normalize_state({}))
            health_path = Path(tmp) / "health.json"
            health_path.write_text(
                '{"sources": {"daily-run": {"status": "ok", "lastAttemptAt": "2026-07-17T07:00:00"}}}',
                encoding="utf-8",
            )

            exit_code = fw.main([
                "--skip-network",
                "--base", str(base_path), "--output", str(base_path),
                "--report", str(Path(tmp) / "report.md"), "--health-output", str(health_path),
            ])
            self.assertEqual(exit_code, 0)
            health_state = fw.read_json(health_path, None)
            self.assertIsNotNone(health_state, "health tracking must self-heal with a fresh, valid file")

    def test_health_mark_running_recovers_from_a_corrupt_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text("{corrupt", encoding="utf-8")
            started_at = fw.health_mark_running(path, fw.SOURCE_FORTIOS_DOCS)
            state = fw.read_json(path, None)
            self.assertIsNotNone(state, "a fresh, valid file must be written despite starting from corruption")
            self.assertEqual(state["sources"][fw.SOURCE_FORTIOS_DOCS]["lastAttemptAt"], started_at)

    def test_record_health_results_recovers_from_a_corrupt_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text('{"sources": [1, 2, 3]}', encoding="utf-8")
            fw.record_health_results(path, {
                fw.SOURCE_FORTIOS_DOCS: fw.HealthSourceResult(
                    status=fw.HEALTH_STATUS_OK, started_at="2026-07-17T07:15:00.000000Z", duration_seconds=1.0,
                    items_collected=10,
                ),
            })
            state = fw.read_json(path, None)
            self.assertEqual(state["sources"][fw.SOURCE_FORTIOS_DOCS]["itemsCollected"], 10)

    def test_main_completes_and_writes_a_catalog_despite_a_corrupt_health_file(self):
        """The literal bug report: a garbled fortios-health.json used to raise JSONDecodeError
        at the very top of main() (reading health_before), before any collection even started,
        taking the whole run down with it."""
        with tempfile.TemporaryDirectory() as tmp:
            base_path = Path(tmp) / "state.json"
            fw.write_json(base_path, fw.normalize_state({}))
            health_path = Path(tmp) / "health.json"
            health_path.write_text('{"sources": {"broken": [1, 2, 3]}}, trailing garbage', encoding="utf-8")

            exit_code = fw.main([
                "--skip-network",
                "--base", str(base_path), "--output", str(base_path),
                "--report", str(Path(tmp) / "report.md"), "--health-output", str(health_path),
            ])
            self.assertEqual(exit_code, 0)
            self.assertTrue(base_path.exists())
            final_state = fw.read_json(base_path, None)
            self.assertIsNotNone(final_state, "the catalog must still be produced despite the corrupt health file")
            # And health tracking must have self-healed: a fresh, valid file now exists.
            health_state = fw.read_json(health_path, None)
            self.assertIsNotNone(health_state)
            self.assertIn("sources", health_state)


class ReadJsonTolerantOSErrorTests(unittest.TestCase):
    """read_json_tolerant() used to only catch JSON-content errors (JSONDecodeError etc.) -- a
    filesystem-level failure (no read permission, or the file vanishing between the exists()
    check and open() -- a TOCTOU race) still raised straight out of it and could abort the whole
    collection. Every one of these must be treated exactly like a missing file: return `default`,
    never archive (there's nothing reliably readable to preserve), never raise.
    """

    def test_permission_denied_file_is_treated_as_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text('{"sources": {}}', encoding="utf-8")
            path.chmod(0o000)
            try:
                if os.access(path, os.R_OK):
                    self.skipTest("this platform/user (e.g. root) can still read a chmod 000 file")
                result = fw.read_json_tolerant(path, {"sources": {}}, validate=fw._is_valid_health_state)
                self.assertEqual(result, {"sources": {}})
                # Nothing readable to preserve -- must not have tried to archive it.
                archived = list(Path(tmp).glob("health.json.corrupt-*"))
                self.assertEqual(archived, [])
                self.assertTrue(path.exists(), "an unreadable file must be left exactly where it was")
            finally:
                path.chmod(0o644)  # restore so the TemporaryDirectory cleanup can remove it

    def test_file_deleted_between_exists_check_and_open_is_treated_as_default(self):
        """Simulates the TOCTOU race: path.exists() returns True, but the file is gone by the
        time path.open() actually runs."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text('{"sources": {}}', encoding="utf-8")

            original_open = Path.open

            def open_raises_after_first_call(self_path, *args, **kwargs):
                if self_path == path:
                    raise FileNotFoundError(f"[Errno 2] No such file or directory: '{path}'")
                return original_open(self_path, *args, **kwargs)

            with patch.object(Path, "open", open_raises_after_first_call):
                result = fw.read_json_tolerant(path, {"sources": {}}, validate=fw._is_valid_health_state)
            self.assertEqual(result, {"sources": {}})

    def test_permission_error_on_open_is_treated_as_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text('{"sources": {}}', encoding="utf-8")

            original_open = Path.open

            def open_denies_this_path(self_path, *args, **kwargs):
                if self_path == path:
                    raise PermissionError(f"[Errno 13] Permission denied: '{path}'")
                return original_open(self_path, *args, **kwargs)

            with patch.object(Path, "open", open_denies_this_path):
                result = fw.read_json_tolerant(path, {"sources": {}}, validate=fw._is_valid_health_state)
            self.assertEqual(result, {"sources": {}})
            # A permission error means we can't reliably read OR rewrite the file -- must not
            # attempt to archive (rename) it either.
            archived = list(Path(tmp).glob("health.json.corrupt-*"))
            self.assertEqual(archived, [])

    def test_main_continues_despite_a_permission_error_reading_the_health_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            base_path = Path(tmp) / "state.json"
            fw.write_json(base_path, fw.normalize_state({}))
            health_path = Path(tmp) / "health.json"
            health_path.write_text('{"sources": {}}', encoding="utf-8")

            original_open = Path.open

            def open_denies_only_the_health_file(self_path, *args, **kwargs):
                if self_path == health_path:
                    raise PermissionError(f"[Errno 13] Permission denied: '{health_path}'")
                return original_open(self_path, *args, **kwargs)

            with patch.object(Path, "open", open_denies_only_the_health_file):
                exit_code = fw.main([
                    "--skip-network",
                    "--base", str(base_path), "--output", str(base_path),
                    "--report", str(Path(tmp) / "report.md"), "--health-output", str(health_path),
                ])
            self.assertEqual(exit_code, 0, "a health file the process can't even read must never abort the collection")
            self.assertTrue(base_path.exists())


class SourceSeverityClassificationTests(unittest.TestCase):
    NOW = "2026-07-16T12:00:00Z"

    def test_recent_success_is_green(self):
        record = {"status": fw.HEALTH_STATUS_OK, "lastSuccessAt": "2026-07-16T07:15:00Z", "consecutiveFailures": 0}
        self.assertEqual(fw.classify_source_severity(record, now=self.NOW), "ok")

    def test_data_older_than_48h_is_red(self):
        record = {"status": fw.HEALTH_STATUS_OK, "lastSuccessAt": "2026-07-13T07:15:00Z", "consecutiveFailures": 0}
        self.assertEqual(fw.classify_source_severity(record, now=self.NOW), "error")

    def test_repeated_failure_is_red_even_if_recent(self):
        record = {
            "status": fw.HEALTH_STATUS_ERROR, "lastSuccessAt": "2026-07-16T07:15:00Z",
            "consecutiveFailures": 2,
        }
        self.assertEqual(fw.classify_source_severity(record, now=self.NOW), "error")

    def test_single_recent_failure_is_orange(self):
        record = {
            "status": fw.HEALTH_STATUS_ERROR, "lastSuccessAt": "2026-07-16T07:15:00Z",
            "consecutiveFailures": 1,
        }
        self.assertEqual(fw.classify_source_severity(record, now=self.NOW), "warning")

    def test_skipped_source_is_orange(self):
        record = {"status": fw.HEALTH_STATUS_SKIPPED, "lastSuccessAt": "2026-07-16T07:15:00Z", "consecutiveFailures": 0}
        self.assertEqual(fw.classify_source_severity(record, now=self.NOW), "warning")

    def test_never_succeeded_is_red(self):
        record = {"status": fw.HEALTH_STATUS_ERROR, "consecutiveFailures": 1}
        self.assertEqual(fw.classify_source_severity(record, now=self.NOW), "error")

    def test_mid_collection_with_no_prior_success_is_orange_not_red(self):
        """Regression: a source legitimately still running (its own health_mark_running() stamp,
        no lastSuccessAt yet because it's the very first collection) was being classified as a
        hard error, which showed several perfectly healthy in-progress sources as "en erreur"
        during a real, otherwise-successful ~5 minute production run (FortiClient scraping alone
        took over 3 minutes) -- a false alarm, not a real failure."""
        record = {"status": fw.HEALTH_STATUS_RUNNING, "consecutiveFailures": 0}
        self.assertEqual(fw.classify_source_severity(record, now=self.NOW), "warning")

    def test_still_running_but_previously_failing_stays_red(self):
        record = {"status": fw.HEALTH_STATUS_RUNNING, "consecutiveFailures": 2}
        self.assertEqual(fw.classify_source_severity(record, now=self.NOW), "error")

    def test_warning_status_with_no_prior_success_is_orange_not_red(self):
        """Regression: a "warning" record with no lastSuccessAt (e.g. hand-built state, or data
        written before _merge_health_source() started stamping lastSuccessAt on warnings) was
        being mapped to "error" because the exemption list only covered running/skipped, not
        warning -- a real production false alarm ("1 source(s) en erreur") for what was actually
        a minor warning, not a failure."""
        record = {"status": fw.HEALTH_STATUS_WARNING, "consecutiveFailures": 0}
        self.assertEqual(fw.classify_source_severity(record, now=self.NOW), "warning")


class MainHealthWiringIntegrationTests(unittest.TestCase):
    """Exercises the actual main() wiring end-to-end, not just the underlying primitives in
    isolation -- that gap (a passing unit test for replace_cves_for_advisory() alone, while
    main()'s real commit sequence still resurrected the CVE) is exactly what let a real bug ship
    in an earlier round despite "passing tests", so every source's health recording here is
    checked against a real main() invocation.
    """

    def test_skip_network_run_marks_every_source_skipped_and_daily_run_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            base_path = Path(tmp) / "state.json"
            fw.write_json(base_path, fw.normalize_state({}))
            health_path = Path(tmp) / "health.json"

            exit_code = fw.main([
                "--skip-network", "--docs-catalog", "--tool-products", "fortianalyzer,fortimanager",
                "--forticlient-catalog", "--cve-catalog",
                "--base", str(base_path), "--output", str(base_path),
                "--report", str(Path(tmp) / "report.md"), "--health-output", str(health_path),
            ])
            self.assertEqual(exit_code, 0)

            health = fw.read_json(health_path, {})
            sources = health["sources"]
            for source_id in (
                fw.SOURCE_FORTIOS_DOCS, fw.SOURCE_FORTIOS_LIFECYCLE, fw.SOURCE_FORTIANALYZER,
                fw.SOURCE_FORTIMANAGER, fw.SOURCE_FORTICLIENT, fw.SOURCE_FORTICLIENT_EMS,
                fw.SOURCE_CVE_PSIRT,
            ):
                self.assertEqual(
                    sources[source_id]["status"], fw.HEALTH_STATUS_SKIPPED,
                    f"{source_id} should be skipped under --skip-network",
                )
            self.assertEqual(sources[fw.SOURCE_DAILY_RUN]["status"], fw.HEALTH_STATUS_OK)
            # compat-matrix is exclusively import_forticlient_compat.py's responsibility.
            self.assertNotIn(fw.SOURCE_COMPAT_MATRIX, sources)

    def test_a_failing_source_does_not_abort_the_run_and_is_recorded_as_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            base_path = Path(tmp) / "state.json"
            fw.write_json(base_path, fw.normalize_state({}))
            health_path = Path(tmp) / "health.json"

            original = fw.discover_docs_versions
            fw.discover_docs_versions = lambda *a, **k: (_ for _ in ()).throw(TimeoutError("docs.fortinet.com unreachable"))
            try:
                exit_code = fw.main([
                    "--docs-catalog", "--docs-major-versions", "8.0",
                    "--base", str(base_path), "--output", str(base_path),
                    "--report", str(Path(tmp) / "report.md"), "--health-output", str(health_path),
                    "--timeout", "5",
                ])
            finally:
                fw.discover_docs_versions = original

            self.assertEqual(exit_code, 0, "one source failing must not crash the whole run")
            health = fw.read_json(health_path, {})
            docs_record = health["sources"][fw.SOURCE_FORTIOS_DOCS]
            self.assertEqual(docs_record["status"], fw.HEALTH_STATUS_ERROR)
            self.assertIn("unreachable", docs_record["lastError"])
            self.assertEqual(health["sources"][fw.SOURCE_DAILY_RUN]["status"], fw.HEALTH_STATUS_ERROR)
            self.assertIn(fw.SOURCE_FORTIOS_DOCS, health["sources"][fw.SOURCE_DAILY_RUN]["lastError"])


if __name__ == "__main__":
    unittest.main()
