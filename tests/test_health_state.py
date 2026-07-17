"""Covers scripts/fortios_watch.py's health-state tracking (data/fortios-health.json).

Each source (fortios-docs, fortianalyzer, fortimanager, forticlient, forticlient-ems, cve-psirt,
fortios-lifecycle, compat-matrix, daily-run) gets a record tracking status, timing, item counts,
and consecutive-failure streaks, written to a file separate from the main catalog so a health
check never touches (or risks corrupting) the actual data.
"""

import multiprocessing
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_watch as fw  # noqa: E402


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
        def writer(path, source_id, started_at, hold_seconds, barrier):
            barrier.wait()
            with fw.cross_process_lock(path):
                state = fw.read_json(path, {"sources": {}})
                time.sleep(hold_seconds)  # widen the window a real race would need to slip through
                state.setdefault("sources", {})[source_id] = {"status": "ok", "lastAttemptAt": started_at}
                fw.write_json(path, state)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            fw.write_json(path, {"sources": {}})
            barrier = multiprocessing.Barrier(2)
            p1 = multiprocessing.Process(target=writer, args=(path, "source-a", "t1", 0.3, barrier))
            p2 = multiprocessing.Process(target=writer, args=(path, "source-b", "t2", 0.3, barrier))
            p1.start()
            p2.start()
            p1.join(timeout=5)
            p2.join(timeout=5)

            state = fw.read_json(path, {})
            # Both writes must have landed -- if the lock didn't serialize them, one process's
            # read-modify-write could have clobbered the other's addition entirely.
            self.assertIn("source-a", state["sources"])
            self.assertIn("source-b", state["sources"])


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
