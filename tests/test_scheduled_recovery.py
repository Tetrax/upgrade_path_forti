"""Targeted 07:45 recovery shared by host systemd and the Docker scheduler."""

import concurrent.futures
import datetime as dt
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from zoneinfo import ZoneInfo

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import container_scheduler as scheduler
import scheduled_refresh as refresh


def _write_health(path: Path, sources: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"sources": sources}), encoding="utf-8")


class _Completed:
    def __init__(self, returncode: int):
        self.returncode = returncode


class RetryPlanTests(unittest.TestCase):
    def test_only_failed_sources_are_selected_and_coupled_collectors_are_deduplicated(self):
        health = {
            "sources": {
                "fortios-docs": {"status": "error"},
                "fortios-lifecycle": {"status": "ok"},
                "fortianalyzer": {"status": "error"},
                "fortimanager": {"status": "ok"},
                "forticlient": {"status": "error"},
                "forticlient-ems": {"status": "error"},
                "cve-psirt": {"status": "ok"},
                "compat-matrix": {"status": "error"},
                "daily-run": {"status": "error"},
            }
        }

        plan = refresh.build_retry_plan(health)

        self.assertEqual(
            plan.catalog_args,
            ("--docs-catalog", "--tool-products", "fortianalyzer", "--forticlient-catalog"),
        )
        self.assertTrue(plan.compatibility)
        self.assertEqual(
            set(plan.source_ids),
            {"fortios-docs", "fortianalyzer", "forticlient", "forticlient-ems", "compat-matrix"},
        )

    def test_no_retry_is_planned_when_every_real_source_is_healthy(self):
        health = {
            "sources": {
                source: {"status": "ok", "consecutiveFailures": 0}
                for source in refresh.RETRYABLE_SOURCE_IDS
            }
        }
        health["sources"]["daily-run"] = {"status": "error"}

        plan = refresh.build_retry_plan(health)

        self.assertFalse(plan.catalog_args)
        self.assertFalse(plan.compatibility)
        self.assertFalse(plan.source_ids)

    def test_source_left_running_by_a_crashed_full_job_is_retried_after_lock_release(self):
        plan = refresh.build_retry_plan({
            "sources": {"forticlient": {"status": "running"}}
        })

        self.assertEqual(plan.catalog_args, ("--forticlient-catalog",))
        self.assertEqual(plan.source_ids, ("forticlient",))

    def test_empty_catalog_warning_is_selected_for_targeted_recovery(self):
        plan = refresh.build_retry_plan({
            "sources": {
                "fortimanager": {
                    "status": "warning",
                    "consecutiveFailures": 0,
                    "lastError": "Aucune version collectée pour fortimanager",
                },
                "cve-psirt": {
                    "status": "warning",
                    "consecutiveFailures": 0,
                    "lastError": "1 avis PSIRT ignoré après les tentatives",
                },
            }
        })

        self.assertEqual(plan.catalog_args, ("--tool-products", "fortimanager"))
        self.assertEqual(plan.source_ids, ("fortimanager",))


class RecoveryExecutionTests(unittest.TestCase):
    def test_recovery_runs_one_combined_scoped_catalog_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "data").mkdir()
            health_path = root / "data" / "fortios-health.json"
            health_path.write_text(
                json.dumps({
                    "sources": {
                        "fortianalyzer": {"status": "error"},
                        "forticlient": {"status": "error"},
                        "forticlient-ems": {"status": "error"},
                    }
                }),
                encoding="utf-8",
            )
            calls = []

            def runner(command, **kwargs):
                calls.append((command, kwargs))
                # Simulate the targeted collector repairing every selected source.
                health_path.write_text(
                    json.dumps({
                        "sources": {
                            "fortianalyzer": {"status": "ok"},
                            "forticlient": {"status": "ok"},
                            "forticlient-ems": {"status": "ok"},
                        }
                    }),
                    encoding="utf-8",
                )
                return type("Completed", (), {"returncode": 0})()

            result = refresh.run_recovery(root=root, runner=runner, python="python-test")

        self.assertEqual(result, 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(
            calls[0][0],
            [
                "python-test", "scripts/fortios_watch.py",
                "--base", "data/fortios-data.generated.json",
                "--tool-products", "fortianalyzer",
                "--forticlient-catalog",
            ],
        )
        self.assertEqual(calls[0][1]["cwd"], root)

    def test_new_failure_in_a_coupled_peer_gets_one_bounded_follow_up_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "data").mkdir()
            health_path = root / refresh.DEFAULT_HEALTH_PATH
            _write_health(health_path, {
                refresh.SOURCE_FORTIOS_DOCS: {"status": "error", "consecutiveFailures": 1},
                refresh.SOURCE_FORTIOS_LIFECYCLE: {"status": "ok", "consecutiveFailures": 0},
            })
            calls = []

            def runner(command, **kwargs):
                calls.append(command)
                _write_health(health_path, {
                    refresh.SOURCE_FORTIOS_DOCS: {"status": "ok", "consecutiveFailures": 0},
                    refresh.SOURCE_FORTIOS_LIFECYCLE: {
                        "status": "error" if len(calls) == 1 else "ok",
                        "consecutiveFailures": 1 if len(calls) == 1 else 0,
                    },
                })
                return _Completed(0)

            result = refresh.run_recovery(root=root, runner=runner, python="python-test")

        self.assertEqual(result, 0)
        self.assertEqual(len(calls), 2)
        self.assertIn("--docs-catalog", calls[0])
        self.assertIn("--docs-catalog", calls[1])

    def test_scoped_daily_run_today_does_not_replace_missing_full_refresh(self):
        paris = ZoneInfo("Europe/Paris")
        now = dt.datetime(2026, 7, 30, 7, 45, tzinfo=paris)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            health_path = root / refresh.DEFAULT_HEALTH_PATH
            _write_health(health_path, {
                "daily-run": {
                    "status": "ok", "lastAttemptAt": "2026-07-30T05:30:00+00:00"
                },
                refresh.SOURCE_FORTIOS_DOCS: {"status": "error", "consecutiveFailures": 1},
            })
            calls = []

            def runner(command, **kwargs):
                calls.append(command)
                if any(part.endswith("import_forticlient_compat.py") for part in command):
                    _write_health(health_path, {
                        "daily-run": {
                            "status": "ok", "lastAttemptAt": "2026-07-30T05:30:00+00:00"
                        },
                        refresh.SOURCE_FORTIOS_DOCS: {
                            "status": "error", "consecutiveFailures": 1
                        },
                        refresh.SOURCE_COMPAT_MATRIX: {
                            "status": "ok", "consecutiveFailures": 0
                        },
                    })
                else:
                    _write_health(health_path, {
                        "daily-run": {
                            "status": "ok", "lastAttemptAt": "2026-07-30T05:30:00+00:00"
                        },
                        refresh.SOURCE_FORTIOS_DOCS: {
                            "status": "ok", "consecutiveFailures": 0
                        },
                        refresh.SOURCE_COMPAT_MATRIX: {
                            "status": "ok", "consecutiveFailures": 0
                        },
                    })
                return _Completed(0)

            result = refresh.run_recovery(
                root=root,
                runner=runner,
                python="catalog-python",
                compatibility_python="compat-python",
                ensure_full_today=True,
                now=now,
                completion_now_fn=lambda: now,
            )
            marker = json.loads(
                (root / "data" / refresh.FULL_REFRESH_ATTEMPT_NAME).read_text(
                    encoding="utf-8"
                )
            )

        self.assertEqual(result, 0)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][:2], ["compat-python", "scripts/import_forticlient_compat.py"])
        self.assertEqual(calls[1][:2], ["catalog-python", "scripts/fortios_watch.py"])
        self.assertEqual(marker["parisDate"], "2026-07-30")

    def test_full_refresh_marker_allows_same_day_targeted_recovery(self):
        paris = ZoneInfo("Europe/Paris")
        now = dt.datetime(2026, 7, 30, 7, 45, tzinfo=paris)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            health_path = root / refresh.DEFAULT_HEALTH_PATH
            _write_health(health_path, {
                refresh.SOURCE_FORTIOS_DOCS: {"status": "error", "consecutiveFailures": 1}
            })
            (root / "data" / refresh.FULL_REFRESH_ATTEMPT_NAME).write_text(
                json.dumps({"parisDate": "2026-07-30"}), encoding="utf-8"
            )
            calls = []

            def runner(command, **kwargs):
                calls.append(command)
                _write_health(health_path, {
                    refresh.SOURCE_FORTIOS_DOCS: {"status": "ok", "consecutiveFailures": 0}
                })
                return _Completed(0)

            result = refresh.run_recovery(
                root=root,
                runner=runner,
                python="catalog-python",
                compatibility_python="compat-python",
                ensure_full_today=True,
                now=now,
            )

        self.assertEqual(result, 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:2], ["catalog-python", "scripts/fortios_watch.py"])
        self.assertIn("--docs-catalog", calls[0])

    def test_repaired_catch_up_still_reports_the_failed_full_attempt(self):
        paris = ZoneInfo("Europe/Paris")
        now = dt.datetime(2026, 7, 30, 7, 45, tzinfo=paris)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            health_path = root / refresh.DEFAULT_HEALTH_PATH
            _write_health(health_path, {
                refresh.SOURCE_FORTIOS_DOCS: {"status": "error", "consecutiveFailures": 1}
            })
            calls = []

            def runner(command, **kwargs):
                calls.append(command)
                if any(part.endswith("import_forticlient_compat.py") for part in command):
                    _write_health(health_path, {
                        refresh.SOURCE_FORTIOS_DOCS: {
                            "status": "error", "consecutiveFailures": 1
                        },
                        refresh.SOURCE_COMPAT_MATRIX: {
                            "status": "ok", "consecutiveFailures": 0
                        },
                    })
                    return _Completed(0)
                if len(calls) == 2:
                    _write_health(health_path, {
                        refresh.SOURCE_FORTIOS_DOCS: {
                            "status": "error", "consecutiveFailures": 2
                        },
                        refresh.SOURCE_COMPAT_MATRIX: {
                            "status": "ok", "consecutiveFailures": 0
                        },
                    })
                    return _Completed(1)
                _write_health(health_path, {
                    refresh.SOURCE_FORTIOS_DOCS: {"status": "ok", "consecutiveFailures": 0},
                    refresh.SOURCE_COMPAT_MATRIX: {"status": "ok", "consecutiveFailures": 0},
                })
                return _Completed(0)

            result = refresh.run_recovery(
                root=root,
                runner=runner,
                python="catalog-python",
                compatibility_python="compat-python",
                ensure_full_today=True,
                now=now,
                completion_now_fn=lambda: now,
            )

        self.assertEqual(result, 1)
        self.assertEqual(len(calls), 3)
        self.assertIn("--docs-catalog", calls[1])
        self.assertIn("--docs-catalog", calls[2])


class FullRefreshExecutionTests(unittest.TestCase):
    def test_compatibility_import_runs_before_catalog_notification_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "data").mkdir()
            calls = []

            def runner(command, **kwargs):
                calls.append(command)
                return _Completed(0)

            refresh.run_full_refresh(
                root=root,
                runner=runner,
                python="catalog-python",
                compatibility_python="compat-python",
            )

        self.assertEqual(calls[0][:2], ["compat-python", "scripts/import_forticlient_compat.py"])
        self.assertEqual(calls[1][:2], ["catalog-python", "scripts/fortios_watch.py"])

    def test_compatibility_spawn_failure_is_recorded_and_catalog_still_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            health_path = root / refresh.DEFAULT_HEALTH_PATH
            _write_health(health_path, {
                refresh.SOURCE_COMPAT_MATRIX: {"status": "ok", "consecutiveFailures": 0}
            })
            calls = []

            def runner(command, **kwargs):
                calls.append(command)
                if any(part.endswith("import_forticlient_compat.py") for part in command):
                    raise OSError("cannot spawn compatibility interpreter")
                return _Completed(0)

            result = refresh.run_full_refresh(
                root=root,
                runner=runner,
                python="catalog-python",
                compatibility_python="compat-python",
            )
            health = refresh.read_health_state(health_path)

        self.assertEqual(result, 1)
        self.assertEqual(len(calls), 2)
        record = health["sources"][refresh.SOURCE_COMPAT_MATRIX]
        self.assertEqual(record["status"], refresh.HEALTH_STATUS_ERROR)
        self.assertEqual(record["consecutiveFailures"], 1)
        self.assertIn("cannot spawn", record["lastError"])

    def test_full_attempt_marker_uses_completion_day_across_paris_midnight(self):
        paris = ZoneInfo("Europe/Paris")
        completed = dt.datetime(2026, 7, 31, 0, 1, tzinfo=paris)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "data").mkdir()

            result = refresh._run_full_and_mark_unlocked(
                root=root,
                runner=lambda command, **kwargs: _Completed(0),
                python="catalog-python",
                compatibility_python="compat-python",
                completion_now_fn=lambda: completed,
            )
            marker = json.loads(
                (root / "data" / refresh.FULL_REFRESH_ATTEMPT_NAME).read_text(
                    encoding="utf-8"
                )
            )

        self.assertEqual(result, 1)
        self.assertEqual(marker["parisDate"], "2026-07-31")
        self.assertEqual(marker["completedAt"], completed.isoformat())
        self.assertEqual(marker["status"], 1)


class CompatibilityNotificationTests(unittest.TestCase):
    def test_compatibility_only_recovery_alerts_at_threshold_and_advances_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            health_path = root / refresh.DEFAULT_HEALTH_PATH
            history_path = root / refresh.DEFAULT_NOTIFY_HISTORY_PATH
            before = {"status": "error", "consecutiveFailures": 1, "lastError": "first"}
            after = {"status": "error", "consecutiveFailures": 2, "lastError": "second"}
            _write_health(health_path, {refresh.SOURCE_COMPAT_MATRIX: after})
            history_path.parent.mkdir(parents=True, exist_ok=True)
            history_path.write_text(json.dumps({
                "sentKeys": {},
                "outbox": [],
                "eolState": {},
                "checkpoint": {
                    "versionsByProduct": {},
                    "cvesById": {},
                    "health": {refresh.SOURCE_COMPAT_MATRIX: before},
                },
            }), encoding="utf-8")
            config = MagicMock(enabled=True, app_url="https://example.test/app/")

            with (
                patch.object(refresh.fortios_notify, "load_email_config", return_value=config),
                patch.object(refresh.fortios_notify, "send_email", return_value=True) as send,
            ):
                refresh._notify_compatibility_transition(root=root)

            notify_state = refresh.fortios_notify.load_notify_state(history_path)

        send.assert_called_once()
        checkpoint_record = notify_state["checkpoint"]["health"][refresh.SOURCE_COMPAT_MATRIX]
        self.assertEqual(checkpoint_record["consecutiveFailures"], 2)
        self.assertTrue(notify_state["sentKeys"])

    def test_disabled_settings_advance_compatibility_checkpoint_without_sending(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            health_path = root / refresh.DEFAULT_HEALTH_PATH
            history_path = root / refresh.DEFAULT_NOTIFY_HISTORY_PATH
            settings_path = root / refresh.DEFAULT_NOTIFICATION_SETTINGS_PATH
            before = {"status": "error", "consecutiveFailures": 1}
            after = {"status": "error", "consecutiveFailures": 2}
            _write_health(health_path, {refresh.SOURCE_COMPAT_MATRIX: after})
            history_path.parent.mkdir(parents=True, exist_ok=True)
            history_path.write_text(
                json.dumps(
                    {
                        "sentKeys": {},
                        "outbox": [],
                        "eolState": {},
                        "checkpoint": {
                            "versionsByProduct": {},
                            "cvesById": {},
                            "health": {refresh.SOURCE_COMPAT_MATRIX: before},
                        },
                    }
                ),
                encoding="utf-8",
            )
            settings_path.write_text("{}", encoding="utf-8")
            config = MagicMock(enabled=False)

            with (
                patch.object(
                    refresh.fortios_notify, "load_email_config", return_value=config
                ),
                patch.object(refresh.fortios_notify, "send_email") as send,
            ):
                refresh._notify_compatibility_transition(root=root)

            notify_state = refresh.fortios_notify.load_notify_state(history_path)

        send.assert_not_called()
        checkpoint_record = notify_state["checkpoint"]["health"][
            refresh.SOURCE_COMPAT_MATRIX
        ]
        self.assertEqual(checkpoint_record["consecutiveFailures"], 2)
        self.assertEqual(notify_state["outbox"], [])


class SystemdDeploymentTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1]

    def test_host_recovery_timer_runs_at_0745_paris(self):
        timer = (self.ROOT / "deploy" / "fortios-recovery.timer").read_text(encoding="utf-8")
        self.assertIn("OnCalendar=*-*-* 07:45:00 Europe/Paris", timer)
        self.assertIn("Persistent=true", timer)

    def test_host_recovery_waits_for_simultaneous_persistent_full_catchup(self):
        service = (self.ROOT / "deploy" / "fortios-recovery.service").read_text(encoding="utf-8")
        self.assertIn("After=fortios-catalog-refresh.service", service)

    def test_host_services_use_the_same_shared_runner_as_docker(self):
        full = (self.ROOT / "deploy" / "fortios-catalog-refresh.service").read_text(encoding="utf-8")
        recovery = (self.ROOT / "deploy" / "fortios-recovery.service").read_text(encoding="utf-8")
        cve = (self.ROOT / "deploy" / "fortios-cve-afternoon-refresh.service").read_text(encoding="utf-8")
        self.assertIn("scripts/scheduled_refresh.py full", full)
        self.assertIn("scripts/scheduled_refresh.py recovery", recovery)
        self.assertIn("scripts/scheduled_refresh.py cve", cve)

    def test_installer_enables_the_recovery_timer(self):
        installer = (self.ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
        self.assertIn("fortios-recovery.service", installer)
        self.assertIn("fortios-recovery.timer", installer)
        self.assertIn("enable --now fortios-recovery.timer", installer)


class ContainerScheduleTests(unittest.TestCase):
    PARIS = ZoneInfo("Europe/Paris")

    def test_recovery_is_the_next_job_at_0745(self):
        now = dt.datetime(2026, 7, 30, 7, 30, tzinfo=self.PARIS)
        scheduled, job = scheduler.next_job(now)
        self.assertEqual(job, "recovery")
        self.assertEqual((scheduled.hour, scheduled.minute), (7, 45))

    def test_recovery_is_run_immediately_when_full_refresh_overruns_0745(self):
        now_values = iter([
            dt.datetime(2026, 7, 30, 7, 0, tzinfo=self.PARIS),
            dt.datetime(2026, 7, 30, 7, 50, tzinfo=self.PARIS),
        ])
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(scheduler, "run_full_refresh", return_value=0),
            patch.object(scheduler, "run_recovery", return_value=0) as recovery,
        ):
            scheduler.run_scheduled_job(
                "full", now_fn=lambda: next(now_values), marker_path=Path(tmp) / "recovery.lock"
            )

        recovery.assert_called_once_with(ensure_full_today=True)

    def test_failed_full_refresh_still_runs_overdue_recovery(self):
        now_values = iter([
            dt.datetime(2026, 7, 30, 7, 0, tzinfo=self.PARIS),
            dt.datetime(2026, 7, 30, 7, 50, tzinfo=self.PARIS),
        ])
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(scheduler, "run_full_refresh", return_value=1),
            patch.object(scheduler, "run_recovery", return_value=0) as recovery,
        ):
            result = scheduler.run_scheduled_job(
                "full", now_fn=lambda: next(now_values), marker_path=Path(tmp) / "recovery.lock"
            )

        self.assertEqual(result, 1)
        recovery.assert_called_once_with(ensure_full_today=True)

    def test_restart_after_afternoon_still_catches_up_the_missed_recovery(self):
        now = dt.datetime(2026, 7, 30, 18, 0, tzinfo=self.PARIS)
        self.assertTrue(scheduler._recovery_missed_during_restart(now))

    def test_repeated_restarts_only_attempt_recovery_once_per_paris_day(self):
        now = dt.datetime(2026, 7, 30, 18, 0, tzinfo=self.PARIS)
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            scheduler, "run_recovery", return_value=1
        ) as recovery:
            marker = Path(tmp) / "recovery.lock"
            first = scheduler.run_recovery_once(now=now, marker_path=marker)
            second = scheduler.run_recovery_once(now=now, marker_path=marker)

        self.assertEqual(first, 1)
        self.assertEqual(second, 0)
        recovery.assert_called_once_with(ensure_full_today=True)

    def test_concurrent_schedulers_claim_only_one_daily_recovery_attempt(self):
        now = dt.datetime(2026, 7, 30, 18, 0, tzinfo=self.PARIS)
        entered = threading.Event()
        release = threading.Event()

        def slow_recovery(**kwargs):
            entered.set()
            release.wait(timeout=2)
            return 0

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(scheduler, "run_recovery", side_effect=slow_recovery) as recovery,
            concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool,
        ):
            marker = Path(tmp) / "recovery.lock"
            first = pool.submit(scheduler.run_recovery_once, now=now, marker_path=marker)
            self.assertTrue(entered.wait(timeout=2))
            second = pool.submit(scheduler.run_recovery_once, now=now, marker_path=marker)
            release.set()
            results = [first.result(timeout=2), second.result(timeout=2)]

        self.assertEqual(results, [0, 0])
        recovery.assert_called_once_with(ensure_full_today=True)


if __name__ == "__main__":
    unittest.main()
