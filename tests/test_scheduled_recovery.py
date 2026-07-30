"""Targeted 07:45 recovery shared by host systemd and the Docker scheduler."""

import datetime as dt
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zoneinfo import ZoneInfo

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import container_scheduler as scheduler  # noqa: E402
import scheduled_refresh as refresh  # noqa: E402


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


class SystemdDeploymentTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1]

    def test_host_recovery_timer_runs_at_0745_paris(self):
        timer = (self.ROOT / "deploy" / "fortios-recovery.timer").read_text(encoding="utf-8")
        self.assertIn("OnCalendar=*-*-* 07:45:00 Europe/Paris", timer)
        self.assertIn("Persistent=true", timer)

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
            patch.object(scheduler, "run_full_refresh", return_value=0),
            patch.object(scheduler, "run_recovery", return_value=0) as recovery,
        ):
            scheduler.run_scheduled_job("full", now_fn=lambda: next(now_values))

        recovery.assert_called_once_with()

    def test_failed_full_refresh_still_runs_overdue_recovery(self):
        now_values = iter([
            dt.datetime(2026, 7, 30, 7, 0, tzinfo=self.PARIS),
            dt.datetime(2026, 7, 30, 7, 50, tzinfo=self.PARIS),
        ])
        with (
            patch.object(scheduler, "run_full_refresh", return_value=1),
            patch.object(scheduler, "run_recovery", return_value=0) as recovery,
        ):
            result = scheduler.run_scheduled_job("full", now_fn=lambda: next(now_values))

        self.assertEqual(result, 1)
        recovery.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
