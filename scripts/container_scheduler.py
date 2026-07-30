#!/usr/bin/env python3
"""Run FortiOS refreshes inside the scheduler container.

Mirrors the legacy host timers at 07:00 (full), 07:45 (targeted recovery), and 15:30 (CVE)
in Europe/Paris.  The recovery pass retries only sources left in error by the full run.
Set FORTIOS_RUN_ON_START=1 for a deliberate initial full refresh after migration.
"""

from __future__ import annotations

import fcntl
import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from scheduled_refresh import run_cve_refresh, run_full_refresh, run_recovery

PARIS = ZoneInfo("Europe/Paris")
MORNING = (7, 0)
RECOVERY = (7, 45)
AFTERNOON = (15, 30)
RECOVERY_ATTEMPT_PATH = Path(__file__).resolve().parents[1] / "data" / "fortios-recovery-attempt.lock"


def next_job(now: datetime) -> tuple[datetime, str]:
    candidates: list[tuple[datetime, str]] = []
    for day_offset in range(2):
        day = (now + timedelta(days=day_offset)).date()
        for hour, minute, job in (
            (*MORNING, "full"),
            (*RECOVERY, "recovery"),
            (*AFTERNOON, "cve"),
        ):
            scheduled = datetime(day.year, day.month, day.day, hour, minute, tzinfo=PARIS)
            if scheduled > now:
                candidates.append((scheduled, job))
    return min(candidates, key=lambda candidate: candidate[0])


def sleep_until(when: datetime) -> None:
    while True:
        remaining = (when - datetime.now(PARIS)).total_seconds()
        if remaining <= 0:
            return
        time.sleep(min(remaining, 60))


def run_recovery_once(*, now: datetime, marker_path: Path = RECOVERY_ATTEMPT_PATH) -> int:
    """Bound restart catch-up to one recovery attempt per Europe/Paris calendar day."""
    paris_now = now.astimezone(PARIS)
    try:
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        with marker_path.open("a+", encoding="utf-8") as marker:
            # Hold this advisory lock through recovery. A second scheduler waits, then sees the
            # winner's date and exits without invoking the collectors a second time.
            fcntl.flock(marker.fileno(), fcntl.LOCK_EX)
            marker.seek(0)
            try:
                payload = json.loads(marker.read() or "{}")
            except (ValueError, TypeError):
                payload = {}
            if payload.get("parisDate") == paris_now.date().isoformat():
                print("07:45 recovery was already attempted today; skipping duplicate.", flush=True)
                return 0
            # Persist before starting: a container killed mid-collection must not retry forever
            # under a restart policy. The next normal opportunity is the following Paris day.
            marker.seek(0)
            marker.truncate()
            json.dump({
                "parisDate": paris_now.date().isoformat(),
                "attemptedAt": paris_now.isoformat(),
            }, marker)
            marker.flush()
            os.fsync(marker.fileno())
            return run_recovery(ensure_full_today=True)
    except OSError as error:
        print(f"Cannot persist recovery attempt marker: {error}", flush=True)
        return 1


def run_scheduled_job(
    job: str,
    *,
    now_fn=None,
    marker_path: Path = RECOVERY_ATTEMPT_PATH,
) -> int:
    now_fn = now_fn or (lambda: datetime.now(PARIS))
    started = now_fn()
    if job == "full":
        result = run_full_refresh()
    elif job == "recovery":
        result = run_recovery_once(now=started, marker_path=marker_path)
    else:
        result = run_cve_refresh()
    finished = now_fn()

    # A slow 07:00 run can finish after 07:45, by which point next_job() would otherwise skip
    # today's recovery slot. Run it immediately after the full lock is released instead.
    recovery_due = datetime(
        finished.year, finished.month, finished.day, *RECOVERY, tzinfo=PARIS
    )
    if job == "full" and started.date() == finished.date() and finished >= recovery_due:
        recovery_result = run_recovery_once(now=finished, marker_path=marker_path)
        if result == 0:
            result = recovery_result
    return result


def _recovery_missed_during_restart(now: datetime) -> bool:
    recovery_at = datetime(now.year, now.month, now.day, *RECOVERY, tzinfo=PARIS)
    return recovery_at <= now


def main() -> int:
    now = datetime.now(PARIS)
    if os.environ.get("FORTIOS_RUN_ON_START") == "1":
        print("Running requested initial full refresh.", flush=True)
        run_scheduled_job("full")
    elif _recovery_missed_during_restart(now):
        # Container restarted after 07:45: perform the cheap health check/recovery once rather
        # than silently waiting until tomorrow. Healthy state exits without network requests.
        print("Running missed 07:45 recovery check after scheduler restart.", flush=True)
        run_recovery_once(now=now)

    while True:
        scheduled, job = next_job(datetime.now(PARIS))
        print(f"Next {job} refresh at {scheduled.isoformat()}", flush=True)
        sleep_until(scheduled)
        print(f"Starting {job} refresh.", flush=True)
        result = run_scheduled_job(job)
        print(f"{job} refresh exited with status {result}.", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
