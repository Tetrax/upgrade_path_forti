#!/usr/bin/env python3
"""Run FortiOS catalog refreshes inside the scheduler container.

The legacy host deployment uses systemd timers at 07:00 and 15:30 Europe/Paris.
This process preserves those two jobs without requiring systemd in a container.
Set FORTIOS_RUN_ON_START=1 for a deliberate initial full refresh after migration.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
PARIS = ZoneInfo("Europe/Paris")
MORNING = (7, 0)
AFTERNOON = (15, 30)


def command(*args: str) -> list[str]:
    return [sys.executable, *args]


def run_full_refresh() -> int:
    catalog = command(
        "scripts/fortios_watch.py",
        "--base", "data/fortios-data.generated.json",
        "--docs-catalog",
        "--tool-products", "fortianalyzer,fortimanager",
        "--forticlient-catalog",
        "--cve-catalog",
    )
    status = subprocess.run(catalog, cwd=ROOT, check=False).returncode
    if status != 0:
        return status
    return subprocess.run(
        command("scripts/import_forticlient_compat.py", "--commit"),
        cwd=ROOT,
        check=False,
    ).returncode


def run_cve_refresh() -> int:
    return subprocess.run(
        command(
            "scripts/fortios_watch.py",
            "--base", "data/fortios-data.generated.json",
            "--cve-catalog",
        ),
        cwd=ROOT,
        check=False,
    ).returncode


def next_job(now: datetime) -> tuple[datetime, str]:
    candidates: list[tuple[datetime, str]] = []
    for day_offset in range(2):
        day = (now + timedelta(days=day_offset)).date()
        for hour, minute, job in ((*MORNING, "full"), (*AFTERNOON, "cve")):
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


def main() -> int:
    if os.environ.get("FORTIOS_RUN_ON_START") == "1":
        print("Running requested initial full refresh.", flush=True)
        run_full_refresh()

    while True:
        scheduled, job = next_job(datetime.now(PARIS))
        print(f"Next {job} refresh at {scheduled.isoformat()}", flush=True)
        sleep_until(scheduled)
        print(f"Starting {job} refresh.", flush=True)
        result = run_full_refresh() if job == "full" else run_cve_refresh()
        print(f"{job} refresh exited with status {result}.", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
