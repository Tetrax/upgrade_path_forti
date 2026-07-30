#!/usr/bin/env python3
"""Shared scheduled refresh runner for systemd and the Docker scheduler.

The 07:00 full run records a first source failure without alerting (the notification threshold is
already two consecutive failures).  At 07:45 ``recovery`` reads the health file and retries only
sources that are still red.  A second failure then reaches the existing threshold and emits the
operational alert; a successful retry silently clears the transient first failure.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import os
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fortios_notify
from fortios_watch import (
    DEFAULT_HEALTH_PATH,
    DEFAULT_NOTIFY_HISTORY_PATH,
    HEALTH_SOURCE_LABELS,
    HEALTH_STATUS_ERROR,
    HEALTH_STATUS_RUNNING,
    HealthSourceResult,
    SOURCE_COMPAT_MATRIX,
    SOURCE_CVE_PSIRT,
    SOURCE_FORTIANALYZER,
    SOURCE_FORTICLIENT,
    SOURCE_FORTICLIENT_EMS,
    SOURCE_FORTIMANAGER,
    SOURCE_FORTIOS_DOCS,
    SOURCE_FORTIOS_LIFECYCLE,
    health_mark_running,
    read_json,
    read_health_state,
    record_health_results,
    utc_now,
    utc_now_precise,
    write_json,
)

ROOT = Path(__file__).resolve().parents[1]
PARIS = ZoneInfo("Europe/Paris")
LOCK_NAME = "fortios-scheduled-refresh.lock"
FULL_REFRESH_ATTEMPT_NAME = "fortios-full-refresh-attempt.lock"
RETRYABLE_SOURCE_IDS = (
    SOURCE_FORTIOS_DOCS,
    SOURCE_FORTIOS_LIFECYCLE,
    SOURCE_FORTIANALYZER,
    SOURCE_FORTIMANAGER,
    SOURCE_FORTICLIENT,
    SOURCE_FORTICLIENT_EMS,
    SOURCE_CVE_PSIRT,
    SOURCE_COMPAT_MATRIX,
)
Runner = Callable[..., Any]


@dataclass(frozen=True)
class RetryPlan:
    catalog_args: tuple[str, ...]
    compatibility: bool
    source_ids: tuple[str, ...]
    checked_source_ids: tuple[str, ...]


def _needs_retry(record: dict[str, Any] | None) -> bool:
    # The process-wide lock is held before this state is inspected, so a "running" record cannot
    # belong to a still-active scheduled job. It was left behind by a killed/crashed collector.
    return bool(record and record.get("status") in {HEALTH_STATUS_ERROR, HEALTH_STATUS_RUNNING})


def build_retry_plan(health_state: dict[str, Any]) -> RetryPlan:
    sources = health_state.get("sources") or {}
    failed = tuple(source_id for source_id in RETRYABLE_SOURCE_IDS if _needs_retry(sources.get(source_id)))
    failed_set = set(failed)
    checked = set(failed)
    args: list[str] = []

    if failed_set & {SOURCE_FORTIOS_DOCS, SOURCE_FORTIOS_LIFECYCLE}:
        args.append("--docs-catalog")
        checked.update((SOURCE_FORTIOS_DOCS, SOURCE_FORTIOS_LIFECYCLE))

    tool_products = [
        product
        for source_id, product in (
            (SOURCE_FORTIANALYZER, "fortianalyzer"),
            (SOURCE_FORTIMANAGER, "fortimanager"),
        )
        if source_id in failed_set
    ]
    if tool_products:
        args.extend(("--tool-products", ",".join(tool_products)))

    if failed_set & {SOURCE_FORTICLIENT, SOURCE_FORTICLIENT_EMS}:
        args.append("--forticlient-catalog")
        checked.update((SOURCE_FORTICLIENT, SOURCE_FORTICLIENT_EMS))
    if SOURCE_CVE_PSIRT in failed_set:
        args.append("--cve-catalog")

    return RetryPlan(
        catalog_args=tuple(args),
        compatibility=SOURCE_COMPAT_MATRIX in failed_set,
        source_ids=failed,
        checked_source_ids=tuple(source_id for source_id in RETRYABLE_SOURCE_IDS if source_id in checked),
    )


def _compatibility_python(root: Path) -> str:
    configured = os.environ.get("FORTIOS_COMPAT_PYTHON")
    if configured:
        return configured
    host_venv = root / ".venv-compat" / "bin" / "python3"
    return str(host_venv) if host_venv.exists() else sys.executable


@contextmanager
def refresh_lock(root: Path = ROOT) -> Iterator[None]:
    """Serialize full, recovery, and afternoon runs across systemd/container processes."""
    lock_path = root / "data" / LOCK_NAME
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w", encoding="utf-8") as descriptor:
        fcntl.flock(descriptor.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(descriptor.fileno(), fcntl.LOCK_UN)


def _run(command: list[str], *, root: Path, runner: Runner) -> int:
    return runner(command, cwd=root, check=False).returncode


def _run_compatibility(*, root: Path, runner: Runner, python: str) -> int:
    """Run the importer while preserving a retryable health state even if it cannot spawn or dies."""
    health_path = root / DEFAULT_HEALTH_PATH
    started_at = health_mark_running(health_path, SOURCE_COMPAT_MATRIX)
    started = time.monotonic()
    try:
        status = _run(
            [python, "scripts/import_forticlient_compat.py", "--commit"],
            root=root,
            runner=runner,
        )
    except Exception as error:  # noqa: BLE001 - subprocess launch failures must be recoverable.
        status = 1
        process_error: Any = error
    else:
        record = (read_health_state(health_path).get("sources") or {}).get(SOURCE_COMPAT_MATRIX) or {}
        process_error = (
            f"Compatibility importer exited with status {status} without finalizing health"
            if record.get("status") == HEALTH_STATUS_RUNNING else None
        )

    if process_error is not None:
        record_health_results(health_path, {
            SOURCE_COMPAT_MATRIX: HealthSourceResult(
                status=HEALTH_STATUS_ERROR,
                started_at=started_at or utc_now_precise(),
                duration_seconds=round(time.monotonic() - started, 3),
                error=process_error,
            )
        })
        return status or 1
    return status


def _notify_compatibility_transition(*, root: Path) -> None:
    """Advance the shared checkpoint when recovery only ran the compatibility importer."""
    config = fortios_notify.load_email_config()
    if not config.enabled:
        return
    health_after = read_health_state(root / DEFAULT_HEALTH_PATH).get("sources", {})
    history_path = root / DEFAULT_NOTIFY_HISTORY_PATH
    checkpoint = fortios_notify.ensure_checkpoint(history_path, {
        "versionsByProduct": {},
        "cvesById": {},
        "health": health_after,
    })
    checkpoint_health = checkpoint.get("health") or {}
    compatibility_after = health_after.get(SOURCE_COMPAT_MATRIX)
    events = fortios_notify.derive_source_health_events(
        {SOURCE_COMPAT_MATRIX: checkpoint_health.get(SOURCE_COMPAT_MATRIX) or {}},
        {SOURCE_COMPAT_MATRIX: compatibility_after or {}},
        HEALTH_SOURCE_LABELS,
    )
    new_health = dict(checkpoint_health)
    if compatibility_after is not None:
        new_health[SOURCE_COMPAT_MATRIX] = compatibility_after
    new_checkpoint = dict(checkpoint)
    new_checkpoint["health"] = new_health
    claimant = f"recovery-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    pending = fortios_notify.commit_events_with_checkpoint(
        history_path,
        new_checkpoint,
        events,
        claimant=claimant,
    )
    composed = fortios_notify.compose_email(pending, app_url=config.app_url, run_timestamp=utc_now())
    if not composed:
        return
    subject, body = composed
    if fortios_notify.send_email(config, subject, body):
        fortios_notify.finalize_sent_events(history_path, pending)
    else:
        fortios_notify.release_claim(history_path, claimant)


def _run_full_unlocked(
    *,
    root: Path,
    runner: Runner,
    python: str,
    compatibility_python: str,
) -> int:
    # Import compatibility first so fortios_watch observes its final health state and advances
    # the shared notification checkpoint in the same scheduled run.
    compat_status = _run_compatibility(
        root=root,
        runner=runner,
        python=compatibility_python,
    )
    catalog_status = _run(
        [
            python,
            "scripts/fortios_watch.py",
            "--base", "data/fortios-data.generated.json",
            "--docs-catalog",
            "--tool-products", "fortianalyzer,fortimanager",
            "--forticlient-catalog",
            "--cve-catalog",
        ],
        root=root,
        runner=runner,
    )
    return catalog_status or compat_status


def run_full_refresh(
    *,
    root: Path = ROOT,
    runner: Runner = subprocess.run,
    python: str = sys.executable,
    compatibility_python: str | None = None,
) -> int:
    with refresh_lock(root):
        return _run_full_and_mark_unlocked(
            root=root,
            runner=runner,
            python=python,
            compatibility_python=compatibility_python or _compatibility_python(root),
        )


def _full_refresh_attempted_today(root: Path, now: dt.datetime) -> bool:
    marker = read_json(root / "data" / FULL_REFRESH_ATTEMPT_NAME, {})
    return bool(
        isinstance(marker, dict)
        and marker.get("parisDate") == now.astimezone(PARIS).date().isoformat()
    )


def _run_full_and_mark_unlocked(
    *,
    root: Path,
    runner: Runner,
    python: str,
    compatibility_python: str,
    completion_now_fn: Callable[[], dt.datetime] | None = None,
) -> int:
    status = _run_full_unlocked(
        root=root,
        runner=runner,
        python=python,
        compatibility_python=compatibility_python,
    )
    paris_now = (
        completion_now_fn() if completion_now_fn else dt.datetime.now(PARIS)
    ).astimezone(PARIS)
    # This is deliberately separate from daily-run: scoped CVE/recovery invocations update that
    # aggregate too. Only a returned full runner writes this durable attempt marker.
    write_json(root / "data" / FULL_REFRESH_ATTEMPT_NAME, {
        "parisDate": paris_now.date().isoformat(),
        "completedAt": paris_now.isoformat(),
        "status": status,
    })
    return status


def run_cve_refresh(
    *, root: Path = ROOT, runner: Runner = subprocess.run, python: str = sys.executable
) -> int:
    with refresh_lock(root):
        return _run(
            [python, "scripts/fortios_watch.py", "--base", "data/fortios-data.generated.json", "--cve-catalog"],
            root=root,
            runner=runner,
        )


def run_recovery(
    *,
    root: Path = ROOT,
    runner: Runner = subprocess.run,
    python: str = sys.executable,
    compatibility_python: str | None = None,
    ensure_full_today: bool = False,
    now: dt.datetime | None = None,
    completion_now_fn: Callable[[], dt.datetime] | None = None,
) -> int:
    health_path = root / DEFAULT_HEALTH_PATH
    with refresh_lock(root):
        before_state = read_health_state(health_path)
        catch_up_status = 0
        recovery_now = now or dt.datetime.now(PARIS)
        if ensure_full_today and not _full_refresh_attempted_today(root, recovery_now):
            # Persistent systemd timers can race at boot. If recovery wins the lock, perform the
            # missing full pass here before consulting health instead of consuming prior-day data.
            # Docker restart catch-up uses the same runtime guarantee.
            print("07:45 recovery: today's full refresh is missing; running it first.", flush=True)
            catch_up_status = _run_full_and_mark_unlocked(
                root=root,
                runner=runner,
                python=python,
                compatibility_python=compatibility_python or _compatibility_python(root),
                completion_now_fn=completion_now_fn,
            )
            before_state = read_health_state(health_path)
        plan = build_retry_plan(before_state)
        if not plan.source_ids:
            print("07:45 recovery: every source is healthy; nothing to retry.", flush=True)
            return catch_up_status

        print(f"07:45 recovery: retrying {', '.join(plan.source_ids)}.", flush=True)
        def execute(retry_plan: RetryPlan) -> int:
            status = 0
            if retry_plan.compatibility:
                status = _run_compatibility(
                    root=root,
                    runner=runner,
                    python=compatibility_python or _compatibility_python(root),
                )
            if retry_plan.catalog_args:
                catalog_status = _run(
                    [
                        python,
                        "scripts/fortios_watch.py",
                        "--base", "data/fortios-data.generated.json",
                        *retry_plan.catalog_args,
                    ],
                    root=root,
                    runner=runner,
                )
                status = status or catalog_status
            elif retry_plan.compatibility:
                _notify_compatibility_transition(root=root)
            return status

        command_status = execute(plan)
        touched_sources = set(plan.checked_source_ids)
        after_state = read_health_state(health_path)
        after_sources = after_state.get("sources") or {}
        newly_failed = [
            source_id
            for source_id in plan.checked_source_ids
            if source_id not in plan.source_ids and _needs_retry(after_sources.get(source_id))
        ]
        if newly_failed:
            # A coupled collector can fail a peer that was healthy at 07:45. Give that new failure
            # exactly one bounded follow-up pass so it either recovers or reaches the alert threshold.
            follow_up = build_retry_plan({
                "sources": {source_id: after_sources[source_id] for source_id in newly_failed}
            })
            follow_up_status = execute(follow_up)
            command_status = command_status or follow_up_status
            touched_sources.update(follow_up.checked_source_ids)
            after_state = read_health_state(health_path)

        remaining = [
            source_id
            for source_id in RETRYABLE_SOURCE_IDS
            if source_id in touched_sources
            if _needs_retry((after_state.get("sources") or {}).get(source_id))
        ]
        if remaining:
            print(f"07:45 recovery failed for: {', '.join(remaining)}.", file=sys.stderr, flush=True)
            return catch_up_status or command_status or 1
        print("07:45 recovery completed successfully.", flush=True)
        return catch_up_status or command_status


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("job", choices=("full", "recovery", "cve"))
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    job = parse_args(argv).job
    if job == "full":
        return run_full_refresh()
    if job == "recovery":
        return run_recovery(ensure_full_today=True)
    return run_cve_refresh()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
