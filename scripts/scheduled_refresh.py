#!/usr/bin/env python3
"""Shared scheduled refresh runner for systemd and the Docker scheduler.

The 07:00 full run records a first source failure without alerting (the notification threshold is
already two consecutive failures).  At 07:45 ``recovery`` reads the health file and retries only
sources that are still red.  A second failure then reaches the existing threshold and emits the
operational alert; a successful retry silently clears the transient first failure.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import subprocess
import sys
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fortios_notify
from fortios_watch import (
    DEFAULT_HEALTH_PATH,
    DEFAULT_NOTIFY_HISTORY_PATH,
    HEALTH_SOURCE_LABELS,
    HEALTH_STATUS_ERROR,
    HEALTH_STATUS_RUNNING,
    SOURCE_COMPAT_MATRIX,
    SOURCE_CVE_PSIRT,
    SOURCE_FORTIANALYZER,
    SOURCE_FORTICLIENT,
    SOURCE_FORTICLIENT_EMS,
    SOURCE_FORTIMANAGER,
    SOURCE_FORTIOS_DOCS,
    SOURCE_FORTIOS_LIFECYCLE,
    read_health_state,
    utc_now,
)

ROOT = Path(__file__).resolve().parents[1]
LOCK_NAME = "fortios-scheduled-refresh.lock"
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


def _needs_retry(record: dict[str, Any] | None) -> bool:
    # The process-wide lock is held before this state is inspected, so a "running" record cannot
    # belong to a still-active scheduled job. It was left behind by a killed/crashed collector.
    return bool(record and record.get("status") in {HEALTH_STATUS_ERROR, HEALTH_STATUS_RUNNING})


def build_retry_plan(health_state: dict[str, Any]) -> RetryPlan:
    sources = health_state.get("sources") or {}
    failed = tuple(source_id for source_id in RETRYABLE_SOURCE_IDS if _needs_retry(sources.get(source_id)))
    failed_set = set(failed)
    args: list[str] = []

    if failed_set & {SOURCE_FORTIOS_DOCS, SOURCE_FORTIOS_LIFECYCLE}:
        args.append("--docs-catalog")

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
    if SOURCE_CVE_PSIRT in failed_set:
        args.append("--cve-catalog")

    return RetryPlan(
        catalog_args=tuple(args),
        compatibility=SOURCE_COMPAT_MATRIX in failed_set,
        source_ids=failed,
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


def _notify_compatibility_transition(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    root: Path,
) -> None:
    """Compatibility import runs outside fortios_watch; give it the same durable alert path."""
    config = fortios_notify.load_email_config()
    if not config.enabled:
        return
    events = fortios_notify.derive_source_health_events(
        {SOURCE_COMPAT_MATRIX: before},
        {SOURCE_COMPAT_MATRIX: after},
        HEALTH_SOURCE_LABELS,
    )
    if not events:
        return

    history_path = root / DEFAULT_NOTIFY_HISTORY_PATH
    claimant = f"recovery-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    pending = fortios_notify.enqueue_and_claim(history_path, events, claimant=claimant)
    composed = fortios_notify.compose_email(pending, app_url=config.app_url, run_timestamp=utc_now())
    if not composed:
        return
    subject, body = composed
    if fortios_notify.send_email(config, subject, body):
        fortios_notify.finalize_sent_events(history_path, pending)
    else:
        fortios_notify.release_claim(history_path, claimant)


def run_full_refresh(
    *,
    root: Path = ROOT,
    runner: Runner = subprocess.run,
    python: str = sys.executable,
    compatibility_python: str | None = None,
) -> int:
    with refresh_lock(root):
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
        compat_status = _run(
            [
                compatibility_python or _compatibility_python(root),
                "scripts/import_forticlient_compat.py",
                "--commit",
            ],
            root=root,
            runner=runner,
        )
    return catalog_status or compat_status


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
) -> int:
    health_path = root / DEFAULT_HEALTH_PATH
    with refresh_lock(root):
        before_state = read_health_state(health_path)
        plan = build_retry_plan(before_state)
        if not plan.source_ids:
            print("07:45 recovery: every source is healthy; nothing to retry.", flush=True)
            return 0

        print(f"07:45 recovery: retrying {', '.join(plan.source_ids)}.", flush=True)
        command_status = 0
        if plan.catalog_args:
            command_status = _run(
                [
                    python,
                    "scripts/fortios_watch.py",
                    "--base", "data/fortios-data.generated.json",
                    *plan.catalog_args,
                ],
                root=root,
                runner=runner,
            )

        if plan.compatibility:
            compat_before = (before_state.get("sources") or {}).get(SOURCE_COMPAT_MATRIX) or {}
            compat_status = _run(
                [
                    compatibility_python or _compatibility_python(root),
                    "scripts/import_forticlient_compat.py",
                    "--commit",
                ],
                root=root,
                runner=runner,
            )
            command_status = command_status or compat_status
            compat_after = (read_health_state(health_path).get("sources") or {}).get(SOURCE_COMPAT_MATRIX) or {}
            _notify_compatibility_transition(compat_before, compat_after, root=root)

        after_state = read_health_state(health_path)
        remaining = [
            source_id
            for source_id in plan.source_ids
            if _needs_retry((after_state.get("sources") or {}).get(source_id))
        ]
        if remaining:
            print(f"07:45 recovery failed for: {', '.join(remaining)}.", file=sys.stderr, flush=True)
            return command_status or 1
        print("07:45 recovery completed successfully.", flush=True)
        return command_status


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("job", choices=("full", "recovery", "cve"))
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    job = parse_args(argv).job
    if job == "full":
        return run_full_refresh()
    if job == "recovery":
        return run_recovery()
    return run_cve_refresh()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
