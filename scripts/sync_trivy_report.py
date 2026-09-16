#!/usr/bin/env python3
"""Download the latest Trivy artifact from CI and hand it to FortiUpgrade's live data directory.

Why this exists on the VPS side: the vulnerability report is produced by GitHub Actions, while the
preferences, the state and the email delivery live in the application. This script is the only
bridge — the application never talks to GitHub, and GitHub never receives the SMTP credentials or
the recipient lists (that rejection is recorded in docs/notifications.md).

Contract, and the failure modes it is built around:

- The downloaded artifact is validated BEFORE it replaces anything. A truncated or malformed
  artifact must never become the ingested state, so the live files are only overwritten once the
  report has been parsed, checked structurally and checksummed.
- The JSON carries no Git SHA (verified on a real artifact), so the run's ``headSha`` is written
  beside it in ``trivy-report.meta.json`` and is the provenance the alerts display.
- A download failure changes nothing: the previous report and its metadata stay in place, so the
  administration keeps showing the last known scan (marked stale by age) instead of losing it.
- Re-running is idempotent: an artifact identical to the ingested one (same commit and checksum)
  is not rewritten, which keeps the state files byte-identical and auditable.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import trivy_report

DEFAULT_REPO = "Tetrax/upgrade_path_forti"
DEFAULT_WORKFLOW = "Tests"
DEFAULT_BRANCH = "main"
DEFAULT_DATA_DIR = Path("data")
ARTIFACT_NAME = "trivy-report"
REPORT_FILENAME = "trivy-report.json"
METADATA_FILENAME = "trivy-report.meta.json"


class SyncError(RuntimeError):
    """The synchronization could not complete; nothing on disk was modified."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def select_report_file(artifact_dir: Path) -> Path:
    """Return the report inside a downloaded artifact directory.

    The workflow writes a single ``trivy.json``; anything else is accepted only when it is the only
    JSON file present, so a future rename does not silently break the ingestion.
    """
    preferred = artifact_dir / "trivy.json"
    if preferred.is_file():
        return preferred
    candidates = sorted(path for path in artifact_dir.glob("*.json") if path.is_file())
    if len(candidates) != 1:
        raise SyncError(
            "Artefact inattendu : "
            f"{len(candidates)} fichier(s) JSON trouvé(s) au lieu d'un rapport unique."
        )
    return candidates[0]


def write_atomic(path: Path, payload: bytes) -> None:
    """Replace a file in one step, so a crash never leaves a half-written live file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def read_json(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def ingest_artifact(
    artifact_dir: Path,
    data_dir: Path,
    *,
    commit: str,
    run_id: str,
    run_url: str,
    now: str | None = None,
) -> tuple[bool, str]:
    """Validate a downloaded artifact and publish it. Returns (changed, message).

    Pure with respect to GitHub: everything it needs is passed in, so it is directly testable and
    the network part stays in main().
    """
    now = now or utc_now()
    report_path = select_report_file(artifact_dir)
    raw = report_path.read_bytes()
    # Strict validation with the very same code path the ingestion uses: nothing is published that
    # the engine would refuse to trust. The message is passed through as-is (it already names the
    # refusal) so one problem never reads like two.
    try:
        trivy_report.parse_container_report(raw, commit=commit)
    except trivy_report.ContainerReportError as error:
        raise SyncError(str(error)) from error

    checksum = hashlib.sha256(raw).hexdigest()
    live_report = data_dir / REPORT_FILENAME
    live_metadata = data_dir / METADATA_FILENAME
    previous = read_json(live_metadata)
    if (
        live_report.is_file()
        and previous.get("sha256") == checksum
        and previous.get("commit") == commit
    ):
        return False, f"Rapport déjà à jour (run {run_id}, commit {commit[:8]})."

    metadata = {
        "commit": commit,
        "runId": run_id,
        "runUrl": run_url,
        "sha256": checksum,
        "downloadedAt": now,
        "artifact": ARTIFACT_NAME,
    }
    # Report first, then its metadata: a crash in between leaves the new report against the old
    # checksum, which the ingestion refuses explicitly ("rapport altéré") instead of diffing an
    # unverified file against the baseline.
    write_atomic(live_report, raw)
    write_atomic(
        live_metadata,
        (json.dumps(metadata, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )
    return True, (
        f"Rapport mis à jour : run {run_id}, commit {commit[:8]}, "
        f"{len(raw)} octets, sha256 {checksum[:12]}…"
    )


def gh_json(arguments: list[str]) -> object:
    try:
        completed = subprocess.run(
            arguments, capture_output=True, text=True, check=False, timeout=120
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SyncError(f"Appel gh impossible ({type(error).__name__}).") from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        raise SyncError(f"gh a échoué ({completed.returncode}) : {detail[-1] if detail else ''}"[:300])
    try:
        return json.loads(completed.stdout)
    except ValueError as error:
        raise SyncError("Réponse gh illisible.") from error


def latest_successful_run(repo: str, workflow: str, branch: str) -> dict:
    """Most recent successful run of the scanning workflow on the tracked branch."""
    runs = gh_json(
        [
            "gh",
            "run",
            "list",
            "--repo",
            repo,
            "--workflow",
            workflow,
            "--branch",
            branch,
            "--status",
            "success",
            "--limit",
            "1",
            "--json",
            "databaseId,headSha,url,conclusion",
        ]
    )
    if not isinstance(runs, list) or not runs:
        raise SyncError(f"Aucun run réussi pour le workflow {workflow} sur {branch}.")
    run = runs[0]
    if not isinstance(run, dict):
        raise SyncError("Description de run invalide.")
    return run


def download_artifact(repo: str, run_id: str, destination: Path) -> None:
    try:
        completed = subprocess.run(
            [
                "gh",
                "run",
                "download",
                str(run_id),
                "--repo",
                repo,
                "--name",
                ARTIFACT_NAME,
                "--dir",
                str(destination),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SyncError(f"Téléchargement impossible ({type(error).__name__}).") from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        raise SyncError(
            f"Téléchargement de l'artefact {ARTIFACT_NAME} impossible : "
            f"{detail[-1] if detail else ''}"[:300]
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Récupère le dernier rapport Trivy de la CI dans data/.",
    )
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--workflow", default=DEFAULT_WORKFLOW)
    parser.add_argument("--branch", default=DEFAULT_BRANCH)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        run = latest_successful_run(args.repo, args.workflow, args.branch)
        run_id = str(run.get("databaseId") or "")
        commit = str(run.get("headSha") or "")
        run_url = str(run.get("url") or "")
        if not run_id or not commit:
            raise SyncError("Run incomplet (identifiant ou commit manquant).")
        with tempfile.TemporaryDirectory(prefix="trivy-artifact-") as tmp:
            download_artifact(args.repo, run_id, Path(tmp))
            changed, message = ingest_artifact(
                Path(tmp),
                args.data_dir,
                commit=commit,
                run_id=run_id,
                run_url=run_url,
            )
    except SyncError as error:
        # No traceback and no partial write: the caller (systemd timer) gets a clear line and a
        # non-zero status, and the application keeps serving the last known report.
        print(f"Synchronisation du rapport Trivy : {error}", file=sys.stderr, flush=True)
        return 1
    print(
        f"Synchronisation du rapport Trivy : {message}"
        + (" (aucune écriture)" if not changed else ""),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
