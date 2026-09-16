"""The VPS-side bridge between the CI artifact and the application's data directory.

This script is the only thing that writes the ingested report, and it is the only place where the
Git commit is attached (the artifact carries none). Asserted here: a bad artifact changes NOTHING
on disk, a re-run is byte-identical, a failure exits non-zero without a traceback, and no
half-written file is ever left behind.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import sync_trivy_report
import trivy_report
from test_trivy_report import report_payload

COMMIT = "05926bb47750208331d9dda00513fd399234736d"
RUN_URL = "https://github.com/Tetrax/upgrade_path_forti/actions/runs/35138272412"


class ArtifactSelectionTests(unittest.TestCase):
    def test_the_workflow_report_is_preferred(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "trivy.json").write_text("{}", encoding="utf-8")
            (directory / "autre.json").write_text("{}", encoding="utf-8")
            self.assertEqual(sync_trivy_report.select_report_file(directory).name, "trivy.json")

    def test_a_single_renamed_report_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "rapport-trivy.json").write_text("{}", encoding="utf-8")
            self.assertEqual(
                sync_trivy_report.select_report_file(directory).name, "rapport-trivy.json"
            )

    def test_an_empty_artifact_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(
            sync_trivy_report.SyncError
        ):
            sync_trivy_report.select_report_file(Path(tmp))

    def test_an_ambiguous_artifact_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "a.json").write_text("{}", encoding="utf-8")
            (directory / "b.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(sync_trivy_report.SyncError):
                sync_trivy_report.select_report_file(directory)


class IngestTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.artifact = self.root / "artifact"
        self.artifact.mkdir()
        self.data = self.root / "data"
        self.data.mkdir()
        self.write_artifact(report_payload())

    def write_artifact(self, payload, name: str = "trivy.json") -> None:
        (self.artifact / name).write_text(json.dumps(payload), encoding="utf-8")

    def ingest(self, *, commit: str = COMMIT, run_id: str = "35138272412"):
        return sync_trivy_report.ingest_artifact(
            self.artifact, self.data, commit=commit, run_id=run_id, run_url=RUN_URL,
            now="2026-09-16T19:00:00Z",
        )

    def test_a_valid_artifact_is_published_with_its_provenance(self) -> None:
        changed, message = self.ingest()
        self.assertTrue(changed)
        self.assertIn("05926bb4", message)
        report = json.loads((self.data / "trivy-report.json").read_text(encoding="utf-8"))
        self.assertEqual(len(report["Results"][0]["Vulnerabilities"]), 12)
        metadata = json.loads((self.data / "trivy-report.meta.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["commit"], COMMIT)
        self.assertEqual(metadata["runId"], "35138272412")
        self.assertEqual(metadata["runUrl"], RUN_URL)
        self.assertEqual(
            metadata["sha256"],
            hashlib.sha256((self.data / "trivy-report.json").read_bytes()).hexdigest(),
        )

    def test_the_published_report_is_byte_identical_to_the_artifact(self) -> None:
        self.ingest()
        self.assertEqual(
            (self.data / "trivy-report.json").read_bytes(),
            (self.artifact / "trivy.json").read_bytes(),
        )

    def test_a_second_identical_run_changes_nothing(self) -> None:
        self.ingest()
        before = {path.name: path.read_bytes() for path in self.data.iterdir()}
        changed, message = self.ingest()
        self.assertFalse(changed)
        self.assertIn("déjà à jour", message)
        self.assertEqual({path.name: path.read_bytes() for path in self.data.iterdir()}, before)

    def test_a_new_commit_republishes_even_with_identical_content(self) -> None:
        """The commit is the provenance the alert displays: it must not go stale."""
        self.ingest()
        changed, _ = self.ingest(commit="b" * 40, run_id="999")
        self.assertTrue(changed)
        metadata = json.loads((self.data / "trivy-report.meta.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["commit"], "b" * 40)
        self.assertEqual(metadata["runId"], "999")

    def test_an_invalid_artifact_writes_nothing_at_all(self) -> None:
        self.write_artifact({"SchemaVersion": 2, "ArtifactType": "container_image", "Results": "x"})
        with self.assertRaises(sync_trivy_report.SyncError):
            self.ingest()
        self.assertEqual(list(self.data.iterdir()), [])

    def test_a_broken_artifact_never_replaces_a_good_one(self) -> None:
        self.ingest()
        published = (self.data / "trivy-report.json").read_bytes()
        (self.artifact / "trivy.json").write_bytes(b"{tronque")
        with self.assertRaises(sync_trivy_report.SyncError):
            self.ingest(commit="b" * 40)
        self.assertEqual((self.data / "trivy-report.json").read_bytes(), published)

    def test_an_invalid_commit_is_refused_by_the_shared_validator(self) -> None:
        with self.assertRaises(sync_trivy_report.SyncError):
            self.ingest(commit="main")
        self.assertEqual(list(self.data.iterdir()), [])

    def test_no_temporary_file_is_left_behind(self) -> None:
        self.ingest()
        self.assertEqual(
            sorted(path.name for path in self.data.iterdir()),
            ["trivy-report.json", "trivy-report.meta.json"],
        )

    def test_the_published_report_is_accepted_by_the_ingestion(self) -> None:
        """The two halves of the bridge must agree: what this script publishes is what the engine
        is willing to trust. This is the seam where a mismatch would be silent."""
        self.ingest()
        scan = trivy_report.ingest_container_report(
            self.data / "trivy-report.json", commit=COMMIT
        )
        self.assertEqual(len(scan.findings), 12)


class MainTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.data = Path(self._tmp.name) / "data"

    def test_a_sync_failure_exits_non_zero_without_a_traceback(self) -> None:
        with mock.patch.object(
            sync_trivy_report,
            "latest_successful_run",
            side_effect=sync_trivy_report.SyncError("gh absent"),
        ), mock.patch("sys.stderr") as stderr:
            status = sync_trivy_report.main(["--data-dir", str(self.data)])
        self.assertEqual(status, 1)
        self.assertIn("gh absent", stderr.write.call_args_list[0][0][0])
        self.assertFalse(self.data.exists())

    def test_an_incomplete_run_is_refused(self) -> None:
        with mock.patch.object(
            sync_trivy_report, "latest_successful_run", return_value={"databaseId": "1"}
        ), mock.patch("sys.stderr"):
            self.assertEqual(
                sync_trivy_report.main(["--data-dir", str(self.data)]), 1
            )
        self.assertFalse(self.data.exists())

    def test_the_full_path_publishes_the_report(self) -> None:
        artifact = Path(self._tmp.name) / "artifact"
        artifact.mkdir()
        (artifact / "trivy.json").write_text(json.dumps(report_payload()), encoding="utf-8")
        with mock.patch.object(
            sync_trivy_report,
            "latest_successful_run",
            return_value={"databaseId": "35138272412", "headSha": COMMIT, "url": RUN_URL},
        ), mock.patch.object(
            sync_trivy_report,
            "download_artifact",
            side_effect=lambda repo, run_id, destination: (
                (Path(destination) / "trivy.json").write_text(
                    (artifact / "trivy.json").read_text(encoding="utf-8"), encoding="utf-8"
                )
            ),
        ):
            self.assertEqual(sync_trivy_report.main(["--data-dir", str(self.data)]), 0)
        metadata = json.loads((self.data / "trivy-report.meta.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["commit"], COMMIT)


if __name__ == "__main__":
    unittest.main()
