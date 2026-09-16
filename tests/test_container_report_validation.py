"""Strict validation of an ingested Trivy report — an untrusted input from CI.

The presentation path (tests/test_trivy_report.py) is deliberately tolerant: a summary must render
what it can from whatever the scan produced. This file covers the other half, which is the opposite
contract — the state baseline is only ever built from a report that passed every check, because a
partially trusted report silently becomes a wrong baseline (a dropped finding looks "new" later, a
mangled identifier breaks the deduplication key).

Every refusal is asserted to name the field and NEVER echo the offending value: these messages are
written into the notification state and displayed in the administration.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
# The report fixture is shared with tests/test_trivy_report.py; its own directory is added so this
# file also runs when invoked directly rather than through `unittest discover -s tests`.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import trivy_report
from test_trivy_report import report_payload

COMMIT = "05926bb47750208331d9dda00513fd399234736d"


def payload_with(**overrides) -> dict:
    """The real report document with individual top-level fields replaced."""
    payload = report_payload()
    payload.update(overrides)
    return payload


def scan(**overrides):
    return trivy_report.validate_container_report(payload_with(**overrides), commit=COMMIT)


def refusals(test: unittest.TestCase, payload: dict, commit: str = COMMIT) -> str:
    """Assert the payload is refused and return the message."""
    with test.assertRaises(trivy_report.ContainerReportError) as raised:
        trivy_report.validate_container_report(payload, commit=commit)
    return str(raised.exception)


class ContainerScanExtractionTests(unittest.TestCase):
    def test_real_report_yields_every_finding_with_a_stable_identity(self) -> None:
        result = scan()
        self.assertEqual(len(result.findings), 12)
        self.assertEqual(result.image, "fortios-upgrade-intelligence:ci-scan")
        self.assertEqual(result.commit, COMMIT)
        # Nanosecond precision is normalised to the second, the format the notification engine uses.
        self.assertEqual(result.scanned_at, "2026-09-16T18:55:13Z")
        self.assertEqual(result.counts()["critical"], 3)
        self.assertEqual(result.counts()["high"], 9)
        self.assertEqual(
            result.findings[0].dedup_key, "trivy|cve|CVE-2026-13221|perl-base"
        )

    def test_dedup_key_ignores_the_installed_version(self) -> None:
        """A base-image refresh that moves a package keeps the SAME identity.

        Including the installed version would re-announce every already-known CVE at each rebuild —
        exactly the noise this system exists to prevent.
        """
        original = scan().findings[0]
        bumped = report_payload()
        bumped["Results"][0]["Vulnerabilities"][0]["InstalledVersion"] = "5.40.1-6+deb13u2"
        moved = trivy_report.validate_container_report(bumped, commit=COMMIT).findings[0]
        self.assertNotEqual(original.installed_version, moved.installed_version)
        self.assertEqual(original.dedup_key, moved.dedup_key)

    def test_clean_package_result_is_accepted_as_empty(self) -> None:
        """The real report writes `"Vulnerabilities": 0` for a clean result, not an empty list."""
        payload = report_payload()
        self.assertEqual(payload["Results"][1]["Vulnerabilities"], 0)
        self.assertEqual(len(scan().findings), 12)

    def test_result_without_the_vulnerabilities_key_is_accepted_as_empty(self) -> None:
        payload = report_payload()
        del payload["Results"][1]["Vulnerabilities"]
        self.assertEqual(
            len(trivy_report.validate_container_report(payload, commit=COMMIT).findings), 12
        )

    def test_validation_is_deterministic(self) -> None:
        self.assertEqual(scan().findings, scan().findings)


class ContainerReportRefusalTests(unittest.TestCase):
    def test_absent_commit_is_refused(self) -> None:
        message = refusals(self, report_payload(), commit="")
        self.assertIn("commit", message.lower())

    def test_non_hex_commit_is_refused(self) -> None:
        message = refusals(self, report_payload(), commit="main")
        self.assertIn("commit", message.lower())

    def test_commit_is_never_echoed_in_the_message(self) -> None:
        message = refusals(self, report_payload(), commit="pas-un-sha-<script>")
        self.assertNotIn("<script>", message)

    def test_unknown_schema_version_is_refused(self) -> None:
        self.assertIn("SchemaVersion", refusals(self, payload_with(SchemaVersion=1)))

    def test_non_integer_schema_version_is_refused(self) -> None:
        self.assertIn("SchemaVersion", refusals(self, payload_with(SchemaVersion="2")))

    def test_wrong_artifact_type_is_refused(self) -> None:
        self.assertIn(
            "ArtifactType", refusals(self, payload_with(ArtifactType="filesystem"))
        )

    def test_results_must_be_a_list(self) -> None:
        self.assertIn("Results", refusals(self, payload_with(Results="os-pkgs")))

    def test_vulnerabilities_of_the_wrong_type_is_refused(self) -> None:
        payload = report_payload()
        payload["Results"][0]["Vulnerabilities"] = "12"
        self.assertIn("Vulnerabilities", refusals(self, payload))

    def test_identifier_out_of_the_cve_format_is_refused(self) -> None:
        payload = report_payload()
        payload["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"] = "GHSA-xxxx"
        message = refusals(self, payload)
        self.assertIn("VulnerabilityID", message)
        self.assertNotIn("GHSA-xxxx", message)

    def test_package_name_out_of_the_expected_charset_is_refused(self) -> None:
        payload = report_payload()
        payload["Results"][0]["Vulnerabilities"][0]["PkgName"] = "perl-base; rm -rf /"
        message = refusals(self, payload)
        self.assertIn("PkgName", message)
        self.assertNotIn("rm -rf", message)

    def test_unknown_severity_is_refused(self) -> None:
        payload = report_payload()
        payload["Results"][0]["Vulnerabilities"][0]["Severity"] = "BLOCKER"
        self.assertIn("Severity", refusals(self, payload))

    def test_oversized_report_is_refused(self) -> None:
        raw = b"{" + b" " * (trivy_report.MAX_REPORT_BYTES + 1) + b"}"
        with self.assertRaises(trivy_report.ContainerReportError) as raised:
            trivy_report.parse_container_report(raw, commit=COMMIT)
        self.assertIn("taille", str(raised.exception))

    def test_unreadable_json_is_refused(self) -> None:
        with self.assertRaises(trivy_report.ContainerReportError):
            trivy_report.parse_container_report(b"{not json", commit=COMMIT)

    def test_non_utf8_payload_is_refused(self) -> None:
        with self.assertRaises(trivy_report.ContainerReportError):
            trivy_report.parse_container_report(b"\xff\xfe\x00", commit=COMMIT)

    def test_absent_file_is_refused_by_the_path_entry_point(self) -> None:
        with self.assertRaises(trivy_report.ContainerReportError):
            trivy_report.ingest_container_report(Path("/nonexistent/trivy.json"), commit=COMMIT)


class AdvisoryUrlTests(unittest.TestCase):
    def test_https_advisory_is_kept(self) -> None:
        self.assertTrue(scan().findings[0].advisory_url.startswith("https://"))

    def test_non_https_advisory_is_dropped_without_refusing_the_finding(self) -> None:
        """The link is decorative: it is removed, the finding is kept."""
        payload = report_payload()
        payload["Results"][0]["Vulnerabilities"][0]["PrimaryURL"] = "javascript:alert(1)"
        result = trivy_report.validate_container_report(payload, commit=COMMIT)
        self.assertEqual(result.findings[0].advisory_url, "")
        self.assertEqual(len(result.findings), 12)

    def test_absent_advisory_is_tolerated(self) -> None:
        payload = report_payload()
        del payload["Results"][0]["Vulnerabilities"][0]["PrimaryURL"]
        self.assertEqual(
            trivy_report.validate_container_report(payload, commit=COMMIT).findings[0].advisory_url,
            "",
        )

    def test_overlong_title_is_truncated_not_refused(self) -> None:
        """Descriptive text is bounded, never fatal: a longer advisory title must not disable the
        control. Identity fields take the opposite decision (see the refusal tests)."""
        payload = report_payload()
        payload["Results"][0]["Vulnerabilities"][0]["Title"] = "x" * 5000
        result = trivy_report.validate_container_report(payload, commit=COMMIT)
        self.assertEqual(len(result.findings), 12)
        self.assertEqual(len(result.findings[0].title), trivy_report.MAX_TITLE_CHARS)


class ParseEntryPointTests(unittest.TestCase):
    def test_bytes_are_validated_exactly_like_the_loaded_document(self) -> None:
        payload = report_payload()
        raw = json.dumps(payload).encode("utf-8")
        self.assertEqual(
            trivy_report.parse_container_report(raw, commit=COMMIT).findings,
            trivy_report.validate_container_report(payload, commit=COMMIT).findings,
        )

    def test_parse_and_validate_refuse_the_same_payload(self) -> None:
        raw = json.dumps({"SchemaVersion": 2, "ArtifactType": "container_image"}).encode()
        with self.assertRaises(trivy_report.ContainerReportError):
            trivy_report.parse_container_report(raw, commit=COMMIT)


if __name__ == "__main__":
    unittest.main()
