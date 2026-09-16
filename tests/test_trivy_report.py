"""The Trivy CI summary: informative presentation, never a blocking control.

The report shape asserted here is the one the `security-scan` job really produces
(trivy-action, `format: json`, `severity: HIGH,CRITICAL`, `ignore-unfixed: true`): a top-level
document with `Results[].Vulnerabilities[]`, one `os-pkgs` result for the Debian packages and one
result per Python package that carries no vulnerability at all.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import trivy_report

# The twelve findings of the real report (job 104922907323, debian 13.6): 3 CRITICAL + 9 HIGH.
REAL_FINDINGS = (
    ("perl-base", "CVE-2026-13221", "CRITICAL", "5.40.1-6", "5.40.1-6+deb13u1"),
    ("perl-base", "CVE-2026-42496", "CRITICAL", "5.40.1-6", "5.40.1-6+deb13u1"),
    ("perl-base", "CVE-2026-8376", "CRITICAL", "5.40.1-6", "5.40.1-6+deb13u1"),
    ("perl-base", "CVE-2026-42497", "HIGH", "5.40.1-6", "5.40.1-6+deb13u1"),
    ("perl-base", "CVE-2026-48962", "HIGH", "5.40.1-6", "5.40.1-6+deb13u1"),
    ("perl-base", "CVE-2026-57432", "HIGH", "5.40.1-6", "5.40.1-6+deb13u1"),
    ("perl-base", "CVE-2026-57433", "HIGH", "5.40.1-6", "5.40.1-6+deb13u1"),
    ("gzip", "CVE-2026-41992", "HIGH", "1.13-1", "1.13-1+deb13u1"),
    ("libpcre2-8-0", "CVE-2026-86145", "HIGH", "10.46-1~deb13u1", "10.46-1~deb13u2"),
    ("libpcre2-8-0", "CVE-2026-89161", "HIGH", "10.46-1~deb13u1", "10.46-1~deb13u2"),
    ("libsqlite3-0", "CVE-2026-11822", "HIGH", "3.46.1-7+deb13u1", "3.46.1-7+deb13u2"),
    ("libsqlite3-0", "CVE-2026-11824", "HIGH", "3.46.1-7+deb13u1", "3.46.1-7+deb13u2"),
)


def report_payload(findings=REAL_FINDINGS) -> dict:
    """The real document, verified against the artifact of run 35136948219.

    Note the shapes that only the real report teaches: `Metadata` carries `ImageID` /`RepoTags` /
    `Reference` but NO `RepoDigests`, and a clean package result carries `"Vulnerabilities": 0`
    rather than omitting the key.
    """
    return {
        "SchemaVersion": 2,
        "ArtifactName": "fortios-upgrade-intelligence:ci-scan",
        "ArtifactType": "container_image",
        "CreatedAt": "2026-09-16T18:55:13.964726549Z",
        "Trivy": {"Version": "0.70.0"},
        "Metadata": {
            "OS": {"Family": "debian", "Name": "13.6"},
            "ImageID": "sha256:81f3d7795c799fae45b1c994301881b06ceee4831a03f8067abf678a04811caa",
            "RepoTags": ["fortios-upgrade-intelligence:ci-scan"],
            "Reference": "fortios-upgrade-intelligence:ci-scan",
            "Size": 211329024,
        },
        "Results": [
            {
                "Target": "fortios-upgrade-intelligence:ci-scan (debian 13.6)",
                "Class": "os-pkgs",
                "Type": "debian",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": cve,
                        "PkgName": package,
                        "InstalledVersion": installed,
                        "FixedVersion": fixed,
                        "Severity": severity,
                        "Status": "fixed",
                        "Title": f"titre {cve}",
                        "PrimaryURL": f"https://avd.aquasec.com/nvd/{cve.lower()}",
                    }
                    for package, cve, severity, installed, fixed in findings
                ],
            },
            {
                # A clean language-package result: 0, not a missing key, in the real report.
                "Target": "Python",
                "Class": "lang-pkgs",
                "Type": "python-pkg",
                "Vulnerabilities": 0,
            },
        ],
    }


class ReportLoadingTests(unittest.TestCase):
    def write(self, directory: str, payload: object, name: str = "trivy.json") -> Path:
        path = Path(directory) / name
        path.write_text(
            payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8"
        )
        return path

    def test_real_report_shape_is_flattened_with_every_field_kept(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report, findings, unavailable = trivy_report.load_report(
                self.write(tmp, report_payload())
            )

        self.assertIsNone(unavailable)
        self.assertEqual(len(findings), 12)
        self.assertEqual(trivy_report.counts(findings), {"CRITICAL": 3, "HIGH": 9})
        first = findings[0]
        self.assertEqual(first.severity, "CRITICAL")
        self.assertEqual(first.package, "perl-base")
        self.assertEqual(first.cve, "CVE-2026-13221")
        self.assertEqual(first.installed_version, "5.40.1-6")
        self.assertEqual(first.fixed_version, "5.40.1-6+deb13u1")
        self.assertEqual(first.title, "titre CVE-2026-13221")
        self.assertEqual(report["ArtifactName"], "fortios-upgrade-intelligence:ci-scan")

    def test_most_severe_findings_are_listed_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _report, findings, _unavailable = trivy_report.load_report(
                self.write(tmp, report_payload())
            )
        self.assertEqual([f.severity for f in findings[:3]], ["CRITICAL"] * 3)
        self.assertEqual(findings[3].severity, "HIGH")

    def test_clean_report_yields_no_finding_and_no_unavailable_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _report, findings, unavailable = trivy_report.load_report(
                self.write(tmp, report_payload(()) | {"Results": [{"Target": "t", "Class": "os-pkgs"}]})
            )
        self.assertEqual(findings, [])
        self.assertIsNone(unavailable)

    def test_malformed_shapes_never_raise(self) -> None:
        payloads = (
            {"Results": "not-a-list"},
            {"Results": [None, "x", {"Vulnerabilities": "not-a-list"}]},
            {"Results": [{"Vulnerabilities": [None, 42, {"PkgName": "p"}]}]},
            {},
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                with tempfile.TemporaryDirectory() as tmp:
                    _report, findings, unavailable = trivy_report.load_report(
                        self.write(tmp, payload)
                    )
                self.assertIsNone(unavailable)
                self.assertIsInstance(findings, list)

    def test_a_missing_or_invalid_report_is_an_explicit_unavailable_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "absent.json"
            _report, findings, unavailable = trivy_report.load_report(missing)
            self.assertEqual(findings, [])
            self.assertIn("absent", unavailable or "")

            _report, _findings, unavailable = trivy_report.load_report(
                self.write(tmp, "not json at all")
            )
            self.assertIn("JSON invalide", unavailable or "")

            _report, _findings, unavailable = trivy_report.load_report(
                self.write(tmp, "[1, 2, 3]")
            )
            self.assertIn("objet JSON attendu", unavailable or "")


class SummaryRenderingTests(unittest.TestCase):
    def render(self, payload: dict) -> str:
        with tempfile.TemporaryDirectory() as tmp:
            report, findings, unavailable = trivy_report.load_report(self._write(tmp, payload))
        return trivy_report.render_summary(findings, unavailable, report=report)

    def _write(self, directory: str, payload: dict) -> Path:
        path = Path(directory) / "trivy.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_summary_reports_counts_and_every_finding_field(self) -> None:
        summary = self.render(report_payload())
        self.assertIn("## ⚠️ Sécurité de l'image Docker — vulnérabilités détectées — contrôle informatif", summary)
        self.assertIn("**12 vulnérabilités corrigibles** (CRITICAL **3** · HIGH **9**)", summary)
        for package, cve, _severity, installed, fixed in REAL_FINDINGS:
            with self.subTest(cve=cve):
                self.assertIn(cve, summary)
                self.assertIn(f"`{package}`", summary)
                self.assertIn(installed, summary)
                self.assertIn(fixed, summary)
        self.assertIn("debian 13.6", summary)

    def test_summary_never_presents_findings_as_a_blocking_failure(self) -> None:
        summary = self.render(report_payload())
        self.assertIn("**Ce job ne bloque pas la CI.**", summary)
        self.assertIn("trivy-report", summary)

    def test_a_clean_report_says_so_without_a_table(self) -> None:
        summary = self.render({"ArtifactName": "img:x", "Results": []})
        self.assertIn("## ✅ Sécurité de l'image Docker — aucune vulnérabilité", summary)
        self.assertNotIn("| Sévérité |", summary)

    def test_an_unavailable_report_is_never_read_as_zero_findings(self) -> None:
        summary = trivy_report.render_summary([], "aucun rapport produit (trivy.json absent)")
        self.assertIn("rapport indisponible", summary)
        self.assertIn("ce n'est PAS un « aucune vulnérabilité »", summary)
        self.assertNotIn("✅", summary)

    def test_the_table_is_bounded_and_announces_the_remainder(self) -> None:
        many = tuple(
            ("pkg", f"CVE-2026-{index:05d}", "HIGH", "1.0", "1.1")
            for index in range(trivy_report.MAX_ROWS + 7)
        )
        summary = self.render(report_payload(many))
        self.assertIn("… et 7 autre(s) dans le rapport JSON.", summary)
        self.assertEqual(summary.count("| HIGH |"), trivy_report.MAX_ROWS)


class MainStreamsTests(unittest.TestCase):
    """The step summary and the annotations must travel on two different streams."""

    def run_main(self, argv: list[str]) -> tuple[int, str]:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = trivy_report.main(argv)
        return code, stdout.getvalue()

    def test_summary_goes_to_the_file_and_annotations_to_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "trivy.json"
            report.write_text(json.dumps(report_payload()), encoding="utf-8")
            summary_file = Path(tmp) / "summary.md"
            code, stdout = self.run_main(
                ["trivy_report.py", str(report), "--summary-file", str(summary_file)]
            )
            summary = summary_file.read_text(encoding="utf-8")

        self.assertEqual(code, 0)
        self.assertIn("::warning title=Vulnérabilités de l'image (contrôle informatif)::", stdout)
        self.assertIn("3 CRITICAL, 9 HIGH", stdout)
        self.assertIn("perl-base", stdout)
        # The annotation command must not leak into the Markdown the operator reads.
        self.assertNotIn("::warning", summary)
        self.assertIn("| Sévérité | Package |", summary)

    def test_no_annotation_is_emitted_when_the_image_is_clean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "trivy.json"
            report.write_text(json.dumps({"ArtifactName": "img:x", "Results": []}), encoding="utf-8")
            code, stdout = self.run_main(["trivy_report.py", str(report)])

        self.assertEqual(code, 0)
        self.assertNotIn("::warning", stdout)
        self.assertIn("## ✅", stdout)

    def test_an_unavailable_report_warns_but_still_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code, stdout = self.run_main(
                ["trivy_report.py", str(Path(tmp) / "absent.json")]
            )

        self.assertEqual(code, 0)
        self.assertIn("::warning::Contrôle Trivy informatif : rapport indisponible", stdout)

    def test_findings_alone_never_produce_a_non_zero_exit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "trivy.json"
            report.write_text(json.dumps(report_payload()), encoding="utf-8")
            code, _stdout = self.run_main(["trivy_report.py", str(report)])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
