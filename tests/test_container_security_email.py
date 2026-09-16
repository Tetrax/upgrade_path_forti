"""The container-security email: same identity as the other internal alerts, own content.

Asserted here: the subject counts findings (never a fixed wording), the body carries what an
operator acts on (CVE, package, installed and fixed versions, severity, advisory), the report's
provenance (image, commit, scan date) is always visible, the CTA only ever points at a validated
GitHub run or falls back to the application, and a long scan is truncated instead of producing an
unreadable email.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import fortios_email_render as render
import fortios_notify

RUN_URL = "https://github.com/Tetrax/upgrade_path_forti/actions/runs/35138272412"


def event(
    cve: str = "CVE-2026-41992",
    *,
    package: str = "gzip",
    severity: str = "high",
    installed: str = "1.13-1",
    fixed: str = "1.13-1+deb13u1",
    title: str = "gzip: buffer overflow",
    url: str = "https://avd.aquasec.com/nvd/cve-2026-41992",
    key: str = "",
    change: str = "new",
    resolved: int = 0,
    report_url: str = RUN_URL,
):
    return fortios_notify.NotificationEvent(
        category=(
            fortios_notify.CATEGORY_CRITICAL
            if severity == "critical"
            else fortios_notify.CATEGORY_DAILY
        ),
        dedup_key=key or f"trivy|cve|{cve}|{package}",
        summary=f"{cve} — {package}",
        severity=severity,
        details={
            "kind": "container-cve",
            "id": cve,
            "package": package,
            "installedVersion": installed,
            "fixedVersion": fixed,
            "title": title,
            "url": url,
            "change": change,
            "resolvedCount": resolved,
            "image": "fortios-upgrade-intelligence:ci-scan",
            "commit": "05926bb47750208331d9dda00513fd399234736d",
            "scannedAt": "2026-09-16T18:55:13Z",
            "reportUrl": report_url,
        },
    )


def compose(events, **kwargs):
    return render.compose_container_security_email(
        events,
        app_url="https://fortiupgrade.valdev.me/",
        run_timestamp="2026-09-17T05:00:00Z",
        display_name="FortiUpgrade",
        **kwargs,
    )


class SubjectTests(unittest.TestCase):
    def test_a_single_finding_reads_in_the_singular(self) -> None:
        subject, _, _ = compose([event()])
        self.assertEqual(subject, "[FortiUpgrade] Sécurité de l'image — 1 nouvelle vulnérabilité")

    def test_several_findings_are_counted(self) -> None:
        subject, _, _ = compose([event(), event(cve="CVE-2026-13221", package="perl-base")])
        self.assertEqual(
            subject, "[FortiUpgrade] Sécurité de l'image — 2 nouvelles vulnérabilités"
        )


class TextBodyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.subject, self.text, self.html = compose(
            [event(), event(cve="CVE-2026-13221", package="perl-base", severity="critical",
                            installed="5.40.1-6", fixed="5.40.1-6+deb13u1",
                            title="perl: use after free")]
        )

    def test_the_actionable_fields_are_present(self) -> None:
        for expected in (
            "CVE-2026-41992",
            "gzip",
            "1.13-1",
            "1.13-1+deb13u1",
            "CVE-2026-13221",
            "perl-base",
        ):
            self.assertIn(expected, self.text)

    def test_the_provenance_is_always_visible(self) -> None:
        for expected in (
            "fortios-upgrade-intelligence:ci-scan",
            "05926bb",
            "2026-09-16T18:55:13Z",
        ):
            self.assertIn(expected, self.text)

    def test_the_severity_counts_are_summarised(self) -> None:
        self.assertIn("Critical", self.text)
        self.assertIn("High", self.text)

    def test_corrected_vulnerabilities_are_only_mentioned_when_there_are_some(self) -> None:
        _, without, _ = compose([event(resolved=0)])
        self.assertNotIn("corrigées", without.lower())
        _, with_some, _ = compose([event(resolved=2)])
        self.assertIn("2", with_some)
        self.assertIn("corrigées", with_some.lower())

    def test_no_fortinet_email_artefact_leaks_in(self) -> None:
        """No product breakdown, no PSIRT vocabulary: this is not a Fortinet advisory."""
        self.assertNotIn("PSIRT", self.text)
        for product in ("FortiGate", "FortiManager", "FortiAnalyzer", "FortiClient"):
            self.assertNotIn(product, self.text)
        self.assertNotIn("Produit", self.text)


class HtmlBodyTests(unittest.TestCase):
    def test_the_identity_is_shared_with_the_other_alerts(self) -> None:
        _, _, html = compose([event()])
        for marker in ("cid:sns-logo", "cid:sns-panther", "ÉQUIPE SUPPORT", "FortiUpgrade"):
            self.assertIn(marker, html)
        self.assertIn("<img", html)

    def test_the_cta_points_at_the_run_when_one_is_available(self) -> None:
        _, _, html = compose([event()])
        self.assertIn(RUN_URL, html)
        self.assertIn("RAPPORT TRIVY", html)

    def test_the_cta_falls_back_to_the_application_without_a_run(self) -> None:
        _, _, html = compose([event(report_url="")])
        self.assertNotIn("github.com", html)
        self.assertIn("https://fortiupgrade.valdev.me/", html)

    def test_a_non_github_cta_target_is_never_rendered(self) -> None:
        """Defence in depth: the ingestion only keeps GitHub URLs, the renderer refuses the rest."""
        _, _, html = compose([event(report_url="https://evil.example.com/report")])
        self.assertNotIn("evil.example.com", html)

    def test_a_long_scan_is_truncated_with_an_explicit_remainder(self) -> None:
        events = [
            event(cve=f"CVE-2026-{10000 + index}", package=f"pkg-{index}")
            for index in range(render.MAX_FINDINGS_PER_EMAIL + 5)
        ]
        _, text, html = compose(events)
        self.assertIn("5 autres", text)
        self.assertIn("5 autres", html)

    def test_an_empty_batch_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            compose([])


class RoutingTests(unittest.TestCase):
    def test_a_container_batch_is_rendered_by_the_container_composer(self) -> None:
        subject, text, html = fortios_notify.compose_email(
            [event()],
            app_url="https://fortiupgrade.valdev.me/",
            run_timestamp="2026-09-17T05:00:00Z",
        )
        self.assertIn("Sécurité de l'image", subject)
        self.assertIn("gzip", text)
        self.assertIn("cid:sns-panther", html)

    def test_a_cve_batch_still_uses_the_fortinet_composer(self) -> None:
        """Regression guard on the routing decision itself."""
        cve = fortios_notify.NotificationEvent(
            category=fortios_notify.CATEGORY_DAILY,
            dedup_key="cve|CVE-2026-1111",
            summary="CVE-2026-1111",
            severity="high",
            details={"kind": "cve", "id": "CVE-2026-1111", "product": "fortios"},
        )
        subject, _, _ = fortios_notify.compose_email(
            [cve],
            app_url="https://fortiupgrade.valdev.me/",
            run_timestamp="2026-09-17T05:00:00Z",
        )
        # The Fortinet subject counts findings by level; the container one names its own domain.
        self.assertEqual(subject, "[FortiUpgrade] 1 nouvelle vulnérabilité — 1 High")
        self.assertNotIn("Sécurité de l'image", subject)


if __name__ == "__main__":
    unittest.main()
