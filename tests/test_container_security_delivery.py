"""The remaining acceptance points of the container-security feature.

Each test here answers one explicit requirement that the other files do not already cover:
delivery over both transports, independence of the three notification batches when one of them
fails, the HTTP-level refusal of an enabled switch without recipients, HTML escaping of a hostile
report, the re-baseline that follows a rollback, and the contract between the scheduled workflow and
the synchronization script.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import cert_admin
import fortios_notify as notify
import sync_trivy_report
from test_cert_web import running_server
from test_container_security import (
    COMMIT,
    GZIP,
    NEXT_SCAN_AT,
    PACKAGE,
    SCAN_AT,
    container_settings,
)
from test_container_security_email import event
from test_microsoft365_notifications import (
    FakeResponse,
    graph_env,
    notification_settings,
)
from test_security_notifications import settings_payload
from test_smtp_admin import authenticated_opener, email_config

WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"


def smtp_client() -> MagicMock:
    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    return client


class TransportDeliveryTests(unittest.TestCase):
    """The container email must travel over both supported transports, unchanged."""

    def setUp(self) -> None:
        self.subject, self.text, self.html = notify.compose_email(
            [event()],
            app_url="https://fortiupgrade.valdev.me/",
            run_timestamp="2026-09-17T05:00:00Z",
        )
        self.recipients = ("image-security@example.com",)

    def test_smtp_delivers_a_multipart_email_carrying_the_findings(self) -> None:
        client = smtp_client()
        with patch("smtplib.SMTP", return_value=client):
            result = notify.send_email_result(
                replace(email_config(), smtp_to=self.recipients),
                self.subject,
                self.text,
                self.html,
                force=True,
            )
        self.assertTrue(result.sent)
        message = client.send_message.call_args.args[0]
        self.assertEqual(message["To"], ", ".join(self.recipients))
        self.assertIn("Sécurité de l'image", message["Subject"])
        # The SNS identity embeds its logo/panther as `cid:` images, so the root is
        # multipart/related; the two readable bodies live in its multipart/alternative child.
        parts = []
        stack = [message]
        while stack:
            part = stack.pop()
            if part.is_multipart():
                stack.extend(part.get_payload())
            else:
                parts.append(part)
        kinds = {part.get_content_type() for part in parts}
        self.assertIn("text/plain", kinds)
        self.assertIn("text/html", kinds)
        for part in parts:
            if part.get_content_type() in {"text/plain", "text/html"}:
                self.assertIn("CVE-2026-41992", part.get_content())
                self.assertIn("1.13-1+deb13u1", part.get_content())

    def test_microsoft_graph_delivers_the_same_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            secret = Path(tmp) / "secret"
            secret.write_text("graph-secret", encoding="utf-8")
            config = replace(
                notify.load_email_config(
                    graph_env(secret),
                    settings=notification_settings(),
                    smtp_settings_path=Path(tmp) / "smtp-settings.json",
                ),
                smtp_to=self.recipients,
            )
            with patch.object(
                notify,
                "_graph_urlopen",
                side_effect=[FakeResponse(200, b'{"access_token":"token"}'), FakeResponse(202, b"")],
            ) as urlopen:
                result = notify.deliver_email_result(config, self.subject, self.text, self.html)

        self.assertTrue(result.sent)
        self.assertEqual(urlopen.call_count, 2)
        payload = urlopen.call_args_list[1].args[0].data.decode("utf-8")
        self.assertIn("Sécurité de l'image", payload)
        self.assertIn("CVE-2026-41992", payload)
        self.assertIn("image-security@example.com", payload)
        # The Graph transport carries the HTML body as well, escaped inside the JSON payload.
        self.assertIn("VOIR LE RAPPORT TRIVY", payload)


class BatchIndependenceTests(unittest.TestCase):
    """A category that was delivered must never be replayed because another one failed."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.history = Path(self._tmp.name) / "fortios-notify-history.json"
        self.settings = notify.validate_notification_settings(
            settings_payload(release_recipients_shared=False, release_recipients=["releases@example.com"])
        )
        self.container_settings = container_settings(recipients=["image@example.com"])
        self.events = [
            notify.NotificationEvent(
                category=notify.CATEGORY_DAILY,
                dedup_key="cve|CVE-2026-1111",
                summary="CVE-2026-1111",
                severity="high",
                details={"kind": "cve", "id": "CVE-2026-1111"},
            ),
            # Built by the production deriver, not hand-rolled: the real dedup key, the real
            # severity handling (a release event carries none) and the real outbox shape.
            notify.derive_version_events(
                {"fortigate-fortios": {"8.0.0"}},
                {"fortigate-fortios": {"8.0.0", "8.0.1"}},
                {"fortigate-fortios": "FortiOS"},
            )[0],
            event(),
        ]

    def claim(self, claimant: str = "worker-1"):
        return notify.commit_events_with_checkpoint(
            self.history,
            {"generatedAt": SCAN_AT, "versionsByProduct": {}, "cvesById": {}, "health": {}},
            self.events,
            claimant=claimant,
            transport="smtp",
        )

    def test_the_three_categories_are_three_batches_with_their_own_recipients(self) -> None:
        pending = self.claim()
        batches = notify.notification_batches(
            pending, self.settings, container_security=self.container_settings
        )
        self.assertEqual(len(batches), 3)
        self.assertEqual(
            sorted(recipient for batch in batches for recipient in batch.recipients),
            ["image@example.com", "releases@example.com", "security@example.com"],
        )

    def test_a_failed_batch_is_retried_while_the_delivered_ones_are_not_replayed(self) -> None:
        claimant = "worker-1"
        pending = self.claim(claimant)
        batches = notify.notification_batches(
            pending, self.settings, container_security=self.container_settings
        )
        failure = notify.SmtpResult(sent=False, message="SMTP indisponible.", error_code="smtp_error")
        def category(batch) -> str:
            """Which category a batch carries, using the production predicates."""
            if all(notify._is_container_security_event(one) for one in batch.events):
                return "container"
            if all(notify._is_release_event(one) for one in batch.events):
                return "release"
            return "cve"

        delivered: dict[str, bool] = {}
        for batch in batches:
            kind = category(batch)
            # The container batch fails; the two other categories are delivered.
            if kind == "container":
                delivered[kind] = False
                notify.release_claim(self.history, claimant, outcome=failure, transport="smtp")
            else:
                delivered[kind] = True
                notify.finalize_sent_events(self.history, list(batch.events))

        self.assertEqual(delivered, {"container": False, "cve": True, "release": True})
        state = notify.load_notify_state(self.history)
        self.assertEqual([entry["dedupKey"] for entry in state["outbox"]], ["trivy|cve|CVE-2026-41992|gzip"])
        self.assertIn("cve|CVE-2026-1111", state["sentKeys"])
        self.assertIn("new-version|fortios|fortios|8.0.1", state["sentKeys"])
        self.assertNotIn("trivy|cve|CVE-2026-41992|gzip", state["sentKeys"])

        # Next pass: the container category is retried, and nothing else is claimed again.
        pending_again = notify.commit_events_with_checkpoint(
            self.history,
            {"generatedAt": NEXT_SCAN_AT, "versionsByProduct": {}, "cvesById": {}, "health": {}},
            [],
            claimant="worker-2",
            transport="smtp",
        )
        self.assertEqual([one.dedup_key for one in pending_again], ["trivy|cve|CVE-2026-41992|gzip"])

    def test_a_delivered_batch_is_definitive_even_after_a_later_failure(self) -> None:
        claimant = "worker-1"
        pending = self.claim(claimant)
        container_batch = next(
            batch
            for batch in notify.notification_batches(
                pending, self.settings, container_security=self.container_settings
            )
            if notify._is_container_security_event(batch.events[0])
        )
        notify.finalize_sent_events(self.history, list(container_batch.events))
        notify.release_claim(
            self.history,
            claimant,
            outcome=notify.SmtpResult(sent=False, message="échec", error_code="smtp_error"),
            transport="smtp",
        )
        state = notify.load_notify_state(self.history)
        self.assertNotIn(
            "trivy|cve|CVE-2026-41992|gzip",
            [entry["dedupKey"] for entry in state["outbox"]],
        )


class EscapingTests(unittest.TestCase):
    def test_a_hostile_report_cannot_inject_markup_into_the_email(self) -> None:
        """The renderer escapes; the report is untrusted input, by construction."""
        hostile = event(
            cve="CVE-2026-41992",
            title="<script>alert('x')</script><img src=x onerror=alert(1)>",
            url="",
        )
        hostile.details["package"] = "<b>gzip</b>"
        _, text, html = notify.compose_email(
            [hostile],
            app_url="https://fortiupgrade.valdev.me/",
            run_timestamp="2026-09-17T05:00:00Z",
        )
        # Only the escaped form is present: no live tag, no live attribute — the payload is text.
        self.assertNotIn("<script>", html)
        self.assertNotIn("<b>gzip</b>", html)
        self.assertNotIn("<img src=x onerror", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("&lt;b&gt;gzip&lt;/b&gt;", html)
        # The plain-text body is not HTML, so it carries the raw text without executing anything.
        self.assertIn("<script>", text)

    def test_the_subject_is_built_from_counts_and_never_from_report_text(self) -> None:
        hostile = event(title="Sujet\r\nBcc: attacker@example.com")
        subject, _, _ = notify.compose_email(
            [hostile],
            app_url="https://fortiupgrade.valdev.me/",
            run_timestamp="2026-09-17T05:00:00Z",
        )
        self.assertNotIn("\n", subject)
        self.assertNotIn("\r", subject)
        self.assertNotIn("attacker@example.com", subject)

    def test_several_findings_still_produce_a_single_email(self) -> None:
        events = [
            event(),
            event(cve="CVE-2026-13221", package="perl-base", severity="critical",
                  installed="5.40.1-6", fixed="5.40.1-6+deb13u1"),
            event(cve="CVE-2026-11822", package="libsqlite3-0"),
        ]
        subject, text, _ = notify.compose_email(
            events,
            app_url="https://fortiupgrade.valdev.me/",
            run_timestamp="2026-09-17T05:00:00Z",
        )
        self.assertEqual(subject, "[FortiUpgrade] Sécurité de l'image — 3 nouvelles vulnérabilités")
        for cve in ("CVE-2026-41992", "CVE-2026-13221", "CVE-2026-11822"):
            self.assertEqual(text.count(cve), 1)


class AdminApiTests(unittest.TestCase):
    """The panel's contract at HTTP level: refusal, persistence, isolation from the CVE document."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.data_dir = root / "data"
        credentials = root / "credentials.json"
        cert_admin.write_credentials(
            credentials,
            cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
        )
        self.environment = {
            "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
            "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            "FORTIOS_TEST_DATA_DIR": str(self.data_dir),
            "FORTIOS_SMTP_PASSWORD_FILE": str(root / "smtp-secrets" / "password"),
        }
        (root / "smtp-secrets").mkdir(mode=0o700)

    def test_enabling_without_a_recipient_is_refused_with_400(self) -> None:
        with running_server(self.environment) as base_url:
            opener, csrf = authenticated_opener(base_url)

            def post(body: dict) -> dict:
                request = urllib.request.Request(
                    f"{base_url}/api/cert/container-security",
                    data=json.dumps(body).encode(),
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Origin": base_url,
                        "X-CSRF-Token": csrf,
                    },
                )
                with opener.open(request, timeout=3) as response:
                    return json.load(response)

            with self.assertRaises(urllib.error.HTTPError) as refused:
                post({"enabled": True, "minimumSeverity": "high", "recipients": []})
            self.assertEqual(refused.exception.code, 400)

            # An unsupported level is refused too, never silently replaced by the default.
            with self.assertRaises(urllib.error.HTTPError) as bad_level:
                post({"enabled": False, "minimumSeverity": "medium", "recipients": []})
            self.assertEqual(bad_level.exception.code, 400)

            with opener.open(f"{base_url}/api/cert/container-security", timeout=3) as response:
                initial = json.load(response)
            self.assertFalse(initial["settings"]["enabled"])
            self.assertEqual(initial["report"]["state"], "absent")
            self.assertIsNone(initial["report"]["total"])

            saved = post(
                {
                    "enabled": True,
                    "minimumSeverity": "critical",
                    "recipients": ["image@example.com"],
                }
            )
            self.assertEqual(
                saved["settings"],
                {
                    "enabled": True,
                    "minimumSeverity": "critical",
                    "recipients": ["image@example.com"],
                },
            )
            with opener.open(f"{base_url}/api/cert/container-security", timeout=3) as response:
                self.assertEqual(json.load(response), saved)

        # The Fortinet preferences document is never touched by this category.
        self.assertFalse((self.data_dir / "notification-settings.json").exists())

    def test_a_malformed_document_is_reported_and_left_alone(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        path = self.data_dir / "container-security-settings.json"
        broken = '{"enabled": true}'
        path.write_text(broken, encoding="utf-8")
        with running_server(self.environment) as base_url:
            opener, _ = authenticated_opener(base_url)
            with opener.open(f"{base_url}/api/cert/container-security", timeout=3) as response:
                payload = json.load(response)
            self.assertFalse(payload["settings"]["enabled"])
            self.assertTrue(payload["report"]["reason"])
        self.assertEqual(path.read_text(encoding="utf-8"), broken)


class RollbackTests(unittest.TestCase):
    """What a rollback really costs, and why it must not produce a flood."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.data = Path(self._tmp.name)
        self.history = self.data / "fortios-notify-history.json"
        self.report = self.data / "trivy-report.json"
        self.metadata = self.data / "trivy-report.meta.json"

    def publish(self, payload: dict) -> None:
        import hashlib

        raw = json.dumps(payload).encode("utf-8")
        self.report.write_bytes(raw)
        self.metadata.write_text(
            json.dumps(
                {
                    "commit": COMMIT,
                    "runId": "1",
                    "runUrl": "https://github.com/Tetrax/upgrade_path_forti/actions/runs/1",
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            ),
            encoding="utf-8",
        )

    def report_of(self, *findings) -> dict:
        return {
            "SchemaVersion": 2,
            "ArtifactName": "fortios-upgrade-intelligence:ci-scan",
            "ArtifactType": "container_image",
            "CreatedAt": SCAN_AT,
            "Results": [
                {
                    "Target": "debian",
                    "Class": "os-pkgs",
                    "Type": "debian",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": cve,
                            "PkgName": package,
                            "Severity": severity,
                            "InstalledVersion": installed,
                            "FixedVersion": fixed,
                            "Status": "fixed",
                        }
                        for (cve, package, severity, installed, fixed) in findings
                    ],
                }
            ],
        }

    def test_an_image_that_drops_the_section_leads_to_a_silent_re_baseline(self) -> None:
        """The writable path of a pre-feature image loses `containerSecurityState`.

        That loss is not corruption: the next ingestion re-establishes a baseline WITHOUT sending
        the whole backlog, which is exactly what makes the rollback acceptable.
        """
        self.publish(self.report_of(PACKAGE, GZIP))
        notify.ingest_container_security_report(
            self.report, self.metadata, container_settings(), history_path=self.history, now=SCAN_AT
        )
        self.assertTrue(
            notify.load_notify_state(self.history)["containerSecurityState"]["findings"]
        )

        # An older image writes the state back through its own loader: the key is dropped.
        legacy = notify._empty_notify_state()
        legacy.pop("containerSecurityState")
        legacy["sentKeys"]["cve|CVE-2026-1"] = SCAN_AT
        notify.write_json(self.history, legacy)

        events, error = notify.ingest_container_security_report(
            self.report,
            self.metadata,
            container_settings(),
            history_path=self.history,
            now="2026-09-17T05:00:00Z",
        )
        self.assertEqual((events, error), ([], ""))
        state = notify.load_notify_state(self.history)
        self.assertEqual(len(state["containerSecurityState"]["findings"]), 2)
        self.assertIn("cve|CVE-2026-1", state["sentKeys"])
        self.assertEqual(state["outbox"], [])

    def test_the_documents_a_rollback_must_restore_are_the_documented_ones(self) -> None:
        documentation = (ROOT / "docs" / "delivery.md").read_text(encoding="utf-8")
        for element in (
            "container-security-settings.json",
            "fortios-notify-history.json",
            "containerSecurityState",
        ):
            self.assertIn(element, documentation)


class ScheduledSyncContractTests(unittest.TestCase):
    """The workflow and the sync script are two halves of one contract; assert it here."""

    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_the_scan_runs_on_a_daily_schedule(self) -> None:
        self.assertIn("schedule:", self.workflow)
        self.assertIn('cron: "17 4 * * *"', self.workflow)

    def test_the_artifact_name_matches_what_the_sync_downloads(self) -> None:
        self.assertIn(f"name: {sync_trivy_report.ARTIFACT_NAME}", self.workflow)

    def test_the_report_filename_matches_what_the_sync_expects(self) -> None:
        self.assertIn("output: trivy.json", self.workflow)
        self.assertEqual(sync_trivy_report.REPORT_FILENAME, "trivy-report.json")

    def test_the_scan_keeps_alerting_only_on_actionable_findings(self) -> None:
        """`ignore-unfixed: true` is a deliberate choice: only fixed vulnerabilities are alerted."""
        self.assertIn("ignore-unfixed: true", self.workflow)
        self.assertIn("exit-code: 0", self.workflow)


if __name__ == "__main__":
    unittest.main()
