"""Release ("nouvelle version") notifications: independent switch, SNS rendering, transports.

Before this change a single `enabled` switch and one recipient list drove every category, so a
new FortiOS version was mailed to the CVE recipients with the historical plain-text renderer
(``Événements détectés : - Nouvelle version ...`` inside a ``<pre>`` block, no SNS identity).

These tests pin the delivered behaviour through the real collector wiring, the real composers and
both transports:

- the CVE/system switch and the release switch are independent, in both directions;
- a release detected while release notifications are off is never replayed after re-enabling;
- release-only emails use the SNS renderer, over SMTP MIME and Microsoft Graph JSON;
- the historical dedup key is unchanged, so a pending outbox entry is never re-sent.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import urllib.request
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import cert_admin
import fortios_email_render as render
import fortios_notify as notify
import fortios_watch as fw

from tests.test_cert_web import running_server
from tests.test_microsoft365_notifications import FakeResponse, graph_env
from tests.test_smtp_admin import (
    authenticated_opener,
    running_smtp_server,
)

APP_URL = "https://fortiupgrade.example/app/"
RUN_TS = "2026-09-16T05:15:22Z"
DETECTED_AT = "2026-09-16T05:15:00Z"
APPEARANCE = {
    "displayName": "FortiUpgrade — Alertes de sécurité Fortinet",
    "introduction": "Introduction de test.",
    "signature": "Signature de test.",
}
SMTP_ENV = {
    "FORTIOS_SMTP_HOST": "smtp.example.com",
    "FORTIOS_SMTP_PORT": "587",
    "FORTIOS_SMTP_FROM": "fortios@example.com",
}
RELEASE_DEDUP_KEY = "new-version|fortios|fortios|8.0.1"


def _firmware(version: str) -> dict[str, Any]:
    return {
        "version": version,
        "links": {
            "release-notes": (
                f"https://docs.fortinet.com/document/fortigate/{version}/fortios-release-notes"
            )
        },
    }


def _catalog(
    *,
    fortios: tuple[str, ...] = ("8.0.0",),
    fortimanager: tuple[str, ...] = (),
    forticlient: tuple[str, ...] = (),
    cves: tuple[dict[str, Any], ...] = (),
) -> dict[str, Any]:
    products: list[dict[str, Any]] = [
        {
            "id": "fortigate-fortios",
            "label": "FortiGate / FortiOS",
            "models": [
                {"id": "FGT-100F", "firmwares": [_firmware(v) for v in fortios]}
            ],
        }
    ]
    if fortimanager:
        products.append(
            {
                "id": "fortimanager",
                "label": "FortiManager",
                "models": [
                    {"id": "FMG-200F", "firmwares": [_firmware(v) for v in fortimanager]}
                ],
            }
        )
    if forticlient:
        products.append(
            {
                "id": "forticlient",
                "label": "FortiClient Windows",
                "models": [
                    {"id": "windows", "firmwares": [_firmware(v) for v in forticlient]}
                ],
            }
        )
    return fw.normalize_state({"products": products, "cves": list(cves)})


def _cve(cve_id: str = "CVE-2026-99999", severity: str = "critical") -> dict[str, Any]:
    return {
        "id": cve_id,
        "advisoryId": "FG-IR-26-900",
        "title": f"Résumé {cve_id}",
        "severity": severity,
        "cvssScore": 9.8,
        "url": "https://fortiguard.fortinet.com/psirt/FG-IR-26-900",
        "affected": [{"product": "fortigate-fortios", "branch": "8.0"}],
    }


def _notification_settings(*, enabled: bool, releases: bool) -> dict[str, Any]:
    return {
        "enabled": enabled,
        "releaseNotificationsEnabled": releases,
        "minimumSeverity": "high",
        "products": {
            "fortigate-fortios": True,
            "fortimanager": True,
            "fortianalyzer": True,
            "forticlient-ems": True,
            "forticlient": {"windows": True, "macos": True, "linux": True},
        },
        "recipients": ["security@example.com"],
    }


def _legacy_notification_settings(*, enabled: bool) -> dict[str, Any]:
    payload = _notification_settings(enabled=enabled, releases=enabled)
    payload.pop("releaseNotificationsEnabled")
    return payload


class _CollectorRun:
    """One real fortios_watch.main() run with a mocked SMTP client and no network."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.base = root / "state.json"
        self.health = root / "health.json"
        self.history = root / "notify-history.json"
        self.settings = root / "notification-settings.json"
        self.messages: list[bytes] = []

    def seed(self, state: dict[str, Any]) -> None:
        fw.write_json(self.base, state)

    def write_settings(self, payload: dict[str, Any]) -> None:
        self.settings.write_text(json.dumps(payload), encoding="utf-8")

    def run(self) -> int:
        client = MagicMock()
        client.__enter__ = MagicMock(return_value=client)
        client.__exit__ = MagicMock(return_value=False)

        def capture(message: Any, *_args: Any, **_kwargs: Any) -> None:
            self.messages.append(message.as_bytes())

        client.send_message = MagicMock(side_effect=capture)
        arguments = [
            "--skip-network",
            "--base", str(self.base), "--output", str(self.base),
            "--report", str(self.root / "report.md"),
            "--health-output", str(self.health),
            "--notify-history-output", str(self.history),
            "--notification-settings-output", str(self.settings),
            "--official-paths-csv", str(self.root / "no-official-paths.csv"),
            "--advisories-csv", str(self.root / "no-advisories.csv"),
            "--upgrade-exports", str(self.root / "no-upgrade-exports"),
        ]
        with patch.dict(os.environ, SMTP_ENV, clear=False), patch(
            "smtplib.SMTP", return_value=client
        ):
            return fw.main(arguments)

    def state(self) -> dict[str, Any]:
        return json.loads(self.history.read_text(encoding="utf-8"))

    def subjects(self) -> list[str]:
        return [
            BytesParser(policy=policy.default).parsebytes(raw)["Subject"]
            for raw in self.messages
        ]


class SwitchIndependenceTests(unittest.TestCase):
    """"The four combinations, driven through the collector's real main()."""

    def _prepare(self, root: Path, settings: dict[str, Any]) -> _CollectorRun:
        run = _CollectorRun(root)
        run.write_settings(settings)
        run.seed(_catalog(fortios=("8.0.0",)))
        self.assertEqual(run.run(), 0)
        # Anchor: this first run only establishes the baseline, nothing is notified.
        self.assertEqual(run.messages, [])
        return run

    def test_both_switches_on_notify_the_release_and_the_cve(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = self._prepare(
                Path(tmp), _notification_settings(enabled=True, releases=True)
            )
            run.seed(_catalog(fortios=("8.0.0", "8.0.1"), cves=(_cve(),)))

            self.assertEqual(run.run(), 0)

            sent_keys = run.state()["sentKeys"]
            self.assertIn(RELEASE_DEDUP_KEY, sent_keys)
            self.assertIn("new-cve|psirt|CVE-2026-99999|critical", sent_keys)
            # One synthetic email per run, CVE-first, with the release folded in.
            self.assertEqual(len(run.messages), 1)
            self.assertIn("nouvelle vulnérabilité", run.subjects()[0])

    def test_release_off_keeps_cve_and_system_notifications_working(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = self._prepare(
                Path(tmp), _notification_settings(enabled=True, releases=False)
            )
            run.seed(_catalog(fortios=("8.0.0", "8.0.1"), cves=(_cve(),)))

            self.assertEqual(run.run(), 0)

            sent_keys = run.state()["sentKeys"]
            self.assertNotIn(RELEASE_DEDUP_KEY, sent_keys)
            self.assertIn("new-cve|psirt|CVE-2026-99999|critical", sent_keys)
            for subject in run.subjects():
                self.assertNotIn("Nouvelle version", subject)

    def test_release_on_with_cves_off_notifies_only_the_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = self._prepare(
                Path(tmp), _notification_settings(enabled=False, releases=True)
            )
            run.seed(_catalog(fortios=("8.0.0", "8.0.1"), cves=(_cve(),)))

            self.assertEqual(run.run(), 0)

            sent_keys = run.state()["sentKeys"]
            self.assertIn(RELEASE_DEDUP_KEY, sent_keys)
            self.assertNotIn("new-cve|psirt|CVE-2026-99999|critical", sent_keys)
            self.assertEqual(len(run.messages), 1)
            self.assertEqual(
                run.subjects()[0],
                "[FortiUpgrade] Nouvelle version — FortiGate / FortiOS 8.0.1",
            )
            message = BytesParser(policy=policy.default).parsebytes(run.messages[0])
            html = message.get_body(preferencelist=("html",)).get_content()
            self.assertIn("cid:sns-logo", html)

    def test_both_switches_off_notify_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = self._prepare(
                Path(tmp), _notification_settings(enabled=False, releases=False)
            )
            run.seed(_catalog(fortios=("8.0.0", "8.0.1"), cves=(_cve(),)))

            self.assertEqual(run.run(), 0)

            self.assertEqual(run.messages, [])
            self.assertEqual(run.state()["outbox"], [])
            self.assertEqual(run.state()["sentKeys"], {})
            self.assertEqual(run.state()["checkpoint"]["versionsByProduct"]["fortigate-fortios"], ["8.0.0", "8.0.1"])

    def test_release_off_advances_the_version_checkpoint_so_reenabling_replays_nothing(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = self._prepare(
                Path(tmp), _notification_settings(enabled=True, releases=False)
            )
            run.seed(_catalog(fortios=("8.0.0", "8.0.1")))

            self.assertEqual(run.run(), 0)
            self.assertEqual(run.messages, [])
            self.assertEqual(
                run.state()["checkpoint"]["versionsByProduct"]["fortigate-fortios"],
                ["8.0.0", "8.0.1"],
            )

            # Re-enabling releases must not replay 8.0.1: the baseline moved while it was off.
            run.write_settings(_notification_settings(enabled=True, releases=True))
            self.assertEqual(run.run(), 0)
            self.assertEqual(run.messages, [])

            # A genuinely newer release is still notified afterwards.
            run.seed(_catalog(fortios=("8.0.0", "8.0.1", "8.0.2")))
            self.assertEqual(run.run(), 0)
            self.assertEqual(len(run.messages), 1)
            self.assertEqual(
                run.subjects()[0],
                "[FortiUpgrade] Nouvelle version — FortiGate / FortiOS 8.0.2",
            )

    def test_legacy_four_key_settings_keep_notifying_releases(self) -> None:
        """A file with no release switch inherits `enabled`: no silent behaviour change."""
        with tempfile.TemporaryDirectory() as tmp:
            run = self._prepare(Path(tmp), _legacy_notification_settings(enabled=True))
            run.seed(_catalog(fortios=("8.0.0", "8.0.1")))

            self.assertEqual(run.run(), 0)

            self.assertIn(RELEASE_DEDUP_KEY, run.state()["sentKeys"])
            self.assertEqual(len(run.messages), 1)
            self.assertIn(
                "Nouvelle version — FortiGate / FortiOS 8.0.1", run.subjects()[0]
            )
            # Recipients are preserved, never rewritten by the loader.
            self.assertEqual(
                json.loads(run.settings.read_text(encoding="utf-8"))["recipients"],
                ["security@example.com"],
            )

    def test_forticlient_versions_are_never_notifiable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = self._prepare(
                Path(tmp),
                _notification_settings(enabled=True, releases=True),
            )
            run.seed(_catalog(fortios=("8.0.0",), forticlient=("7.4.3",)))

            self.assertEqual(run.run(), 0)

            self.assertEqual(run.messages, [])
            self.assertEqual(run.state()["sentKeys"], {})

    def test_fortimanager_and_fortianalyzer_releases_are_notified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = self._prepare(
                Path(tmp), _notification_settings(enabled=True, releases=True)
            )
            run.seed(_catalog(fortios=("8.0.0",), fortimanager=("7.6.7",)))

            self.assertEqual(run.run(), 0)

            self.assertIn("new-version|fortimanager|fortimanager|7.6.7", run.state()["sentKeys"])


class ReleaseEventTests(unittest.TestCase):
    def test_release_event_keeps_the_historical_dedup_key_and_adds_details(self) -> None:
        events = notify.derive_version_events(
            {"fortigate-fortios": {"8.0.0"}},
            {"fortigate-fortios": {"8.0.0", "8.0.1"}},
            {"fortigate-fortios": "FortiGate / FortiOS"},
            detected_at=DETECTED_AT,
            release_links={
                "fortigate-fortios": {
                    "8.0.1": "https://docs.fortinet.com/document/fortigate/8.0.1/fortios-release-notes"
                }
            },
        )

        self.assertEqual([event.dedup_key for event in events], [RELEASE_DEDUP_KEY])
        details = events[0].details
        self.assertEqual(details["kind"], "release")
        self.assertEqual(details["product"], "fortigate-fortios")
        self.assertEqual(details["productLabel"], "FortiGate / FortiOS")
        self.assertEqual(details["version"], "8.0.1")
        self.assertEqual(details["detectedAt"], DETECTED_AT)
        self.assertTrue(details["releaseNotesUrl"].startswith("https://docs.fortinet.com/"))

    def test_structured_details_survive_the_outbox_round_trip(self) -> None:
        """A retried event must still render product/version, not an empty card."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            event = notify.derive_version_events(
                {"fortigate-fortios": {"8.0.0"}},
                {"fortigate-fortios": {"8.0.0", "8.0.1"}},
                {"fortigate-fortios": "FortiGate / FortiOS"},
                detected_at=DETECTED_AT,
            )[0]
            claimed = notify.enqueue_and_claim(path, [event], claimant="run-1")

            self.assertEqual(len(claimed), 1)
            self.assertEqual(claimed[0].dedup_key, RELEASE_DEDUP_KEY)
            self.assertEqual(claimed[0].details["version"], "8.0.1")


class ReleaseRendererTests(unittest.TestCase):
    def compose(self, events: list[Any], *, other: list[Any] | None = None) -> tuple[str, str, str]:
        composed = notify.compose_email(
            events + (other or []),
            app_url=APP_URL,
            run_timestamp=RUN_TS,
            appearance=notify.validate_email_appearance(APPEARANCE),
        )
        assert composed is not None
        return composed

    def releases(self, *versions: str) -> list[Any]:
        return notify.derive_version_events(
            {"fortigate-fortios": {"8.0.0"}},
            {"fortigate-fortios": {"8.0.0", *versions}},
            {"fortigate-fortios": "FortiGate / FortiOS"},
            detected_at=DETECTED_AT,
            release_links={
                "fortigate-fortios": {
                    version: (
                        f"https://docs.fortinet.com/document/fortigate/{version}/fortios-release-notes"
                    )
                    for version in versions
                }
            },
        )

    def test_release_only_email_uses_the_sns_renderer(self) -> None:
        subject, _text, html = self.compose(self.releases("8.0.1"))

        self.assertEqual(subject, "[FortiUpgrade] Nouvelle version — FortiGate / FortiOS 8.0.1")
        # The historical plain-text <pre> rendering is gone; the SNS identity is used instead.
        self.assertNotIn("<pre", html)
        self.assertNotIn("Resume quotidien", subject)
        self.assertIn("cid:sns-logo", html)
        self.assertIn("cid:sns-panther", html)
        self.assertIn("ALERTE INTERNE", html)
        self.assertIn("ÉQUIPE SUPPORT", html)
        self.assertIn("OUVRIR FORTIUPGRADE", html)
        # No CVE business component leaks into a release email.
        self.assertNotIn("vulnérabilit", html)
        self.assertNotIn("CVSS", html)
        self.assertIn("Une nouvelle version Fortinet est disponible.", html)

    def test_release_email_shows_product_version_and_detection_date(self) -> None:
        _, text, html = self.compose(self.releases("8.0.1"))

        for body in (text, html):
            self.assertIn("FortiGate / FortiOS", body)
            self.assertIn("8.0.1", body)
            self.assertIn("16 septembre 2026", body)
        self.assertIn("Notes de version Fortinet", html)
        self.assertIn(
            "https://docs.fortinet.com/document/fortigate/8.0.1/fortios-release-notes", html
        )
        # The analyst appearance is applied to the release email too.
        self.assertIn("Introduction de test.", text)
        self.assertIn("Signature de test.", text)

    def test_multi_release_email_renders_every_release_in_one_email(self) -> None:
        subject, text, html = self.compose(self.releases("8.0.1", "8.0.2"))

        self.assertEqual(subject, "[FortiUpgrade] 2 nouvelles versions Fortinet")
        self.assertIn("2 nouvelles versions Fortinet sont disponibles.", html)
        self.assertIn("VERSIONS DÉTECTÉES", html)
        for version in ("8.0.1", "8.0.2"):
            self.assertIn(version, html)
            self.assertIn(version, text)
        self.assertEqual(html.count("NOUVELLE VERSION"), 2)

    def test_release_email_keeps_system_events_in_their_own_section(self) -> None:
        eol = notify.NotificationEvent(
            category="OPERATIONS",
            dedup_key="eol|7.0|branch",
            summary="Branche 7.0 en fin de support",
        )
        _, text, html = self.compose(self.releases("8.0.1"), other=[eol])

        self.assertIn("AUTRES ÉVÉNEMENTS", html)
        self.assertIn("Branche 7.0 en fin de support", html)
        self.assertIn("Autres événements :", text)

    def test_pending_release_event_from_an_older_build_still_renders(self) -> None:
        """An event queued before structured details existed has only its summary."""
        legacy = notify.NotificationEvent(
            category="DAILY",
            dedup_key=RELEASE_DEDUP_KEY,
            summary="Nouvelle version FortiGate / FortiOS 8.0.1",
        )
        subject, _text, html = self.compose([legacy])

        self.assertEqual(subject, "[FortiUpgrade] Nouvelle version — Nouvelle version FortiGate / FortiOS 8.0.1")
        self.assertIn("Nouvelle version FortiGate / FortiOS 8.0.1", html)
        self.assertIn("cid:sns-logo", html)

    def test_a_pathological_release_batch_is_truncated_with_a_clear_note(self) -> None:
        """A huge batch must not produce an unbounded email, exactly like the system section."""
        events = notify.derive_version_events(
            {"fortigate-fortios": set()},
            {"fortigate-fortios": {f"7.{index}.0" for index in range(30)}},
            {"fortigate-fortios": "FortiGate / FortiOS"},
        )
        _, text, html = self.compose(events)

        self.assertEqual(html.count("NOUVELLE VERSION"), render.MAX_RELEASES_PER_EMAIL)
        for body in (text, html):
            self.assertIn("et 10 de plus", body)
            self.assertIn("tronquée", body)

    def test_release_notes_link_must_be_an_absolute_http_url(self) -> None:
        for candidate in ("javascript:alert(1)", "/relative/path", "https://u:p@host/x"):
            event = notify.NotificationEvent(
                category="DAILY",
                dedup_key=RELEASE_DEDUP_KEY,
                summary="Nouvelle version FortiGate / FortiOS 8.0.1",
                details={
                    "kind": "release",
                    "productLabel": "FortiGate / FortiOS",
                    "version": "8.0.1",
                    "detectedAt": DETECTED_AT,
                    "releaseNotesUrl": candidate,
                },
            )
            _, _, html = self.compose([event])

            self.assertNotIn(candidate, html)
            self.assertNotIn("Notes de version Fortinet", html)

    def test_catalog_values_are_escaped(self) -> None:
        event = notify.NotificationEvent(
            category="DAILY",
            dedup_key=RELEASE_DEDUP_KEY,
            summary="x",
            details={
                "kind": "release",
                "productLabel": "<script>alert(1)</script>",
                "version": "8.0.1",
                "detectedAt": DETECTED_AT,
            },
        )
        _, _, html = self.compose([event])

        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)


class ReleaseTransportTests(unittest.TestCase):
    def _config(self, root: Path, **overrides: Any) -> notify.EmailConfig:
        settings = notify.validate_notification_settings(
            _notification_settings(enabled=True, releases=True)
        )
        environment = {**SMTP_ENV, **overrides}
        return notify.load_email_config(
            environment,
            settings=settings,
            settings_path=root / "notification-settings.json",
        )

    def _composed(self) -> tuple[str, str, str]:
        events = notify.derive_version_events(
            {"fortigate-fortios": {"8.0.0"}},
            {"fortigate-fortios": {"8.0.0", "8.0.1"}},
            {"fortigate-fortios": "FortiGate / FortiOS"},
            detected_at=DETECTED_AT,
        )
        composed = notify.compose_email(
            events, app_url=APP_URL, run_timestamp=RUN_TS, appearance=None
        )
        assert composed is not None
        return composed

    def test_release_email_over_smtp_is_clean_utf8_mime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with running_smtp_server() as smtp:
                config = self._config(
                    Path(tmp),
                    FORTIOS_SMTP_HOST="127.0.0.1",
                    FORTIOS_SMTP_PORT=str(smtp.server_address[1]),
                    FORTIOS_SMTP_SECURITY="none",
                    FORTIOS_SMTP_ALLOW_INSECURE="true",
                )
                subject, text, html = self._composed()
                result = notify.send_email_result(config, subject, text, html)

            self.assertTrue(result.sent, result.message)
            self.assertEqual(len(smtp.messages), 1)
            raw = smtp.messages[0]

        self.assertNotIn(b"quoted-printable", raw.lower())
        self.assertNotIn(b"=C3", raw)
        message = BytesParser(policy=policy.default).parsebytes(raw)
        self.assertEqual(message["Subject"], subject)
        self.assertEqual(message["To"], "security@example.com")
        plain = message.get_body(preferencelist=("plain",)).get_content()
        self.assertIn("FortiGate / FortiOS — 8.0.1", plain)
        self.assertIn("Détectée le 16 septembre 2026", plain)
        rendered_html = message.get_body(preferencelist=("html",)).get_content()
        self.assertIn("cid:sns-logo", rendered_html)
        self.assertIn("8.0.1", rendered_html)

    def test_release_email_over_microsoft365_sends_utf8_html_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = root / "microsoft365-client-secret"
            secret.write_text("secret-value\n", encoding="utf-8")
            settings = notify.validate_notification_settings(
                _notification_settings(enabled=False, releases=True)
            )
            config = notify.load_email_config(
                graph_env(secret),
                settings=settings,
                settings_path=root / "notification-settings.json",
                smtp_settings_path=root / "smtp-settings.json",
            )
            subject, text, html = self._composed()
            with patch.object(
                notify,
                "_graph_urlopen",
                side_effect=[
                    FakeResponse(200, b'{"access_token":"access-token"}'),
                    FakeResponse(202),
                ],
            ) as urlopen:
                result = notify.send_email_result(config, subject, text, html)

        self.assertTrue(result.sent)
        self.assertEqual(result.transport, "microsoft365")
        payload = json.loads(urlopen.call_args_list[1].args[0].data.decode("utf-8"))
        message = payload["message"]
        self.assertEqual(message["subject"], subject)
        self.assertEqual(message["body"]["contentType"], "HTML")
        self.assertIn("FortiGate / FortiOS", message["body"]["content"])
        self.assertIn("8.0.1", message["body"]["content"])
        self.assertIn("16 septembre 2026", message["body"]["content"])
        self.assertEqual(
            message["toRecipients"],
            [{"emailAddress": {"address": "security@example.com"}}],
        )


class ReleasePreviewTests(unittest.TestCase):
    def preview(self, scenario: str) -> dict[str, str]:
        return notify.compose_email_preview(
            scenario,
            app_url=APP_URL,
            run_timestamp=RUN_TS,
            appearance=notify.validate_email_appearance(APPEARANCE),
        )

    def test_release_scenarios_are_rendered_by_the_production_composer(self) -> None:
        self.assertIn("release", notify.EMAIL_PREVIEW_SCENARIOS)
        self.assertIn("release-multi", notify.EMAIL_PREVIEW_SCENARIOS)

        single = self.preview("release")
        multi = self.preview("release-multi")

        expected = notify.compose_email(
            notify.build_email_preview_events("release", detected_at=RUN_TS),
            app_url=APP_URL,
            run_timestamp=RUN_TS,
            appearance=notify.validate_email_appearance(APPEARANCE),
        )
        assert expected is not None
        self.assertEqual((single["subject"], single["text"], single["html"]), expected)
        self.assertEqual(
            single["subject"], "[FortiUpgrade] Nouvelle version — FortiGate / FortiOS 8.0.1"
        )
        self.assertEqual(multi["subject"], "[FortiUpgrade] 2 nouvelles versions Fortinet")
        self.assertTrue(multi["html"].startswith("<!doctype html>"))
        self.assertEqual(multi["html"].count("NOUVELLE VERSION"), 2)
        # The preview must not leak the CVE business components.
        self.assertNotIn("CVSS", single["html"])

    def test_release_preview_is_served_by_the_admin_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "data"
            credentials = root / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_TEST_DATA_DIR": str(data_dir),
            }
            with running_server(environment) as base_url:
                opener, csrf_token = authenticated_opener(base_url)
                request = urllib.request.Request(
                    f"{base_url}/api/cert/notifications/preview",
                    data=json.dumps(
                        {"scenario": "release", "appearance": APPEARANCE}
                    ).encode(),
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Origin": base_url,
                        "X-CSRF-Token": csrf_token,
                    },
                )
                with opener.open(request, timeout=5) as response:
                    preview = json.load(response)

                # The JSON response carries a session-bound render URL rather than the raw
                # HTML: fetch it, exactly like the admin page does.
                with opener.open(f"{base_url}{preview['renderUrl']}", timeout=5) as rendered:
                    served = rendered.read().decode("utf-8")

        self.assertEqual(preview["scenario"], "release")
        self.assertIn("Nouvelle version", preview["subject"])
        self.assertIn("FortiGate / FortiOS", preview["text"])
        # Served document: CID assets are inlined as data URIs for display only, and the raw
        # HTML is deliberately not part of the JSON response (only the session-bound URL).
        self.assertNotIn("html", preview)
        self.assertIn("data:image/png;base64,", served)
        self.assertNotIn("<pre", served)
        self.assertIn("8.0.1", served)


class ReleaseEmailIntegrationPointTests(unittest.TestCase):
    """The renderer is reachable from the transport-agnostic composer, not only from tests."""

    def test_compose_email_routes_release_batches_to_the_release_renderer(self) -> None:
        events = notify.derive_version_events(
            {"fortigate-fortios": {"8.0.0"}},
            {"fortigate-fortios": {"8.0.0", "8.0.1"}},
            {"fortigate-fortios": "FortiGate / FortiOS"},
        )
        captured: list[Any] = []
        original = render.compose_release_email

        def recording(*args: Any, **kwargs: Any) -> tuple[str, str, str]:
            captured.append(args[0])
            return original(*args, **kwargs)

        with patch.object(render, "compose_release_email", side_effect=recording):
            notify.compose_email([events[0]], app_url=APP_URL, run_timestamp=RUN_TS)

        self.assertEqual(len(captured), 1)
        self.assertEqual([event.dedup_key for event in captured[0]], [RELEASE_DEDUP_KEY])


if __name__ == "__main__":
    unittest.main()
