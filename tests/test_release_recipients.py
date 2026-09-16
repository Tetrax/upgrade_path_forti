"""Dedicated release recipients: settings model, delivery routing, partial failures.

The release category can now deliver to its own recipient list. The rules this module pins:

- a settings file written before the two new keys inherits `releaseRecipientsShared = true`, so
  releases keep going to the CVE list and nothing is rewritten or lost;
- a dedicated list is only used when sharing is explicitly disabled, and an empty dedicated list
  is refused instead of silently falling back or silently sending nowhere;
- events are grouped into one email per effective recipient list, so CVEs + releases still travel
  in a single grouped email while the lists are shared, and split into two emails when they are
  not;
- each batch is finalized (or released) on its own, which is what keeps one category's failure
  from blocking or duplicating the other while dedup, outbox, claims and retries stay untouched.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_notify as notify
import fortios_watch as fw

from tests.test_microsoft365_notifications import FakeResponse, graph_env
from tests.test_release_notifications import (
    SMTP_ENV,
)
from tests.test_release_notifications import (
    _catalog as catalog,
)
from tests.test_release_notifications import (
    _CollectorRun as OneCollectorRun,
)

CVE_RECIPIENTS = ("support@sns-security.fr", "v.hebert@sns-security.fr")
RELEASE_RECIPIENTS = ("firmware@sns-security.fr",)
RELEASE_KEY = "new-version|fortios|fortios|8.0.1"
CVE_KEY = "new-cve|psirt|CVE-2026-99999|critical"


def cve_payload(cve_id: str = "CVE-2026-99999", severity: str = "critical") -> dict[str, Any]:
    """The reference critical CVE used by the collector-level delivery tests."""
    return {
        "id": cve_id,
        "advisoryId": "FG-IR-26-900",
        "title": f"Résumé {cve_id}",
        "severity": severity,
        "cvssScore": 9.8,
        "url": "https://fortiguard.fortinet.com/psirt/FG-IR-26-900",
        "affected": [{"product": "fortigate-fortios", "branch": "8.0"}],
    }


def settings_payload(
    *,
    enabled: bool = True,
    releases: bool = True,
    recipients: tuple[str, ...] = CVE_RECIPIENTS,
    release_recipients_shared: bool | None = None,
    release_recipients: tuple[str, ...] = (),
    include_new_keys: bool = True,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
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
        "recipients": list(recipients),
    }
    if include_new_keys:
        payload["releaseRecipientsShared"] = (
            True if release_recipients_shared is None else release_recipients_shared
        )
        payload["releaseRecipients"] = list(release_recipients)
    return payload


class SettingsModelTests(unittest.TestCase):
    def test_legacy_payload_without_the_new_keys_shares_the_cve_list(self) -> None:
        settings = notify.validate_notification_settings(
            settings_payload(include_new_keys=False)
        )

        self.assertTrue(settings.release_recipients_shared)
        self.assertEqual(settings.release_recipients_effective(), CVE_RECIPIENTS)

    def test_intermediate_payload_with_only_the_release_switch_still_shares(self) -> None:
        """Schema deployed before this change: releaseNotificationsEnabled only."""
        settings = notify.validate_notification_settings(
            settings_payload(include_new_keys=False) | {"releaseNotificationsEnabled": True}
        )

        self.assertTrue(settings.release_notifications_enabled)
        self.assertTrue(settings.release_recipients_shared)
        self.assertEqual(settings.release_recipients_effective(), CVE_RECIPIENTS)

    def test_shared_true_uses_the_cve_list_even_with_a_stale_dedicated_list(self) -> None:
        settings = notify.validate_notification_settings(
            settings_payload(release_recipients_shared=True, release_recipients=RELEASE_RECIPIENTS)
        )

        self.assertEqual(settings.release_recipients_effective(), CVE_RECIPIENTS)
        # The detached list is preserved for a later re-detachment, not dropped.
        self.assertEqual(settings.release_recipients, RELEASE_RECIPIENTS)

    def test_shared_false_uses_the_dedicated_list(self) -> None:
        settings = notify.validate_notification_settings(
            settings_payload(
                release_recipients_shared=False, release_recipients=RELEASE_RECIPIENTS
            )
        )

        self.assertFalse(settings.release_recipients_shared)
        self.assertEqual(settings.release_recipients_effective(), RELEASE_RECIPIENTS)

    def test_shared_false_with_an_empty_list_is_refused(self) -> None:
        with self.assertRaises(ValueError) as raised:
            notify.validate_notification_settings(
                settings_payload(release_recipients_shared=False, release_recipients=())
            )

        self.assertIn("obligatoire", str(raised.exception))

    def test_dedicated_list_applies_the_same_validation_rules(self) -> None:
        cases = {
            "not-an-email": "invalide",
            "  spaced@sns-security.fr  ": None,
            "DUP@sns-security.fr": "dupliquée",
        }
        for candidate, expected in cases.items():
            payload = settings_payload(
                release_recipients_shared=False,
                release_recipients=(candidate, "dup@sns-security.fr"),
            )
            if expected is None:
                settings = notify.validate_notification_settings(payload)
                # Trimmed on load, exactly like the CVE list.
                self.assertEqual(settings.release_recipients[0], candidate.strip())
                continue
            with self.assertRaises(ValueError) as raised:
                notify.validate_notification_settings(payload)
            self.assertIn(expected, str(raised.exception))

    def test_non_boolean_share_flag_is_rejected(self) -> None:
        payload = settings_payload()
        payload["releaseRecipientsShared"] = "yes"
        with self.assertRaises(TypeError):
            notify.validate_notification_settings(payload)

    def test_unknown_keys_are_still_rejected(self) -> None:
        payload = settings_payload()
        payload["releaseRecipientsMode"] = "shared"
        with self.assertRaises(ValueError):
            notify.validate_notification_settings(payload)

    def test_payload_round_trips_with_both_new_keys(self) -> None:
        payload = settings_payload(
            release_recipients_shared=False, release_recipients=RELEASE_RECIPIENTS
        )
        settings = notify.validate_notification_settings(payload)

        self.assertEqual(settings.to_payload(), payload)


class LegacyMigrationTests(unittest.TestCase):
    def test_four_key_file_loads_shared_without_rewrite_or_corruption(self) -> None:
        """Legacy file: no new key, no rewrite, no corrupt marker, recipients preserved."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notification-settings.json"
            payload = settings_payload(include_new_keys=False)
            payload["recipients"] = list(CVE_RECIPIENTS)
            raw = json.dumps(payload)
            path.write_text(raw, encoding="utf-8")

            settings = notify.load_notification_settings(path, env={})

            self.assertTrue(settings.release_recipients_shared)
            self.assertEqual(settings.recipients, CVE_RECIPIENTS)
            self.assertEqual(settings.release_recipients_effective(), CVE_RECIPIENTS)
            self.assertEqual(path.read_text(encoding="utf-8"), raw)
            self.assertEqual(list(Path(tmp).glob("notification-settings.json.corrupt-*")), [])

    def test_five_key_file_from_the_previous_release_still_loads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notification-settings.json"
            payload = settings_payload(include_new_keys=False)
            payload["releaseNotificationsEnabled"] = True
            raw = json.dumps(payload)
            path.write_text(raw, encoding="utf-8")

            settings = notify.load_notification_settings(path, env={})

            self.assertTrue(settings.release_notifications_enabled)
            self.assertTrue(settings.release_recipients_shared)
            self.assertEqual(path.read_text(encoding="utf-8"), raw)

    def test_dedicated_configuration_round_trips_through_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notification-settings.json"
            payload = settings_payload(
                release_recipients_shared=False, release_recipients=RELEASE_RECIPIENTS
            )

            notify.save_notification_settings(path, payload)
            settings = notify.load_notification_settings(path, env={})

            self.assertEqual(settings.release_recipients_effective(), RELEASE_RECIPIENTS)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), payload)


class BatchRoutingTests(unittest.TestCase):
    def _events(self, settings: notify.NotificationSettings) -> tuple[list, list]:
        releases = notify.derive_version_events(
            {"fortigate-fortios": {"8.0.0"}},
            {"fortigate-fortios": {"8.0.0", "8.0.1"}},
            {"fortigate-fortios": "FortiGate / FortiOS"},
        )
        cves = notify.derive_new_cve_events([cve_payload()], settings)
        return cves, releases

    def test_shared_recipients_produce_one_grouped_email(self) -> None:
        settings = notify.validate_notification_settings(settings_payload())
        cves, releases = self._events(settings)

        batches = notify.notification_batches(cves + releases, settings)

        self.assertEqual(len(batches), 1)
        self.assertEqual(batches[0].recipients, CVE_RECIPIENTS)
        self.assertEqual(
            sorted(event.dedup_key for event in batches[0].events),
            sorted([CVE_KEY, RELEASE_KEY]),
        )

    def test_different_recipients_produce_two_emails(self) -> None:
        settings = notify.validate_notification_settings(
            settings_payload(
                release_recipients_shared=False, release_recipients=RELEASE_RECIPIENTS
            )
        )
        cves, releases = self._events(settings)

        batches = notify.notification_batches(cves + releases, settings)

        self.assertEqual(len(batches), 2)
        self.assertEqual(batches[0].recipients, CVE_RECIPIENTS)
        self.assertEqual([event.dedup_key for event in batches[0].events], [CVE_KEY])
        self.assertEqual(batches[1].recipients, RELEASE_RECIPIENTS)
        self.assertEqual([event.dedup_key for event in batches[1].events], [RELEASE_KEY])

    def test_single_category_uses_its_own_list(self) -> None:
        settings = notify.validate_notification_settings(
            settings_payload(
                release_recipients_shared=False, release_recipients=RELEASE_RECIPIENTS
            )
        )
        cves, releases = self._events(settings)

        release_only = notify.notification_batches(releases, settings)
        cve_only = notify.notification_batches(cves, settings)

        self.assertEqual([(batch.recipients, len(batch.events)) for batch in release_only],
                         [(RELEASE_RECIPIENTS, 1)])
        self.assertEqual([(batch.recipients, len(batch.events)) for batch in cve_only],
                         [(CVE_RECIPIENTS, 1)])

    def test_system_events_travel_with_the_cve_email(self) -> None:
        settings = notify.validate_notification_settings(
            settings_payload(
                release_recipients_shared=False, release_recipients=RELEASE_RECIPIENTS
            )
        )
        _, releases = self._events(settings)
        eol = notify.NotificationEvent(
            category="OPERATIONS", dedup_key="eol|7.0|branch", summary="Branche 7.0 en fin de support"
        )

        batches = notify.notification_batches([eol, *releases], settings)

        self.assertEqual([batch.recipients for batch in batches], [CVE_RECIPIENTS, RELEASE_RECIPIENTS])
        self.assertEqual([event.dedup_key for event in batches[0].events], ["eol|7.0|branch"])


class _DeliveryRun(OneCollectorRun):
    """One collector run whose SMTP client can refuse a chosen recipient list."""

    def __init__(self, root: Path, *, fail_to: tuple[str, ...] = ()) -> None:
        super().__init__(root)
        self.fail_to = tuple(address.casefold() for address in fail_to)
        self.sent: list[tuple[str, ...]] = []
        self.failed: list[tuple[str, ...]] = []

    def run(self) -> int:
        client = MagicMock()
        client.__enter__ = MagicMock(return_value=client)
        client.__exit__ = MagicMock(return_value=False)
        import smtplib

        def send_message(message: Any, *_args: Any, **_kwargs: Any) -> None:
            recipients = tuple(
                address.strip().casefold()
                for address in str(message["To"]).split(",")
                if address.strip()
            )
            if self.fail_to and any(address in self.fail_to for address in recipients):
                self.failed.append(recipients)
                raise smtplib.SMTPException("refusé par le test")
            self.sent.append(recipients)
            self.messages.append(message.as_bytes())

        client.send_message = MagicMock(side_effect=send_message)
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

    def sent_keys(self) -> dict[str, str]:
        return self.state()["sentKeys"]

    def outbox_keys(self) -> list[str]:
        return [entry["dedupKey"] for entry in self.state()["outbox"]]


class CollectorDeliveryRoutingTests(unittest.TestCase):
    def _prepare(
        self, root: Path, settings: dict[str, Any], *, fail_to: tuple[str, ...] = ()
    ) -> _DeliveryRun:
        run = _DeliveryRun(root, fail_to=fail_to)
        run.write_settings(settings)
        run.seed(catalog(fortios=("8.0.0",)))
        self.assertEqual(run.run(), 0)
        self.assertEqual(run.messages, [], "le premier run ne fait qu'ancrer la référence")
        return run

    def test_shared_recipients_send_one_grouped_email(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = self._prepare(Path(tmp), settings_payload())
            run.seed(catalog(fortios=("8.0.0", "8.0.1"), cves=(cve_payload(),)))

            self.assertEqual(run.run(), 0)

            self.assertEqual(len(run.messages), 1)
            self.assertEqual(run.sent, [CVE_RECIPIENTS])
            self.assertIn(RELEASE_KEY, run.sent_keys())
            self.assertIn(CVE_KEY, run.sent_keys())
            subject = BytesParser(policy=policy.default).parsebytes(run.messages[0])["Subject"]
            self.assertIn("vulnérabilité", subject)

    def test_dedicated_recipients_send_two_emails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = self._prepare(
                Path(tmp),
                settings_payload(
                    release_recipients_shared=False, release_recipients=RELEASE_RECIPIENTS
                ),
            )
            run.seed(catalog(fortios=("8.0.0", "8.0.1"), cves=(cve_payload(),)))

            self.assertEqual(run.run(), 0)

            self.assertEqual(len(run.messages), 2)
            self.assertEqual(run.sent, [CVE_RECIPIENTS, RELEASE_RECIPIENTS])
            subjects = [
                BytesParser(policy=policy.default).parsebytes(raw)["Subject"]
                for raw in run.messages
            ]
            self.assertIn("vulnérabilité", subjects[0])
            self.assertIn("Nouvelle version", subjects[1])
            self.assertEqual(run.outbox_keys(), [])
            self.assertEqual(sorted(run.sent_keys()), sorted([CVE_KEY, RELEASE_KEY]))

    def test_legacy_settings_deliver_releases_to_the_cve_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = self._prepare(Path(tmp), settings_payload(include_new_keys=False))
            run.seed(catalog(fortios=("8.0.0", "8.0.1")))

            self.assertEqual(run.run(), 0)

            self.assertEqual(run.sent, [CVE_RECIPIENTS])
            self.assertIn(RELEASE_KEY, run.sent_keys())

    def test_dedicated_recipients_used_for_a_release_only_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = self._prepare(
                Path(tmp),
                settings_payload(
                    release_recipients_shared=False, release_recipients=RELEASE_RECIPIENTS
                ),
            )
            run.seed(catalog(fortios=("8.0.0", "8.0.1")))

            self.assertEqual(run.run(), 0)

            self.assertEqual(run.sent, [RELEASE_RECIPIENTS])


class PartialFailureTests(unittest.TestCase):
    """One category failing must neither block nor duplicate the other."""

    def _prepare(
        self, root: Path, *, fail_to: tuple[str, ...]
    ) -> _DeliveryRun:
        settings = settings_payload(
            release_recipients_shared=False, release_recipients=RELEASE_RECIPIENTS
        )
        run = _DeliveryRun(root, fail_to=fail_to)
        run.write_settings(settings)
        run.seed(catalog(fortios=("8.0.0",)))
        self.assertEqual(run.run(), 0)
        return run

    def test_cve_failure_keeps_the_release_sent_and_never_resends_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = self._prepare(root, fail_to=CVE_RECIPIENTS)
            run.seed(catalog(fortios=("8.0.0", "8.0.1"), cves=(cve_payload(),)))

            # Run 1: the CVE email is refused, the release email goes out.
            self.assertEqual(run.run(), 0)
            self.assertEqual(run.sent, [RELEASE_RECIPIENTS])
            self.assertEqual(run.failed, [CVE_RECIPIENTS])
            self.assertIn(RELEASE_KEY, run.sent_keys())
            self.assertNotIn(CVE_KEY, run.sent_keys())
            self.assertEqual(run.outbox_keys(), [CVE_KEY])

            # Run 2: only the failed category is retried.
            run.fail_to = ()
            self.assertEqual(run.run(), 0)
            self.assertEqual(len(run.messages), 2)
            self.assertEqual(run.sent[-1], CVE_RECIPIENTS)
            self.assertEqual(run.outbox_keys(), [])
            self.assertIn(CVE_KEY, run.sent_keys())
            # The release was delivered once and only once.
            self.assertEqual(run.sent.count(RELEASE_RECIPIENTS), 1)

    def test_release_failure_keeps_the_cve_sent_and_never_resends_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = self._prepare(root, fail_to=RELEASE_RECIPIENTS)
            run.seed(catalog(fortios=("8.0.0", "8.0.1"), cves=(cve_payload(),)))

            self.assertEqual(run.run(), 0)
            self.assertEqual(run.sent, [CVE_RECIPIENTS])
            self.assertEqual(run.failed, [RELEASE_RECIPIENTS])
            self.assertIn(CVE_KEY, run.sent_keys())
            self.assertNotIn(RELEASE_KEY, run.sent_keys())
            self.assertEqual(run.outbox_keys(), [RELEASE_KEY])

            run.fail_to = ()
            self.assertEqual(run.run(), 0)
            self.assertEqual(len(run.messages), 2)
            self.assertEqual(run.sent[-1], RELEASE_RECIPIENTS)
            self.assertEqual(run.outbox_keys(), [])
            self.assertIn(RELEASE_KEY, run.sent_keys())
            self.assertEqual(run.sent.count(CVE_RECIPIENTS), 1)


class TransportRecipientTests(unittest.TestCase):
    def _batches(self) -> list[notify.NotificationBatch]:
        settings = notify.validate_notification_settings(
            settings_payload(
                release_recipients_shared=False, release_recipients=RELEASE_RECIPIENTS
            )
        )
        cves = notify.derive_new_cve_events([cve_payload()], settings)
        releases = notify.derive_version_events(
            {"fortigate-fortios": {"8.0.0"}},
            {"fortigate-fortios": {"8.0.0", "8.0.1"}},
            {"fortigate-fortios": "FortiGate / FortiOS"},
        )
        return notify.notification_batches(cves + releases, settings)

    def _compose(self, batch: notify.NotificationBatch) -> tuple[str, str, str]:
        composed = notify.compose_email(
            list(batch.events),
            app_url="https://fortiupgrade.example/app/",
            run_timestamp="2026-09-16T05:15:22Z",
            appearance=None,
        )
        assert composed is not None
        return composed

    def test_smtp_sends_each_batch_to_its_own_recipients(self) -> None:
        from dataclasses import replace

        from tests.test_smtp_admin import running_smtp_server

        with tempfile.TemporaryDirectory() as tmp:
            with running_smtp_server() as smtp:
                config = notify.load_email_config(
                    {
                        **SMTP_ENV,
                        "FORTIOS_SMTP_HOST": "127.0.0.1",
                        "FORTIOS_SMTP_PORT": str(smtp.server_address[1]),
                        "FORTIOS_SMTP_SECURITY": "none",
                        "FORTIOS_SMTP_ALLOW_INSECURE": "true",
                    },
                    settings=notify.validate_notification_settings(settings_payload()),
                    settings_path=Path(tmp) / "notification-settings.json",
                )
                for batch in self._batches():
                    subject, text, html = self._compose(batch)
                    result = notify.send_email_result(
                        replace(config, smtp_to=batch.recipients), subject, text, html
                    )
                    self.assertTrue(result.sent, result.message)

            self.assertEqual(len(smtp.messages), 2)

        recipients = [
            tuple(
                address.strip()
                for address in BytesParser(policy=policy.default)
                .parsebytes(raw)["To"]
                .split(",")
                if address.strip()
            )
            for raw in smtp.messages
        ]
        self.assertEqual(recipients[0], CVE_RECIPIENTS)
        self.assertEqual(recipients[1], RELEASE_RECIPIENTS)

    def test_microsoft365_sends_each_batch_to_its_own_recipients(self) -> None:
        from dataclasses import replace

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = root / "microsoft365-client-secret"
            secret.write_text("secret-value\n", encoding="utf-8")
            config = notify.load_email_config(
                graph_env(secret),
                settings=notify.validate_notification_settings(settings_payload()),
                settings_path=root / "notification-settings.json",
                smtp_settings_path=root / "smtp-settings.json",
            )
            payloads: list[dict[str, Any]] = []
            with patch.object(
                notify,
                "_graph_urlopen",
                side_effect=[
                    FakeResponse(200, b'{"access_token":"access-token"}'),
                    FakeResponse(202),
                    FakeResponse(200, b'{"access_token":"access-token"}'),
                    FakeResponse(202),
                ],
            ) as urlopen:
                for batch in self._batches():
                    subject, text, html = self._compose(batch)
                    result = notify.send_email_result(
                        replace(config, smtp_to=batch.recipients), subject, text, html
                    )
                    self.assertTrue(result.sent)

            for index in (1, 3):
                payloads.append(
                    json.loads(urlopen.call_args_list[index].args[0].data.decode("utf-8"))
                )

        self.assertEqual(
            payloads[0]["message"]["toRecipients"],
            [{"emailAddress": {"address": address}} for address in CVE_RECIPIENTS],
        )
        self.assertEqual(
            payloads[1]["message"]["toRecipients"],
            [{"emailAddress": {"address": address}} for address in RELEASE_RECIPIENTS],
        )
        self.assertIn("HTML", payloads[1]["message"]["body"]["contentType"])


class NotificationApiValidationTests(unittest.TestCase):
    """The admin API refuses an empty dedicated list instead of falling back silently."""

    def _environment(self, root: Path) -> dict[str, str]:
        import cert_admin

        credentials = root / "credentials.json"
        cert_admin.write_credentials(
            credentials, cert_admin.credential_payload("valentin", "mot-de-passe-solide")
        )
        data_dir = root / "data"
        data_dir.mkdir(exist_ok=True)
        return {
            "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
            "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            "FORTIOS_TEST_DATA_DIR": str(data_dir),
        }

    def _post(
        self, base_url: str, opener: Any, csrf_token: str, payload: dict[str, Any]
    ) -> Any:
        request = urllib.request.Request(
            f"{base_url}/api/cert/notifications",
            data=json.dumps(payload).encode(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Origin": base_url,
                "X-CSRF-Token": csrf_token,
            },
        )
        return opener.open(request, timeout=5)

    def test_api_rejects_detached_share_with_an_empty_list(self) -> None:
        from tests.test_smtp_admin import authenticated_opener, running_server

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            environment = self._environment(root)
            with running_server(environment) as base_url:
                opener, csrf_token = authenticated_opener(base_url)
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    self._post(
                        base_url,
                        opener,
                        csrf_token,
                        settings_payload(
                            release_recipients_shared=False, release_recipients=()
                        ),
                    )

            self.assertEqual(raised.exception.code, 400)
            message = json.loads(raised.exception.read().decode("utf-8"))["error"]
            self.assertIn("obligatoire", message)
            self.assertFalse((root / "data" / "notification-settings.json").exists())

    def test_api_round_trips_a_dedicated_list(self) -> None:
        from tests.test_smtp_admin import authenticated_opener, running_server

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            environment = self._environment(root)
            payload = settings_payload(
                release_recipients_shared=False, release_recipients=RELEASE_RECIPIENTS
            )
            with running_server(environment) as base_url:
                opener, csrf_token = authenticated_opener(base_url)
                with self._post(base_url, opener, csrf_token, payload) as response:
                    self.assertEqual(response.status, 200)
                    saved = json.load(response)["settings"]

                self.assertEqual(saved, payload)

            # A second server reading the same data dir is what the UI does on reload.
            with running_server(environment) as restarted:
                opener, _ = authenticated_opener(restarted)
                with opener.open(f"{restarted}/api/cert/notifications", timeout=5) as response:
                    reloaded = json.load(response)["settings"]

        self.assertIs(reloaded["releaseRecipientsShared"], False)
        self.assertEqual(reloaded["releaseRecipients"], list(RELEASE_RECIPIENTS))
        self.assertEqual(reloaded["recipients"], list(CVE_RECIPIENTS))


if __name__ == "__main__":
    unittest.main()
