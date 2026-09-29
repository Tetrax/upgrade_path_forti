"""System alerts: dedicated switch, dedicated recipients, dedicated email, no catch-up.

The system category (end-of-support crossings, repeated collection failures and recoveries, and
the technical events that are neither CVEs, releases nor image findings) is separated from the
CVE recipients. The rules this module pins:

- `enabled` is the CVE switch alone; a settings file written before `systemNotificationsEnabled` /
  `systemRecipients` keeps loading, byte-identical on disk, with the category suspended
  (`false` / `[]`);
- enabling the category with an empty dedicated list is refused explicitly (`400` from the API,
  explicit message in the form) -- there is no sharing and no fallback to the CVE list, in either
  direction;
- system events share a dedicated email, even when the addresses are identical to the CVE list,
  and each batch is composed, delivered and finalized independently (a partial failure neither
  blocks nor duplicates the other category);
- while the switch is off the EOL and collection-health baselines still advance, so re-enabling
  never replays history, and a system entry already queued in the outbox stays there until the
  category is active again -- it is never delivered to the CVE list.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_notify as notify

from tests.test_microsoft365_notifications import FakeResponse, graph_env
from tests.test_release_notifications import SMTP_ENV
from tests.test_release_notifications import _catalog as catalog
from tests.test_release_recipients import _DeliveryRun
from tests.test_security_notifications import (
    settings_payload as current_settings_payload,
)

APP_URL = "https://fortiupgrade.example/app/"
RUN_TS = "2026-09-16T05:15:22Z"
CVE_RECIPIENTS = ("security@example.invalid",)
SYSTEM_RECIPIENTS = ("operations@example.invalid",)
CVE_KEY = "new-cve|psirt|CVE-2026-99999|critical"
EOL_KEY = "support-eol|fortios|7.6|2026-01-01"
NO_CVE_STATUS = "image: fortios/fortiupgrade:test\nreport: none\n"


def cve_payload(
    cve_id: str = "CVE-2026-99999", severity: str = "critical"
) -> dict[str, Any]:
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
    releases: bool = False,
    recipients: tuple[str, ...] = CVE_RECIPIENTS,
    release_recipients_shared: bool | None = None,
    release_recipients: tuple[str, ...] = (),
    system: bool = False,
    system_recipients: tuple[str, ...] = (),
    include_system_keys: bool = True,
) -> dict[str, Any]:
    payload = current_settings_payload(
        enabled=enabled,
        release_notifications=releases,
        release_recipients_shared=(
            True if release_recipients_shared is None else release_recipients_shared
        ),
        release_recipients=list(release_recipients),
    )
    payload["recipients"] = list(recipients)
    if include_system_keys:
        payload["systemNotificationsEnabled"] = system
        payload["systemRecipients"] = list(system_recipients)
    else:
        payload.pop("systemNotificationsEnabled")
        payload.pop("systemRecipients")
    return payload


def system_event(
    summary: str = "Collecte PSIRT en échec depuis 3 exécutions consécutives",
    *,
    category: str = "OPERATIONS",
    dedup_key: str = "source-failure|psirt|consecutive|3",
) -> notify.NotificationEvent:
    return notify.NotificationEvent(
        category=category, dedup_key=dedup_key, summary=summary
    )


def system_outbox_entry(
    *,
    dedup_key: str = EOL_KEY,
    summary: str = "FortiOS 7.6 est passé en fin de support (depuis le 2026-01-01)",
) -> dict[str, Any]:
    """The canonical persisted shape, exactly as _enqueue_new_events() writes it."""
    return {
        "category": "DAILY",
        "dedupKey": dedup_key,
        "summary": summary,
        "severity": None,
        "details": {},
        "queuedAt": "2026-01-02T07:00:00Z",
        "claimedBy": None,
        "claimedAt": None,
        "nextAttemptAt": None,
        "lastTransport": None,
        "lastErrorCode": None,
    }


def seed_history(
    run: _DeliveryRun,
    *,
    eol_state: dict[str, bool] | None = None,
    outbox: list[dict[str, Any]] | None = None,
) -> None:
    run.history.write_text(
        json.dumps(
            {
                "sentKeys": {},
                "outbox": list(outbox or []),
                "eolState": dict(eol_state or {}),
            }
        ),
        encoding="utf-8",
    )


def set_eol_state(run: _DeliveryRun, eol_state: dict[str, bool]) -> None:
    state = run.state()
    state["eolState"] = dict(eol_state)
    run.history.write_text(json.dumps(state), encoding="utf-8")


def lifecycle_catalog(*branches: str, support: str = "2026-01-01") -> dict[str, Any]:
    state = catalog(fortios=("8.0.0",))
    state["fortiosLifecycle"] = {branch: {"support": support} for branch in branches}
    return state


class SettingsModelTests(unittest.TestCase):
    def test_legacy_file_without_the_system_keys_loads_suspended_byte_identical(
        self,
    ) -> None:
        """A file written before the two keys: no rewrite, no corrupt marker, category off."""
        for drop_release_keys in (False, True):
            with (
                self.subTest(drop_release_keys=drop_release_keys),
                tempfile.TemporaryDirectory() as tmp,
            ):
                path = Path(tmp) / "notification-settings.json"
                payload = settings_payload(include_system_keys=False)
                if drop_release_keys:
                    for key in (
                        "releaseNotificationsEnabled",
                        "releaseRecipientsShared",
                        "releaseRecipients",
                    ):
                        payload.pop(key)
                raw = json.dumps(payload)
                path.write_text(raw, encoding="utf-8")

                settings = notify.load_notification_settings(path, env={})

                self.assertFalse(settings.system_notifications_enabled)
                self.assertEqual(settings.system_recipients, ())
                self.assertEqual(settings.recipients, CVE_RECIPIENTS)
                self.assertEqual(path.read_text(encoding="utf-8"), raw)
                self.assertEqual(
                    list(Path(tmp).glob("notification-settings.json.corrupt-*")), []
                )

    def test_disabled_switch_with_a_stale_list_keeps_it(self) -> None:
        settings = notify.validate_notification_settings(
            settings_payload(system=False, system_recipients=SYSTEM_RECIPIENTS)
        )

        self.assertFalse(settings.system_notifications_enabled)
        # The detached list is preserved for a later activation, not dropped.
        self.assertEqual(settings.system_recipients, SYSTEM_RECIPIENTS)

    def test_enabling_without_a_list_is_refused(self) -> None:
        with self.assertRaises(ValueError) as raised:
            notify.validate_notification_settings(
                settings_payload(system=True, system_recipients=())
            )

        self.assertIn("obligatoire", str(raised.exception))

    def test_switch_must_be_boolean(self) -> None:
        payload = settings_payload()
        payload["systemNotificationsEnabled"] = "yes"
        with self.assertRaises(TypeError):
            notify.validate_notification_settings(payload)

    def test_dedicated_list_applies_the_same_validation_rules(self) -> None:
        cases = {
            "not-an-email": "invalide",
            "  spaced@example.invalid  ": None,
            "DUP@example.invalid": "dupliquée",
        }
        for candidate, expected in cases.items():
            payload = settings_payload(
                system=True,
                system_recipients=(candidate, "dup@example.invalid"),
            )
            if expected is None:
                settings = notify.validate_notification_settings(payload)
                # Trimmed on load, exactly like the CVE list.
                self.assertEqual(settings.system_recipients[0], candidate.strip())
                continue
            with self.assertRaises(ValueError) as raised:
                notify.validate_notification_settings(payload)
            self.assertIn(expected, str(raised.exception))

    def test_unknown_keys_are_still_rejected(self) -> None:
        payload = settings_payload()
        payload["systemRecipientsMode"] = "dedicated"
        with self.assertRaises(ValueError):
            notify.validate_notification_settings(payload)

    def test_payload_round_trips_with_both_new_keys(self) -> None:
        payload = settings_payload(system=True, system_recipients=SYSTEM_RECIPIENTS)
        settings = notify.validate_notification_settings(payload)

        self.assertEqual(settings.to_payload(), payload)

    def test_saved_payload_round_trips_through_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notification-settings.json"
            payload = settings_payload(system=True, system_recipients=SYSTEM_RECIPIENTS)

            notify.save_notification_settings(path, payload)
            settings = notify.load_notification_settings(path, env={})

            self.assertTrue(settings.system_notifications_enabled)
            self.assertEqual(settings.system_recipients, SYSTEM_RECIPIENTS)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), payload)

    def test_env_only_installation_keeps_the_category_suspended(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = notify.load_notification_settings(
                Path(tmp) / "missing.json",
                env={"FORTIOS_EMAIL_ENABLED": "true", "FORTIOS_SMTP_TO": "a@b.example"},
            )

        self.assertTrue(settings.enabled)
        self.assertFalse(settings.system_notifications_enabled)
        self.assertEqual(settings.system_recipients, ())


class BatchRoutingTests(unittest.TestCase):
    def _cve(self, settings: notify.NotificationSettings) -> notify.NotificationEvent:
        return notify.derive_new_cve_events([cve_payload()], settings)[0]

    def test_system_batch_is_separate_even_with_identical_addresses(self) -> None:
        settings = notify.validate_notification_settings(
            settings_payload(
                recipients=SYSTEM_RECIPIENTS,
                system=True,
                system_recipients=SYSTEM_RECIPIENTS,
            )
        )
        events = [self._cve(settings), system_event()]

        batches = notify.notification_batches(events, settings)

        self.assertEqual(len(batches), 2)
        self.assertEqual(
            [batch.recipients for batch in batches],
            [SYSTEM_RECIPIENTS, SYSTEM_RECIPIENTS],
        )
        self.assertEqual([event.dedup_key for event in batches[0].events], [CVE_KEY])
        self.assertEqual(
            [event.dedup_key for event in batches[1].events],
            ["source-failure|psirt|consecutive|3"],
        )

    def test_no_system_batch_while_the_switch_is_off(self) -> None:
        settings = notify.validate_notification_settings(settings_payload(system=False))

        cve_only = notify.notification_batches([self._cve(settings)], settings)
        suspended = notify.notification_batches([system_event()], settings)

        self.assertEqual([batch.recipients for batch in cve_only], [CVE_RECIPIENTS])
        self.assertEqual(suspended, [])

    def test_system_only_batch_uses_the_dedicated_list(self) -> None:
        settings = notify.validate_notification_settings(
            settings_payload(system=True, system_recipients=SYSTEM_RECIPIENTS)
        )

        batches = notify.notification_batches([system_event()], settings)

        self.assertEqual(
            [(batch.recipients, len(batch.events)) for batch in batches],
            [(SYSTEM_RECIPIENTS, 1)],
        )


class CategoryMatrixTests(unittest.TestCase):
    def test_four_categories_partition_even_when_all_lists_are_identical(self):
        settings = notify.validate_notification_settings(
            settings_payload(
                releases=True,
                recipients=SYSTEM_RECIPIENTS,
                system=True,
                system_recipients=SYSTEM_RECIPIENTS,
            )
        )
        cve = notify.derive_new_cve_events([cve_payload()], settings)[0]
        releases = notify.derive_version_events(
            {"fortigate-fortios": {"8.0.0"}},
            {"fortigate-fortios": {"8.0.0", "8.0.1"}},
            {},
        )
        system = system_event()
        container = notify.NotificationEvent(
            category="CRITICAL",
            dedup_key="trivy|cve|CVE-2026-99998|test-package",
            summary="Synthetic image finding",
            severity="critical",
        )
        batches = notify.notification_batches(
            [cve, *releases, system, container],
            settings,
            container_security=notify.ContainerSecuritySettings(
                True, "high", SYSTEM_RECIPIENTS
            ),
        )
        self.assertEqual(
            [batch.events for batch in batches],
            [(cve, *releases), (system,), (container,)],
        )
        self.assertEqual(
            [batch.recipients for batch in batches], [SYSTEM_RECIPIENTS] * 3
        )

    def test_each_of_three_failed_batches_retries_without_replaying_the_other_two(self):
        recipients = [CVE_RECIPIENTS, ("releases@example.invalid",), SYSTEM_RECIPIENTS]
        for failed in recipients:
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "history.json"
                settings = notify.validate_notification_settings(
                    settings_payload(
                        releases=True,
                        release_recipients_shared=False,
                        release_recipients=recipients[1],
                        system=True,
                        system_recipients=SYSTEM_RECIPIENTS,
                    )
                )
                events = notify.derive_new_cve_events([cve_payload()], settings)
                events += notify.derive_version_events(
                    {"fortigate-fortios": {"8.0.0"}},
                    {"fortigate-fortios": {"8.0.0", "8.0.1"}},
                    {},
                )
                events.append(system_event())
                config = notify.load_email_config(
                    SMTP_ENV,
                    settings=settings,
                    settings_path=Path(tmp) / "settings.json",
                )
                pending = notify.enqueue_and_claim(
                    path, events, claimant="one", settings=settings
                )
                accepted = []

                def deliver(config, *_args, failed=failed, accepted=accepted):
                    if config.smtp_to != failed:
                        accepted.append(config.smtp_to)
                    return notify.SmtpResult(
                        config.smtp_to != failed, "synthetic", transport="smtp"
                    )

                with patch.object(notify, "deliver_email_result", side_effect=deliver):
                    notify.deliver_notification_batches(
                        path,
                        pending,
                        claimant="one",
                        settings=settings,
                        config=config,
                        run_timestamp=RUN_TS,
                    )
                self.assertEqual(accepted, [r for r in recipients if r != failed])
                state = notify.load_notify_state(path)
                self.assertEqual(len(state["sentKeys"]), 2)
                self.assertEqual(len(state["outbox"]), 1)
                self.assertIsNone(state["outbox"][0]["claimedBy"])
                pending = notify.enqueue_and_claim(
                    path, [], claimant="two", settings=settings
                )
                with patch.object(
                    notify,
                    "deliver_email_result",
                    return_value=notify.SmtpResult(True, "accepted"),
                ) as send:
                    notify.deliver_notification_batches(
                        path,
                        pending,
                        claimant="two",
                        settings=settings,
                        config=config,
                        run_timestamp=RUN_TS,
                    )
                send.assert_called_once()
                self.assertEqual(send.call_args.args[0].smtp_to, failed)
                self.assertEqual(notify.load_notify_state(path)["outbox"], [])


class ClaimIsolationTests(unittest.TestCase):
    def test_disabled_system_is_not_claimed_or_rewritten_by_a_cve_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            event = system_event()
            notify.enqueue_and_claim(path, [event], claimant="seed")
            notify.release_claim(path, "seed")
            before = notify.load_notify_state(path)["outbox"]
            settings = notify.validate_notification_settings(settings_payload())
            cve = notify.derive_new_cve_events([cve_payload()], settings)[0]
            claimed = notify.enqueue_and_claim(
                path, [cve], claimant="cve-run", settings=settings
            )
            self.assertEqual(claimed, [cve])
            self.assertEqual(notify.load_notify_state(path)["outbox"][:1], before)

    def test_partial_release_preserves_other_claims_and_retry_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            settings = notify.validate_notification_settings(settings_payload())
            cve = notify.derive_new_cve_events([cve_payload()], settings)[0]
            system = system_event()
            notify.enqueue_and_claim(path, [cve, system], claimant="first", now=RUN_TS)
            notify.release_claim(
                path,
                "first",
                now=RUN_TS,
                events=[cve],
                outcome=notify.SmtpResult(
                    False,
                    "throttled",
                    transport="microsoft365",
                    retry_after_seconds=600,
                ),
            )
            self.assertEqual(
                notify.enqueue_and_claim(path, [], claimant="second", now=RUN_TS), []
            )
            cve_entry, system_entry = notify.load_notify_state(path)["outbox"]
            self.assertIsNone(cve_entry["claimedBy"])
            self.assertIsNotNone(cve_entry["nextAttemptAt"])
            self.assertEqual(system_entry["claimedBy"], "first")
            self.assertIsNone(system_entry["nextAttemptAt"])

    def test_collector_keeps_following_batches_claimed_after_a_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = _DeliveryRun(Path(tmp), fail_to=CVE_RECIPIENTS)
            run.write_settings(
                settings_payload(system=True, system_recipients=SYSTEM_RECIPIENTS)
            )
            run.seed(lifecycle_catalog("7.6"))
            self.assertEqual(run.run(), 0)
            state = lifecycle_catalog("7.6")
            state["cves"] = [cve_payload()]
            run.seed(state)
            set_eol_state(run, {"7.6": False})
            deliver = notify.deliver_email_result
            probes = []

            def competing_attempt(config, *args):
                if config.smtp_to == SYSTEM_RECIPIENTS:
                    probes.append(
                        notify.enqueue_and_claim(run.history, [], claimant="competitor")
                    )
                    notify.release_claim(run.history, "competitor")
                return deliver(config, *args)

            with patch.object(
                notify, "deliver_email_result", side_effect=competing_attempt
            ):
                self.assertEqual(run.run(), 0)
            self.assertEqual(len(probes), 1)
            self.assertNotIn(EOL_KEY, [event.dedup_key for event in probes[0]])
            self.assertEqual(run.sent, [SYSTEM_RECIPIENTS])
            run.fail_to = ()
            self.assertEqual(run.run(), 0)
            self.assertEqual(run.sent, [SYSTEM_RECIPIENTS, CVE_RECIPIENTS])

    def test_composition_exception_does_not_block_other_batches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = _DeliveryRun(Path(tmp))
            run.write_settings(
                settings_payload(system=True, system_recipients=SYSTEM_RECIPIENTS)
            )
            run.seed(lifecycle_catalog("7.6"))
            self.assertEqual(run.run(), 0)
            state = lifecycle_catalog("7.6")
            state["cves"] = [cve_payload()]
            run.seed(state)
            set_eol_state(run, {"7.6": False})
            compose = notify.compose_email

            def fail_cve(events, **kwargs):
                if any(event.dedup_key == CVE_KEY for event in events):
                    raise ValueError("synthetic composition failure")
                return compose(events, **kwargs)

            with patch.object(notify, "compose_email", side_effect=fail_cve):
                self.assertEqual(run.run(), 0)
            self.assertEqual(run.sent, [SYSTEM_RECIPIENTS])
            self.assertIsNone(run.state()["outbox"][0]["claimedBy"])
            self.assertEqual(run.run(), 0)
            self.assertEqual(run.sent, [SYSTEM_RECIPIENTS, CVE_RECIPIENTS])


class RendererTests(unittest.TestCase):
    def test_summary_is_escaped_and_cve_introduction_is_not_reused(self):
        event = system_event("Source <img src=x onerror=alert(1)> & reprise")
        appearance = notify.EmailAppearance(
            "FortiUpgrade", "Introduction CVE uniquement", "Signature test"
        )
        subject, text, html = notify.compose_email(
            [event], app_url=APP_URL, run_timestamp=RUN_TS, appearance=appearance
        )
        self.assertIn("Alerte système", subject)
        self.assertIn(event.summary, text)
        self.assertIn("&lt;img", html)
        self.assertNotIn("<img src=x", html)
        self.assertNotIn(appearance.introduction, text + html)
        self.assertIn(appearance.signature, text)
        self.assertIn(appearance.signature, html)

    def test_system_email_uses_the_sns_shell_without_cve_or_release_components(
        self,
    ) -> None:
        event = system_event()
        composed = notify.compose_email(
            [event], app_url=APP_URL, run_timestamp=RUN_TS, appearance=None
        )
        assert composed is not None
        subject, text_body, html_body = composed

        self.assertEqual(subject, f"[FortiUpgrade] Alerte système — {event.summary}")
        # The historical plain-text <pre> rendering is gone; the SNS identity is used instead.
        self.assertNotIn("<pre", html_body)
        self.assertIn("cid:sns-logo", html_body)
        self.assertIn("cid:sns-panther", html_body)
        self.assertIn("ÉQUIPE SUPPORT", html_body)
        self.assertIn("#0B0B0D", html_body)
        self.assertIn("OUVRIR FORTIUPGRADE", html_body)
        self.assertIn(event.summary, text_body)
        self.assertIn(event.summary, html_body)
        self.assertIn(
            "FortiUpgrade a détecté un événement système nécessitant votre attention.",
            html_body,
        )
        # No CVE and no release business component leaks into a system email.
        self.assertNotIn("vulnérabilit", html_body)
        self.assertNotIn("CVSS", html_body)
        self.assertNotIn("NOUVELLE VERSION", html_body)

    def test_several_system_events_share_one_email(self) -> None:
        events = [
            system_event(),
            system_event(
                "Collecte endoflife.date de nouveau opérationnelle (après 3 échecs)",
                dedup_key="source-recovered|endoflife|lastSuccessAt|2026-09-16",
            ),
        ]
        composed = notify.compose_email(
            events, app_url=APP_URL, run_timestamp=RUN_TS, appearance=None
        )
        assert composed is not None
        subject, text_body, _html = composed

        self.assertEqual(subject, "[FortiUpgrade] 2 alertes système")
        for event in events:
            self.assertIn(event.summary, text_body)

    def test_empty_batch_is_not_composable(self) -> None:
        self.assertIsNone(
            notify.compose_email(
                [], app_url=APP_URL, run_timestamp=RUN_TS, appearance=None
            )
        )


class SuspendedSystemOutboxTests(unittest.TestCase):
    """A queued system entry waits for its own category, never for the CVE list."""

    def test_invalid_system_configuration_cannot_drain_the_historical_outbox(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = _DeliveryRun(Path(tmp))
            notify.write_json(
                run.settings, settings_payload(system=True, system_recipients=())
            )
            run.seed(catalog(fortios=("8.0.0",)))
            seed_history(run, outbox=[system_outbox_entry()])
            self.assertEqual(run.run(), 0)
            self.assertEqual(run.messages, [])
            self.assertEqual(run.state()["outbox"], [system_outbox_entry()])
            run.write_settings(
                settings_payload(
                    enabled=False,
                    recipients=(),
                    system=True,
                    system_recipients=SYSTEM_RECIPIENTS,
                )
            )
            self.assertEqual(run.run(), 0)
            self.assertEqual(run.sent, [SYSTEM_RECIPIENTS])
            self.assertEqual(run.state()["outbox"], [])

    def test_entry_waits_while_off_then_delivers_to_the_system_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = _DeliveryRun(Path(tmp))
            run.write_settings(settings_payload(enabled=True, system=False))
            run.seed(catalog(fortios=("8.0.0",)))
            seed_history(run, outbox=[system_outbox_entry()])

            self.assertEqual(run.run(), 0)

            self.assertEqual(
                run.messages, [], "un événement système suspendu n'est jamais envoyé"
            )
            self.assertEqual(run.sent_keys(), {})
            state = run.state()
            self.assertEqual(
                [entry["dedupKey"] for entry in state["outbox"]], [EOL_KEY]
            )
            # The claim is released: a later activation finds the entry immediately eligible.
            self.assertIsNone(state["outbox"][0]["claimedBy"])

            # Activation with the dedicated list delivers the very next run.
            run.write_settings(
                settings_payload(
                    enabled=True, system=True, system_recipients=SYSTEM_RECIPIENTS
                )
            )
            self.assertEqual(run.run(), 0)

            self.assertEqual(run.sent, [SYSTEM_RECIPIENTS])
            self.assertIn(EOL_KEY, run.sent_keys())
            self.assertEqual(run.state()["outbox"], [])
            self.assertIn("Alerte système", run.subjects()[0])


class CollectorEolTests(unittest.TestCase):
    def test_eol_transition_goes_only_to_the_system_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = _DeliveryRun(Path(tmp))
            # CVEs stay off: the system category is fully independent.
            run.write_settings(
                settings_payload(
                    enabled=False, system=True, system_recipients=SYSTEM_RECIPIENTS
                )
            )
            run.seed(lifecycle_catalog("7.6"))
            seed_history(run, eol_state={"7.6": False})

            self.assertEqual(run.run(), 0)

            self.assertEqual(len(run.messages), 1)
            self.assertEqual(run.sent, [SYSTEM_RECIPIENTS])
            subject = BytesParser(policy=policy.default).parsebytes(run.messages[0])[
                "Subject"
            ]
            self.assertEqual(
                subject,
                "[FortiUpgrade] Alerte système — FortiOS 7.6 est passé en fin de support "
                "(depuis le 2026-01-01)",
            )
            html = (
                BytesParser(policy=policy.default)
                .parsebytes(run.messages[0])
                .get_body(preferencelist=("html",))
                .get_content()
            )
            self.assertNotIn("<pre", html)
            self.assertIn(EOL_KEY, run.sent_keys())

    def test_switch_off_advances_the_baseline_without_catch_up(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = _DeliveryRun(Path(tmp))
            run.write_settings(settings_payload(enabled=True, system=False))
            run.seed(lifecycle_catalog("7.6"))
            seed_history(run, eol_state={"7.6": False})

            # 1. System off: the crossing is recorded silently.
            self.assertEqual(run.run(), 0)
            self.assertEqual(run.messages, [])
            self.assertEqual(run.state()["eolState"], {"7.6": True})
            self.assertEqual(run.state()["outbox"], [])

            # 2. Re-enabling replays nothing.
            run.write_settings(
                settings_payload(
                    enabled=True, system=True, system_recipients=SYSTEM_RECIPIENTS
                )
            )
            self.assertEqual(run.run(), 0)
            self.assertEqual(run.messages, [])

            # 3. A genuinely later crossing is notified once, on the system list only.
            run.seed(lifecycle_catalog("7.6", "7.4"))
            set_eol_state(run, {"7.6": True, "7.4": False})
            self.assertEqual(run.run(), 0)

            self.assertEqual(len(run.messages), 1)
            self.assertEqual(run.sent, [SYSTEM_RECIPIENTS])
            self.assertIn("FortiOS 7.4", run.subjects()[0])

    def test_backfill_preserves_an_enabled_eol_crossing_for_the_next_normal_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = _DeliveryRun(Path(tmp))
            run.write_settings(
                settings_payload(
                    enabled=True, system=True, system_recipients=SYSTEM_RECIPIENTS
                )
            )
            run.seed(lifecycle_catalog("7.6"))
            seed_history(run, eol_state={"7.6": False})

            self.assertEqual(run.run("--cve-backfill"), 0)
            self.assertEqual(run.messages, [])
            self.assertEqual(run.state()["eolState"], {"7.6": False})

            self.assertEqual(run.run(), 0)
            self.assertEqual(run.sent, [SYSTEM_RECIPIENTS])
            self.assertIn(EOL_KEY, run.sent_keys())

    def test_backfill_still_advances_the_eol_baseline_while_system_alerts_are_off(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = _DeliveryRun(Path(tmp))
            run.write_settings(settings_payload(enabled=True, system=False))
            run.seed(lifecycle_catalog("7.6"))
            seed_history(run, eol_state={"7.6": False})

            self.assertEqual(run.run("--cve-backfill"), 0)
            self.assertEqual(run.messages, [])
            self.assertEqual(run.state()["eolState"], {"7.6": True})

            run.write_settings(
                settings_payload(
                    enabled=True, system=True, system_recipients=SYSTEM_RECIPIENTS
                )
            )
            self.assertEqual(run.run(), 0)
            self.assertEqual(run.messages, [])

    def test_same_addresses_still_produce_two_emails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = _DeliveryRun(Path(tmp))
            run.write_settings(
                settings_payload(
                    enabled=True,
                    recipients=SYSTEM_RECIPIENTS,
                    system=True,
                    system_recipients=SYSTEM_RECIPIENTS,
                )
            )
            state = lifecycle_catalog("7.6")
            run.seed(state)
            self.assertEqual(run.run(), 0)
            state["cves"] = [cve_payload()]
            run.seed(state)
            set_eol_state(run, {"7.6": False})

            self.assertEqual(run.run(), 0)

            self.assertEqual(len(run.messages), 2)
            self.assertEqual(run.sent, [SYSTEM_RECIPIENTS, SYSTEM_RECIPIENTS])
            subjects = run.subjects()
            self.assertTrue(any("vulnérabilité" in subject for subject in subjects))
            self.assertTrue(any("Alerte système" in subject for subject in subjects))

    def test_partial_failure_neither_blocks_nor_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = _DeliveryRun(Path(tmp), fail_to=SYSTEM_RECIPIENTS)
            run.write_settings(
                settings_payload(
                    enabled=True, system=True, system_recipients=SYSTEM_RECIPIENTS
                )
            )
            state = lifecycle_catalog("7.6")
            run.seed(state)
            self.assertEqual(run.run(), 0)
            state["cves"] = [cve_payload()]
            run.seed(state)
            set_eol_state(run, {"7.6": False})

            # Run 1: the system email is refused, the CVE email goes out.
            self.assertEqual(run.run(), 0)
            self.assertEqual(run.sent, [CVE_RECIPIENTS])
            self.assertEqual(run.failed, [SYSTEM_RECIPIENTS])
            self.assertIn(CVE_KEY, run.sent_keys())
            self.assertNotIn(EOL_KEY, run.sent_keys())
            self.assertEqual(run.outbox_keys(), [EOL_KEY])

            # Run 2: only the failed category is retried.
            run.fail_to = ()
            self.assertEqual(run.run(), 0)

            self.assertEqual(run.sent, [CVE_RECIPIENTS, SYSTEM_RECIPIENTS])
            self.assertEqual(run.state()["outbox"], [])
            self.assertIn(EOL_KEY, run.sent_keys())
            # The CVE was delivered once and only once.
            self.assertEqual(run.sent.count(CVE_RECIPIENTS), 1)


class CollectorHealthTests(unittest.TestCase):
    def test_off_baselines_advance_for_all_gate_combinations_then_only_new_transitions_notify(
        self,
    ):
        for cves, releases in ((False, False), (True, False), (False, True)):
            with (
                self.subTest(cves=cves, releases=releases),
                tempfile.TemporaryDirectory() as tmp,
            ):
                run = _DeliveryRun(Path(tmp))
                run.write_settings(settings_payload(enabled=cves, releases=releases))
                run.seed(lifecycle_catalog("7.6"))
                seed_history(run, eol_state={"7.6": False})
                notify.write_json(
                    run.health,
                    {
                        "sources": {
                            "cve-psirt": {
                                "status": "error",
                                "consecutiveFailures": 1,
                            }
                        }
                    },
                )
                self.assertEqual(run.run(), 0)
                self.assertTrue(run.state()["eolState"]["7.6"])
                notify.write_json(
                    run.health,
                    {
                        "sources": {
                            "cve-psirt": {
                                "status": "error",
                                "consecutiveFailures": 2,
                            }
                        }
                    },
                )
                self.assertEqual(run.run(), 0)
                self.assertEqual(
                    run.state()["checkpoint"]["health"]["cve-psirt"][
                        "consecutiveFailures"
                    ],
                    2,
                )
                run.write_settings(
                    settings_payload(
                        enabled=cves,
                        releases=releases,
                        system=True,
                        system_recipients=SYSTEM_RECIPIENTS,
                    )
                )
                self.assertEqual(run.run(), 0)
                self.assertEqual(run.messages, [])
                notify.write_json(
                    run.health,
                    {
                        "sources": {
                            "cve-psirt": {
                                "status": "ok",
                                "consecutiveFailures": 0,
                                "lastSuccessAt": RUN_TS,
                            }
                        }
                    },
                )
                self.assertEqual(run.run(), 0)
                self.assertEqual(run.sent, [SYSTEM_RECIPIENTS])
                self.assertIn("de nouveau opérationnelle", run.subjects()[0])
                self.assertEqual(run.run(), 0)
                self.assertEqual(len(run.messages), 1)


class CompatibilityRecoveryTests(unittest.TestCase):
    def test_system_off_advances_health_and_suspends_old_outbox_then_resumes_dedicated(
        self,
    ):
        import scheduled_refresh as refresh

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings_path = root / refresh.DEFAULT_NOTIFICATION_SETTINGS_PATH
            history_path = root / refresh.DEFAULT_NOTIFY_HISTORY_PATH
            health_path = root / refresh.DEFAULT_HEALTH_PATH
            settings = notify.save_notification_settings(
                settings_path, settings_payload()
            )
            state = notify._empty_notify_state()
            state["checkpoint"] = {
                "versionsByProduct": {},
                "cvesById": {},
                "health": {
                    "compat-matrix": {"status": "error", "consecutiveFailures": 1}
                },
            }
            state["outbox"] = [system_outbox_entry()]
            notify.write_json(history_path, state)
            notify.write_json(
                health_path,
                {
                    "sources": {
                        "compat-matrix": {"status": "error", "consecutiveFailures": 2}
                    }
                },
            )
            config = notify.load_email_config(
                SMTP_ENV, settings=settings, settings_path=settings_path
            )
            with (
                patch.object(notify, "load_email_config", return_value=config),
                patch.object(
                    notify,
                    "deliver_email_result",
                    return_value=notify.SmtpResult(True, "accepted"),
                ) as send,
            ):
                refresh._notify_compatibility_transition(root=root)
                send.assert_not_called()
                state = notify.load_notify_state(history_path)
                self.assertEqual(state["outbox"], [system_outbox_entry()])
                self.assertEqual(
                    state["checkpoint"]["health"]["compat-matrix"][
                        "consecutiveFailures"
                    ],
                    2,
                )
                notify.save_notification_settings(
                    settings_path,
                    settings_payload(system=True, system_recipients=SYSTEM_RECIPIENTS),
                )
                refresh._notify_compatibility_transition(root=root)
                send.assert_called_once()
                self.assertEqual(send.call_args.args[0].smtp_to, SYSTEM_RECIPIENTS)
                state = notify.load_notify_state(history_path)
                self.assertEqual(list(state["sentKeys"]), [EOL_KEY])
                self.assertEqual(state["outbox"], [])

    def test_system_only_recovery_uses_system_gate_and_never_wakes_cve_outbox(self):
        import scheduled_refresh as refresh

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings_path = root / refresh.DEFAULT_NOTIFICATION_SETTINGS_PATH
            history_path = root / refresh.DEFAULT_NOTIFY_HISTORY_PATH
            health_path = root / refresh.DEFAULT_HEALTH_PATH
            settings = notify.save_notification_settings(
                settings_path,
                settings_payload(
                    enabled=False,
                    recipients=(),
                    system=True,
                    system_recipients=SYSTEM_RECIPIENTS,
                ),
            )
            state = notify._empty_notify_state()
            state["checkpoint"] = {
                "versionsByProduct": {},
                "cvesById": {},
                "health": {
                    "compat-matrix": {"status": "error", "consecutiveFailures": 2}
                },
            }
            notify.write_json(history_path, state)
            cve = notify.derive_new_cve_events([cve_payload()])[0]
            notify.enqueue_and_claim(history_path, [cve], claimant="seed")
            notify.release_claim(history_path, "seed")
            notify.write_json(
                health_path,
                {
                    "sources": {
                        "compat-matrix": {
                            "status": "ok",
                            "consecutiveFailures": 0,
                            "lastSuccessAt": RUN_TS,
                        }
                    }
                },
            )
            config = notify.load_email_config(
                SMTP_ENV, settings=settings, settings_path=settings_path
            )
            with (
                patch.object(notify, "load_email_config", return_value=config),
                patch.object(
                    notify,
                    "deliver_email_result",
                    return_value=notify.SmtpResult(True, "accepted"),
                ) as send,
            ):
                refresh._notify_compatibility_transition(root=root)
                send.assert_called_once()
                self.assertEqual(send.call_args.args[0].smtp_to, SYSTEM_RECIPIENTS)
                self.assertIn("de nouveau opérationnelle", send.call_args.args[2])
                state = notify.load_notify_state(history_path)
                self.assertEqual(
                    [entry["dedupKey"] for entry in state["outbox"]], [CVE_KEY]
                )
                self.assertIsNone(state["outbox"][0]["claimedBy"])


class TransportRecipientTests(unittest.TestCase):
    def test_graph_system_only_without_cve_recipients_is_deliverable(self):
        from dataclasses import replace

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = root / "synthetic-secret"
            secret.write_text("test-only")
            settings = notify.validate_notification_settings(
                settings_payload(
                    enabled=False,
                    recipients=(),
                    system=True,
                    system_recipients=SYSTEM_RECIPIENTS,
                )
            )
            config = notify.load_email_config(
                graph_env(secret),
                settings=settings,
                settings_path=root / "settings.json",
            )
            self.assertFalse(config.enabled)
            self.assertFalse(config.release_notifications_enabled)
            batch = notify.notification_batches([system_event()], settings)[0]
            with patch.object(
                notify,
                "_graph_urlopen",
                side_effect=[
                    FakeResponse(200, b'{"access_token":"synthetic-token"}'),
                    FakeResponse(202),
                ],
            ) as urlopen:
                result = notify.send_email_result(
                    replace(config, smtp_to=batch.recipients), *self._compose(batch)
                )
            self.assertTrue(result.sent)
            payload = json.loads(urlopen.call_args_list[1].args[0].data)
            self.assertEqual(
                payload["message"]["toRecipients"],
                [
                    {"emailAddress": {"address": address}}
                    for address in SYSTEM_RECIPIENTS
                ],
            )

    def _batches(self) -> list[notify.NotificationBatch]:
        settings = notify.validate_notification_settings(
            settings_payload(system=True, system_recipients=SYSTEM_RECIPIENTS)
        )
        cves = notify.derive_new_cve_events([cve_payload()], settings)
        return notify.notification_batches([*cves, system_event()], settings)

    def _compose(self, batch: notify.NotificationBatch) -> tuple[str, str, str]:
        composed = notify.compose_email(
            list(batch.events),
            app_url=APP_URL,
            run_timestamp=RUN_TS,
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
        self.assertEqual(recipients[1], SYSTEM_RECIPIENTS)

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
                    json.loads(
                        urlopen.call_args_list[index].args[0].data.decode("utf-8")
                    )
                )

        self.assertEqual(
            payloads[0]["message"]["toRecipients"],
            [{"emailAddress": {"address": address}} for address in CVE_RECIPIENTS],
        )
        self.assertEqual(
            payloads[1]["message"]["toRecipients"],
            [{"emailAddress": {"address": address}} for address in SYSTEM_RECIPIENTS],
        )


class NotificationApiValidationTests(unittest.TestCase):
    """The admin API refuses an empty dedicated list instead of falling back silently."""

    def _environment(self, root: Path) -> dict[str, str]:
        import cert_admin

        credentials = root / "credentials.json"
        cert_admin.write_credentials(
            credentials,
            cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
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

    def test_api_rejects_enabling_system_alerts_without_a_list(self) -> None:
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
                        settings_payload(system=True, system_recipients=()),
                    )

            self.assertEqual(raised.exception.code, 400)
            message = json.loads(raised.exception.read().decode("utf-8"))["error"]
            self.assertIn("obligatoire", message)
            self.assertFalse((root / "data" / "notification-settings.json").exists())

    def test_api_round_trips_the_dedicated_list(self) -> None:
        from tests.test_smtp_admin import authenticated_opener, running_server

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            environment = self._environment(root)
            payload = settings_payload(system=True, system_recipients=SYSTEM_RECIPIENTS)
            with running_server(environment) as base_url:
                opener, csrf_token = authenticated_opener(base_url)
                with self._post(base_url, opener, csrf_token, payload) as response:
                    self.assertEqual(response.status, 200)
                    saved = json.load(response)["settings"]

                self.assertEqual(saved, payload)

            # A second server reading the same data dir is what the UI does on reload.
            with running_server(environment) as restarted:
                opener, _ = authenticated_opener(restarted)
                with opener.open(
                    f"{restarted}/api/cert/notifications", timeout=5
                ) as response:
                    reloaded = json.load(response)["settings"]

        self.assertIs(reloaded["systemNotificationsEnabled"], True)
        self.assertEqual(reloaded["systemRecipients"], list(SYSTEM_RECIPIENTS))
        self.assertEqual(reloaded["recipients"], list(CVE_RECIPIENTS))


if __name__ == "__main__":
    unittest.main()
