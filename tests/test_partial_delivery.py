"""F1 regression coverage: partial SMTP refusals must be represented, persisted and retried
without ever resending the email to the recipients the server already accepted.

The historical bug: ``smtplib.SMTP.send_message()`` returns the mapping of recipients the server
refused whenever at least one other recipient was accepted. ``fortios_notify`` discarded that
mapping, finalized the whole batch, cleared the outbox entry and recorded its dedup key -- so the
refused recipient was lost with no retry, and the diagnostic claimed a complete acceptance.

These tests drive the real send path (a loopback SMTP sink or the exact smtplib return contract)
through the real outbox, restart the collector, and verify that only the refused recipients are
retried while the accepted ones are never resent.
"""

from __future__ import annotations

import json
import os
import socketserver
import sys
import tempfile
import threading
import unittest
from collections.abc import Iterator
from contextlib import contextmanager, redirect_stderr
from email import policy
from email.parser import BytesParser
from io import StringIO
from pathlib import Path
from typing import Any, ClassVar
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_notify as notify
import fortios_watch as fw

from tests.test_microsoft365_notifications import FakeResponse, graph_env
from tests.test_release_notifications import _catalog as catalog
from tests.test_release_recipients import (
    CVE_KEY,
    RELEASE_KEY,
    RELEASE_RECIPIENTS,
    _DeliveryRun,
    cve_payload,
    settings_payload,
)

A = "alice@example.invalid"
B = "bob@example.invalid"
C = "carol@example.invalid"
RUN_TS = "2026-09-16T05:15:22Z"
LEGACY_KEY = "new-cve|psirt|CVE-2020-0001|critical"


def cve_event(key: str = CVE_KEY) -> notify.NotificationEvent:
    return notify.NotificationEvent(
        category="CRITICAL",
        dedup_key=key,
        summary="Résumé synthétique",
        severity="critical",
        details={"kind": "cve"},
    )


def partial_result(
    refused: tuple[str, ...], permanent: tuple[str, ...] = ()
) -> notify.SmtpResult:
    return notify.SmtpResult(
        True,
        "Email partiellement accepté par le serveur SMTP.",
        ("Expéditeur accepté",),
        error_code="smtp_partial_delivery",
        transport=notify.EMAIL_TRANSPORT_SMTP,
        refused_recipients=tuple(refused),
        permanent_refusals=tuple(permanent),
    )


def test_settings(
    recipients: tuple[str, ...] = (A, B),
) -> notify.NotificationSettings:
    return notify.validate_notification_settings(
        settings_payload(releases=False, recipients=recipients)
    )


def smtp_config(
    port: int = 25, recipients: tuple[str, ...] = (A, B)
) -> notify.EmailConfig:
    return notify.EmailConfig(
        enabled=True,
        smtp_host="127.0.0.1",
        smtp_port=port,
        smtp_username="",
        smtp_password="",
        smtp_from="fortiupgrade@example.invalid",
        smtp_to=tuple(recipients),
        smtp_starttls=False,
        smtp_timeout=3,
        app_url="https://upgrade.example.invalid/app/",
        smtp_allow_insecure=True,
    )


class _PartialSmtpHandler(socketserver.StreamRequestHandler):
    """Loopback SMTP sink that refuses chosen recipients and records accepted ones."""

    refusals: ClassVar[dict[str, int]] = {}
    messages: ClassVar[list[tuple[tuple[str, ...], bytes]]] = []

    def handle(self) -> None:
        self.wfile.write(b"220 localhost partial test SMTP\r\n")
        accepted: list[str] = []
        data_mode = False
        message = bytearray()
        while True:
            line = self.rfile.readline()
            if not line:
                return
            if data_mode:
                if line == b".\r\n":
                    type(self).messages.append((tuple(accepted), bytes(message)))
                    self.wfile.write(b"250 queued\r\n")
                    data_mode = False
                else:
                    message.extend(line)
                continue
            command = line.decode("ascii", errors="ignore")
            upper = command.upper()
            if upper.startswith(("EHLO", "HELO")):
                self.wfile.write(b"250-localhost\r\n250 SIZE 10485760\r\n")
            elif upper.startswith("MAIL FROM"):
                self.wfile.write(b"250 sender ok\r\n")
            elif upper.startswith("RCPT TO"):
                address = command.split("<", 1)[-1].split(">", 1)[0].strip()
                code = type(self).refusals.get(address.casefold())
                if code:
                    self.wfile.write(
                        f"{code} recipient refused by the test sink\r\n".encode("ascii")
                    )
                else:
                    accepted.append(address)
                    self.wfile.write(b"250 recipient ok\r\n")
            elif upper.startswith("DATA"):
                data_mode = True
                message.clear()
                self.wfile.write(b"354 end with dot\r\n")
            elif upper.startswith("QUIT"):
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                self.wfile.write(b"250 ok\r\n")


@contextmanager
def partial_smtp_server(refusals: dict[str, int]) -> Iterator[int]:
    _PartialSmtpHandler.refusals = {
        address.casefold(): code for address, code in refusals.items()
    }
    _PartialSmtpHandler.messages = []
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _PartialSmtpHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


class LoopbackPartialSmtpTests(unittest.TestCase):
    """The real sender against a real SMTP dialogue: partial refusals are not success."""

    def test_transient_partial_refusal_is_reported_without_leaking_provider_text(self) -> None:
        with partial_smtp_server({B: 450}) as port:
            result = notify.send_email_result(
                smtp_config(port), "Sujet", "Corps", None
            )

        self.assertTrue(result.sent, "the message was accepted for at least one recipient")
        self.assertEqual(result.refused_recipients, (B,))
        self.assertEqual(result.permanent_refusals, ())
        self.assertIn("partiel", result.message.lower())
        self.assertNotIn(B, result.message)
        diagnostics = " ".join(result.checks)
        self.assertNotIn(B, diagnostics)
        self.assertNotIn("test sink", result.message)
        self.assertNotIn("test sink", diagnostics)
        self.assertEqual(_PartialSmtpHandler.messages[0][0], (A,))

    def test_permanent_partial_refusal_is_classified_per_recipient(self) -> None:
        with partial_smtp_server({B: 550}) as port:
            result = notify.send_email_result(
                smtp_config(port), "Sujet", "Corps", None
            )

        self.assertTrue(result.sent)
        self.assertEqual(result.refused_recipients, (B,))
        self.assertEqual(result.permanent_refusals, (B,))
        self.assertFalse(result.retryable)

    def test_mixed_refusals_keep_the_transient_recipient_immediately_retryable(self) -> None:
        with partial_smtp_server({B: 450, C: 550}) as port:
            result = notify.send_email_result(
                smtp_config(port, (A, B, C)), "Sujet", "Corps", None
            )

        self.assertEqual(result.refused_recipients, (B, C))
        self.assertEqual(result.permanent_refusals, (C,))
        self.assertTrue(result.retryable, "a 4xx refusal must stay retryable")

    def test_all_refused_recipients_keep_the_historical_total_failure(self) -> None:
        with partial_smtp_server({A: 450, B: 450}) as port:
            result = notify.send_email_result(
                smtp_config(port), "Sujet", "Corps", None
            )

        self.assertFalse(result.sent)
        self.assertFalse(result.retryable)
        self.assertEqual(result.error_code, "smtp_delivery")
        self.assertEqual(result.refused_recipients, ())
        self.assertEqual(result.permanent_refusals, ())

    def test_complete_acceptance_keeps_the_historical_success(self) -> None:
        with partial_smtp_server({}) as port:
            result = notify.send_email_result(
                smtp_config(port), "Sujet", "Corps", None
            )

        self.assertTrue(result.sent)
        self.assertEqual(result.message, "Email envoyé.")
        self.assertEqual(result.refused_recipients, ())
        self.assertEqual(result.permanent_refusals, ())
        self.assertEqual(_PartialSmtpHandler.messages[0][0], (A, B))


class PartialOutboxLifecycleTests(unittest.TestCase):
    def _seed_partial(
        self, path: Path, *, refused: tuple[str, ...] = (B,)
    ) -> notify.NotificationSettings:
        settings = test_settings()
        event = cve_event()
        claimed = notify.enqueue_and_claim(
            path, [event], claimant="run-1", settings=settings
        )
        result = partial_result(refused)
        with patch.object(notify, "deliver_email_result", return_value=result) as deliver:
            notify.deliver_notification_batches(
                path,
                claimed,
                claimant="run-1",
                settings=settings,
                config=smtp_config(),
                run_timestamp=RUN_TS,
            )
        self.assertEqual(deliver.call_args.args[0].smtp_to, (A, B))
        return settings

    def test_partial_send_keeps_only_the_refused_recipient_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            self._seed_partial(path)

            state = notify.load_notify_state(path)
            (entry,) = state["outbox"]
            self.assertEqual(entry["remainingRecipients"], [B])
            self.assertIsNone(entry["claimedBy"])
            self.assertIsNone(entry["claimedAt"])
            self.assertIsNone(entry["nextAttemptAt"])
            self.assertEqual(entry["lastErrorCode"], "smtp_partial_delivery")
            self.assertNotIn(CVE_KEY, state["sentKeys"])

    def test_next_collection_retries_only_the_refused_recipient_and_finalizes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            settings = self._seed_partial(path)

            claimed = notify.enqueue_and_claim(
                path, [], claimant="run-2", settings=settings
            )
            self.assertEqual([event.dedup_key for event in claimed], [CVE_KEY])
            self.assertEqual(claimed[0].remaining_recipients, (B,))

            with patch.object(
                notify, "deliver_email_result", return_value=notify.SmtpResult(True, "ok")
            ) as deliver:
                notify.deliver_notification_batches(
                    path,
                    claimed,
                    claimant="run-2",
                    settings=settings,
                    config=smtp_config(),
                    run_timestamp=RUN_TS,
                )
            self.assertEqual(deliver.call_args.args[0].smtp_to, (B,))
            self.assertEqual(notify.load_notify_state(path)["outbox"], [])
            self.assertIn(CVE_KEY, notify.load_notify_state(path)["sentKeys"])

    def test_repeated_partial_failures_converge_without_duplicating_accepted_recipients(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            settings = self._seed_partial(path)

            claimed = notify.enqueue_and_claim(
                path, [], claimant="run-2", settings=settings
            )
            with patch.object(
                notify, "deliver_email_result", return_value=partial_result((B,))
            ) as second:
                notify.deliver_notification_batches(
                    path,
                    claimed,
                    claimant="run-2",
                    settings=settings,
                    config=smtp_config(),
                    run_timestamp=RUN_TS,
                )
            self.assertEqual(second.call_args.args[0].smtp_to, (B,))
            state = notify.load_notify_state(path)
            self.assertEqual(state["outbox"][0]["remainingRecipients"], [B])
            self.assertNotIn(CVE_KEY, state["sentKeys"])

            claimed = notify.enqueue_and_claim(
                path, [], claimant="run-3", settings=settings
            )
            with patch.object(
                notify, "deliver_email_result", return_value=notify.SmtpResult(True, "ok")
            ) as third:
                notify.deliver_notification_batches(
                    path,
                    claimed,
                    claimant="run-3",
                    settings=settings,
                    config=smtp_config(),
                    run_timestamp=RUN_TS,
                )
            self.assertEqual(third.call_args.args[0].smtp_to, (B,))
            self.assertEqual(notify.load_notify_state(path)["outbox"], [])

    def test_all_permanent_refusals_wait_for_the_bounded_cooldown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            settings = test_settings()
            event = cve_event()
            claimed = notify.enqueue_and_claim(
                path, [event], claimant="run-1", settings=settings,
                now="2026-07-17T07:00:00Z",
            )
            notify.record_partial_delivery(
                path,
                "run-1",
                events=claimed,
                recipients=(A, B),
                refused_recipients=(B,),
                permanent_refusals=(B,),
                transport="smtp",
                now="2026-07-17T07:00:00Z",
            )

            entry = notify.load_notify_state(path)["outbox"][0]
            self.assertEqual(entry["nextAttemptAt"], "2026-07-17T07:05:00Z")
            self.assertEqual(entry["lastErrorCode"], "smtp_partial_delivery")
            self.assertEqual(entry["lastTransport"], "smtp")
            self.assertEqual(entry["remainingRecipients"], [B])

            self.assertEqual(
                notify.enqueue_and_claim(
                    path, [], claimant="run-2", now="2026-07-17T07:04:00Z"
                ),
                [],
                "a permanent partial refusal must not be retried before its cooldown",
            )
            reclaimed = notify.enqueue_and_claim(
                path, [], claimant="run-3", now="2026-07-17T07:05:01Z"
            )
            self.assertEqual([event.dedup_key for event in reclaimed], [CVE_KEY])
            self.assertEqual(reclaimed[0].remaining_recipients, (B,))

    def test_total_refusal_still_gets_the_permanent_cooldown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            settings = test_settings()
            event = cve_event()
            claimed = notify.enqueue_and_claim(
                path, [event], claimant="run-1", settings=settings,
                now="2026-07-17T07:00:00Z",
            )
            failure = notify.SmtpResult(
                False,
                "Destinataire refusé par le serveur SMTP.",
                error_code="smtp_delivery",
                retryable=False,
                transport=notify.EMAIL_TRANSPORT_SMTP,
            )
            with patch.object(notify, "deliver_email_result", return_value=failure):
                notify.deliver_notification_batches(
                    path,
                    claimed,
                    claimant="run-1",
                    settings=settings,
                    config=smtp_config(),
                    run_timestamp=RUN_TS,
                )
            entry = notify.load_notify_state(path)["outbox"][0]
            self.assertIsNotNone(entry["nextAttemptAt"])
            self.assertNotIn("remainingRecipients", entry)


class PartialBatchPartitionTests(unittest.TestCase):
    def _seed_entries(
        self, path: Path, *, events: list[tuple[str, list[str] | None]]
    ) -> notify.NotificationSettings:
        settings = test_settings(recipients=(A, B, C))
        notify.enqueue_and_claim(
            path,
            [cve_event(key) for key, _ in events],
            claimant="seed",
            settings=settings,
        )
        state = notify.load_notify_state(path)
        remaining = {key: value for key, value in events if value is not None}
        for entry in state["outbox"]:
            if entry["dedupKey"] in remaining:
                entry["remainingRecipients"] = remaining[entry["dedupKey"]]
        fw.write_json(path, state)
        notify.release_claim(path, "seed")
        return settings

    def test_events_with_different_remaining_sets_are_never_merged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            key_one = "new-cve|psirt|CVE-2026-50001|critical"
            key_two = "new-cve|psirt|CVE-2026-50002|critical"
            settings = self._seed_entries(
                path, events=[(key_one, [B]), (key_two, None)]
            )
            claimed = notify.enqueue_and_claim(
                path, [], claimant="run-2", settings=settings
            )

            batches = notify.notification_batches(claimed, settings)
            self.assertEqual(
                {
                    (batch.recipients, tuple(event.dedup_key for event in batch.events))
                    for batch in batches
                },
                {((B,), (key_one,)), ((A, B, C), (key_two,))},
            )

            with patch.object(
                notify, "deliver_email_result", return_value=notify.SmtpResult(True, "ok")
            ) as deliver:
                notify.deliver_notification_batches(
                    path,
                    claimed,
                    claimant="run-2",
                    settings=settings,
                    config=smtp_config(),
                    run_timestamp=RUN_TS,
                )
            self.assertEqual(
                {call.args[0].smtp_to for call in deliver.call_args_list},
                {(B,), (A, B, C)},
                "an event already accepted for some recipients must not ride the full list",
            )
            self.assertEqual(notify.load_notify_state(path)["outbox"], [])

    def test_all_remaining_recipients_removed_resolves_without_sending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            key = "new-cve|psirt|CVE-2026-50001|critical"
            self._seed_entries(path, events=[(key, [B])])
            settings = test_settings(recipients=(A,))
            claimed = notify.enqueue_and_claim(
                path, [], claimant="run-2", settings=settings
            )

            stderr = StringIO()
            with redirect_stderr(stderr), patch.object(
                notify, "deliver_email_result"
            ) as deliver:
                notify.deliver_notification_batches(
                    path,
                    claimed,
                    claimant="run-2",
                    settings=settings,
                    config=smtp_config(),
                    run_timestamp=RUN_TS,
                )
            deliver.assert_not_called()
            state = notify.load_notify_state(path)
            self.assertEqual(state["outbox"], [])
            self.assertIn(key, state["sentKeys"])
            diagnostic = stderr.getvalue()
            self.assertIn("destinataire", diagnostic)
            self.assertNotIn(B, diagnostic)
            self.assertNotIn(A, diagnostic)

    def test_a_new_recipient_is_never_retroactively_notified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            key = "new-cve|psirt|CVE-2026-50001|critical"
            self._seed_entries(path, events=[(key, [B])])
            settings = test_settings(recipients=(A, B, C))
            claimed = notify.enqueue_and_claim(
                path, [], claimant="run-2", settings=settings
            )

            with patch.object(
                notify, "deliver_email_result", return_value=notify.SmtpResult(True, "ok")
            ) as deliver:
                notify.deliver_notification_batches(
                    path,
                    claimed,
                    claimant="run-2",
                    settings=settings,
                    config=smtp_config(),
                    run_timestamp=RUN_TS,
                )
            self.assertEqual(deliver.call_args.args[0].smtp_to, (B,))
            self.assertEqual(notify.load_notify_state(path)["outbox"], [])

    def test_a_removed_recipient_is_dropped_from_the_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            key = "new-cve|psirt|CVE-2026-50001|critical"
            self._seed_entries(path, events=[(key, [B, C])])
            settings = test_settings(recipients=(A, B))
            claimed = notify.enqueue_and_claim(
                path, [], claimant="run-2", settings=settings
            )

            with patch.object(
                notify, "deliver_email_result", return_value=notify.SmtpResult(True, "ok")
            ) as deliver:
                notify.deliver_notification_batches(
                    path,
                    claimed,
                    claimant="run-2",
                    settings=settings,
                    config=smtp_config(),
                    run_timestamp=RUN_TS,
                )
            self.assertEqual(deliver.call_args.args[0].smtp_to, (B,))

    def test_a_partial_cve_batch_neither_holds_nor_replays_the_system_batch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            s1, s2 = "ops1@example.invalid", "ops2@example.invalid"
            settings = notify.validate_notification_settings(
                settings_payload(
                    releases=False,
                    recipients=(A, B),
                    system=True,
                    system_recipients=(s1, s2),
                )
            )
            cve = cve_event()
            system_event = notify.NotificationEvent(
                category="OPERATIONS",
                dedup_key="eol|7.6|branch",
                summary="Fin de support",
                details={"kind": "eol"},
            )
            claimed = notify.enqueue_and_claim(
                path, [cve, system_event], claimant="run-1", settings=settings
            )
            self.assertEqual(
                [event.dedup_key for event in claimed], [CVE_KEY, "eol|7.6|branch"]
            )

            def deliver(config: notify.EmailConfig, *args: Any) -> notify.SmtpResult:
                if config.smtp_to == (A, B):
                    return partial_result((B,))
                self.assertEqual(config.smtp_to, (s1, s2))
                return notify.SmtpResult(True, "ok")

            with patch.object(
                notify, "deliver_email_result", side_effect=deliver
            ) as deliver_mock:
                notify.deliver_notification_batches(
                    path,
                    claimed,
                    claimant="run-1",
                    settings=settings,
                    config=smtp_config(),
                    run_timestamp=RUN_TS,
                )
            self.assertEqual(
                {call.args[0].smtp_to for call in deliver_mock.call_args_list},
                {(A, B), (s1, s2)},
            )
            state = notify.load_notify_state(path)
            self.assertEqual(
                [entry["dedupKey"] for entry in state["outbox"]], [CVE_KEY]
            )
            self.assertEqual(state["outbox"][0]["remainingRecipients"], [B])
            self.assertIsNone(state["outbox"][0]["claimedBy"])
            self.assertIn(
                "eol|7.6|branch",
                state["sentKeys"],
                "the fully delivered system batch must be finalized",
            )
            self.assertNotIn(CVE_KEY, state["sentKeys"])

            claimed = notify.enqueue_and_claim(
                path, [], claimant="run-2", settings=settings
            )
            self.assertEqual([event.dedup_key for event in claimed], [CVE_KEY])
            self.assertEqual(claimed[0].remaining_recipients, (B,))


class PartialClaimOwnershipTests(unittest.TestCase):
    def test_a_stale_previous_owner_cannot_overwrite_the_new_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            event = cve_event()
            notify.enqueue_and_claim(
                path, [event], claimant="run-a", now="2026-07-17T07:00:00Z"
            )
            stolen = notify.enqueue_and_claim(
                path, [], claimant="run-b", now="2026-07-17T07:11:00Z"
            )
            self.assertEqual([item.dedup_key for item in stolen], [CVE_KEY])
            before = notify.load_notify_state(path)["outbox"][0]

            notify.record_partial_delivery(
                path,
                "run-a",
                events=[event],
                recipients=(A, B),
                refused_recipients=(B,),
                permanent_refusals=(),
                transport="smtp",
                now="2026-07-17T07:12:00Z",
            )

            after = notify.load_notify_state(path)["outbox"][0]
            self.assertEqual(after, before)
            self.assertEqual(after["claimedBy"], "run-b")
            self.assertNotIn("remainingRecipients", after)

    def test_a_foreign_claimant_cannot_record_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            event = cve_event()
            notify.enqueue_and_claim(
                path, [event], claimant="run-a", now="2026-07-17T07:00:00Z"
            )
            before = notify.load_notify_state(path)["outbox"][0]

            notify.record_partial_delivery(
                path,
                "someone-else",
                events=[event],
                recipients=(A, B),
                refused_recipients=(B,),
                permanent_refusals=(),
                transport="smtp",
                now="2026-07-17T07:01:00Z",
            )

            after = notify.load_notify_state(path)["outbox"][0]
            self.assertEqual(after, before)


class TotalRefusalBatchIndependenceTests(unittest.TestCase):
    def test_partial_cve_failure_does_not_replay_the_release_already_sent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = _DeliveryRun(Path(tmp), refuse_to=((B, 450),))
            run.write_settings(
                settings_payload(
                    release_recipients_shared=False,
                    release_recipients=RELEASE_RECIPIENTS,
                    recipients=(A, B),
                )
            )
            run.seed(catalog(fortios=("8.0.0",)))
            self.assertEqual(run.run(), 0)
            run.seed(catalog(fortios=("8.0.0", "8.0.1"), cves=(cve_payload(),)))

            self.assertEqual(run.run(), 0)
            self.assertEqual(run.sent, [(A,), RELEASE_RECIPIENTS])
            self.assertIn(RELEASE_KEY, run.sent_keys())
            self.assertNotIn(CVE_KEY, run.sent_keys())
            self.assertEqual(run.outbox_keys(), [CVE_KEY])
            entry = run.state()["outbox"][0]
            self.assertEqual(entry["remainingRecipients"], [B])

            run.refuse_to = {}
            self.assertEqual(run.run(), 0)
            self.assertEqual(run.sent[-1], (B,))
            self.assertEqual(run.outbox_keys(), [])
            self.assertIn(CVE_KEY, run.sent_keys())
            self.assertEqual(
                run.sent.count(RELEASE_RECIPIENTS), 1, "the sent release must never be replayed"
            )


class CollectorPartialDeliveryTests(unittest.TestCase):
    """The real collector wiring: a partial refusal survives the process boundary."""

    def _prepare(
        self, root: Path, *, refuse_to: tuple[tuple[str, int], ...]
    ) -> _DeliveryRun:
        run = _DeliveryRun(root, refuse_to=refuse_to)
        run.write_settings(settings_payload(releases=False, recipients=(A, B)))
        run.seed(catalog(fortios=("8.0.0",)))
        self.assertEqual(run.run(), 0)
        self.assertEqual(run.messages, [])
        return run

    def test_partial_smtp_refusal_survives_restart_and_resumes_only_the_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = self._prepare(Path(tmp), refuse_to=((B, 450),))
            run.seed(catalog(fortios=("8.0.0", "8.0.1"), cves=(cve_payload(),)))

            # Collection 1: the server accepts A and refuses B.
            self.assertEqual(run.run(), 0)
            self.assertEqual(run.sent, [(A,)])
            self.assertEqual(run.refused, [((A, B), (B,))])
            state = run.state()
            self.assertEqual(run.outbox_keys(), [CVE_KEY])
            entry = state["outbox"][0]
            self.assertEqual(entry["remainingRecipients"], [B])
            self.assertIsNone(entry["claimedBy"])
            self.assertIsNone(entry["nextAttemptAt"])
            self.assertNotIn(CVE_KEY, state["sentKeys"])

            # Collection 2 (restart, no new event): only B is retried.
            run.refuse_to = {}
            self.assertEqual(run.run(), 0)
            self.assertEqual(run.sent[-1], (B,))
            self.assertEqual(len(run.messages), 2)
            retry = BytesParser(policy=policy.default).parsebytes(run.messages[-1])
            self.assertEqual(str(retry["To"]).strip(), B)
            self.assertNotIn(A, str(retry["To"]))
            self.assertIn(
                "CVE-2026-99999",
                retry.get_body(preferencelist=("plain",)).get_content(),
            )
            state = run.state()
            self.assertEqual(state["outbox"], [])
            self.assertIn(CVE_KEY, state["sentKeys"])

            # Collection 3: nothing is ever replayed.
            self.assertEqual(run.run(), 0)
            self.assertEqual(len(run.messages), 2)
            self.assertEqual(run.sent, [(A,), (B,)])

    def test_permanent_partial_refusal_is_diagnosed_and_waits_for_its_cooldown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = self._prepare(Path(tmp), refuse_to=((B, 550),))
            run.seed(catalog(fortios=("8.0.0", "8.0.1"), cves=(cve_payload(),)))

            self.assertEqual(run.run(), 0)
            entry = run.state()["outbox"][0]
            self.assertEqual(entry["remainingRecipients"], [B])
            self.assertEqual(entry["lastErrorCode"], "smtp_partial_delivery")
            self.assertIsNotNone(entry["nextAttemptAt"])
            self.assertEqual(run.sent, [(A,)])

            # The bounded cooldown must prevent a tight retry loop on the next pass.
            self.assertEqual(run.run(), 0)
            self.assertEqual(len(run.messages), 1)
            self.assertEqual(run.outbox_keys(), [CVE_KEY])


class TransportChangeTests(unittest.TestCase):
    def test_switching_to_graph_retries_only_the_pending_recipients(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "history.json"
            settings = test_settings()
            event = cve_event()
            notify.enqueue_and_claim(path, [event], claimant="smtp-run", settings=settings)
            notify.record_partial_delivery(
                path,
                "smtp-run",
                events=[event],
                recipients=(A, B),
                refused_recipients=(B,),
                permanent_refusals=(B,),
                transport="smtp",
                now="2026-07-17T07:00:00Z",
            )
            notify.prepare_retry_for_transport(path, "microsoft365")

            secret = root / "microsoft365-secret"
            secret.write_text("secret-value", encoding="utf-8")
            config = notify.load_email_config(
                graph_env(secret),
                settings=settings,
                smtp_settings_path=root / "smtp-settings.json",
            )
            self.assertTrue(config.is_complete())
            claimed = notify.enqueue_and_claim(
                path, [], claimant="graph-run", transport="microsoft365"
            )
            self.assertEqual([item.dedup_key for item in claimed], [CVE_KEY])
            self.assertEqual(claimed[0].remaining_recipients, (B,))

            delivered: list[dict[str, Any]] = []

            def fake_urlopen(request: Any, *, timeout: int) -> FakeResponse:
                if request.full_url.startswith("https://login.microsoftonline.com/"):
                    return FakeResponse(200, b'{"access_token": "token-value"}')
                delivered.append(json.loads(request.data.decode("utf-8")))
                return FakeResponse(202)

            with patch.object(notify, "_graph_urlopen", side_effect=fake_urlopen):
                notify.deliver_notification_batches(
                    path,
                    claimed,
                    claimant="graph-run",
                    settings=settings,
                    config=config,
                    run_timestamp=RUN_TS,
                )

            self.assertEqual(
                [
                    recipient["emailAddress"]["address"]
                    for recipient in delivered[0]["message"]["toRecipients"]
                ],
                [B],
                "the accepted recipient must not be notified again after a transport change",
            )
            state = notify.load_notify_state(path)
            self.assertEqual(state["outbox"], [])
            self.assertIn(CVE_KEY, state["sentKeys"])


class LegacyAndCorruptionTests(unittest.TestCase):
    def test_a_legacy_entry_without_remaining_recipients_still_delivers_to_the_full_list(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            entry = {
                "category": "CRITICAL",
                "dedupKey": LEGACY_KEY,
                "summary": "legacy",
                "queuedAt": "2026-07-17T07:00:00Z",
                "claimedBy": None,
                "claimedAt": None,
            }
            checkpoint = {
                "versionsByProduct": {"fortigate-fortios": ["7.4.0"]},
                "cvesById": {"CVE-2020-0001": {"severity": "critical"}},
                "health": {"psirt": {"consecutiveFailures": 0}},
            }
            raw = json.dumps(
                {
                    "sentKeys": {},
                    "outbox": [entry],
                    "eolState": {},
                    "checkpoint": checkpoint,
                }
            )
            path.write_text(raw, encoding="utf-8")

            state = notify.load_notify_state(path)
            self.assertEqual(len(state["outbox"]), 1)
            self.assertEqual(state["checkpoint"], checkpoint)
            self.assertNotIn("remainingRecipients", state["outbox"][0])
            self.assertEqual(path.read_text(encoding="utf-8"), raw, "a pure read never rewrites")

            settings = test_settings()
            claimed = notify.enqueue_and_claim(
                path, [], claimant="run-1", settings=settings
            )
            self.assertEqual(len(claimed), 1)
            self.assertIsNone(claimed[0].remaining_recipients)
            with patch.object(
                notify, "deliver_email_result", return_value=notify.SmtpResult(True, "ok")
            ) as deliver:
                notify.deliver_notification_batches(
                    path,
                    claimed,
                    claimant="run-1",
                    settings=settings,
                    config=smtp_config(),
                    run_timestamp=RUN_TS,
                )
            self.assertEqual(deliver.call_args.args[0].smtp_to, (A, B))
            state = notify.load_notify_state(path)
            self.assertEqual(state["outbox"], [])
            self.assertIn(LEGACY_KEY, state["sentKeys"])
            self.assertEqual(
                state["checkpoint"],
                checkpoint,
                "the finalize write must preserve the historical checkpoint",
            )

    def test_malformed_remaining_recipients_are_rejected_without_mutation(self) -> None:
        for bad_value in ([], "bob@example.invalid", [1], [""], [None], [A, 2], {}):
            with self.subTest(value=bad_value), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "history.json"
                entry = {
                    "category": "CRITICAL",
                    "dedupKey": LEGACY_KEY,
                    "summary": "x",
                    "queuedAt": "2026-07-17T07:00:00Z",
                    "claimedBy": None,
                    "claimedAt": None,
                    "remainingRecipients": bad_value,
                }
                path.write_text(
                    json.dumps({"sentKeys": {}, "outbox": [entry], "eolState": {}}),
                    encoding="utf-8",
                )
                raw = path.read_bytes()

                with self.assertRaises(notify.NotifyStateError):
                    notify.load_notify_state(path)

                self.assertEqual(path.read_bytes(), raw)
                self.assertEqual(
                    list(path.parent.glob(f"{path.name}.corrupt-*")), []
                )

    def test_main_completes_and_preserves_a_malformed_partial_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base_path = Path(tmp) / "state.json"
            fw.write_json(base_path, fw.normalize_state({}))
            history_path = Path(tmp) / "notify-history.json"
            entry = {
                "category": "CRITICAL",
                "dedupKey": LEGACY_KEY,
                "summary": "x",
                "queuedAt": "2026-07-17T07:00:00Z",
                "claimedBy": "dead-run",
                "claimedAt": None,
                "remainingRecipients": [B, ""],
            }
            history_path.write_text(
                json.dumps({"sentKeys": {}, "outbox": [entry], "eolState": {}}),
                encoding="utf-8",
            )
            raw = history_path.read_bytes()

            environment = {
                "FORTIOS_EMAIL_ENABLED": "true",
                "FORTIOS_SMTP_HOST": "smtp.example.com",
                "FORTIOS_SMTP_FROM": "fortios@example.com",
                "FORTIOS_SMTP_TO": "alice@example.com",
            }
            with patch.dict(os.environ, environment, clear=False), patch(
                "smtplib.SMTP", side_effect=ConnectionRefusedError("refused")
            ):
                exit_code = fw.main(
                    [
                        "--skip-network",
                        "--base", str(base_path), "--output", str(base_path),
                        "--report", str(Path(tmp) / "report.md"),
                        "--health-output", str(Path(tmp) / "health.json"),
                        "--notify-history-output", str(history_path),
                    ]
                )
            self.assertEqual(exit_code, 0)
            self.assertEqual(history_path.read_bytes(), raw)
            self.assertEqual(
                list(Path(tmp).glob("notify-history.json.corrupt-*")), []
            )


if __name__ == "__main__":
    unittest.main()
