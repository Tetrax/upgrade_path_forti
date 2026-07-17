"""Covers scripts/fortios_notify.py: SMTP config loading, event derivation, deduplication,
email composition, and sending -- entirely with mocks, no real network or SMTP server.
"""

import os
import smtplib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_notify as notify  # noqa: E402
import fortios_watch as fw  # noqa: E402


def make_config(**overrides) -> notify.EmailConfig:
    defaults = dict(
        enabled=True, smtp_host="smtp.example.com", smtp_port=587,
        smtp_username="user@example.com", smtp_password="hunter2",
        smtp_from="fortios@example.com", smtp_to=("alice@example.com",),
        smtp_starttls=True, smtp_timeout=10, app_url="https://valdev.me:3001/app/",
    )
    defaults.update(overrides)
    return notify.EmailConfig(**defaults)


class ConfigLoadingTests(unittest.TestCase):
    def test_disabled_by_default(self):
        config = notify.load_email_config({})
        self.assertFalse(config.enabled)

    def test_multiple_recipients_parsed(self):
        config = notify.load_email_config({"FORTIOS_SMTP_TO": "a@example.com, b@example.com ,c@example.com"})
        self.assertEqual(config.smtp_to, ("a@example.com", "b@example.com", "c@example.com"))

    def test_starttls_defaults_true(self):
        config = notify.load_email_config({})
        self.assertTrue(config.smtp_starttls)

    def test_is_complete_requires_host_from_to(self):
        self.assertFalse(notify.EmailConfig(
            enabled=True, smtp_host="", smtp_port=587, smtp_username="", smtp_password="",
            smtp_from="a@b.com", smtp_to=("c@d.com",), smtp_starttls=True, smtp_timeout=10, app_url="",
        ).is_complete())
        self.assertTrue(make_config().is_complete())

    def test_is_complete_rejects_out_of_range_port(self):
        self.assertFalse(make_config(smtp_port=0).is_complete())
        self.assertFalse(make_config(smtp_port=70000).is_complete())
        self.assertFalse(make_config(smtp_port=-1).is_complete())

    def test_is_complete_rejects_non_positive_timeout(self):
        self.assertFalse(make_config(smtp_timeout=0).is_complete())
        self.assertFalse(make_config(smtp_timeout=-5).is_complete())

    def test_is_complete_rejects_malformed_from_address(self):
        self.assertFalse(make_config(smtp_from="not-an-email").is_complete())
        self.assertFalse(make_config(smtp_from="has a space@example.com").is_complete())
        self.assertFalse(make_config(smtp_from="evil\nBcc: x@evil.com@example.com").is_complete())

    def test_is_complete_rejects_malformed_to_address(self):
        self.assertFalse(make_config(smtp_to=("not-an-email",)).is_complete())
        self.assertFalse(make_config(smtp_to=("alice@example.com", "not-an-email")).is_complete())


class SendEmailTests(unittest.TestCase):
    def test_disabled_config_never_touches_smtplib(self):
        with patch("smtplib.SMTP") as smtp_mock:
            result = notify.send_email(make_config(enabled=False), "subj", "body")
        self.assertFalse(result)
        smtp_mock.assert_not_called()

    def test_incomplete_config_never_touches_smtplib(self):
        with patch("smtplib.SMTP") as smtp_mock:
            result = notify.send_email(make_config(smtp_host=""), "subj", "body")
        self.assertFalse(result)
        smtp_mock.assert_not_called()

    def test_successful_send(self):
        client = MagicMock()
        client.__enter__ = MagicMock(return_value=client)
        client.__exit__ = MagicMock(return_value=False)
        with patch("smtplib.SMTP", return_value=client) as smtp_mock:
            result = notify.send_email(make_config(), "Subject line", "Body text")
        self.assertTrue(result)
        smtp_mock.assert_called_once_with("smtp.example.com", 587, timeout=10)
        client.starttls.assert_called_once()
        client.login.assert_called_once_with("user@example.com", "hunter2")
        client.send_message.assert_called_once()
        sent_message = client.send_message.call_args[0][0]
        self.assertEqual(sent_message["Subject"], "Subject line")
        self.assertEqual(sent_message["To"], "alice@example.com")

    def test_multiple_recipients_joined_in_header(self):
        client = MagicMock()
        client.__enter__ = MagicMock(return_value=client)
        client.__exit__ = MagicMock(return_value=False)
        config = make_config(smtp_to=("alice@example.com", "bob@example.com"))
        with patch("smtplib.SMTP", return_value=client):
            notify.send_email(config, "Subject", "Body")
        sent_message = client.send_message.call_args[0][0]
        self.assertEqual(sent_message["To"], "alice@example.com, bob@example.com")

    def test_connection_failure_returns_false_without_raising(self):
        with patch("smtplib.SMTP", side_effect=ConnectionRefusedError("refused")):
            result = notify.send_email(make_config(), "subj", "body")
        self.assertFalse(result)

    def test_starttls_failure_returns_false_without_raising(self):
        client = MagicMock()
        client.__enter__ = MagicMock(return_value=client)
        client.__exit__ = MagicMock(return_value=False)
        client.starttls.side_effect = smtplib.SMTPException("STARTTLS not supported")
        with patch("smtplib.SMTP", return_value=client):
            result = notify.send_email(make_config(), "subj", "body")
        self.assertFalse(result)

    def test_auth_failure_returns_false_without_raising(self):
        client = MagicMock()
        client.__enter__ = MagicMock(return_value=client)
        client.__exit__ = MagicMock(return_value=False)
        client.login.side_effect = smtplib.SMTPAuthenticationError(535, b"bad credentials")
        with patch("smtplib.SMTP", return_value=client):
            result = notify.send_email(make_config(), "subj", "body")
        self.assertFalse(result)

    def test_subject_with_embedded_newline_does_not_raise(self):
        """Regression: EmailMessage construction used to happen BEFORE send_email()'s try block,
        so a header value containing a raw newline (e.g. a CVE title that somehow made it into
        the subject un-sanitized, or a header-injection attempt) raised ValueError straight out
        of the function instead of being caught like every other send failure."""
        with patch("smtplib.SMTP") as smtp_mock:
            try:
                result = notify.send_email(make_config(), "Subject line\nBcc: attacker@evil.com", "body")
            except Exception as error:  # noqa: BLE001
                self.fail(f"send_email() must never raise, got {error!r}")
        self.assertFalse(result)
        smtp_mock.assert_not_called()

    def test_smtp_failure_never_raises_up_to_the_caller(self):
        """The literal guarantee: whatever goes wrong in smtplib must never propagate as an
        exception out of send_email(), since main() must never fail because of this."""
        with patch("smtplib.SMTP", side_effect=TimeoutError("timed out")):
            try:
                result = notify.send_email(make_config(), "subj", "body")
            except Exception as error:  # noqa: BLE001
                self.fail(f"send_email() must never raise, got {error!r}")
        self.assertFalse(result)


class DeduplicationTests(unittest.TestCase):
    def test_new_event_passes_filter(self):
        event = notify.NotificationEvent(category="DAILY", dedup_key="new-version|fortios|fortios|7.6.8", summary="x")
        self.assertEqual(notify.filter_new_events([event], {}), [event])

    def test_already_sent_event_is_filtered_out(self):
        event = notify.NotificationEvent(category="DAILY", dedup_key="new-version|fortios|fortios|7.6.8", summary="x")
        history = {"new-version|fortios|fortios|7.6.8": "2026-07-15T07:15:00Z"}
        self.assertEqual(notify.filter_new_events([event], history), [])

    def test_record_sent_events_persists_and_dedups_next_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            event = notify.NotificationEvent(category="DAILY", dedup_key="new-version|fortios|fortios|7.6.8", summary="x")
            notify.record_sent_events(path, [event])
            history = notify.load_notify_history(path)
            self.assertIn(event.dedup_key, history)
            # Simulate the next run: the same event must now be filtered out.
            self.assertEqual(notify.filter_new_events([event], history), [])


class EventGroupingAndComposeTests(unittest.TestCase):
    def test_no_events_produces_no_email(self):
        self.assertIsNone(notify.compose_email([], app_url="https://x", run_timestamp="2026-07-16T07:15:00Z"))

    def test_multiple_events_grouped_into_one_email(self):
        events = [
            notify.NotificationEvent(category="CRITICAL", dedup_key="new-cve|psirt|CVE-2026-00001|critical", summary="CVE-2026-00001 — FortiOS 7.4.0 à 7.4.8 (critical)"),
            notify.NotificationEvent(category="CRITICAL", dedup_key="new-cve|psirt|CVE-2026-00002|critical", summary="CVE-2026-00002 — FortiManager 7.2 (critical)"),
            notify.NotificationEvent(category="DAILY", dedup_key="new-version|fortios|fortios|7.6.8", summary="Nouvelle version FortiOS 7.6.8"),
            notify.NotificationEvent(category="OPERATIONS", dedup_key="source-failure|forticlient|consecutive|2", summary="Collecte FortiClient en échec depuis 2 exécutions"),
        ]
        subject, body = notify.compose_email(events, app_url="https://valdev.me:3001/app/", run_timestamp="2026-07-16T07:15:00Z")
        self.assertIn("2 nouvelle(s) CVE critique(s)", subject)
        self.assertIn("CVE-2026-00001", body)
        self.assertIn("CVE-2026-00002", body)
        self.assertIn("Nouvelle version FortiOS 7.6.8", body)
        self.assertIn("Collecte FortiClient en échec", body)
        self.assertIn("https://valdev.me:3001/app/", body)
        self.assertIn("2026-07-16T07:15:00Z", body)

    def test_long_event_list_is_truncated_with_a_clear_note(self):
        events = [
            notify.NotificationEvent(category="DAILY", dedup_key=f"new-version|fortios|fortios|7.{i}.0", summary=f"Nouvelle version FortiOS 7.{i}.0")
            for i in range(30)
        ]
        _, body = notify.compose_email(events, app_url="https://x", run_timestamp="2026-07-16T07:15:00Z")
        self.assertIn("tronquée", body)
        self.assertIn("et 10 de plus", body)


class VersionEventDerivationTests(unittest.TestCase):
    def test_new_version_detected(self):
        before = {"fortigate-fortios": {"7.6.7"}}
        after = {"fortigate-fortios": {"7.6.7", "7.6.8"}}
        events = notify.derive_version_events(before, after, {"fortigate-fortios": "FortiGate/FortiOS"})
        self.assertEqual(len(events), 1)
        self.assertIn("7.6.8", events[0].summary)
        self.assertEqual(events[0].dedup_key, "new-version|fortios|fortios|7.6.8")

    def test_no_new_version_produces_no_event(self):
        before = {"fortigate-fortios": {"7.6.7"}}
        after = {"fortigate-fortios": {"7.6.7"}}
        self.assertEqual(notify.derive_version_events(before, after, {}), [])

    def test_forticlient_versions_never_notify(self):
        before = {"forticlient": set()}
        after = {"forticlient": {"7.4.1"}}
        self.assertEqual(notify.derive_version_events(before, after, {}), [])

    def test_first_activation_with_no_real_changes_produces_no_events(self):
        """Simulates a first-time run where before == after (nothing genuinely new this run,
        regardless of how much history is already in the catalog) -- must never notify about
        the whole existing catalog."""
        before = {"fortigate-fortios": {f"7.{i}.0" for i in range(20)}}
        after = dict(before)
        self.assertEqual(notify.derive_version_events(before, after, {}), [])


class CveEventDerivationTests(unittest.TestCase):
    def test_new_critical_cve(self):
        cve = {"id": "CVE-2026-00001", "severity": "critical", "affected": [{"product": "fortigate-fortios", "from": "7.4.0", "to": "7.4.8"}]}
        events = notify.derive_new_cve_events([cve])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].category, "CRITICAL")
        self.assertIn("7.4.0", events[0].summary)

    def test_new_non_critical_cve_is_daily_category(self):
        cve = {"id": "CVE-2026-00002", "severity": "medium", "affected": []}
        events = notify.derive_new_cve_events([cve])
        self.assertEqual(events[0].category, "DAILY")

    def test_severity_change_to_critical_is_flagged(self):
        before = {"CVE-2026-00003": {"id": "CVE-2026-00003", "severity": "medium", "affected": []}}
        after = {"CVE-2026-00003": {"id": "CVE-2026-00003", "severity": "critical", "affected": []}}
        events = notify.derive_cve_modification_events(before, after)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].category, "CRITICAL")

    def test_unchanged_severity_is_not_flagged(self):
        before = {"CVE-2026-00004": {"id": "CVE-2026-00004", "severity": "medium", "cvssScore": 5.0, "affected": []}}
        after = {"CVE-2026-00004": {"id": "CVE-2026-00004", "severity": "medium", "cvssScore": 5.1, "affected": []}}
        # cvssScore changed but severity did not -- not significant enough to notify.
        self.assertEqual(notify.derive_cve_modification_events(before, after), [])

    def test_affected_scope_extension_is_flagged(self):
        before = {"CVE-2026-00005": {
            "id": "CVE-2026-00005", "severity": "medium",
            "affected": [{"product": "fortigate-fortios", "branch": "7.4", "from": "7.4.0", "to": "7.4.5"}],
        }}
        after = {"CVE-2026-00005": {
            "id": "CVE-2026-00005", "severity": "medium",
            "affected": [
                {"product": "fortigate-fortios", "branch": "7.4", "from": "7.4.0", "to": "7.4.5"},
                {"product": "fortianalyzer", "branch": "7.2", "from": "7.2.0", "to": "7.2.3"},
            ],
        }}
        events = notify.derive_cve_modification_events(before, after)
        self.assertEqual(len(events), 1)
        self.assertIn("périmètre étendu", events[0].summary)

    def test_affected_scope_reduction_is_flagged(self):
        before = {"CVE-2026-00006": {
            "id": "CVE-2026-00006", "severity": "medium",
            "affected": [
                {"product": "fortigate-fortios", "branch": "7.4", "from": "7.4.0", "to": "7.4.5"},
                {"product": "fortianalyzer", "branch": "7.2", "from": "7.2.0", "to": "7.2.3"},
            ],
        }}
        after = {"CVE-2026-00006": {
            "id": "CVE-2026-00006", "severity": "medium",
            "affected": [{"product": "fortigate-fortios", "branch": "7.4", "from": "7.4.0", "to": "7.4.5"}],
        }}
        events = notify.derive_cve_modification_events(before, after)
        self.assertEqual(len(events), 1)
        self.assertIn("périmètre réduit", events[0].summary)

    def test_version_range_change_is_flagged_as_scope_change(self):
        before = {"CVE-2026-00007": {
            "id": "CVE-2026-00007", "severity": "medium",
            "affected": [{"product": "fortigate-fortios", "branch": "7.4", "from": "7.4.0", "to": "7.4.5"}],
        }}
        after = {"CVE-2026-00007": {
            "id": "CVE-2026-00007", "severity": "medium",
            "affected": [{"product": "fortigate-fortios", "branch": "7.4", "from": "7.4.0", "to": "7.4.8"}],
        }}
        events = notify.derive_cve_modification_events(before, after)
        self.assertEqual(len(events), 1)

    def test_fixed_version_becoming_known_is_flagged(self):
        """A `to` bound appearing for the first time (open-ended -> a fix is now identified) is
        itself a version-range change and must notify, even with severity/CVSS unchanged."""
        before = {"CVE-2026-00008": {
            "id": "CVE-2026-00008", "severity": "high", "cvssScore": 7.0,
            "affected": [{"product": "fortigate-fortios", "branch": "7.4", "from": "7.4.0", "to": None}],
        }}
        after = {"CVE-2026-00008": {
            "id": "CVE-2026-00008", "severity": "high", "cvssScore": 7.0,
            "affected": [{"product": "fortigate-fortios", "branch": "7.4", "from": "7.4.0", "to": "7.4.9"}],
        }}
        events = notify.derive_cve_modification_events(before, after)
        self.assertEqual(len(events), 1)

    def test_significant_cvss_change_is_flagged(self):
        before = {"CVE-2026-00009": {"id": "CVE-2026-00009", "severity": "medium", "cvssScore": 5.0, "affected": []}}
        after = {"CVE-2026-00009": {"id": "CVE-2026-00009", "severity": "medium", "cvssScore": 6.5, "affected": []}}
        events = notify.derive_cve_modification_events(before, after)
        self.assertEqual(len(events), 1)
        self.assertIn("CVSS 5.0 → 6.5", events[0].summary)

    def test_small_cvss_change_alone_is_not_flagged(self):
        before = {"CVE-2026-00010": {"id": "CVE-2026-00010", "severity": "medium", "cvssScore": 5.0, "affected": []}}
        after = {"CVE-2026-00010": {"id": "CVE-2026-00010", "severity": "medium", "cvssScore": 5.9, "affected": []}}
        self.assertEqual(notify.derive_cve_modification_events(before, after), [])

    def test_multiple_simultaneous_changes_produce_a_single_combined_event(self):
        before = {"CVE-2026-00011": {
            "id": "CVE-2026-00011", "severity": "medium", "cvssScore": 5.0,
            "affected": [{"product": "fortigate-fortios", "branch": "7.4", "from": "7.4.0", "to": "7.4.5"}],
        }}
        after = {"CVE-2026-00011": {
            "id": "CVE-2026-00011", "severity": "critical", "cvssScore": 9.0,
            "affected": [{"product": "fortigate-fortios", "branch": "7.4", "from": "7.4.0", "to": "7.4.8"}],
        }}
        events = notify.derive_cve_modification_events(before, after)
        self.assertEqual(len(events), 1, "one combined notification, not one per changed field")
        self.assertEqual(events[0].category, "CRITICAL")
        self.assertIn("sévérité medium → critical", events[0].summary)
        self.assertIn("CVSS 5.0 → 9.0", events[0].summary)

    def test_purely_technical_or_ordering_change_is_not_flagged(self):
        """Only title/description wording or updatedAt changed -- severity, CVSS, and affected
        scope are all identical, so this must never generate a notification."""
        before = {"CVE-2026-00012": {
            "id": "CVE-2026-00012", "severity": "medium", "cvssScore": 5.0, "title": "Old title",
            "updatedAt": "2026-07-01", "affected": [{"product": "fortigate-fortios", "branch": "7.4", "from": "7.4.0", "to": "7.4.5"}],
        }}
        after = {"CVE-2026-00012": {
            "id": "CVE-2026-00012", "severity": "medium", "cvssScore": 5.0, "title": "Reworded title",
            "updatedAt": "2026-07-16", "affected": [{"product": "fortigate-fortios", "branch": "7.4", "from": "7.4.0", "to": "7.4.5"}],
        }}
        self.assertEqual(notify.derive_cve_modification_events(before, after), [])

    def test_different_dedup_keys_for_different_change_states(self):
        """Two DIFFERENT changes to the same CVE (e.g. weeks apart) must each get their own,
        distinct dedup key -- otherwise the second, genuinely new change would be silently
        swallowed by the history left behind by the first."""
        state_a = {"id": "CVE-2026-00013", "severity": "medium", "cvssScore": 5.0, "affected": []}
        state_b = {"id": "CVE-2026-00013", "severity": "high", "cvssScore": 5.0, "affected": []}
        state_c = {"id": "CVE-2026-00013", "severity": "critical", "cvssScore": 5.0, "affected": []}
        events_1 = notify.derive_cve_modification_events({"CVE-2026-00013": state_a}, {"CVE-2026-00013": state_b})
        events_2 = notify.derive_cve_modification_events({"CVE-2026-00013": state_b}, {"CVE-2026-00013": state_c})
        self.assertNotEqual(events_1[0].dedup_key, events_2[0].dedup_key)


class SourceHealthEventDerivationTests(unittest.TestCase):
    LABELS = {"forticlient": "FortiClient"}

    def test_no_email_on_first_failure(self):
        before = {"forticlient": {"consecutiveFailures": 0}}
        after = {"forticlient": {"consecutiveFailures": 1}}
        self.assertEqual(notify.derive_source_health_events(before, after, self.LABELS), [])

    def test_email_after_two_consecutive_failures(self):
        before = {"forticlient": {"consecutiveFailures": 1}}
        after = {"forticlient": {"consecutiveFailures": 2}}
        events = notify.derive_source_health_events(before, after, self.LABELS)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].category, "OPERATIONS")
        self.assertIn("2 exécutions", events[0].summary)

    def test_recovery_email_after_failures(self):
        before = {"forticlient": {"consecutiveFailures": 3}}
        after = {"forticlient": {"consecutiveFailures": 0, "lastSuccessAt": "2026-07-16T07:15:00Z"}}
        events = notify.derive_source_health_events(before, after, self.LABELS)
        self.assertEqual(len(events), 1)
        self.assertIn("opérationnelle", events[0].summary)

    def test_skipped_source_never_notifies(self):
        before = {"forticlient": {"consecutiveFailures": 0, "status": "skipped"}}
        after = {"forticlient": {"consecutiveFailures": 0, "status": "skipped"}}
        self.assertEqual(notify.derive_source_health_events(before, after, self.LABELS), [])

    def test_daily_run_source_is_never_itself_reported(self):
        before = {"daily-run": {"consecutiveFailures": 1}}
        after = {"daily-run": {"consecutiveFailures": 2}}
        self.assertEqual(notify.derive_source_health_events(before, after, self.LABELS), [])


def _mock_smtp_client():
    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    return client


class MainIntegrationTests(unittest.TestCase):
    """Exercises fortios_watch.py's real main() wiring, not just fortios_notify's primitives in
    isolation -- the CVE-resurrection bug earlier this session shipped specifically because an
    isolated unit test passed while the real commit sequence didn't; the same discipline applies
    here for email notifications.
    """

    ENV = {
        "FORTIOS_EMAIL_ENABLED": "true",
        "FORTIOS_SMTP_HOST": "smtp.example.com",
        "FORTIOS_SMTP_FROM": "fortios@example.com",
        "FORTIOS_SMTP_TO": "alice@example.com",
    }

    def test_no_email_during_cve_backfill(self):
        """--cve-backfill imports potentially hundreds of historical CVEs at once -- none of
        that may ever generate a notification, since it's not real-time news."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            base_path = tmp / "state.json"
            fw.write_json(base_path, fw.normalize_state({}))

            original_collect = fw.collect_cve_catalog
            original_psirt_versions = fw.fetch_psirt_versions
            fw.collect_cve_catalog = lambda *a, **k: (
                {"FG-IR-26-001": [{
                    "id": "CVE-2026-00001", "advisoryId": "FG-IR-26-001", "title": "t",
                    "severity": "critical", "affected": [], "publishedAt": "2020-01-01", "updatedAt": "2020-01-01",
                }]},
                [],
            )
            fw.fetch_psirt_versions = lambda *a, **k: set()  # never hit the real PSIRT RSS feed
            client = _mock_smtp_client()
            try:
                with patch.dict(os.environ, self.ENV, clear=False), patch("smtplib.SMTP", return_value=client):
                    exit_code = fw.main([
                        "--cve-backfill",
                        "--base", str(base_path), "--output", str(base_path),
                        "--report", str(tmp / "report.md"), "--health-output", str(tmp / "health.json"),
                        "--notify-history-output", str(tmp / "notify-history.json"),
                        "--official-paths-csv", str(tmp / "no-official-paths.csv"),
                        "--advisories-csv", str(tmp / "no-advisories.csv"),
                        "--upgrade-exports", str(tmp / "no-upgrade-exports"),
                    ])
            finally:
                fw.collect_cve_catalog = original_collect
                fw.fetch_psirt_versions = original_psirt_versions

            self.assertEqual(exit_code, 0)
            self.assertFalse(client.send_message.called, "a --cve-backfill run must never send an email")

    def test_test_email_mode_never_touches_catalog_health_or_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            base_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            original_catalog = fw.normalize_state({"advisories": [{"id": "adv-A", "title": "A", "product": "fortigate-fortios", "severity": "high"}]})
            fw.write_json(base_path, original_catalog)

            client = _mock_smtp_client()
            with patch.dict(os.environ, self.ENV, clear=False), patch("smtplib.SMTP", return_value=client):
                exit_code = fw.main([
                    "--test-email",
                    "--base", str(base_path), "--output", str(base_path),
                    "--health-output", str(health_path), "--notify-history-output", str(history_path),
                ])

            self.assertEqual(exit_code, 0)
            self.assertTrue(client.send_message.called)
            sent = client.send_message.call_args[0][0]
            self.assertIn("test", sent["Subject"].lower())

            # The catalog must be byte-for-byte untouched, and no health/history file created.
            self.assertEqual(fw.read_json(base_path, None), original_catalog)
            self.assertFalse(health_path.exists(), "--test-email must never run a collection")
            self.assertFalse(history_path.exists(), "--test-email must never touch dedup history")

    def test_smtp_failure_queues_the_event_and_a_later_run_retries_it_successfully(self):
        """The literal bug this whole outbox exists to fix: a new critical CVE is detected, SMTP
        is down that day, and the notification must NOT be lost -- a later run (even with no new
        catalog changes at all) must still pick it up from the outbox and send it.
        """
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            base_path = tmp / "state.json"
            health_path = tmp / "health.json"
            history_path = tmp / "notify-history.json"
            fw.write_json(base_path, fw.normalize_state({}))

            fake_cve = {
                "id": "CVE-2026-00099", "advisoryId": "FG-IR-26-099", "title": "t",
                "severity": "critical", "affected": [], "publishedAt": "2026-07-17", "updatedAt": "2026-07-17",
            }
            original_collect = fw.collect_cve_catalog
            original_psirt_versions = fw.fetch_psirt_versions
            fw.collect_cve_catalog = lambda *a, **k: ({"FG-IR-26-099": [fake_cve]}, [])
            fw.fetch_psirt_versions = lambda *a, **k: set()  # never hit the real PSIRT RSS feed
            try:
                # Run 1: SMTP is down.
                with patch.dict(os.environ, self.ENV, clear=False), patch("smtplib.SMTP", side_effect=ConnectionRefusedError("refused")):
                    exit_code_1 = fw.main([
                        "--cve-catalog",
                        "--base", str(base_path), "--output", str(base_path),
                        "--report", str(tmp / "report.md"), "--health-output", str(health_path),
                        "--notify-history-output", str(history_path),
                        # Point every other input at paths that don't exist inside this isolated
                        # tmp dir -- the real repo's data/official-path-requests.csv would
                        # otherwise get picked up by its own default path and trigger a real
                        # network call to Fortinet, which this test must never depend on.
                        "--official-paths-csv", str(tmp / "no-official-paths.csv"),
                        "--advisories-csv", str(tmp / "no-advisories.csv"),
                        "--upgrade-exports", str(tmp / "no-upgrade-exports"),
                    ])
                self.assertEqual(exit_code_1, 0, "a notification failure must never fail the run")
                state_after_run_1 = notify.load_notify_state(history_path)
                self.assertEqual(len(state_after_run_1["outbox"]), 1, "the event must be queued, not lost")
                self.assertNotIn("new-cve|psirt|CVE-2026-00099|critical", state_after_run_1["sentKeys"])

                # Run 2: nothing new in the catalog (the CVE is already known), but SMTP is back up.
                client = _mock_smtp_client()
                with patch.dict(os.environ, self.ENV, clear=False), patch("smtplib.SMTP", return_value=client):
                    exit_code_2 = fw.main([
                        "--cve-catalog",
                        "--base", str(base_path), "--output", str(base_path),
                        "--report", str(tmp / "report.md"), "--health-output", str(health_path),
                        "--notify-history-output", str(history_path),
                        # Point every other input at paths that don't exist inside this isolated
                        # tmp dir -- the real repo's data/official-path-requests.csv would
                        # otherwise get picked up by its own default path and trigger a real
                        # network call to Fortinet, which this test must never depend on.
                        "--official-paths-csv", str(tmp / "no-official-paths.csv"),
                        "--advisories-csv", str(tmp / "no-advisories.csv"),
                        "--upgrade-exports", str(tmp / "no-upgrade-exports"),
                    ])
            finally:
                fw.collect_cve_catalog = original_collect
                fw.fetch_psirt_versions = original_psirt_versions

            self.assertEqual(exit_code_2, 0)
            self.assertTrue(client.send_message.called, "the retried event must actually be sent this time")
            sent_body = client.send_message.call_args[0][0].get_content()
            self.assertIn("CVE-2026-00099", sent_body)

            state_after_run_2 = notify.load_notify_state(history_path)
            self.assertEqual(state_after_run_2["outbox"], [], "sent event must be cleared from the outbox")
            self.assertIn("new-cve|psirt|CVE-2026-00099|critical", state_after_run_2["sentKeys"])


if __name__ == "__main__":
    unittest.main()
