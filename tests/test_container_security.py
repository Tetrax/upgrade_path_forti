"""Container image security (Trivy): settings, baseline, derivation, routing, ingestion.

The properties asserted here are the ones that decide whether this category is trustworthy:

- it shares NOTHING with the Fortinet categories (own document, own switch, own threshold, own
  recipient list, own email) — a failure or a misconfiguration in one never reaches the other;
- a first activation is silent, and lowering the threshold never replays what is already known;
- "no report" can never be read as "no vulnerability";
- a refused report keeps the previous baseline and says why, instead of degrading silently.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fortios_notify
import trivy_report
from test_security_notifications import settings_payload

COMMIT = "05926bb47750208331d9dda00513fd399234736d"
LATER_COMMIT = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
SCAN_AT = "2026-09-16T18:55:13Z"
NEXT_SCAN_AT = "2026-09-17T02:30:00Z"


def scan_of(*findings, scan_at: str = SCAN_AT, commit: str = COMMIT):
    """A Trivy-shaped report holding exactly the requested findings.

    ``findings`` are (cve, package, severity, installed, fixed) tuples, in the real report's order.
    """
    vulnerabilities = [
        {
            "VulnerabilityID": cve,
            "PkgName": package,
            "Severity": severity,
            "InstalledVersion": installed,
            "FixedVersion": fixed,
            "Status": "fixed",
            "Title": f"{package}: advisory",
            "PrimaryURL": f"https://avd.aquasec.com/nvd/{cve.lower()}",
        }
        for (cve, package, severity, installed, fixed) in findings
    ]
    payload = {
        "SchemaVersion": 2,
        "ArtifactName": "fortios-upgrade-intelligence:ci-scan",
        "ArtifactType": "container_image",
        "CreatedAt": scan_at,
        "Results": [
            {
                "Target": "debian",
                "Class": "os-pkgs",
                "Type": "debian",
                "Vulnerabilities": vulnerabilities,
            }
        ],
    }
    return trivy_report.validate_container_report(payload, commit=commit)


PACKAGE = ("CVE-2026-13221", "perl-base", "CRITICAL", "5.40.1-6", "5.40.1-6+deb13u1")
GZIP = ("CVE-2026-41992", "gzip", "HIGH", "1.13-1", "1.13-1+deb13u1")
SQLITE = ("CVE-2026-11822", "libsqlite3-0", "HIGH", "3.46.1-7+deb13u1", "3.46.1-7+deb13u2")


def container_settings(*, enabled: bool = True, severity: str = "high", recipients=None):
    return fortios_notify.validate_container_security_settings(
        {
            "enabled": enabled,
            "minimumSeverity": severity,
            "recipients": ["devops@example.com"] if recipients is None else recipients,
        }
    )


class ContainerSettingsTests(unittest.TestCase):
    def test_a_missing_file_is_a_disabled_default_and_is_not_created(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "container-security-settings.json"
            settings, error = fortios_notify.load_container_security_settings(path)
            self.assertEqual(error, "")
            self.assertFalse(settings.enabled)
            self.assertEqual(settings.minimum_severity, "high")
            self.assertEqual(settings.recipients, ())
            self.assertFalse(path.exists(), "le fichier ne doit pas être créé par une lecture")

    def test_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "container-security-settings.json"
            fortios_notify.save_container_security_settings(
                path,
                {
                    "enabled": True,
                    "minimumSeverity": "critical",
                    "recipients": ["a@example.com", "b@example.com"],
                },
            )
            settings, error = fortios_notify.load_container_security_settings(path)
            self.assertEqual(error, "")
            self.assertTrue(settings.enabled)
            self.assertEqual(settings.minimum_severity, "critical")
            self.assertEqual(settings.recipients, ("a@example.com", "b@example.com"))

    def test_unknown_key_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            fortios_notify.validate_container_security_settings(
                {"enabled": False, "minimumSeverity": "high", "recipients": [], "extra": 1}
            )

    def test_a_severity_outside_the_two_level_domain_is_refused(self) -> None:
        """Critical/High only: the engine and the report only ever cross those two."""
        for severity in ("medium", "low", "urgent", "High", ""):
            with self.assertRaises(ValueError):
                fortios_notify.validate_container_security_settings(
                    {"enabled": False, "minimumSeverity": severity, "recipients": []}
                )

    def test_an_invalid_recipient_is_refused(self) -> None:
        with self.assertRaises((TypeError, ValueError)):
            fortios_notify.validate_container_security_settings(
                {"enabled": True, "minimumSeverity": "high", "recipients": ["pas-un-email"]}
            )

    def test_enabling_without_any_recipient_is_refused(self) -> None:
        """A green switch that sends nothing anywhere is the misconfiguration to prevent."""
        with self.assertRaises(ValueError):
            fortios_notify.validate_container_security_settings(
                {"enabled": True, "minimumSeverity": "high", "recipients": []}
            )

    def test_an_invalid_document_is_reported_and_left_byte_identical(self) -> None:
        """The historical strict validator overwrote a file it could not read.

        This one does not: a hand-edited or truncated document is reported, the feature stays
        disabled, and the operator's file is still there to be inspected.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "container-security-settings.json"
            broken = '{"enabled": true, "minimumSeverity": "urgent"}'
            path.write_text(broken, encoding="utf-8")
            settings, error = fortios_notify.load_container_security_settings(path)
            self.assertFalse(settings.enabled)
            self.assertTrue(error)
            self.assertEqual(path.read_text(encoding="utf-8"), broken)
            self.assertEqual(
                sorted(p.name for p in Path(tmp).iterdir()),
                ["container-security-settings.json"],
                "aucune archive ni fichier de sauvegarde ne doit être créé",
            )


class ContainerDerivationTests(unittest.TestCase):
    """A scan is only ever diffed against the previous one when it is genuinely newer.

    Every scan here therefore carries its own `CreatedAt`: re-ingesting the same artifact (same
    timestamp) is a no-op by design, and a test that forgets the timestamp would silently exercise
    that no-op instead of the transition it means to check.
    """

    def setUp(self) -> None:
        self.settings = container_settings()
        self.state = fortios_notify._empty_container_security_state()

    def derive(self, findings, state, *, at=SCAN_AT, settings=None, report_url=""):
        return fortios_notify.derive_container_security_events(
            scan_of(*findings, scan_at=at, commit=COMMIT if at == SCAN_AT else LATER_COMMIT),
            settings or self.settings,
            state,
            now=at,
            report_url=report_url,
        )

    def test_the_first_activation_establishes_the_baseline_silently(self) -> None:
        """Even a CRITICAL present from the start stays silent: no flood on enable."""
        events, state = self.derive([PACKAGE, GZIP], self.state)
        self.assertEqual(events, [])
        self.assertEqual(len(state["findings"]), 2)
        self.assertEqual(state["lastScanAt"], SCAN_AT)

    def test_an_identical_report_produces_nothing(self) -> None:
        _, state = self.derive([PACKAGE, GZIP], self.state)
        events, _ = self.derive([PACKAGE, GZIP], state)
        self.assertEqual(events, [])

    def test_a_new_finding_produces_exactly_one_event(self) -> None:
        _, state = self.derive([PACKAGE], self.state)
        events, _ = self.derive([PACKAGE, GZIP], state, at=NEXT_SCAN_AT)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.dedup_key, "trivy|cve|CVE-2026-41992|gzip")
        self.assertEqual(event.category, fortios_notify.CATEGORY_DAILY)
        self.assertEqual(event.severity, "high")
        self.assertEqual(event.details["kind"], "container-cve")
        self.assertEqual(event.details["package"], "gzip")
        self.assertEqual(event.details["installedVersion"], "1.13-1")
        self.assertEqual(event.details["fixedVersion"], "1.13-1+deb13u1")
        self.assertEqual(event.details["image"], "fortios-upgrade-intelligence:ci-scan")
        self.assertEqual(event.details["commit"], LATER_COMMIT)
        self.assertEqual(event.details["scannedAt"], NEXT_SCAN_AT)
        self.assertEqual(event.details["change"], "new")

    def test_a_new_critical_uses_the_critical_category(self) -> None:
        _, state = self.derive([GZIP], self.state)
        events, _ = self.derive([GZIP, PACKAGE], state, at=NEXT_SCAN_AT)
        self.assertEqual([event.category for event in events], [fortios_notify.CATEGORY_CRITICAL])

    def test_the_report_url_is_carried_for_the_email_cta(self) -> None:
        _, state = self.derive([PACKAGE], self.state)
        events, _ = self.derive(
            [PACKAGE, GZIP],
            state,
            at=NEXT_SCAN_AT,
            report_url="https://github.com/Tetrax/upgrade_path_forti/actions/runs/1",
        )
        self.assertEqual(
            events[0].details["reportUrl"],
            "https://github.com/Tetrax/upgrade_path_forti/actions/runs/1",
        )

    def test_an_escalation_notifies_with_the_transition_in_its_key(self) -> None:
        _, state = self.derive([GZIP], self.state)
        escalated = ("CVE-2026-41992", "gzip", "CRITICAL", "1.13-1", "1.13-1+deb13u1")
        events, _ = self.derive([escalated], state, at=NEXT_SCAN_AT)
        self.assertEqual(len(events), 1)
        self.assertEqual(
            events[0].dedup_key, "trivy-severity|CVE-2026-41992|gzip|high-to-critical"
        )
        self.assertEqual(events[0].category, fortios_notify.CATEGORY_CRITICAL)
        self.assertEqual(events[0].severity, "critical")

    def test_a_de_escalation_updates_the_baseline_without_notifying(self) -> None:
        _, state = self.derive([PACKAGE], self.state)
        downgraded = ("CVE-2026-13221", "perl-base", "HIGH", "5.40.1-6", "5.40.1-6+deb13u1")
        events, state = self.derive([downgraded], state, at=NEXT_SCAN_AT)
        self.assertEqual(events, [])
        self.assertEqual(state["findings"]["trivy|cve|CVE-2026-13221|perl-base"]["severity"], "high")

    def test_a_finding_below_the_threshold_is_known_but_never_notified(self) -> None:
        """Recorded in the baseline, no event — the whole point of the no-replay guarantee."""
        settings = container_settings(severity="critical")
        _, state = self.derive([GZIP], self.state, settings=settings)
        events, state = self.derive([GZIP, SQLITE], state, at=NEXT_SCAN_AT, settings=settings)
        self.assertEqual(events, [])
        self.assertIn("trivy|cve|CVE-2026-11822|libsqlite3-0", state["findings"])

    def test_lowering_the_threshold_does_not_replay_known_findings(self) -> None:
        high = container_settings(severity="critical")
        _, state = self.derive([PACKAGE, GZIP], self.state, settings=high)
        events, _ = self.derive(
            [PACKAGE, GZIP], state, at=NEXT_SCAN_AT, settings=container_settings(severity="high")
        )
        self.assertEqual(events, [], "aucun rattrapage historique lors d'une baisse de seuil")

    def test_a_returning_finding_is_reactivated_without_a_second_alert(self) -> None:
        """Deliberate: a return is NOT one of the two notified transitions.

        The operator already received this CVE+package alert, and it is still in the state; only a
        transition the operator has not seen yet is worth an email. The entry becomes active again,
        so the administration shows it as an open finding.
        """
        _, state = self.derive([PACKAGE, GZIP], self.state)
        _, state = self.derive([PACKAGE], state, at=NEXT_SCAN_AT)
        self.assertTrue(
            state["findings"]["trivy|cve|CVE-2026-41992|gzip"]["resolvedAt"],
            "un finding absent du rapport est marqué corrigé",
        )
        events, state = self.derive([PACKAGE, GZIP], state, at="2026-09-18T02:30:00Z")
        self.assertEqual(events, [])
        self.assertEqual(
            state["findings"]["trivy|cve|CVE-2026-41992|gzip"]["resolvedAt"], ""
        )

    def test_resolutions_are_counted_on_the_next_event(self) -> None:
        """A corrected vulnerability is worth a line in the email — but never an email of its own."""
        _, state = self.derive([PACKAGE, SQLITE], self.state)
        events, state = self.derive([PACKAGE, GZIP], state, at=NEXT_SCAN_AT)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].details["resolvedCount"], 1)
        self.assertEqual(
            state["findings"]["trivy|cve|CVE-2026-11822|libsqlite3-0"]["resolvedAt"], NEXT_SCAN_AT
        )

    def test_a_resolution_alone_produces_no_email(self) -> None:
        _, state = self.derive([PACKAGE, GZIP], self.state)
        events, state = self.derive([PACKAGE], state, at=NEXT_SCAN_AT)
        self.assertEqual(events, [])
        self.assertEqual(
            state["findings"]["trivy|cve|CVE-2026-41992|gzip"]["resolvedAt"], NEXT_SCAN_AT
        )

    def test_an_already_resolved_finding_is_not_counted_twice(self) -> None:
        _, state = self.derive([PACKAGE, GZIP], self.state)
        _, state = self.derive([PACKAGE], state, at=NEXT_SCAN_AT)
        _, state = self.derive([PACKAGE], state, at="2026-09-18T02:30:00Z")
        events, _ = self.derive([PACKAGE, SQLITE], state, at="2026-09-19T02:30:00Z")
        self.assertEqual([event.details["resolvedCount"] for event in events], [0])

    def test_an_older_report_changes_nothing(self) -> None:
        """A replay of an already-ingested scan must not be diffed as if it were new."""
        _, state = self.derive([PACKAGE, GZIP], self.state, at=NEXT_SCAN_AT)
        before = json.loads(json.dumps(state))
        events, after = self.derive([PACKAGE], state, at=SCAN_AT)
        self.assertEqual(events, [])
        self.assertEqual(after, before, "l'état est rendu tel quel, sans réécriture")

    def test_resolved_findings_are_pruned_after_retention(self) -> None:
        _, state = self.derive([PACKAGE, GZIP], self.state)
        _, state = self.derive([PACKAGE], state, at=NEXT_SCAN_AT)
        _, state = self.derive([PACKAGE], state, at="2027-09-19T02:30:00Z")
        self.assertNotIn("trivy|cve|CVE-2026-41992|gzip", state["findings"])
        self.assertIn("trivy|cve|CVE-2026-13221|perl-base", state["findings"])

    def test_the_produced_state_is_json_serialisable(self) -> None:
        _, state = self.derive([PACKAGE, GZIP], self.state)
        json.dumps(state)


class ContainerRoutingTests(unittest.TestCase):
    def test_the_container_category_has_its_own_recipients(self) -> None:
        events = [
            fortios_notify.NotificationEvent(
                category="daily",
                dedup_key="trivy|cve|CVE-2026-41992|gzip",
                summary="gzip",
                severity="high",
                details={"kind": "container-cve"},
            ),
            fortios_notify.NotificationEvent(
                category="daily",
                dedup_key="cve|CVE-2026-1",
                summary="CVE",
                severity="high",
                details={"kind": "cve"},
            ),
        ]
        batches = fortios_notify.notification_batches(
            events,
            fortios_notify.validate_notification_settings(settings_payload()),
            container_security=container_settings(recipients=["image@example.com"]),
        )
        self.assertEqual(len(batches), 2)
        self.assertEqual([len(batch.events) for batch in batches], [1, 1])
        self.assertEqual(batches[0].recipients, ("security@example.com",))
        self.assertEqual(batches[1].recipients, ("image@example.com",))

    def test_identical_recipient_lists_still_produce_two_emails(self) -> None:
        """Unlike CVE + releases, the container category is never folded into another email."""
        shared = "security@example.com"
        events = [
            fortios_notify.NotificationEvent(
                category="daily",
                dedup_key="trivy|cve|CVE-2026-41992|gzip",
                summary="gzip",
                severity="high",
                details={"kind": "container-cve"},
            ),
            fortios_notify.NotificationEvent(
                category="daily",
                dedup_key="cve|CVE-2026-1",
                summary="CVE",
                severity="high",
                details={"kind": "cve"},
            ),
        ]
        batches = fortios_notify.notification_batches(
            events,
            fortios_notify.validate_notification_settings(settings_payload()),
            container_security=container_settings(recipients=[shared]),
        )
        self.assertEqual(len(batches), 2)

    def test_the_historical_routing_is_untouched_without_container_events(self) -> None:
        """Regression guard: no container event means the previous partitioning, verbatim."""
        release = fortios_notify.NotificationEvent(
            category="daily", dedup_key="release|fortios|7.6.5", summary="7.6.5",
            severity="", details={"kind": "release"},
        )
        cve = fortios_notify.NotificationEvent(
            category="daily", dedup_key="cve|CVE-2026-1", summary="CVE",
            severity="high", details={"kind": "cve"},
        )
        settings = fortios_notify.validate_notification_settings(settings_payload())
        self.assertEqual(fortios_notify.notification_batches([cve], settings)[0].recipients,
                         settings.recipients)
        self.assertEqual(fortios_notify.notification_batches([release], settings)[0].recipients,
                         settings.release_recipients_effective())
        merged = fortios_notify.notification_batches([cve, release], settings)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].events, (cve, release))

    def test_an_event_without_structured_details_is_recognised_by_its_key(self) -> None:
        event = fortios_notify.NotificationEvent(
            category="daily",
            dedup_key="trivy-severity|CVE-2026-41992|gzip|high-to-critical",
            summary="gzip",
            severity="critical",
            details={},
        )
        self.assertTrue(fortios_notify._is_container_security_event(event))


class ContainerIngestionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.data = Path(self._tmp.name)
        self.report = self.data / "trivy-report.json"
        self.metadata = self.data / "trivy-report.meta.json"
        self.history = self.data / "fortios-notify-history.json"
        self.settings = container_settings()

    def publish(self, payload: dict, *, commit: str = COMMIT, sha256: str | None = None,
                raw: bytes | None = None) -> None:
        raw = raw if raw is not None else json.dumps(payload).encode("utf-8")
        self.report.write_bytes(raw)
        import hashlib

        self.metadata.write_text(
            json.dumps(
                {
                    "commit": commit,
                    "runId": "35138272412",
                    "runUrl": "https://github.com/Tetrax/upgrade_path_forti/actions/runs/35138272412",
                    "sha256": sha256 if sha256 is not None else hashlib.sha256(raw).hexdigest(),
                    "downloadedAt": SCAN_AT,
                }
            ),
            encoding="utf-8",
        )

    def ingest(self, **kwargs):
        return fortios_notify.ingest_container_security_report(
            self.report, self.metadata, kwargs.pop("settings", self.settings),
            history_path=self.history, now=kwargs.pop("now", SCAN_AT),
        )

    def report_payload_of(self, *findings, scan_at: str = SCAN_AT) -> dict:
        payload = {
            "SchemaVersion": 2,
            "ArtifactName": "fortios-upgrade-intelligence:ci-scan",
            "ArtifactType": "container_image",
            "CreatedAt": scan_at,
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
        return payload

    def test_a_valid_report_establishes_the_baseline_and_queues_nothing(self) -> None:
        self.publish(self.report_payload_of(PACKAGE, GZIP))
        events, error = self.ingest()
        self.assertEqual((events, error), ([], ""))
        state = fortios_notify.load_notify_state(self.history)
        self.assertEqual(len(state["containerSecurityState"]["findings"]), 2)
        self.assertEqual(state["containerSecurityState"]["commit"], COMMIT)
        self.assertEqual(state["outbox"], [])

    def test_a_new_finding_is_queued_in_the_outbox_atomically_with_the_baseline(self) -> None:
        self.publish(self.report_payload_of(PACKAGE))
        self.ingest()
        self.publish(self.report_payload_of(PACKAGE, GZIP, scan_at=NEXT_SCAN_AT),
                     commit=LATER_COMMIT)
        events, error = self.ingest(now=NEXT_SCAN_AT)
        self.assertEqual(error, "")
        self.assertEqual(len(events), 1)
        state = fortios_notify.load_notify_state(self.history)
        self.assertEqual(len(state["outbox"]), 1)
        self.assertEqual(state["outbox"][0]["dedupKey"], "trivy|cve|CVE-2026-41992|gzip")
        self.assertEqual(len(state["containerSecurityState"]["findings"]), 2)

    def test_a_missing_report_and_metadata_is_a_normal_state(self) -> None:
        events, error = self.ingest()
        self.assertEqual((events, error), ([], ""))
        self.assertFalse(self.history.exists(), "rien à écrire : aucun churn")

    def test_a_report_without_its_metadata_is_refused(self) -> None:
        """Provenance is not optional: the report carries no Git SHA of its own."""
        self.report.write_text(json.dumps(self.report_payload_of(PACKAGE)), encoding="utf-8")
        events, error = self.ingest()
        self.assertEqual(events, [])
        self.assertIn("Métadonnées", error)

    def test_a_corrupted_report_is_refused_by_its_checksum(self) -> None:
        self.publish(self.report_payload_of(PACKAGE), sha256="0" * 64)
        events, error = self.ingest()
        self.assertEqual(events, [])
        self.assertIn("altéré", error)

    def test_a_refused_report_keeps_the_previous_baseline_and_records_the_reason(self) -> None:
        self.publish(self.report_payload_of(PACKAGE, GZIP))
        self.ingest()
        before = fortios_notify.load_notify_state(self.history)["containerSecurityState"]
        import hashlib

        broken = b'{"SchemaVersion": 2, "ArtifactType": "container_image", "Results": "os-pkgs"}'
        self.report.write_bytes(broken)
        self.metadata.write_text(
            json.dumps(
                {
                    "commit": COMMIT,
                    "sha256": hashlib.sha256(broken).hexdigest(),
                    "downloadedAt": SCAN_AT,
                }
            ),
            encoding="utf-8",
        )
        events, error = self.ingest()
        self.assertEqual(events, [])
        self.assertTrue(error)
        after = fortios_notify.load_notify_state(self.history)["containerSecurityState"]
        self.assertEqual(after["findings"], before["findings"])
        self.assertEqual(after["lastScanAt"], before["lastScanAt"])
        self.assertIn("refusé", after["reportError"])

    def test_a_refused_report_is_never_read_as_a_clean_scan(self) -> None:
        self.publish(self.report_payload_of(PACKAGE, GZIP))
        self.ingest()
        self.report.write_bytes(b"[]")
        self.ingest()
        state = fortios_notify.load_notify_state(self.history)["containerSecurityState"]
        self.assertEqual(len(state["findings"]), 2, "aucun finding ne doit être marqué corrigé")

    def test_ingestion_is_idempotent(self) -> None:
        self.publish(self.report_payload_of(PACKAGE, GZIP))
        self.ingest()
        first = self.history.read_bytes()
        events, error = self.ingest(now="2026-09-16T23:00:00Z")
        self.assertEqual((events, error), ([], ""))
        self.assertEqual(self.history.read_bytes(), first)

    def test_the_ingestion_never_touches_the_other_categories_of_the_state(self) -> None:
        state = fortios_notify.load_notify_state(self.history)
        state["checkpoint"] = {"generatedAt": SCAN_AT}
        state["sentKeys"]["cve|CVE-2026-1"] = SCAN_AT
        fortios_notify.write_json(self.history, state)
        self.publish(self.report_payload_of(PACKAGE))
        self.ingest()
        after = fortios_notify.load_notify_state(self.history)
        self.assertEqual(after["checkpoint"], {"generatedAt": SCAN_AT})
        self.assertIn("cve|CVE-2026-1", after["sentKeys"])


class ContainerStateCompatibilityTests(unittest.TestCase):
    def test_the_empty_state_carries_the_container_section(self) -> None:
        state = fortios_notify._empty_notify_state()
        self.assertIn("containerSecurityState", state)
        self.assertEqual(state["containerSecurityState"]["findings"], {})

    def test_a_legacy_state_file_without_the_key_still_loads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            fortios_notify.write_json(
                path, {"sentKeys": {}, "outbox": [], "eolState": {}, "checkpoint": None}
            )
            state = fortios_notify.load_notify_state(path)
            self.assertEqual(state["containerSecurityState"]["findings"], {})

    def test_a_malformed_container_section_is_isolated(self) -> None:
        """It must not invalidate the checkpoint or the outbox, whose loss is unrecoverable."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            fortios_notify.write_json(
                path,
                {
                    "sentKeys": {"cve|CVE-2026-1": SCAN_AT},
                    "outbox": [],
                    "eolState": {},
                    "checkpoint": {"generatedAt": SCAN_AT},
                    "containerSecurityState": {"findings": "not-a-mapping"},
                },
            )
            state = fortios_notify.load_notify_state(path)
            self.assertEqual(state["checkpoint"], {"generatedAt": SCAN_AT})
            self.assertEqual(
                state["containerSecurityState"]["findings"], {},
                "la section est réinitialisée, le reste est préservé",
            )

    def test_committing_the_container_state_preserves_the_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            state = fortios_notify._empty_notify_state()
            state["checkpoint"] = {"generatedAt": SCAN_AT}
            fortios_notify.write_json(path, state)
            container_state = fortios_notify._empty_container_security_state()
            container_state["lastScanAt"] = SCAN_AT
            fortios_notify.commit_container_security_transition(
                path, container_state, [], now=SCAN_AT
            )
            after = fortios_notify.load_notify_state(path)
            self.assertEqual(after["checkpoint"], {"generatedAt": SCAN_AT})
            self.assertEqual(after["containerSecurityState"]["lastScanAt"], SCAN_AT)


class ContainerStatusTests(unittest.TestCase):
    def status(self, state, *, settings=None, error="", now=SCAN_AT):
        return fortios_notify.container_security_status(
            settings or container_settings(), state, error=error, now=now
        )

    def test_no_report_is_never_rendered_as_zero_vulnerabilities(self) -> None:
        report = self.status(fortios_notify._empty_container_security_state())["report"]
        self.assertEqual(report["state"], "absent")
        self.assertIsNone(report["total"])
        self.assertIsNone(report["critical"])
        self.assertIsNone(report["high"])

    def test_a_current_report_shows_its_counts(self) -> None:
        _, state = fortios_notify.derive_container_security_events(
            scan_of(PACKAGE, GZIP), container_settings(),
            fortios_notify._empty_container_security_state(), now=SCAN_AT,
        )
        report = self.status(state, now="2026-09-16T20:00:00Z")["report"]
        self.assertEqual(report["state"], "current")
        self.assertEqual((report["total"], report["critical"], report["high"]), (2, 1, 1))

    def test_an_old_report_is_reported_as_stale(self) -> None:
        _, state = fortios_notify.derive_container_security_events(
            scan_of(PACKAGE), container_settings(),
            fortios_notify._empty_container_security_state(), now=SCAN_AT,
        )
        report = self.status(state, now="2026-09-19T08:00:00Z")["report"]
        self.assertEqual(report["state"], "stale")

    def test_an_invalid_report_keeps_the_last_known_counts(self) -> None:
        _, state = fortios_notify.derive_container_security_events(
            scan_of(PACKAGE, GZIP), container_settings(),
            fortios_notify._empty_container_security_state(), now=SCAN_AT,
        )
        report = self.status(state, error="Rapport Trivy refusé : Severity hors liste.")["report"]
        self.assertEqual(report["state"], "invalid")
        self.assertEqual(report["total"], 2)
        self.assertIn("Severity", report["reason"])

    def test_the_configuration_error_is_surfaced_verbatim(self) -> None:
        payload = self.status(
            fortios_notify._empty_container_security_state(),
            error="La sévérité minimale de sécurité conteneur doit être l'une des valeurs suivantes : critical, high.",
        )
        self.assertIn("critical, high", payload["report"]["reason"])
        self.assertEqual(payload["report"]["state"], "invalid")

    def test_the_status_exposes_the_settings_the_interface_must_show(self) -> None:
        payload = self.status(fortios_notify._empty_container_security_state())
        self.assertEqual(payload["settings"]["minimumSeverity"], "high")
        self.assertEqual(payload["settings"]["recipients"], ["devops@example.com"])

    def test_resolved_findings_are_reported_separately(self) -> None:
        _, state = fortios_notify.derive_container_security_events(
            scan_of(PACKAGE, GZIP, scan_at=SCAN_AT), container_settings(),
            fortios_notify._empty_container_security_state(), now=SCAN_AT,
        )
        _, state = fortios_notify.derive_container_security_events(
            scan_of(PACKAGE, scan_at=NEXT_SCAN_AT, commit=LATER_COMMIT), container_settings(),
            state, now=NEXT_SCAN_AT,
        )
        report = self.status(state, now=NEXT_SCAN_AT)["report"]
        self.assertEqual(report["total"], 1)
        self.assertEqual(report["resolved"], 1)


if __name__ == "__main__":
    unittest.main()
