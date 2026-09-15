"""Tests for the SNS Security email redesign and the UTF-8/MIME corruption fix.

Three areas:
1. Rendering (scripts/fortios_email_render.py + compose_email): severity/product counting,
   subject grammar (singular/plural), hero title grammar, per-CVE structure.
2. Encoding guarantees: no quoted-printable soft-break artifacts (=C3, =E2, =strong, Forti=ate,
   sns=security, U+FFFD), clean French/URL/HTML round-trip, HTML escaping of external fields.
3. Transport: SMTP message uses base64 CTE (never quoted-printable) and attaches inline images by
   Content-ID; Microsoft Graph uses JSON body.content/body.contentType (never pre-encoded MIME).
"""

from __future__ import annotations

import io
import json
import sys
import unittest
from contextlib import redirect_stderr
from email import policy
from email.parser import BytesParser
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_email_render as render
import fortios_notify as notify


def _cve(cve_id, severity, cvss, products, title="Résumé non disponible", url=""):
    return {
        "id": cve_id,
        "severity": severity,
        "cvssScore": cvss,
        "title": title,
        "url": url,
        "affected": [{"product": product, "branch": branch} for product, branch in products],
    }


def _events_for(cves):
    return notify.derive_new_cve_events(cves)


class ScenarioATests(unittest.TestCase):
    """3 CVE / same product (FortiGate / FortiOS)."""

    def _events(self):
        return _events_for(
            [
                _cve("CVE-2026-00001", "critical", 9.8, [("fortigate-fortios", "7.0"), ("fortigate-fortios", "7.2")]),
                _cve("CVE-2026-00002", "high", 8.1, [("fortigate-fortios", "7.4")]),
                _cve("CVE-2026-00003", "high", 7.5, [("fortigate-fortios", "7.6")]),
            ]
        )

    def test_severity_counts(self):
        events = self._events()
        subject, text, _html = render.compose_email(
            events, app_url="https://x/app/", run_timestamp="2026-09-15T05:00:00Z", display_name="FortiUpgrade"
        )
        self.assertEqual(subject, "[FortiUpgrade] 3 nouvelles vulnérabilités — 1 Critical / 2 High")
        self.assertIn("Critical : 1", text)
        self.assertIn("High     : 2", text)
        self.assertIn("Total    : 3", text)

    def test_product_counts_single_product(self):
        events = self._events()
        _subject, text, _html = render.compose_email(
            events, app_url="https://x/app/", run_timestamp="2026-09-15T05:00:00Z", display_name="FortiUpgrade"
        )
        self.assertIn("FortiGate / FortiOS : 3", text)
        # exactly one product row
        counts = render._product_counts(events)
        self.assertEqual(counts, [("FortiGate / FortiOS", 3)])


class ScenarioBTests(unittest.TestCase):
    """Multi-product: one CVE affecting two products counts +1 for each."""

    def _events(self):
        return _events_for(
            [
                _cve(
                    "CVE-2026-00001", "critical", 9.8,
                    [("fortigate-fortios", "7.0"), ("fortimanager", "7.4")],
                ),
                _cve("CVE-2026-00002", "high", 8.1, [("forticlient", "windows")]),
                _cve(
                    "CVE-2026-00003", "high", 7.5,
                    [("fortianalyzer", "7.2"), ("fortigate-fortios", "7.6")],
                ),
            ]
        )

    def test_product_counts_multi_product(self):
        events = _events_for(
            [
                _cve(
                    "CVE-2026-00001", "critical", 9.8,
                    [("fortigate-fortios", "7.0"), ("fortimanager", "7.4")],
                ),
                {
                    "id": "CVE-2026-00002", "severity": "high", "cvssScore": 8.1,
                    "title": "High FortiClient", "url": "",
                    "affected": [{"product": "forticlient", "models": ["windows"], "branch": "7.4"}],
                },
                _cve(
                    "CVE-2026-00003", "high", 7.5,
                    [("fortianalyzer", "7.2"), ("fortigate-fortios", "7.6")],
                ),
            ]
        )
        counts = render._product_counts(events)
        expected = [
            ("FortiGate / FortiOS", 2),
            ("FortiManager", 1),
            ("FortiClient Windows", 1),
            ("FortiAnalyzer", 1),
        ]
        self.assertEqual(counts, expected)

    def test_severity_counts(self):
        events = self._events()
        _subject, text, _html = render.compose_email(
            events, app_url="https://x/app/", run_timestamp="2026-09-15T05:00:00Z", display_name="FortiUpgrade"
        )
        self.assertIn("Critical : 1", text)
        self.assertIn("High     : 2", text)
        self.assertIn("Total    : 3", text)


class ScenarioCTests(unittest.TestCase):
    """A single Critical CVE: grammar must be singular."""

    def _events(self):
        return _events_for(
            [_cve("CVE-2026-00001", "critical", 9.8, [("fortigate-fortios", "7.0"), ("fortigate-fortios", "7.2")])]
        )

    def test_subject_singular(self):
        events = self._events()
        subject, _text, _html = render.compose_email(
            events, app_url="https://x/app/", run_timestamp="2026-09-15T05:00:00Z", display_name="FortiUpgrade"
        )
        self.assertEqual(subject, "[FortiUpgrade] 1 nouvelle vulnérabilité Critical — FortiGate / FortiOS")

    def test_hero_title_singular(self):
        events = self._events()
        _subject, text, _html = render.compose_email(
            events, app_url="https://x/app/", run_timestamp="2026-09-15T05:00:00Z", display_name="FortiUpgrade"
        )
        self.assertIn("1 nouvelle vulnérabilité détectée", text)
        self.assertNotIn("1 nouvelles vulnérabilités détectées", text)
        self.assertNotIn("détectées", text)


class SubjectGrammarTests(unittest.TestCase):
    def test_single_high_has_no_critical_segment(self):
        events = _events_for([_cve("CVE-2026-00002", "high", 8.1, [("fortigate-fortios", "7.4")])])
        subject, _, _ = render.compose_email(
            events, app_url="https://x/app/", run_timestamp="2026-09-15T05:00:00Z", display_name="FortiUpgrade"
        )
        self.assertEqual(subject, "[FortiUpgrade] 1 nouvelle vulnérabilité — 1 High")

    def test_two_high_no_critical(self):
        events = _events_for(
            [
                _cve("CVE-2026-00002", "high", 8.1, [("fortigate-fortios", "7.4")]),
                _cve("CVE-2026-00003", "high", 7.5, [("fortigate-fortios", "7.6")]),
            ]
        )
        subject, _, _ = render.compose_email(
            events, app_url="https://x/app/", run_timestamp="2026-09-15T05:00:00Z", display_name="FortiUpgrade"
        )
        self.assertEqual(subject, "[FortiUpgrade] 2 nouvelles vulnérabilités — 2 High")

    def test_two_critical_plural(self):
        events = _events_for(
            [
                _cve("CVE-2026-00001", "critical", 9.8, [("fortigate-fortios", "7.0")]),
                _cve("CVE-2026-00004", "critical", 9.1, [("fortimanager", "7.4")]),
            ]
        )
        subject, _, _ = render.compose_email(
            events, app_url="https://x/app/", run_timestamp="2026-09-15T05:00:00Z", display_name="FortiUpgrade"
        )
        self.assertEqual(subject, "[FortiUpgrade] 2 nouvelles vulnérabilités — 2 Critical")


class EncodingTests(unittest.TestCase):
    """Quoted-printable / double-encoding regression guards."""

    FRENCH = "é è ê ë à â ù û ç É À Ç — – ' ’ / & = : () []"

    def _events_with_french(self):
        return _events_for(
            [
                _cve(
                    "CVE-2026-00001", "critical", 9.8,
                    [("fortigate-fortios", "7.0")],
                    title="Résumé de la vulnérabilité : é è ê à ç — traitement 'défensif'",
                    url="https://www.fortiguard.com/psirt/CVE-2026-00001?x=1&y=2&a=b",
                )
            ]
        )

    def test_rendered_text_has_no_quoted_printable_artifacts(self):
        events = self._events_with_french()
        subject, text, html = render.compose_email(
            events, app_url="https://fortiupgrade.sns-security.lan/app/",
            run_timestamp="2026-09-15T05:00:00Z", display_name="FortiUpgrade",
        )
        for artifact in ("=C3", "=E2", "=strong", "Forti=ate", "sns=security", "=trong>", "=iUpgrade"):
            self.assertNotIn(artifact, subject)
            self.assertNotIn(artifact, text)
            self.assertNotIn(artifact, html)
        self.assertNotIn("\ufffd", text)
        self.assertNotIn("\ufffd", html)

    def test_french_accents_are_preserved_in_rendered_output(self):
        events = self._events_with_french()
        _subject, text, html = render.compose_email(
            events, app_url="https://x/app/", run_timestamp="2026-09-15T05:00:00Z", display_name="FortiUpgrade"
        )
        self.assertIn("é", text)
        self.assertIn("Résumé de la vulnérabilité", text)
        self.assertIn("é", html)

    def test_url_query_string_with_equals_is_not_corrupted(self):
        events = self._events_with_french()
        _subject, _text, html = render.compose_email(
            events, app_url="https://x/app/", run_timestamp="2026-09-15T05:00:00Z", display_name="FortiUpgrade"
        )
        # The literal '=' in the URL survives in the HTML (as &amp; for the query separator,
        # but the '=' itself must remain '=').
        self.assertIn("CVE-2026-00001?x=1", html)

    def test_html_escaping_of_external_title(self):
        events = _events_for(
            [
                _cve(
                    "CVE-2026-00001", "critical", 9.8, [("fortigate-fortios", "7.0")],
                    title="<script>alert('xss')</script><img src=x onerror=alert(1)>",
                )
            ]
        )
        _subject, _text, html = render.compose_email(
            events, app_url="https://x/app/", run_timestamp="2026-09-15T05:00:00Z", display_name="FortiUpgrade"
        )
        self.assertNotIn("<script>", html)
        self.assertNotIn("<script", html)
        # The injected <img src=x onerror=...> must be escaped, not emitted as a live tag.
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("&lt;img", html)


class TransportEncodingTests(unittest.TestCase):
    """The actual wire format: base64 CTE for SMTP, JSON body.content for Graph."""

    def _config(self):
        return notify.EmailConfig(
            enabled=True,
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_username="",
            smtp_password="",
            smtp_from="fortios@example.com",
            smtp_to=("alice@example.com",),
            smtp_starttls=True,
            smtp_timeout=10,
            app_url="https://x/app/",
        )

    def _events(self):
        return _events_for(
            [_cve("CVE-2026-00001", "critical", 9.8, [("fortigate-fortios", "7.0")],
                  title="Résumé accentué é è à ç")]
        )

    def test_smtp_message_uses_base64_not_quoted_printable(self):
        events = self._events()
        subject, text_body, html_body = notify.compose_email(
            events, app_url="https://x/app/", run_timestamp="2026-09-15T05:00:00Z"
        )
        message = notify._build_smtp_message(self._config(), subject, text_body, html_body)
        raw = message.as_bytes()
        raw_text = raw.decode("ascii", errors="replace")
        self.assertNotIn("quoted-printable", raw_text)
        self.assertIn("Content-Transfer-Encoding: base64", raw_text)
        # Round-trip through a MIME parser: the plain and html bodies decode back to clean UTF-8.
        parsed = BytesParser(policy=policy.default).parsebytes(raw)
        plain = parsed.get_body(preferencelist=("plain",)).get_content()
        html_ = parsed.get_body(preferencelist=("html",)).get_content()
        self.assertIn("Résumé accentué", plain)
        self.assertIn("Résumé accentué", html_)
        self.assertNotIn("=C3", plain)
        self.assertNotIn("\ufffd", plain)

    def test_smtp_message_attaches_inline_images_by_cid(self):
        events = self._events()
        subject, text_body, html_body = notify.compose_email(
            events, app_url="https://x/app/", run_timestamp="2026-09-15T05:00:00Z"
        )
        message = notify._build_smtp_message(self._config(), subject, text_body, html_body)
        raw = message.as_bytes()
        raw_text = raw.decode("ascii", errors="replace")
        # Content-ID headers are present for both inline images.
        self.assertIn("Content-ID: sns-logo", raw_text)
        self.assertIn("Content-ID: sns-panther", raw_text)
        # The HTML body (base64-encoded in the wire message) references both by cid.
        parsed = BytesParser(policy=policy.default).parsebytes(raw)
        html_ = parsed.get_body(preferencelist=("html",)).get_content()
        self.assertIn("cid:sns-logo", html_)
        self.assertIn("cid:sns-panther", html_)


class GraphTransportEncodingTests(unittest.TestCase):
    """Graph JSON body uses body.content/body.contentType, never MIME base64."""

    def _config(self):
        return notify.EmailConfig(
            enabled=True,
            smtp_host="",
            smtp_port=587,
            smtp_username="",
            smtp_password="",
            smtp_from="",
            smtp_to=("alerts@example.test",),
            smtp_starttls=True,
            smtp_timeout=10,
            app_url="https://x/app/",
            transport="microsoft365",
            graph_tenant_id="tenant.example.test",
            graph_client_id="11111111-2222-3333-4444-555555555555",
            graph_client_secret="secret-value",
            graph_sender="fortiupgrade@example.test",
            graph_display_name="FortiUpgrade Notifications",
            graph_mailbox_identity="fortiupgrade@example.test",
        )

    def test_graph_payload_is_json_body_content(self):
        events = _events_for(
            [_cve("CVE-2026-00001", "critical", 9.8, [("fortigate-fortios", "7.0")],
                  title="Résumé é")]
        )
        subject, text_body, html_body = notify.compose_email(
            events, app_url="https://x/app/", run_timestamp="2026-09-15T05:00:00Z"
        )

        class FakeResponse:
            def __init__(self, status, body=b""):
                self._status = status
                self._body = body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return None

            def read(self, _n=-1):
                return self._body

            def getcode(self):
                return self._status

        captured = {}

        def fake_urlopen(request, timeout=0):
            if "oauth2" in request.full_url:
                captured["token_url"] = request.full_url
                return FakeResponse(200, b'{"access_token":"access-token"}')
            captured["graph"] = request
            return FakeResponse(202)

        logs = io.StringIO()
        with redirect_stderr(logs), patch.object(notify, "_graph_urlopen", side_effect=fake_urlopen):
            result = notify.send_email_result(self._config(), subject, text_body, html_body)

        self.assertTrue(result.sent)
        graph_request = captured["graph"]
        self.assertEqual(graph_request.get_header("Content-type"), "application/json")
        payload = json.loads(graph_request.data.decode("utf-8"))
        message = payload["message"]
        self.assertEqual(message["body"]["contentType"], "HTML")
        self.assertIn("Résumé é", message["body"]["content"])
        self.assertNotIn("=C3", message["body"]["content"])
        # Inline images carried as Graph file attachments, referenced by cid in the HTML.
        self.assertIn("cid:sns-logo", message["body"]["content"])
        content_ids = {a["contentId"] for a in message.get("attachments", [])}
        self.assertIn("sns-logo", content_ids)
        self.assertIn("sns-panther", content_ids)


if __name__ == "__main__":
    unittest.main()
