"""Email notifications for FortiOS Upgrade Intelligence — stdlib only (smtplib,
email.message.EmailMessage), disabled by default, activated purely by environment variables.

Design in one paragraph: main() derives a list of NotificationEvents by diffing this run's
before/after state (never by re-scanning the whole catalog, which is what keeps a first-time
activation or a --cve-backfill from spamming years of history). Events are deduplicated against
a small persistent history file keyed by a stable string, then whatever's left gets folded into
a single synthetic email per run (never one email per event) and sent over SMTP. Any failure
anywhere in this module — bad config, network, auth, whatever — is caught and logged without a
traceback or a leaked password, and never propagates to the caller: a broken mailbox must never
break the actual data collection.
"""

from __future__ import annotations

import os
import smtplib
import ssl
import sys
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fortios_watch import (  # noqa: E402
    DEFAULT_NOTIFY_HISTORY_PATH,
    cross_process_lock,
    read_json,
    sanitize_health_error,
    utc_now,
    write_json,
)

CATEGORY_CRITICAL = "CRITICAL"
CATEGORY_DAILY = "DAILY"
CATEGORY_OPERATIONS = "OPERATIONS"

NOTIFY_HISTORY_RETENTION_DAYS = 180
MAX_EVENTS_PER_SECTION = 20
CONSECUTIVE_FAILURE_NOTIFY_THRESHOLD = 2

# Short, stable names for dedup keys (type|source|resource_id|new_value) — independent of our
# internal product ids so the key format stays human-readable and matches the spec's examples.
PRODUCT_SHORT_NAMES = {
    "fortigate-fortios": "fortios",
    "fortianalyzer": "fortianalyzer",
    "fortimanager": "fortimanager",
}
# Only these three ever generate "new version" notifications — FortiClient/EMS churn far more
# often and isn't what an engineer needs paged about.
NOTIFIABLE_VERSION_PRODUCTS = tuple(PRODUCT_SHORT_NAMES)


@dataclass
class EmailConfig:
    enabled: bool
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    smtp_from: str
    smtp_to: tuple[str, ...]
    smtp_starttls: bool
    smtp_timeout: int
    app_url: str

    def is_complete(self) -> bool:
        return bool(self.smtp_host and self.smtp_from and self.smtp_to)


@dataclass
class NotificationEvent:
    category: str
    dedup_key: str
    summary: str


def _env_bool(env: dict[str, str], key: str, default: bool) -> bool:
    value = env.get(key)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env_int(env: dict[str, str], key: str, default: int) -> int:
    value = (env.get(key) or "").strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def load_email_config(env: dict[str, str] | None = None) -> EmailConfig:
    env = os.environ if env is None else env
    smtp_to = tuple(addr.strip() for addr in (env.get("FORTIOS_SMTP_TO") or "").split(",") if addr.strip())
    return EmailConfig(
        enabled=_env_bool(env, "FORTIOS_EMAIL_ENABLED", False),
        smtp_host=(env.get("FORTIOS_SMTP_HOST") or "").strip(),
        smtp_port=_env_int(env, "FORTIOS_SMTP_PORT", 587),
        smtp_username=(env.get("FORTIOS_SMTP_USERNAME") or "").strip(),
        smtp_password=env.get("FORTIOS_SMTP_PASSWORD") or "",
        smtp_from=(env.get("FORTIOS_SMTP_FROM") or "").strip(),
        smtp_to=smtp_to,
        smtp_starttls=_env_bool(env, "FORTIOS_SMTP_STARTTLS", True),
        smtp_timeout=_env_int(env, "FORTIOS_SMTP_TIMEOUT", 10),
        app_url=(env.get("FORTIOS_APP_URL") or "https://valdev.me:3001/app/").strip(),
    )


# --- Deduplication history ----------------------------------------------------------------

def load_notify_history(path: Path) -> dict[str, str]:
    return read_json(path, {}).get("sentKeys", {})


def prune_notify_history(history: dict[str, str], *, now: str | None = None) -> dict[str, str]:
    import datetime as dt

    now_dt = dt.datetime.fromisoformat((now or utc_now()).replace("Z", "+00:00"))
    cutoff = now_dt - dt.timedelta(days=NOTIFY_HISTORY_RETENTION_DAYS)
    pruned: dict[str, str] = {}
    for key, sent_at in history.items():
        try:
            sent_dt = dt.datetime.fromisoformat(sent_at.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue
        if sent_dt >= cutoff:
            pruned[key] = sent_at
    return pruned


def filter_new_events(events: list[NotificationEvent], history: dict[str, str]) -> list[NotificationEvent]:
    """Only events whose dedup_key hasn't already been sent -- this is also what makes a first
    activation or a --cve-backfill safe: those never produce events in the first place (see
    derive_*_events() below, which only ever diffs this run's before/after), but this is the
    second line of defense against ever re-sending the same thing twice.
    """
    return [event for event in events if event.dedup_key not in history]


def record_sent_events(path: Path, events: list[NotificationEvent]) -> None:
    if not events:
        return
    now = utc_now()
    with cross_process_lock(path):
        data = read_json(path, {})
        history = data.get("sentKeys", {})
        for event in events:
            history[event.dedup_key] = now
        data["sentKeys"] = prune_notify_history(history, now=now)
        write_json(path, data)


# --- Event derivation ---------------------------------------------------------------------

def derive_version_events(
    before_versions_by_product: dict[str, set[str]],
    after_versions_by_product: dict[str, set[str]],
    product_labels: dict[str, str],
) -> list[NotificationEvent]:
    events = []
    for product_id in NOTIFIABLE_VERSION_PRODUCTS:
        short_name = PRODUCT_SHORT_NAMES[product_id]
        new_versions = sorted(
            after_versions_by_product.get(product_id, set()) - before_versions_by_product.get(product_id, set())
        )
        label = product_labels.get(product_id, product_id)
        for version in new_versions:
            events.append(NotificationEvent(
                category=CATEGORY_DAILY,
                dedup_key=f"new-version|{short_name}|{short_name}|{version}",
                summary=f"Nouvelle version {label} {version}",
            ))
    return events


def _cve_product_summary(cve: dict[str, Any]) -> str:
    parts = []
    for affected in cve.get("affected", []) or []:
        product = affected.get("product", "?")
        branch = affected.get("branch", "")
        from_v, to_v = affected.get("from"), affected.get("to")
        if from_v and to_v:
            parts.append(f"{product} {from_v} à {to_v}")
        elif branch:
            parts.append(f"{product} {branch}")
        else:
            parts.append(product)
    return ", ".join(parts) or "produit non précisé"


def derive_new_cve_events(newly_added_cves: list[dict[str, Any]]) -> list[NotificationEvent]:
    events = []
    for cve in newly_added_cves:
        severity = (cve.get("severity") or "unknown").lower()
        category = CATEGORY_CRITICAL if severity == "critical" else CATEGORY_DAILY
        events.append(NotificationEvent(
            category=category,
            dedup_key=f"new-cve|psirt|{cve['id']}|{severity}",
            summary=f"{cve['id']} — {_cve_product_summary(cve)} ({severity})",
        ))
    return events


def derive_cve_modification_events(
    cves_before_by_id: dict[str, dict[str, Any]],
    cves_after_by_id: dict[str, dict[str, Any]],
) -> list[NotificationEvent]:
    events = []
    for cve_id, after in cves_after_by_id.items():
        before = cves_before_by_id.get(cve_id)
        if before is None or before == after:
            continue  # brand new (handled by derive_new_cve_events) or genuinely unchanged
        before_severity = (before.get("severity") or "unknown").lower()
        after_severity = (after.get("severity") or "unknown").lower()
        if before_severity == after_severity:
            continue  # some other field changed (CVSS refinement, affected range) -- not
            # significant enough on its own to page anyone; severity crossing a boundary is.
        category = CATEGORY_CRITICAL if after_severity == "critical" else CATEGORY_DAILY
        events.append(NotificationEvent(
            category=category,
            dedup_key=f"cve-modified|psirt|{cve_id}|{before_severity}->{after_severity}",
            summary=f"{cve_id} : sévérité {before_severity} → {after_severity} ({_cve_product_summary(after)})",
        ))
    return events


def derive_eol_events(
    before_lifecycle: dict[str, dict[str, Any]],
    after_lifecycle: dict[str, dict[str, Any]],
    *, now: str | None = None,
) -> list[NotificationEvent]:
    import datetime as dt

    now_date = dt.datetime.fromisoformat((now or utc_now()).replace("Z", "+00:00")).date()
    events = []
    for branch, after in after_lifecycle.items():
        support_date = after.get("support")
        if not support_date:
            continue
        try:
            support_dt = dt.date.fromisoformat(support_date)
        except ValueError:
            continue
        before = before_lifecycle.get(branch) or {}
        before_support_date = before.get("support")
        was_already_eol = False
        if before_support_date:
            try:
                was_already_eol = dt.date.fromisoformat(before_support_date) < now_date
            except ValueError:
                was_already_eol = False
        is_eol_now = support_dt < now_date
        if is_eol_now and not was_already_eol:
            events.append(NotificationEvent(
                category=CATEGORY_DAILY,
                dedup_key=f"support-eol|fortios|{branch}|{support_date}",
                summary=f"FortiOS {branch} est passé en fin de support (depuis le {support_date})",
            ))
    return events


def derive_source_health_events(
    health_before: dict[str, dict[str, Any]],
    health_after: dict[str, dict[str, Any]],
    source_labels: dict[str, str],
) -> list[NotificationEvent]:
    events = []
    for source_id, after in health_after.items():
        if source_id == "daily-run":
            continue  # the aggregate summary, not a real source of its own
        before = health_before.get(source_id) or {}
        before_failures = before.get("consecutiveFailures") or 0
        after_failures = after.get("consecutiveFailures") or 0
        label = source_labels.get(source_id, source_id)

        if after_failures >= CONSECUTIVE_FAILURE_NOTIFY_THRESHOLD and before_failures < CONSECUTIVE_FAILURE_NOTIFY_THRESHOLD:
            events.append(NotificationEvent(
                category=CATEGORY_OPERATIONS,
                dedup_key=f"source-failure|{source_id}|consecutive|{after_failures}",
                summary=f"Collecte {label} en échec depuis {after_failures} exécutions consécutives",
            ))
        elif before_failures >= CONSECUTIVE_FAILURE_NOTIFY_THRESHOLD and after_failures == 0 and after.get("lastSuccessAt"):
            success_date = after["lastSuccessAt"][:10]
            events.append(NotificationEvent(
                category=CATEGORY_OPERATIONS,
                dedup_key=f"source-recovered|{source_id}|lastSuccessAt|{success_date}",
                summary=f"Collecte {label} de nouveau opérationnelle (après {before_failures} échecs)",
            ))
    return events


# --- Email composition and sending ---------------------------------------------------------

def _format_event_lines(events: list[NotificationEvent]) -> list[str]:
    shown = events[:MAX_EVENTS_PER_SECTION]
    lines = [f"- {event.summary}" for event in shown]
    remaining = len(events) - len(shown)
    if remaining > 0:
        lines.append(f"... et {remaining} de plus (liste tronquée).")
    return lines


def compose_email(
    events: list[NotificationEvent], *, app_url: str, run_timestamp: str
) -> tuple[str, str] | None:
    """Folds every event from a single run into one synthetic email (never one email per
    event, to avoid spamming) -- returns None if there's nothing to report.
    """
    if not events:
        return None

    critical = [event for event in events if event.category == CATEGORY_CRITICAL]
    daily = [event for event in events if event.category == CATEGORY_DAILY]
    operations = [event for event in events if event.category == CATEGORY_OPERATIONS]

    if critical:
        subject = f"[FortiOS Upgrade Intelligence] {len(critical)} nouvelle(s) CVE critique(s)"
    elif operations:
        subject = f"[FortiOS Upgrade Intelligence] {len(operations)} evenement(s) operationnel(s)"
    else:
        subject = f"[FortiOS Upgrade Intelligence] Resume quotidien ({len(daily)} changement(s))"

    lines: list[str] = []
    if critical:
        plural = "s" if len(critical) > 1 else ""
        verb = "ont" if len(critical) > 1 else "a"
        lines.append(f"{len(critical)} nouvelle{plural} CVE critique{plural} {verb} été détectée{plural}.")
        lines.append("")
        lines.extend(_format_event_lines(critical))
        lines.append("")

    other = daily + operations
    if other:
        lines.append("Autres événements :" if critical else "Événements détectés :")
        lines.extend(_format_event_lines(other))
        lines.append("")

    lines.append(f"Application : {app_url}")
    lines.append(f"Collecte : {run_timestamp}")
    return subject, "\n".join(lines)


def send_email(config: EmailConfig, subject: str, text_body: str) -> bool:
    """Never raises -- every failure mode (bad config, DNS, connection refused, STARTTLS,
    auth, timeout) is caught, logged without the password, and reported as a plain False so a
    broken mailbox can never break the actual data collection.
    """
    if not config.enabled:
        return False
    if not config.is_complete():
        sys.stderr.write("Notification email ignorée : configuration SMTP incomplète (host/from/to).\n")
        return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = config.smtp_from
    message["To"] = ", ".join(config.smtp_to)
    message.set_content(text_body)

    try:
        with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=config.smtp_timeout) as client:
            if config.smtp_starttls:
                client.starttls(context=ssl.create_default_context())
            if config.smtp_username:
                client.login(config.smtp_username, config.smtp_password)
            client.send_message(message)
        return True
    except (smtplib.SMTPException, OSError, TimeoutError) as error:
        sys.stderr.write(f"Échec de l'envoi de l'email de notification : {sanitize_health_error(error)}\n")
        return False


def send_test_email(config: EmailConfig) -> bool:
    if not config.enabled:
        print("FORTIOS_EMAIL_ENABLED=false : activez-le dans /etc/fortios-upgrade-intelligence.env avant de tester.", file=sys.stderr)
        return False
    if not config.is_complete():
        missing = [
            name for name, value in (
                ("FORTIOS_SMTP_HOST", config.smtp_host),
                ("FORTIOS_SMTP_FROM", config.smtp_from),
                ("FORTIOS_SMTP_TO", config.smtp_to),
            ) if not value
        ]
        print(f"Configuration SMTP incomplète, variable(s) manquante(s) : {', '.join(missing)}.", file=sys.stderr)
        return False

    subject = "[FortiOS Upgrade Intelligence] Email de test"
    body = (
        "Ceci est un email de test envoyé manuellement via --test-email.\n"
        "Si vous le recevez, la configuration SMTP est fonctionnelle.\n\n"
        f"Application : {config.app_url}\n"
    )
    sent = send_email(config, subject, body)
    if sent:
        print(f"Email de test envoyé à {', '.join(config.smtp_to)}.")
    else:
        print("Échec de l'envoi de l'email de test (voir le message d'erreur ci-dessus).", file=sys.stderr)
    return sent
