"""Email notifications for FortiOS Upgrade Intelligence — stdlib only (smtplib,
email.message.EmailMessage), disabled by default, with functional settings persisted in data/ and
SMTP infrastructure supplied by environment variables plus a mounted password file.

Design in one paragraph: main() derives a list of NotificationEvents by diffing the durable
pre-collection checkpoint against the collected state (never by re-scanning the whole catalog, which is what keeps a first-time
activation or a --cve-backfill from spamming years of history). Events are deduplicated against
a small persistent history file keyed by a stable string, then whatever's left gets folded into
a single synthetic email per run (never one email per event) and sent over SMTP. Any failure
anywhere in this module — bad config, network, auth, whatever — is caught and logged without a
traceback or a leaked password, and never propagates to the caller: a broken mailbox must never
break the actual data collection.
"""

from __future__ import annotations

import datetime as dt
import html
import json
import os
import re
import smtplib
import ssl
import sys
from collections import Counter
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fortios_watch import (
    cross_process_lock,
    parse_health_timestamp,
    read_json_tolerant,
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
# How long a claimed-but-unfinished outbox entry stays "reserved" before a later run is allowed
# to retry it -- long enough to cover the slowest realistic SMTP timeout many times over, short
# enough that a genuinely crashed run's claim doesn't block retries for hours.
CLAIM_STALE_SECONDS = 600

_EMAIL_ADDRESS_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

DEFAULT_NOTIFICATION_SETTINGS_PATH = Path("data/notification-settings.json")
_SETTINGS_PRODUCT_KEYS = (
    "fortigate-fortios",
    "fortimanager",
    "fortianalyzer",
    "forticlient-ems",
)
_FORTICLIENT_PLATFORM_KEYS = ("windows", "macos", "linux")
_MONITORED_SEVERITIES = frozenset({"high", "critical"})
_SEVERITY_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
PRODUCT_DISPLAY_LABELS = {
    "fortigate-fortios": "FortiGate / FortiOS",
    "fortimanager": "FortiManager",
    "fortianalyzer": "FortiAnalyzer",
    "forticlient-ems": "FortiClient EMS",
    "forticlient:windows": "FortiClient Windows",
    "forticlient:macos": "FortiClient macOS",
    "forticlient:linux": "FortiClient Linux",
}


def _default_notification_settings_payload() -> dict[str, Any]:
    return {
        "enabled": False,
        "minimumSeverity": "high",
        "products": {
            **{key: True for key in _SETTINGS_PRODUCT_KEYS},
            "forticlient": {key: True for key in _FORTICLIENT_PLATFORM_KEYS},
        },
        "recipients": [],
    }


@dataclass(frozen=True)
class NotificationSettings:
    enabled: bool
    minimum_severity: str
    products: dict[str, Any]
    recipients: tuple[str, ...]

    def to_payload(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "minimumSeverity": self.minimum_severity,
            "products": {
                **{key: self.products[key] for key in _SETTINGS_PRODUCT_KEYS},
                "forticlient": dict(self.products["forticlient"]),
            },
            "recipients": list(self.recipients),
        }

    def selected_product_keys(self) -> dict[str, bool]:
        selected = {key: bool(self.products[key]) for key in _SETTINGS_PRODUCT_KEYS}
        selected.update(
            {
                f"forticlient-{platform}": bool(
                    self.products["forticlient"][platform]
                )
                for platform in _FORTICLIENT_PLATFORM_KEYS
            }
        )
        return selected


def validate_notification_settings(payload: Any) -> NotificationSettings:
    if not isinstance(payload, dict) or set(payload) != {
        "enabled",
        "minimumSeverity",
        "products",
        "recipients",
    }:
        raise ValueError("Configuration de notifications invalide.")
    if not isinstance(payload["enabled"], bool):
        raise TypeError("Le champ enabled doit être un booléen.")
    if payload["minimumSeverity"] != "high":
        raise ValueError("La sévérité minimale doit être high.")

    products = payload["products"]
    expected_product_keys = {*_SETTINGS_PRODUCT_KEYS, "forticlient"}
    if not isinstance(products, dict) or set(products) != expected_product_keys:
        raise ValueError("Liste de produits surveillés invalide.")
    if any(not isinstance(products[key], bool) for key in _SETTINGS_PRODUCT_KEYS):
        raise ValueError("Chaque produit surveillé doit être un booléen.")
    forticlient = products["forticlient"]
    if not isinstance(forticlient, dict) or set(forticlient) != set(
        _FORTICLIENT_PLATFORM_KEYS
    ):
        raise ValueError("Plateformes FortiClient invalides.")
    if any(not isinstance(forticlient[key], bool) for key in _FORTICLIENT_PLATFORM_KEYS):
        raise ValueError("Chaque plateforme FortiClient doit être un booléen.")

    recipients = payload["recipients"]
    if not isinstance(recipients, list) or len(recipients) > 50:
        raise ValueError("Liste de destinataires invalide (50 maximum).")
    normalized: list[str] = []
    seen: set[str] = set()
    for value in recipients:
        if not isinstance(value, str):
            raise TypeError("Chaque destinataire doit être une adresse email.")
        address = value.strip()
        if not _EMAIL_ADDRESS_RE.fullmatch(address):
            raise ValueError(f"Adresse email destinataire invalide : {address or '?'}.")
        folded = address.casefold()
        if folded in seen:
            raise ValueError(f"Adresse email destinataire dupliquée : {address}.")
        seen.add(folded)
        normalized.append(address)

    return NotificationSettings(
        enabled=payload["enabled"],
        minimum_severity="high",
        products={
            **{key: products[key] for key in _SETTINGS_PRODUCT_KEYS},
            "forticlient": dict(forticlient),
        },
        recipients=tuple(normalized),
    )


def _legacy_settings_from_env(env: dict[str, str]) -> NotificationSettings:
    payload = _default_notification_settings_payload()
    payload["enabled"] = _env_bool(env, "FORTIOS_EMAIL_ENABLED", False)
    payload["recipients"] = [
        address.strip()
        for address in (env.get("FORTIOS_SMTP_TO") or "").split(",")
        if address.strip()
    ]
    try:
        return validate_notification_settings(payload)
    except (TypeError, ValueError):
        return validate_notification_settings(_default_notification_settings_payload())


def _archive_corrupt_settings_marker(path: Path, raw_text: str) -> None:
    """Record corruption without copying potentially secret unknown fields from invalid JSON."""
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%d%H%M%S%f")
    archive = path.with_name(f"{path.name}.corrupt-{timestamp}")
    temporary = archive.with_name(f"{archive.name}.tmp-{os.getpid()}")
    try:
        write_json(
            temporary,
            {
                "invalidNotificationSettings": True,
                "originalSizeBytes": len(raw_text.encode("utf-8")),
            },
        )
        os.replace(temporary, archive)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def load_notification_settings(
    path: Path = DEFAULT_NOTIFICATION_SETTINGS_PATH,
    *,
    env: dict[str, str] | None = None,
) -> NotificationSettings:
    environment = dict(os.environ) if env is None else env
    if not path.exists():
        # Backward-compatible bootstrap for existing deployments. As soon as the web UI saves
        # notification-settings.json, that file becomes authoritative and these two legacy
        # functional environment variables are ignored.
        return _legacy_settings_from_env(environment)
    safe_default = validate_notification_settings(_default_notification_settings_payload())
    with cross_process_lock(path):
        # It existed before locking but disappeared while a competing operation held the lock:
        # fail closed for this run rather than treating the race as a first migration.
        if not path.exists():
            return safe_default
        try:
            raw_text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return safe_default
        try:
            return validate_notification_settings(json.loads(raw_text))
        except (json.JSONDecodeError, TypeError, ValueError):
            # Write a secret-free marker first (never move/copy the invalid payload): if the
            # safe-default write fails, the invalid live file remains present and every later
            # process continues to fail closed. The same lock is also used by
            # save_notification_settings(), so a concurrent valid save cannot be mistaken for
            # the invalid file we just read.
            _archive_corrupt_settings_marker(path, raw_text)
            try:
                write_json(path, safe_default.to_payload())
            except OSError:
                pass
            return safe_default


def save_notification_settings(path: Path, payload: Any) -> NotificationSettings:
    settings = validate_notification_settings(payload)
    with cross_process_lock(path):
        write_json(path, settings.to_payload())
    return settings

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
    smtp_password_file: str = ""
    smtp_password_error: str = ""

    def is_complete(self) -> bool:
        if not (self.smtp_host and self.smtp_from and self.smtp_to):
            return False
        if not (0 < self.smtp_port <= 65535):
            return False
        if self.smtp_timeout <= 0:
            return False
        if not _EMAIL_ADDRESS_RE.match(self.smtp_from.strip()):
            return False
        if not all(_EMAIL_ADDRESS_RE.match(addr.strip()) for addr in self.smtp_to):
            return False
        return not (
            self.smtp_username and (not self.smtp_password or self.smtp_password_error)
        )


@dataclass
class NotificationEvent:
    category: str
    dedup_key: str
    summary: str
    severity: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


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


def _env_secret(env: dict[str, str], key: str) -> tuple[str, str, str]:
    secret_file = (env.get(f"{key}_FILE") or "").strip()
    if not secret_file:
        return "", "", ""
    try:
        value = Path(secret_file).read_text(encoding="utf-8").rstrip("\r\n")
    except (OSError, UnicodeError) as error:
        return "", secret_file, sanitize_health_error(error) or "Secret SMTP illisible."
    if not value:
        return "", secret_file, "Le fichier secret SMTP est vide."
    return value, secret_file, ""


def load_email_config(
    env: dict[str, str] | None = None,
    *,
    settings: NotificationSettings | None = None,
    settings_path: Path = DEFAULT_NOTIFICATION_SETTINGS_PATH,
) -> EmailConfig:
    environment = dict(os.environ) if env is None else env
    settings = settings or load_notification_settings(settings_path, env=environment)
    smtp_password, smtp_password_file, smtp_password_error = _env_secret(
        environment, "FORTIOS_SMTP_PASSWORD"
    )
    return EmailConfig(
        enabled=settings.enabled,
        smtp_host=(environment.get("FORTIOS_SMTP_HOST") or "").strip(),
        smtp_port=_env_int(environment, "FORTIOS_SMTP_PORT", 587),
        smtp_username=(environment.get("FORTIOS_SMTP_USERNAME") or "").strip(),
        smtp_password=smtp_password,
        smtp_from=(environment.get("FORTIOS_SMTP_FROM") or "").strip(),
        smtp_to=settings.recipients,
        smtp_starttls=_env_bool(environment, "FORTIOS_SMTP_STARTTLS", True),
        smtp_timeout=_env_int(environment, "FORTIOS_SMTP_TIMEOUT", 10),
        app_url=(
            environment.get("FORTIOS_APP_URL") or "https://valdev.me:3001/app/"
        ).strip(),
        smtp_password_file=smtp_password_file,
        smtp_password_error=smtp_password_error,
    )


def smtp_public_status(config: EmailConfig) -> dict[str, Any]:
    return {
        "state": "operational" if config.is_complete() else "incomplete",
        "host": config.smtp_host,
        "port": config.smtp_port,
        "starttls": config.smtp_starttls,
        "from": config.smtp_from,
    }


# --- Persistent state: sent-history dedup, pending outbox, EOL bootstrap state ------------
#
# All three live in one JSON file (data/fortios-notify-history.json by default) so they share a
# single cross_process_lock()'d read-modify-write cycle:
#   {"sentKeys": {dedup_key: sentAtIso, ...},
#    "outbox": [{"category", "dedupKey", "summary", "queuedAt", "claimedBy", "claimedAt"}, ...],
#    "eolState": {branch: isEolBooleanAsOfLastCheck, ...}}
#
# See the "Notifications email" section of README.md for the full outbox lifecycle and the
# recovery procedure for a corrupted state file.

_REQUIRED_OUTBOX_STRING_FIELDS = ("category", "dedupKey", "summary", "queuedAt")
_REQUIRED_OUTBOX_NULLABLE_STRING_FIELDS = ("claimedBy", "claimedAt")
_REQUIRED_OUTBOX_KEYS = (
    _REQUIRED_OUTBOX_STRING_FIELDS + _REQUIRED_OUTBOX_NULLABLE_STRING_FIELDS
)
_VALID_EVENT_CATEGORIES = frozenset(
    {CATEGORY_CRITICAL, CATEGORY_DAILY, CATEGORY_OPERATIONS}
)


def _is_valid_notify_timestamp(value: Any) -> bool:
    """Same rule as the health file's timestamps (see fortios_watch.parse_health_timestamp()):
    must be a real, timezone-aware ISO 8601 string, not just any non-empty string. A naive or
    garbled queuedAt/claimedAt must never reach the claim-staleness arithmetic in
    enqueue_and_claim() (a naive-vs-aware subtraction raises TypeError there just like it did in
    the health file)."""
    if not isinstance(value, str):
        return False
    try:
        parse_health_timestamp(value)
    except ValueError:
        return False
    return True


def _is_valid_outbox_entry(entry: Any) -> bool:
    """Every field below is read unconditionally elsewhere (enqueue_and_claim() builds a
    NotificationEvent straight from entry["category"]/entry["dedupKey"]/entry["summary"],
    finalize_sent_events() matches on entry["dedupKey"]) -- an entry missing one of them used to
    pass validation (only "dedupKey" was checked) and then raise KeyError the moment any of those
    functions touched it, permanently stuck since the notify pipeline never got a chance to
    self-heal past that entry.

    Beyond presence/type, this also rejects semantically inconsistent entries that the earlier,
    shallower validator let through:
    - `category` outside the three real values -- an unrecognized one would silently vanish from
      compose_email()'s critical/daily/operations grouping (neither shown nor ever cleaned up).
    - `queuedAt`/`claimedAt` that don't actually parse as timezone-aware timestamps.
    - `claimedBy` set while `claimedAt` is null (or vice versa) -- a claim with no timestamp can
      never be recognized as stale by enqueue_and_claim(), so it would stay reserved forever with
      no path to ever being retried.
    - empty or whitespace-only strings anywhere a real value is required.
    """
    if not isinstance(entry, dict):
        return False
    if not all(key in entry for key in _REQUIRED_OUTBOX_KEYS):
        return False

    for key in _REQUIRED_OUTBOX_STRING_FIELDS:
        value = entry[key]
        if not isinstance(value, str) or not value.strip():
            return False

    if entry["category"] not in _VALID_EVENT_CATEGORIES:
        return False
    if not _is_valid_notify_timestamp(entry["queuedAt"]):
        return False

    claimed_by = entry["claimedBy"]
    claimed_at = entry["claimedAt"]
    for value in (claimed_by, claimed_at):
        if value is not None and not isinstance(value, str):
            return False
    if claimed_by is not None and not claimed_by.strip():
        return False
    if claimed_at is not None and (
        not claimed_at.strip() or not _is_valid_notify_timestamp(claimed_at)
    ):
        return False
    severity = entry.get("severity")
    if severity is not None and severity not in _MONITORED_SEVERITIES:
        return False
    details = entry.get("details", {})
    if not isinstance(details, dict):
        return False
    # must be both-null (unclaimed) or both-set (claimed) -- never just one
    return (claimed_by is None) == (claimed_at is None)


def _is_valid_checkpoint(value: Any) -> bool:
    """None (absent) is fine -- first activation, or notifications never enabled yet, both fall
    back to the current run's own before/after snapshot (see main()'s wiring). Otherwise must be
    the exact shape commit_events_with_checkpoint() writes: versionsByProduct (product -> list of
    version strings), cvesById (cve id -> full CVE dict, needed to detect modifications, not just
    presence), health (source id -> health record dict, needed for derive_source_health_events()'s
    consecutiveFailures/lastSuccessAt comparison).
    """
    if value is None:
        return True
    if not isinstance(value, dict):
        return False

    versions_by_product = value.get("versionsByProduct", {})
    if not isinstance(versions_by_product, dict):
        return False
    for product, versions in versions_by_product.items():
        if not isinstance(product, str) or not isinstance(versions, list):
            return False
        if not all(isinstance(version, str) for version in versions):
            return False

    cves_by_id = value.get("cvesById", {})
    if not isinstance(cves_by_id, dict):
        return False
    if not all(
        isinstance(cve_id, str) and isinstance(cve, dict)
        for cve_id, cve in cves_by_id.items()
    ):
        return False

    health = value.get("health", {})
    if not isinstance(health, dict):
        return False
    return all(
        isinstance(source_id, str) and isinstance(record, dict)
        for source_id, record in health.items()
    )


def _is_valid_notify_state(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False

    sent_keys = payload.get("sentKeys", {})
    if not isinstance(sent_keys, dict):
        return False
    if not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in sent_keys.items()
    ):
        return False

    outbox = payload.get("outbox", [])
    if not isinstance(outbox, list) or not all(
        _is_valid_outbox_entry(entry) for entry in outbox
    ):
        return False

    eol_state = payload.get("eolState", {})
    if not isinstance(eol_state, dict):
        return False
    if not all(
        isinstance(key, str) and isinstance(value, bool)
        for key, value in eol_state.items()
    ):
        return False

    return _is_valid_checkpoint(payload.get("checkpoint"))


def _empty_notify_state() -> dict[str, Any]:
    return {"sentKeys": {}, "outbox": [], "eolState": {}, "checkpoint": None}


def load_notify_state(path: Path) -> dict[str, Any]:
    """Tolerant read: corrupt JSON, wrong top-level type, or a malformed outbox/sentKeys/
    eolState/checkpoint shape is treated as a fresh empty state rather than raised (see
    fortios_watch.read_json_tolerant()) -- notifications are entirely best-effort and must never
    break the daily collection they're reporting on. The bad file is archived aside for
    diagnosis, same as the health-tracking file. A corrupt or absent checkpoint specifically just
    means the next diff falls back to this run's own before/after snapshot, same as a genuine
    first activation -- never a crash, and never a spam-the-whole-history event either.
    """
    state = read_json_tolerant(
        path, None, validate=_is_valid_notify_state, archive_suffix="corrupt"
    )
    if state is None:
        return _empty_notify_state()
    return {
        "sentKeys": dict(state.get("sentKeys", {})),
        "outbox": [dict(entry) for entry in state.get("outbox", [])],
        "eolState": dict(state.get("eolState", {})),
        "checkpoint": state.get("checkpoint"),
    }


def load_notify_history(path: Path) -> dict[str, str]:
    return load_notify_state(path)["sentKeys"]


def prune_notify_history(
    history: dict[str, str], *, now: str | None = None
) -> dict[str, str]:
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


def filter_new_events(
    events: list[NotificationEvent], history: dict[str, str]
) -> list[NotificationEvent]:
    """Only events whose dedup_key hasn't already been sent -- this is also what makes a first
    activation or a --cve-backfill safe: those never produce events in the first place (see
    derive_*_events() below, which only ever diffs this run's before/after), but this is the
    second line of defense against ever re-sending the same thing twice.
    """
    return [event for event in events if event.dedup_key not in history]


def _parse_iso(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _enqueue_new_events(
    outbox: list[dict[str, Any]],
    sent_keys: dict[str, str],
    new_events: list[NotificationEvent],
    now: str,
) -> None:
    """Mutates `outbox` in place, appending any of `new_events` not already sent or already
    queued. Shared by enqueue_and_claim() and commit_eol_transition() so both agree on exactly
    the same dedup rule, and so an EOL event can be queued under the very same lock/write that
    records the state transition that produced it (see commit_eol_transition()).
    """
    queued_keys = {entry["dedupKey"] for entry in outbox}
    for event in filter_new_events(new_events, sent_keys):
        if event.dedup_key in queued_keys:
            continue
        outbox.append(
            {
                "category": event.category,
                "dedupKey": event.dedup_key,
                "summary": event.summary,
                "severity": event.severity,
                "details": event.details,
                "queuedAt": now,
                "claimedBy": None,
                "claimedAt": None,
            }
        )
        queued_keys.add(event.dedup_key)


def _claim_outstanding(
    outbox: list[dict[str, Any]], *, claimant: str, now: str, now_dt: dt.datetime
) -> list[NotificationEvent]:
    """Claims every outbox entry not currently held by another still-live attempt, mutating
    `outbox` in place. A claim is "live" for CLAIM_STALE_SECONDS: long enough to cover any real
    SMTP timeout many times over, so only a genuinely crashed run's claim is ever stolen. Shared
    by enqueue_and_claim() and commit_events_with_checkpoint() so both agree on exactly the same
    claim rule.
    """
    claimed: list[NotificationEvent] = []
    for entry in outbox:
        claimed_at = _parse_iso(entry.get("claimedAt"))
        is_stale = (
            claimed_at is not None
            and (now_dt - claimed_at).total_seconds() > CLAIM_STALE_SECONDS
        )
        if entry.get("claimedBy") and not is_stale:
            continue  # actively held by another still-live attempt
        entry["claimedBy"] = claimant
        entry["claimedAt"] = now
        claimed.append(
            NotificationEvent(
                category=entry["category"],
                dedup_key=entry["dedupKey"],
                summary=entry["summary"],
                severity=entry.get("severity"),
                details=dict(entry.get("details") or {}),
            )
        )
    return claimed


def enqueue_and_claim(
    path: Path,
    new_events: list[NotificationEvent],
    *,
    claimant: str,
    now: str | None = None,
) -> list[NotificationEvent]:
    """Atomically (a) add any of `new_events` not already sent or already queued to the
    persistent outbox -- BEFORE any attempt to send, so a crash or an SMTP failure right after
    this can never lose them -- then (b) claim every outbox entry not currently held by another
    still-live attempt for `claimant`, persisting the claim before returning.

    Two collections running at the same time can't both send the same batch -- the second one's
    claim step runs under the same cross_process_lock() and sees the first one's fresh claim
    already in place, so it claims nothing for those entries.

    Returns every event this caller just claimed (previously-queued retries AND brand-new events
    together) -- the caller should attempt to send all of them as one email, then call
    finalize_sent_events() on success or release_claim() on failure.

    Does NOT touch the notify checkpoint -- see commit_events_with_checkpoint() for the version
    that also advances it atomically alongside the events it produced (used by main()'s
    catalog-derived notifications specifically).
    """
    now = now or utc_now()
    now_dt = dt.datetime.fromisoformat(now.replace("Z", "+00:00"))
    with cross_process_lock(path):
        state = load_notify_state(path)
        _enqueue_new_events(state["outbox"], state["sentKeys"], new_events, now)
        claimed = _claim_outstanding(
            state["outbox"], claimant=claimant, now=now, now_dt=now_dt
        )
        write_json(path, state)
    return claimed


def ensure_checkpoint(path: Path, bootstrap: dict[str, Any]) -> dict[str, Any]:
    """Returns the currently persisted notify checkpoint, bootstrapping it to `bootstrap` first
    if none exists yet (compare-and-set under the same lock, so two concurrent first-ever runs
    still agree on a single winner). Must be called BEFORE this run's own catalog collection
    starts (see main()'s wiring in fortios_watch.py) -- not merely when checkpoint happens to be
    missing at commit time.

    Why this can't just be "fall back to this run's own before/after when checkpoint is None":
    picture the very first run ever with email enabled, which ALSO happens to be the run that
    discovers a new CVE, and then crashes before commit_events_with_checkpoint() ever runs. If
    the checkpoint were only established at that (now-skipped) commit point, the NEXT run would
    still see checkpoint=None and would fall back to reading `before` fresh off disk -- but that
    `before` already reflects the first run's own (successful) catalog write, i.e. it already
    contains the CVE. The diff would then find nothing new, and the notification would be lost
    exactly like before this fix existed. Bootstrapping the checkpoint immediately, before
    collection can change anything, closes that one remaining crack: even if everything after it
    fails, the pre-collection baseline this run started from is already safely anchored.
    """
    with cross_process_lock(path):
        state = load_notify_state(path)
        if state["checkpoint"] is not None:
            return state["checkpoint"]
        state["checkpoint"] = bootstrap
        write_json(path, state)
        return bootstrap


def advance_checkpoint_silently(path: Path, checkpoint: dict[str, Any]) -> None:
    """Advance the diff baseline without enqueuing or claiming events.

    Used while persisted notification settings are disabled: collections performed during that
    period become the new baseline, while an older SMTP-failure outbox remains untouched for a
    future retry if the operator re-enables notifications.
    """
    with cross_process_lock(path):
        state = load_notify_state(path)
        state["checkpoint"] = checkpoint
        write_json(path, state)


def commit_disabled_notification_state(
    path: Path,
    eol_state: dict[str, bool],
    checkpoint: dict[str, Any],
) -> None:
    """Atomically advance every notification baseline while delivery is disabled."""
    with cross_process_lock(path):
        state = load_notify_state(path)
        state["eolState"] = eol_state
        state["checkpoint"] = checkpoint
        write_json(path, state)


def commit_events_with_checkpoint(
    path: Path,
    checkpoint: dict[str, Any],
    new_events: list[NotificationEvent],
    *,
    claimant: str,
    now: str | None = None,
) -> list[NotificationEvent]:
    """Atomically (a) advance the persisted notify checkpoint to `checkpoint`, (b) enqueue
    `new_events` into the outbox, and (c) claim every outstanding entry for `claimant` -- all
    under a single cross_process_lock()/write_json(), for exactly the same reason
    commit_eol_transition() bundles its own state update with its events: the checkpoint is what
    the NEXT run diffs the catalog against to decide what's genuinely new (see main()'s wiring in
    fortios_watch.py), so advancing it in a write separate from queuing the events it was derived
    from would let a crash in between silently and permanently lose the notification -- the
    checkpoint would already reflect the new catalog state, so a later run's diff would find
    nothing new left to report.
    """
    now = now or utc_now()
    now_dt = dt.datetime.fromisoformat(now.replace("Z", "+00:00"))
    with cross_process_lock(path):
        state = load_notify_state(path)
        state["checkpoint"] = checkpoint
        _enqueue_new_events(state["outbox"], state["sentKeys"], new_events, now)
        claimed = _claim_outstanding(
            state["outbox"], claimant=claimant, now=now, now_dt=now_dt
        )
        write_json(path, state)
    return claimed


def finalize_sent_events(
    path: Path, sent_events: list[NotificationEvent], *, now: str | None = None
) -> None:
    """After a successful send: remove `sent_events` from the outbox and record their dedup keys
    in sentKeys (so a future run's diff-derived duplicate is filtered out before it's even
    queued), pruning old history.
    """
    if not sent_events:
        return
    now = now or utc_now()
    sent_dedup_keys = {event.dedup_key for event in sent_events}
    with cross_process_lock(path):
        state = load_notify_state(path)
        state["outbox"] = [
            entry
            for entry in state["outbox"]
            if entry["dedupKey"] not in sent_dedup_keys
        ]
        for event in sent_events:
            state["sentKeys"][event.dedup_key] = now
        state["sentKeys"] = prune_notify_history(state["sentKeys"], now=now)
        write_json(path, state)


# Kept as the historical name for finalize_sent_events(): every existing caller/test refers to
# "recording sent events", and the behavior (dedup-history bookkeeping after a real send) is the
# same -- it just also clears any matching outbox entries now, which is a no-op if none exist.
record_sent_events = finalize_sent_events


def release_claim(path: Path, claimant: str) -> None:
    """On send failure: release this run's claim on its outbox entries (clear claimedBy/
    claimedAt) so a future run can retry them immediately rather than waiting out
    CLAIM_STALE_SECONDS. The events themselves stay in the outbox untouched.
    """
    with cross_process_lock(path):
        state = load_notify_state(path)
        changed = False
        for entry in state["outbox"]:
            if entry.get("claimedBy") == claimant:
                entry["claimedBy"] = None
                entry["claimedAt"] = None
                changed = True
        if changed:
            write_json(path, state)


def commit_eol_transition(
    path: Path,
    eol_state: dict[str, bool],
    events: list[NotificationEvent],
    *,
    now: str | None = None,
) -> None:
    """Persist an EOL state transition and the notification event(s) it produced in ONE atomic
    read-modify-write, under a single cross_process_lock() acquisition.

    Regression this fixes: eolState used to be saved by a separate save_eol_state() call BEFORE
    the resulting event was queued via enqueue_and_claim(). A crash (or the process simply being
    killed) between those two writes would leave eolState already marking the branch as handled
    while the event was never queued anywhere -- and since derive_eol_events() only ever fires on
    the False -> True transition of that exact persisted state, a future run would see `was_eol`
    already True and never regenerate the event. The notification would be permanently lost with
    no way to detect or recover it after the fact. Doing both under one lock/write removes the
    window entirely: either both land, or (if this call itself never completes) neither does, and
    the next run's derive_eol_events() will still see the pre-transition state and fire normally.
    """
    now = now or utc_now()
    with cross_process_lock(path):
        state = load_notify_state(path)
        state["eolState"] = eol_state
        _enqueue_new_events(state["outbox"], state["sentKeys"], events, now)
        write_json(path, state)


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
            after_versions_by_product.get(product_id, set())
            - before_versions_by_product.get(product_id, set())
        )
        label = product_labels.get(product_id, product_id)
        for version in new_versions:
            events.append(
                NotificationEvent(
                    category=CATEGORY_DAILY,
                    dedup_key=f"new-version|{short_name}|{short_name}|{version}",
                    summary=f"Nouvelle version {label} {version}",
                )
            )
    return events


def _default_detection_settings() -> NotificationSettings:
    return validate_notification_settings(_default_notification_settings_payload())


def _selected_affected_entries(
    cve: dict[str, Any], settings: NotificationSettings
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for item in cve.get("affected", []) or []:
        if not isinstance(item, dict):
            continue
        product = item.get("product")
        filtered = dict(item)
        if product == "forticlient":
            models = [
                str(model)
                for model in (item.get("models") or [])
                if str(model) in _FORTICLIENT_PLATFORM_KEYS
                and settings.products["forticlient"][str(model)]
            ]
            if item.get("models") and not models:
                continue
            if not item.get("models") and not any(
                settings.products["forticlient"].values()
            ):
                continue
            filtered["models"] = models
        elif product in _SETTINGS_PRODUCT_KEYS:
            if not settings.products[product]:
                continue
        else:
            continue
        signature = (
            filtered.get("product"),
            tuple(filtered.get("models") or []),
            filtered.get("branch"),
            filtered.get("from"),
            filtered.get("to"),
        )
        if signature not in seen:
            selected.append(filtered)
            seen.add(signature)
    return selected


def _affected_product_labels(affected: list[dict[str, Any]]) -> list[str]:
    labels: list[str] = []
    for item in affected:
        product = str(item.get("product") or "")
        if product == "forticlient":
            models = item.get("models") or []
            item_labels = [
                PRODUCT_DISPLAY_LABELS[f"forticlient:{model}"]
                for model in models
                if f"forticlient:{model}" in PRODUCT_DISPLAY_LABELS
            ]
            if not item_labels:
                item_labels = ["FortiClient (plateforme non précisée)"]
        else:
            item_labels = [PRODUCT_DISPLAY_LABELS.get(product, product)]
        for label in item_labels:
            if label and label not in labels:
                labels.append(label)
    return labels


def _security_event(
    cve: dict[str, Any],
    affected: list[dict[str, Any]],
    *,
    dedup_key: str,
    change: str,
) -> NotificationEvent:
    severity = str(cve.get("severity") or "unknown").lower()
    labels = _affected_product_labels(affected)
    details = {
        "kind": "cve",
        "id": cve["id"],
        "severity": severity,
        "cvssScore": cve.get("cvssScore"),
        "title": str(cve.get("title") or "Résumé non disponible"),
        "url": str(cve.get("url") or ""),
        "affected": affected,
        "productLabels": labels,
        "change": change,
    }
    return NotificationEvent(
        category=CATEGORY_CRITICAL if severity == "critical" else CATEGORY_DAILY,
        dedup_key=dedup_key,
        summary=f"{cve['id']} — {', '.join(labels)} ({severity})",
        severity=severity,
        details=details,
    )


def derive_new_cve_events(
    newly_added_cves: list[dict[str, Any]],
    settings: NotificationSettings | None = None,
) -> list[NotificationEvent]:
    settings = settings or _default_detection_settings()
    events = []
    for cve in newly_added_cves:
        severity = (cve.get("severity") or "unknown").lower()
        if severity not in _MONITORED_SEVERITIES:
            continue
        affected = _selected_affected_entries(cve, settings)
        if not affected:
            continue
        events.append(
            _security_event(
                cve,
                affected,
                dedup_key=f"new-cve|psirt|{cve['id']}|{severity}",
                change="new",
            )
        )
    return events


def derive_cve_modification_events(
    cves_before_by_id: dict[str, dict[str, Any]],
    cves_after_by_id: dict[str, dict[str, Any]],
    settings: NotificationSettings | None = None,
) -> list[NotificationEvent]:
    """Notify only a severity escalation that reaches High/Critical.

    Re-publication, wording/CVSS/scope edits, and an unchanged High/Critical severity are silent.
    This keeps the PSIRT diff authoritative without turning every advisory refresh into a new
    security alert.
    """
    settings = settings or _default_detection_settings()
    events = []
    for cve_id, after in cves_after_by_id.items():
        before = cves_before_by_id.get(cve_id)
        if before is None:
            continue  # brand new (handled by derive_new_cve_events)

        before_severity = (before.get("severity") or "unknown").lower()
        after_severity = (after.get("severity") or "unknown").lower()
        if after_severity not in _MONITORED_SEVERITIES:
            continue
        if _SEVERITY_RANK.get(after_severity, 0) <= _SEVERITY_RANK.get(
            before_severity, 0
        ):
            continue
        affected = _selected_affected_entries(after, settings)
        if not affected:
            continue
        events.append(
            _security_event(
                after,
                affected,
                dedup_key=(
                    f"cve-severity|psirt|{cve_id}|"
                    f"{before_severity}-to-{after_severity}"
                ),
                change=f"{before_severity}-to-{after_severity}",
            )
        )
    return events


def derive_eol_events(
    after_lifecycle: dict[str, dict[str, Any]],
    eol_state: dict[str, bool],
    *,
    now: str | None = None,
) -> tuple[list[NotificationEvent], dict[str, bool]]:
    """Fires once when a FortiOS branch's support window naturally elapses.

    Comparing this run's before/after catalog snapshot for the same calendar day never catches
    this: the `support` date endoflife.date reports for a branch doesn't change from one run to
    the next -- only `now` moving past it does, and re-fetching the exact same date on both sides
    of a diff can never look like a change. So "is this branch EOL" is tracked here instead,
    persisted across runs in `eol_state` (branch -> EOL-ness as of the last time this ran).

    A branch seen for the very first time (not yet a key in `eol_state`) has its current EOL-ness
    recorded silently, with no event -- otherwise turning this on for the first time would
    immediately email every branch already long past its support date. After that, the event
    fires exactly once on the transition (False -> True), including correctly across a gap of
    several days without a single collection: whatever `eol_state` said last time this genuinely
    ran is what's compared against, not "yesterday".

    Returns (events, updated_eol_state) -- the caller must persist the updated state (see
    save_eol_state()) regardless of whether the email actually sends, since the crossing itself
    was correctly observed either way.
    """
    now_date = dt.datetime.fromisoformat(
        (now or utc_now()).replace("Z", "+00:00")
    ).date()
    updated_state = dict(eol_state)
    events: list[NotificationEvent] = []
    for branch, info in after_lifecycle.items():
        support_date = info.get("support")
        if not support_date:
            continue
        try:
            support_dt = dt.date.fromisoformat(support_date)
        except ValueError:
            continue

        is_eol_now = support_dt < now_date
        was_eol = eol_state.get(branch)
        if was_eol is None:
            updated_state[branch] = (
                is_eol_now  # first sighting: bootstrap silently, no event
            )
            continue
        if is_eol_now and not was_eol:
            events.append(
                NotificationEvent(
                    category=CATEGORY_DAILY,
                    dedup_key=f"support-eol|fortios|{branch}|{support_date}",
                    summary=f"FortiOS {branch} est passé en fin de support (depuis le {support_date})",
                )
            )
        updated_state[branch] = is_eol_now
    return events, updated_state


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

        if (
            after_failures >= CONSECUTIVE_FAILURE_NOTIFY_THRESHOLD
            and before_failures < CONSECUTIVE_FAILURE_NOTIFY_THRESHOLD
        ):
            events.append(
                NotificationEvent(
                    category=CATEGORY_OPERATIONS,
                    dedup_key=f"source-failure|{source_id}|consecutive|{after_failures}",
                    summary=f"Collecte {label} en échec depuis {after_failures} exécutions consécutives",
                )
            )
        elif (
            before_failures >= CONSECUTIVE_FAILURE_NOTIFY_THRESHOLD
            and after_failures == 0
            and after.get("lastSuccessAt")
        ):
            success_date = after["lastSuccessAt"][:10]
            events.append(
                NotificationEvent(
                    category=CATEGORY_OPERATIONS,
                    dedup_key=f"source-recovered|{source_id}|lastSuccessAt|{success_date}",
                    summary=f"Collecte {label} de nouveau opérationnelle (après {before_failures} échecs)",
                )
            )
    return events


# --- Email composition and sending ---------------------------------------------------------


def _format_event_lines(events: list[NotificationEvent]) -> list[str]:
    shown = events[:MAX_EVENTS_PER_SECTION]
    lines = [f"- {event.summary}" for event in shown]
    remaining = len(events) - len(shown)
    if remaining > 0:
        lines.append(f"... et {remaining} de plus (liste tronquée).")
    return lines


def _affected_version_line(item: dict[str, Any]) -> str:
    labels = _affected_product_labels([item])
    label = ", ".join(labels) or str(item.get("product") or "Produit")
    from_version = item.get("from")
    to_version = item.get("to")
    branch = item.get("branch")
    if from_version and to_version and from_version != to_version:
        scope = f"{from_version} à {to_version}"
    elif from_version:
        scope = str(from_version)
    elif branch:
        scope = f"branche {branch}"
    else:
        scope = "versions non précisées"
    return f"{label} : {scope}"


def _compose_security_text(
    security_events: list[NotificationEvent], *, app_url: str, run_timestamp: str
) -> str:
    severities = Counter(event.severity for event in security_events)
    product_counts: Counter[str] = Counter()
    for event in security_events:
        product_counts.update(set(event.details.get("productLabels") or []))

    lines = [
        f"{len(security_events)} nouvelles vulnérabilités High / Critical détectées",
        "",
        f"Critical : {severities['critical']}",
        f"High     : {severities['high']}",
        "",
    ]
    lines.extend(f"{label} : {count}" for label, count in product_counts.items())
    lines.append("")

    for event in security_events:
        details = event.details
        lines.extend(
            [
                f"{(event.severity or '').upper()} — {details.get('id', '?')}",
                f"CVSS : {details.get('cvssScore') if details.get('cvssScore') is not None else 'Non précisé'}",
                "",
                "Produits concernés",
            ]
        )
        lines.extend(str(label) for label in details.get("productLabels") or [])
        lines.extend(["", "Versions affectées"])
        lines.extend(
            _affected_version_line(item) for item in details.get("affected") or []
        )
        lines.extend(
            [
                "",
                "Versions corrigées",
                "Non précisées dans le flux CVRF — consulter l’advisory Fortinet.",
                "",
                "Résumé",
                str(details.get("title") or "Résumé non disponible"),
                "",
                "Fortinet PSIRT",
                f"→ {details.get('url') or app_url}",
                "",
            ]
        )
    lines.extend([f"Application : {app_url}", f"Collecte : {run_timestamp}"])
    return "\n".join(lines)


def _compose_security_html(
    security_events: list[NotificationEvent],
    *,
    app_url: str,
    run_timestamp: str,
    other_events: list[NotificationEvent] | None = None,
) -> str:
    severities = Counter(event.severity for event in security_events)
    product_counts: Counter[str] = Counter()
    for event in security_events:
        product_counts.update(set(event.details.get("productLabels") or []))

    product_rows = "".join(
        f"<tr><td style='padding:3px 12px 3px 0'>{html.escape(label)}</td>"
        f"<td style='padding:3px 0;font-weight:700'>{count}</td></tr>"
        for label, count in product_counts.items()
    )
    sections: list[str] = []
    for event in security_events:
        details = event.details
        severity = (event.severity or "high").upper()
        color = "#b42318" if event.severity == "critical" else "#b54708"
        products = "<br>".join(
            html.escape(str(label)) for label in details.get("productLabels") or []
        )
        affected = "<br>".join(
            html.escape(_affected_version_line(item))
            for item in details.get("affected") or []
        )
        url = str(details.get("url") or app_url)
        sections.append(
            "<div style='border-top:1px solid #d0d5dd;padding:20px 0'>"
            f"<h2 style='margin:0 0 10px;font-size:18px;color:{color}'>"
            f"{html.escape(severity)} — {html.escape(str(details.get('id', '?')))}</h2>"
            f"<p style='margin:0 0 14px'><strong>CVSS :</strong> "
            f"{html.escape(str(details.get('cvssScore') if details.get('cvssScore') is not None else 'Non précisé'))}</p>"
            "<p style='margin:0 0 4px'><strong>Produits concernés</strong></p>"
            f"<p style='margin:0 0 14px'>{products}</p>"
            "<p style='margin:0 0 4px'><strong>Versions affectées</strong></p>"
            f"<p style='margin:0 0 14px'>{affected}</p>"
            "<p style='margin:0 0 4px'><strong>Versions corrigées</strong></p>"
            "<p style='margin:0 0 14px'>Non précisées dans le flux CVRF — consulter l’advisory Fortinet.</p>"
            "<p style='margin:0 0 4px'><strong>Résumé</strong></p>"
            f"<p style='margin:0 0 14px'>{html.escape(str(details.get('title') or 'Résumé non disponible'))}</p>"
            f"<p style='margin:0'><a href='{html.escape(url, quote=True)}' "
            "style='color:#175cd3'>Fortinet PSIRT → advisory</a></p></div>"
        )

    other_events = other_events or []
    other_html = ""
    if other_events:
        shown = other_events[:MAX_EVENTS_PER_SECTION]
        items = "".join(
            f"<li style='margin-bottom:6px'>{html.escape(event.summary)}</li>"
            for event in shown
        )
        if len(other_events) > len(shown):
            items += (
                f"<li>… et {len(other_events) - len(shown)} de plus "
                "(liste tronquée).</li>"
            )
        other_html = (
            "<div style='border-top:1px solid #d0d5dd;padding:18px 0'>"
            "<h2 style='margin:0 0 10px;font-size:16px'>Autres événements</h2>"
            f"<ul style='margin:0;padding-left:20px'>{items}</ul></div>"
        )

    return (
        "<!doctype html><html><body style='margin:0;padding:0;background:#ffffff'>"
        "<div style='max-width:680px;margin:0 auto;padding:20px;font-family:Arial,sans-serif;"
        "font-size:14px;line-height:1.45;color:#101828'>"
        f"<h1 style='margin:0 0 8px;font-size:22px'>{len(security_events)} nouvelles "
        "vulnérabilités High / Critical détectées</h1>"
        "<table role='presentation' style='border-collapse:collapse;margin:0 0 14px'>"
        f"<tr><td style='padding:3px 16px 3px 0'>Critical</td><td style='font-weight:700'>{severities['critical']}</td></tr>"
        f"<tr><td style='padding:3px 16px 3px 0'>High</td><td style='font-weight:700'>{severities['high']}</td></tr>"
        "</table>"
        f"<table role='presentation' style='border-collapse:collapse;margin:0 0 18px'>{product_rows}</table>"
        f"{''.join(sections)}"
        f"{other_html}"
        f"<p style='color:#667085;font-size:12px'>Application : "
        f"<a href='{html.escape(app_url, quote=True)}'>{html.escape(app_url)}</a><br>"
        f"Collecte : {html.escape(run_timestamp)}</p></div></body></html>"
    )


def compose_email(
    events: list[NotificationEvent], *, app_url: str, run_timestamp: str
) -> tuple[str, str, str] | None:
    """Folds every event from a single run into one synthetic email (never one email per
    event, to avoid spamming) -- returns None if there's nothing to report.
    """
    if not events:
        return None

    security = [event for event in events if event.details.get("kind") == "cve"]
    critical = [event for event in events if event.category == CATEGORY_CRITICAL]
    daily = [event for event in events if event.category == CATEGORY_DAILY]
    operations = [event for event in events if event.category == CATEGORY_OPERATIONS]

    if security:
        highest = "CRITICAL" if any(event.severity == "critical" for event in security) else "HIGH"
        subject = (
            f"[FortiUpgrade][{highest}] {len(security)} nouvelles vulnérabilités Fortinet"
        )
        text_body = _compose_security_text(
            security, app_url=app_url, run_timestamp=run_timestamp
        )
        non_security = [event for event in events if event not in security]
        if non_security:
            text_body += "\n\nAutres événements :\n" + "\n".join(
                _format_event_lines(non_security)
            )
        html_body = _compose_security_html(
            security,
            app_url=app_url,
            run_timestamp=run_timestamp,
            other_events=non_security,
        )
        return subject, text_body, html_body
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
        lines.append(
            f"{len(critical)} nouvelle{plural} CVE critique{plural} {verb} été détectée{plural}."
        )
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
    text_body = "\n".join(lines)
    html_body = (
        "<!doctype html><html><body><pre style='font-family:Arial,sans-serif;white-space:pre-wrap'>"
        f"{html.escape(text_body)}</pre></body></html>"
    )
    return subject, text_body, html_body


@dataclass(frozen=True)
class SmtpResult:
    sent: bool
    message: str


def send_email_result(
    config: EmailConfig,
    subject: str,
    text_body: str,
    html_body: str | None = None,
    *,
    force: bool = False,
) -> SmtpResult:
    """Never raises -- every failure mode (bad config, a malformed header, DNS, connection
    refused, STARTTLS, auth, timeout) is caught, logged without the password, and reported as a
    plain False so a broken mailbox can never break the actual data collection.

    Message construction happens INSIDE the protected block on purpose:
    EmailMessage.__setitem__ raises ValueError on a header value containing a stray newline
    (e.g. a fat-fingered FORTIOS_SMTP_FROM, or a "To" header injection attempt) -- building the
    message before the try block used to let exactly that kind of ValueError escape uncaught.
    """
    if not config.enabled and not force:
        return SmtpResult(False, "Notifications désactivées.")
    if not config.is_complete():
        sys.stderr.write(
            "Notification email ignorée : configuration SMTP incomplète ou invalide (host/port/from/to).\n"
        )
        return SmtpResult(False, "Configuration SMTP incomplète.")

    try:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = config.smtp_from
        message["To"] = ", ".join(config.smtp_to)
        message.set_content(text_body)
        if html_body:
            message.add_alternative(html_body, subtype="html")

        with smtplib.SMTP(
            config.smtp_host, config.smtp_port, timeout=config.smtp_timeout
        ) as client:
            if config.smtp_starttls:
                client.starttls(context=ssl.create_default_context())
            if config.smtp_username:
                client.login(config.smtp_username, config.smtp_password)
            client.send_message(message)
        return SmtpResult(True, "Email envoyé.")
    except smtplib.SMTPAuthenticationError as error:
        sys.stderr.write(
            f"Échec de l'envoi de l'email de notification : {sanitize_health_error(error)}\n"
        )
        return SmtpResult(False, "Authentification SMTP refusée.")
    except (ConnectionError, TimeoutError, OSError) as error:
        sys.stderr.write(
            f"Échec de l'envoi de l'email de notification : {sanitize_health_error(error)}\n"
        )
        return SmtpResult(False, "Connexion SMTP impossible.")
    except (smtplib.SMTPException, ValueError) as error:
        sys.stderr.write(
            f"Échec de l'envoi de l'email de notification : {sanitize_health_error(error)}\n"
        )
        return SmtpResult(False, "Envoi SMTP impossible.")


def send_email(
    config: EmailConfig,
    subject: str,
    text_body: str,
    html_body: str | None = None,
) -> bool:
    return send_email_result(config, subject, text_body, html_body).sent


def send_test_email_result(config: EmailConfig) -> SmtpResult:
    subject = "[FortiUpgrade] Email de test"
    body = (
        "Ceci est un email de test envoyé depuis l’administration FortiUpgrade.\n"
        "Si vous le recevez, la configuration SMTP est fonctionnelle.\n\n"
        f"Application : {config.app_url}\n"
    )
    result = send_email_result(config, subject, body, force=True)
    if result.sent:
        return SmtpResult(True, "Email de test envoyé.")
    return result


def send_test_email(config: EmailConfig) -> bool:
    result = send_test_email_result(config)
    if result.sent:
        print(f"Email de test envoyé à {', '.join(config.smtp_to)}.")
    else:
        print(result.message, file=sys.stderr)
    return result.sent
