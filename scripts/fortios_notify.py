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

import datetime as dt
import os
import re
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
# A CVSS delta smaller than this is rounding/rescoring noise, not worth an email on its own.
CVSS_SIGNIFICANT_DELTA = 1.0
# How long a claimed-but-unfinished outbox entry stays "reserved" before a later run is allowed
# to retry it -- long enough to cover the slowest realistic SMTP timeout many times over, short
# enough that a genuinely crashed run's claim doesn't block retries for hours.
CLAIM_STALE_SECONDS = 600

_EMAIL_ADDRESS_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

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
        return True


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
_REQUIRED_OUTBOX_KEYS = _REQUIRED_OUTBOX_STRING_FIELDS + _REQUIRED_OUTBOX_NULLABLE_STRING_FIELDS


def _is_valid_outbox_entry(entry: Any) -> bool:
    """Every field below is read unconditionally elsewhere (enqueue_and_claim() builds a
    NotificationEvent straight from entry["category"]/entry["dedupKey"]/entry["summary"],
    finalize_sent_events() matches on entry["dedupKey"]) -- an entry missing one of them used to
    pass validation (only "dedupKey" was checked) and then raise KeyError the moment any of those
    functions touched it, permanently stuck since the notify pipeline never got a chance to
    self-heal past that entry.
    """
    if not isinstance(entry, dict):
        return False
    if not all(key in entry for key in _REQUIRED_OUTBOX_KEYS):
        return False
    for key in _REQUIRED_OUTBOX_STRING_FIELDS:
        if not isinstance(entry[key], str) or not entry[key]:
            return False
    for key in _REQUIRED_OUTBOX_NULLABLE_STRING_FIELDS:
        if entry[key] is not None and not isinstance(entry[key], str):
            return False
    return True


def _is_valid_notify_state(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False

    sent_keys = payload.get("sentKeys", {})
    if not isinstance(sent_keys, dict):
        return False
    if not all(isinstance(key, str) and isinstance(value, str) for key, value in sent_keys.items()):
        return False

    outbox = payload.get("outbox", [])
    if not isinstance(outbox, list) or not all(_is_valid_outbox_entry(entry) for entry in outbox):
        return False

    eol_state = payload.get("eolState", {})
    if not isinstance(eol_state, dict):
        return False
    if not all(isinstance(key, str) and isinstance(value, bool) for key, value in eol_state.items()):
        return False

    return True


def _empty_notify_state() -> dict[str, Any]:
    return {"sentKeys": {}, "outbox": [], "eolState": {}}


def load_notify_state(path: Path) -> dict[str, Any]:
    """Tolerant read: corrupt JSON, wrong top-level type, or a malformed outbox/sentKeys/eolState
    shape is treated as a fresh empty state rather than raised (see
    fortios_watch.read_json_tolerant()) -- notifications are entirely best-effort and must never
    break the daily collection they're reporting on. The bad file is archived aside for
    diagnosis, same as the health-tracking file.
    """
    state = read_json_tolerant(path, None, validate=_is_valid_notify_state, archive_suffix="corrupt")
    if state is None:
        return _empty_notify_state()
    return {
        "sentKeys": dict(state.get("sentKeys", {})),
        "outbox": [dict(entry) for entry in state.get("outbox", [])],
        "eolState": dict(state.get("eolState", {})),
    }


def load_notify_history(path: Path) -> dict[str, str]:
    return load_notify_state(path)["sentKeys"]


def prune_notify_history(history: dict[str, str], *, now: str | None = None) -> dict[str, str]:
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


def _parse_iso(value: str | None) -> "dt.datetime | None":
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _enqueue_new_events(
    outbox: list[dict[str, Any]], sent_keys: dict[str, str], new_events: list[NotificationEvent], now: str
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
        outbox.append({
            "category": event.category,
            "dedupKey": event.dedup_key,
            "summary": event.summary,
            "queuedAt": now,
            "claimedBy": None,
            "claimedAt": None,
        })
        queued_keys.add(event.dedup_key)


def enqueue_and_claim(
    path: Path, new_events: list[NotificationEvent], *, claimant: str, now: str | None = None
) -> list[NotificationEvent]:
    """Atomically (a) add any of `new_events` not already sent or already queued to the
    persistent outbox -- BEFORE any attempt to send, so a crash or an SMTP failure right after
    this can never lose them -- then (b) claim every outbox entry not currently held by another
    still-live attempt for `claimant`, persisting the claim before returning.

    A claim is "live" for CLAIM_STALE_SECONDS: long enough to cover any real SMTP timeout many
    times over, so only a genuinely crashed run's claim is ever stolen. Two collections running
    at the same time can't both send the same batch -- the second one's claim step runs under
    the same cross_process_lock() and sees the first one's fresh claim already in place, so it
    claims nothing for those entries.

    Returns every event this caller just claimed (previously-queued retries AND brand-new events
    together) -- the caller should attempt to send all of them as one email, then call
    finalize_sent_events() on success or release_claim() on failure.
    """
    now = now or utc_now()
    now_dt = dt.datetime.fromisoformat(now.replace("Z", "+00:00"))
    with cross_process_lock(path):
        state = load_notify_state(path)
        outbox = state["outbox"]
        _enqueue_new_events(outbox, state["sentKeys"], new_events, now)

        claimed: list[NotificationEvent] = []
        for entry in outbox:
            claimed_at = _parse_iso(entry.get("claimedAt"))
            is_stale = claimed_at is not None and (now_dt - claimed_at).total_seconds() > CLAIM_STALE_SECONDS
            if entry.get("claimedBy") and not is_stale:
                continue  # actively held by another still-live attempt
            entry["claimedBy"] = claimant
            entry["claimedAt"] = now
            claimed.append(NotificationEvent(
                category=entry["category"], dedup_key=entry["dedupKey"], summary=entry["summary"],
            ))

        write_json(path, state)
    return claimed


def finalize_sent_events(path: Path, sent_events: list[NotificationEvent], *, now: str | None = None) -> None:
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
        state["outbox"] = [entry for entry in state["outbox"] if entry["dedupKey"] not in sent_dedup_keys]
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
    path: Path, eol_state: dict[str, bool], events: list[NotificationEvent], *, now: str | None = None
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


def _affected_signature(affected: list[dict[str, Any]] | None) -> "frozenset[tuple[str, str, tuple[str, ...], str, str]]":
    """A hashable, fully-comparable snapshot of a CVE's affected scope -- None values normalized
    to "" so entries can be sorted/set-diffed without ever comparing None to str (which raises).
    """
    return frozenset(
        (
            str(item.get("product") or ""),
            str(item.get("branch") or ""),
            tuple(sorted(str(model) for model in (item.get("models") or []))),
            str(item.get("from") or ""),
            str(item.get("to") or ""),
        )
        for item in (affected or [])
    )


def _cvss_changed_significantly(before_score: float | None, after_score: float | None) -> bool:
    if before_score is None or after_score is None:
        return before_score != after_score  # a score appearing/disappearing is itself significant
    return abs(after_score - before_score) >= CVSS_SIGNIFICANT_DELTA


def derive_cve_modification_events(
    cves_before_by_id: dict[str, dict[str, Any]],
    cves_after_by_id: dict[str, dict[str, Any]],
) -> list[NotificationEvent]:
    """Beyond a plain severity change, also flags: affected products/models/version-range
    changes (scope extended or reduced -- this also covers a fix version newly appearing, since
    that's simply the affected range's upper bound (`to`) being set for the first time), and a
    significant CVSS score move (>= CVSS_SIGNIFICANT_DELTA). Purely technical/ordering changes
    (title wording, updatedAt, a sub-CVSS_SIGNIFICANT_DELTA score wobble) are deliberately never
    flagged on their own.
    """
    events = []
    for cve_id, after in cves_after_by_id.items():
        before = cves_before_by_id.get(cve_id)
        if before is None or before == after:
            continue  # brand new (handled by derive_new_cve_events) or genuinely unchanged

        before_severity = (before.get("severity") or "unknown").lower()
        after_severity = (after.get("severity") or "unknown").lower()
        severity_changed = before_severity != after_severity

        before_affected = _affected_signature(before.get("affected"))
        after_affected = _affected_signature(after.get("affected"))
        scope_changed = before_affected != after_affected

        cvss_changed = _cvss_changed_significantly(before.get("cvssScore"), after.get("cvssScore"))

        if not (severity_changed or scope_changed or cvss_changed):
            continue

        changes: list[str] = []
        if severity_changed:
            changes.append(f"sévérité {before_severity} → {after_severity}")
        if cvss_changed:
            before_cvss = before.get("cvssScore")
            after_cvss = after.get("cvssScore")
            changes.append(f"CVSS {before_cvss if before_cvss is not None else '?'} → {after_cvss if after_cvss is not None else '?'}")
        if scope_changed:
            added = after_affected - before_affected
            removed = before_affected - after_affected
            if added and removed:
                changes.append("périmètre modifié")
            elif added:
                changes.append("périmètre étendu")
            else:
                changes.append("périmètre réduit")

        category = CATEGORY_CRITICAL if after_severity == "critical" else CATEGORY_DAILY
        # Keyed to the new state (not a description of the diff) so a DIFFERENT later change to
        # the same CVE still gets its own notification, while an identical already-notified
        # state never resends just because this run happened to re-derive it.
        dedup_key = "|".join([
            "cve-modified", "psirt", cve_id, after_severity,
            str(after.get("cvssScore")), str(sorted(after_affected)),
        ])
        events.append(NotificationEvent(
            category=category,
            dedup_key=dedup_key,
            summary=f"{cve_id} : {', '.join(changes)} ({_cve_product_summary(after)})",
        ))
    return events


def derive_eol_events(
    after_lifecycle: dict[str, dict[str, Any]],
    eol_state: dict[str, bool],
    *, now: str | None = None,
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
    now_date = dt.datetime.fromisoformat((now or utc_now()).replace("Z", "+00:00")).date()
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
            updated_state[branch] = is_eol_now  # first sighting: bootstrap silently, no event
            continue
        if is_eol_now and not was_eol:
            events.append(NotificationEvent(
                category=CATEGORY_DAILY,
                dedup_key=f"support-eol|fortios|{branch}|{support_date}",
                summary=f"FortiOS {branch} est passé en fin de support (depuis le {support_date})",
            ))
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
    """Never raises -- every failure mode (bad config, a malformed header, DNS, connection
    refused, STARTTLS, auth, timeout) is caught, logged without the password, and reported as a
    plain False so a broken mailbox can never break the actual data collection.

    Message construction happens INSIDE the protected block on purpose:
    EmailMessage.__setitem__ raises ValueError on a header value containing a stray newline
    (e.g. a fat-fingered FORTIOS_SMTP_FROM, or a "To" header injection attempt) -- building the
    message before the try block used to let exactly that kind of ValueError escape uncaught.
    """
    if not config.enabled:
        return False
    if not config.is_complete():
        sys.stderr.write("Notification email ignorée : configuration SMTP incomplète ou invalide (host/port/from/to).\n")
        return False

    try:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = config.smtp_from
        message["To"] = ", ".join(config.smtp_to)
        message.set_content(text_body)

        with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=config.smtp_timeout) as client:
            if config.smtp_starttls:
                client.starttls(context=ssl.create_default_context())
            if config.smtp_username:
                client.login(config.smtp_username, config.smtp_password)
            client.send_message(message)
        return True
    except (smtplib.SMTPException, OSError, TimeoutError, ValueError) as error:
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
