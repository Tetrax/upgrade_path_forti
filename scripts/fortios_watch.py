#!/usr/bin/env python3
"""Generate data for the FortiOS Upgrade Intelligence UI.

The script is intentionally stdlib-only so it can run from cron or a systemd
timer on a company Linux server.

Current stable inputs:
- Existing UI JSON data.
- Local Fortinet upgrade-tool exports pasted/saved as CSV, TSV, JSON or text.
- Optional FortiCare/FNDN JSON export files, until the authenticated API shape
  is confirmed with the company account.
- Public FortiGuard PSIRT RSS as a weak signal for newly mentioned versions.

The target output is compatible with app/index.html.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import fcntl
import html
import http.client
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

VERSION_RE = re.compile(r"\b\d+\.\d+\.\d+(?:\.\d+)?\b")
DOC_MODEL_RE = re.compile(r"\b(?:FG|FWF|FGR|FFW)-[A-Z0-9][A-Z0-9-]*\b")
DEFAULT_PRODUCT_ID = "fortigate-fortios"
DEFAULT_PRODUCT_LABEL = "FortiGate / FortiOS"
PSIRT_RSS_URL = "https://www.fortiguard.com/rss/ir.xml"
FORTINET_DOCS_BASE_URL = "https://docs.fortinet.com"
# Fortinet's Upgrade Path Tool moved in 2026-09: `/upgrade-tool/products/<slug>.json` and
# `POST /upgrade-tool/upgrade-path` now answer 404. The tool's own page
# (docs.fortinet.com/upgrade-tool/<slug>) calls these two JSON endpoints instead — observed on the
# public page's JS bundle, not a contractually guaranteed API; a change there is treated as a
# response-format failure (UpgradeToolResponseError), never as "no versions available".
FORTINET_UPGRADE_TOOL_API_URL = f"{FORTINET_DOCS_BASE_URL}/api/tools/upgrade-path"
FORTINET_UPGRADE_TOOL_MODELS_URL = f"{FORTINET_UPGRADE_TOOL_API_URL}/models"
DEFAULT_DOCS_MAJOR_VERSIONS = (
    "8.4",
    "8.2",
    "8.0",
    "7.6",
    "7.4",
    "7.2",
    "7.0",
    "6.4",
    "6.2",
    "6.0",
    "5.6",
    "5.4",
    "5.2",
    "5.0",
)

FORTICLIENT_PRODUCT_ID = "forticlient"
FORTICLIENT_EMS_PRODUCT_ID = "forticlient-ems"

# Products supported by Fortinet's public Upgrade Path Tool (docs.fortinet.com/upgrade-tool).
# FortiClient / FortiClient EMS are intentionally absent: they aren't in that tool's own
# product list (confirmed by reading its JS), so they can only get a version catalog and
# internal advisories, no automated recommended-path lookup — see NO_PATH_PRODUCT_LABELS.
PRODUCTS = {
    DEFAULT_PRODUCT_ID: {"slug": "fortigate", "label": DEFAULT_PRODUCT_LABEL},
    "fortianalyzer": {"slug": "fortianalyzer", "label": "FortiAnalyzer"},
    "fortimanager": {"slug": "fortimanager", "label": "FortiManager"},
}
NO_PATH_PRODUCT_LABELS = {
    FORTICLIENT_PRODUCT_ID: "FortiClient (Windows/macOS/Linux)",
    FORTICLIENT_EMS_PRODUCT_ID: "FortiClient EMS",
}
# Every known product, for validating advisories/catalogs regardless of upgrade-path support.
PRODUCT_LABELS = {
    **{product_id: meta["label"] for product_id, meta in PRODUCTS.items()},
    **NO_PATH_PRODUCT_LABELS,
}
UPGRADE_DIRECTION_ERROR = (
    "La version cible doit être supérieure à la version source. "
    "Upgrade Path ne prend pas en charge les downgrades."
)
RELEASE_NOTES_DOC_SLUGS = {
    DEFAULT_PRODUCT_ID: "fortios-release-notes",
    "fortianalyzer": "release-notes",
    "fortimanager": "release-notes",
}


class UpgradeToolResponseError(Exception):
    """The Upgrade Path Tool answered with a shape this collector doesn't understand.

    Deliberately NOT a ValueError: a malformed upstream body is a gateway/format problem, so the
    server must not report it to a browser as a 400 "bad request" (see fortios_server.py's
    handle_official_path). Raised instead of returning an empty result so a broken or evolved
    Fortinet response can never be mistaken for "this model/product has no version".
    """


@dataclass(frozen=True)
class Firmware:
    product: str
    model: str
    version: str
    build: str = "-"
    notes: tuple[str, ...] = ()
    links: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class UpgradePath:
    product: str
    model: str
    from_version: str
    to_version: str
    hops: tuple[str, ...]
    source: str


@dataclass(frozen=True)
class OfficialPathRequest:
    model: str
    from_version: str
    to_version: str
    product: str = DEFAULT_PRODUCT_ID


@dataclass(frozen=True)
class DocsRelease:
    version: str
    build: str
    models: tuple[str, ...]
    source_url: str


def utc_now() -> str:
    return (
        dt.datetime.now(dt.UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def utc_now_precise() -> str:
    """Same as utc_now() but keeps microsecond resolution. Used only for the health-tracking
    subsystem's started_at/lastAttemptAt, which double as the ordering key that decides whether
    an older, slower attempt is allowed to clobber a newer one's result (see
    _merge_health_source()) -- two attempts starting within the same whole second are otherwise
    indistinguishable by that comparison, letting a stale write win over a fresher one. Every
    other timestamp in the app (generatedAt, createdAt, requestedAt...) keeps using utc_now()
    unchanged; this isn't a global format change.
    """
    return dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _archive_corrupt_file(path: Path, suffix: str) -> None:
    """Rename a bad file aside instead of silently overwriting it in place, so evidence of the
    corruption survives the next successful write. Best-effort: losing the forensic copy (e.g. a
    read-only directory) is never worth failing the run over.
    """
    try:
        archived = path.with_name(f"{path.name}.{suffix}-{int(time.time())}")
        os.replace(path, archived)
    except OSError:
        pass


def read_json_tolerant(
    path: Path,
    default: Any,
    *,
    validate: Callable[[Any], bool] | None = None,
    archive_suffix: str = "corrupt",
) -> Any:
    """Best-effort JSON read for files that must never be allowed to break the process reading
    them: a missing file returns `default` (like read_json()); a file that exists but is corrupt
    (invalid JSON, wrong encoding), the wrong top-level type, or fails the optional `validate`
    structure check also returns `default` instead of raising. The bad file is archived aside
    (see _archive_corrupt_file()) for diagnosis rather than left in place or clobbered blind.
    """
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        # The file WAS read -- its CONTENT is corrupt. That's evidence of a bug (ours or a
        # writer's) worth preserving, so archive it aside for diagnosis.
        _archive_corrupt_file(path, archive_suffix)
        return default
    except OSError as error:
        # The file itself couldn't be read at all: permission denied, or it disappeared between
        # the exists() check above and open() (a TOCTOU race -- also OSError, as
        # FileNotFoundError). Nothing to archive here: renaming a file this process can't even
        # open would likely fail the exact same way, and unlike corrupt JSON this isn't evidence
        # of a bug in our own writer -- it's an environment/permissions issue outside this
        # process's control. Best-effort: log a short warning (no traceback, no secrets) and
        # carry on exactly as if the file were simply absent.
        sys.stderr.write(
            f"Avertissement : lecture de {path} impossible ({sanitize_health_error(error)}), traité comme absent.\n"
        )
        return default
    if validate is not None and not validate(payload):
        _archive_corrupt_file(path, archive_suffix)
        return default
    return payload


def write_json(path: Path, payload: Any) -> None:
    """Write via a temp file + atomic rename so a crash mid-write (or a racing writer — see
    cross_process_lock() below) can never leave `path` truncated or half-written.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.tmp-{os.getpid()}")
    with tmp_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    os.replace(tmp_path, path)


@contextmanager
def cross_process_lock(target_path: Path):
    """Exclusive lock scoped to `target_path`, shared by every writer of the generated JSON:
    fortios_server.py's live request handlers, this script's daily batch run, and
    import_forticlient_compat.py. An in-process threading.Lock (what fortios_server.py used to
    rely on alone) only serializes that one process's own threads — it does nothing to stop a
    second process from reading the file mid-way through another process's read-modify-write.

    Hold this only around the actual read -> modify -> write critical section, never around slow
    network I/O (the daily script's multi-minute scraping happens entirely before it's acquired).
    """
    lock_path = target_path.with_name(f"{target_path.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "w", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


# --- Health-state tracking --------------------------------------------------------------------
# A separate JSON file from the main catalog (data/fortios-health.json by default), recording
# per-source collection status so the UI can show "how fresh/healthy is our data" without
# conflating that with the catalog content itself. Written under cross_process_lock() like
# everything else; a failure to write health state must never fail the actual collection (see
# main()'s call site, which wraps record_health_results() in a try/except of its own).

HEALTH_STATUS_OK = "ok"
HEALTH_STATUS_WARNING = "warning"
HEALTH_STATUS_ERROR = "error"
HEALTH_STATUS_RUNNING = "running"
HEALTH_STATUS_SKIPPED = "skipped"

SOURCE_FORTIOS_DOCS = "fortios-docs"
SOURCE_FORTIANALYZER = "fortianalyzer"
SOURCE_FORTIMANAGER = "fortimanager"
SOURCE_FORTICLIENT = "forticlient"
SOURCE_FORTICLIENT_EMS = "forticlient-ems"
SOURCE_CVE_PSIRT = "cve-psirt"
SOURCE_FORTIOS_LIFECYCLE = "fortios-lifecycle"
SOURCE_COMPAT_MATRIX = "compat-matrix"
SOURCE_DAILY_RUN = "daily-run"

ALL_HEALTH_SOURCES = (
    SOURCE_FORTIOS_DOCS,
    SOURCE_FORTIANALYZER,
    SOURCE_FORTIMANAGER,
    SOURCE_FORTICLIENT,
    SOURCE_FORTICLIENT_EMS,
    SOURCE_CVE_PSIRT,
    SOURCE_FORTIOS_LIFECYCLE,
    SOURCE_COMPAT_MATRIX,
    SOURCE_DAILY_RUN,
)

HEALTH_SOURCE_LABELS = {
    SOURCE_FORTIOS_DOCS: "Catalogue FortiOS",
    SOURCE_FORTIANALYZER: "FortiAnalyzer",
    SOURCE_FORTIMANAGER: "FortiManager",
    SOURCE_FORTICLIENT: "FortiClient",
    SOURCE_FORTICLIENT_EMS: "FortiClient EMS",
    SOURCE_CVE_PSIRT: "CVE PSIRT",
    SOURCE_FORTIOS_LIFECYCLE: "Cycle de vie FortiOS",
    SOURCE_COMPAT_MATRIX: "Matrice de compatibilité EMS/FortiClient",
}

DEFAULT_HEALTH_PATH = Path("data/fortios-health.json")
DEFAULT_NOTIFY_HISTORY_PATH = Path("data/fortios-notify-history.json")
DEFAULT_NOTIFICATION_SETTINGS_PATH = Path("data/notification-settings.json")


_VALID_HEALTH_STATUSES = frozenset(
    {
        HEALTH_STATUS_OK,
        HEALTH_STATUS_WARNING,
        HEALTH_STATUS_ERROR,
        HEALTH_STATUS_RUNNING,
        HEALTH_STATUS_SKIPPED,
    }
)


def _is_valid_health_timestamp(value: Any) -> bool:
    """None/absent is fine (e.g. a source that's never succeeded has no lastSuccessAt yet) -- but
    anything present must be a string that actually parses, since every reader of this field
    (classify_source_severity(), _merge_health_source()'s clobber-guard) calls
    parse_health_timestamp() on it unconditionally and that raises ValueError on garbage like
    "not-a-date", which used to propagate straight out of main().
    """
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    try:
        parse_health_timestamp(value)
    except (ValueError, AttributeError):
        return False
    return True


def _is_strict_int(value: Any) -> bool:
    # bool is a subclass of int in Python (isinstance(True, int) is True) -- a stray boolean
    # here would silently pass a plain isinstance(value, int) check, so it's excluded explicitly.
    return isinstance(value, int) and not isinstance(value, bool)


def _is_valid_health_source_record(record: Any) -> bool:
    if not isinstance(record, dict):
        return False

    status = record.get("status")
    if status is not None and status not in _VALID_HEALTH_STATUSES:
        return False

    for timestamp_field in ("lastAttemptAt", "lastSuccessAt", "lastErrorAt"):
        if not _is_valid_health_timestamp(record.get(timestamp_field)):
            return False

    consecutive_failures = record.get("consecutiveFailures")
    if consecutive_failures is not None and not _is_strict_int(consecutive_failures):
        return False

    items_collected = record.get("itemsCollected")
    if items_collected is not None and not _is_strict_int(items_collected):
        return False

    duration_seconds = record.get("durationSeconds")
    if duration_seconds is not None and (
        isinstance(duration_seconds, bool)
        or not isinstance(duration_seconds, (int, float))
    ):
        return False

    last_error = record.get("lastError")
    return not (last_error is not None and not isinstance(last_error, str))


def _is_valid_health_state(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    sources = payload.get("sources", {})
    if not isinstance(sources, dict):
        return False
    return all(_is_valid_health_source_record(record) for record in sources.values())


def read_health_state(path: Path) -> dict[str, Any]:
    """Tolerant read of the health-tracking file: corrupt JSON, a wrong top-level type, or a
    malformed "sources" map is treated as a fresh empty state rather than raised. Health tracking
    is diagnostic, never allowed to abort the actual catalog collection it watches over -- a
    truncated or garbled fortios-health.json used to raise JSONDecodeError right here and take
    the whole run down with it.
    """
    return read_json_tolerant(
        path, {"sources": {}}, validate=_is_valid_health_state, archive_suffix="corrupt"
    )


# A health entry is meant to be a short, human-readable summary shown directly in the UI, never
# a debugging dump -- scrub anything that looks like a credential/token before it's ever
# persisted, and never let a full traceback or SMTP auth detail leak through.
_HEALTH_SECRET_PATTERNS = (
    re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*\S+"),
    re.compile(r"(?i)Authorization:\s*\S+"),
)


def sanitize_health_error(error: BaseException | str | None) -> str | None:
    """A short, readable error string safe to store in the health file and show in the UI --
    never a full traceback, and never a credential/token that might have leaked into an
    exception message (e.g. an SMTP auth failure).
    """
    if error is None:
        return None
    message = str(error).strip()
    if not message:
        message = (
            type(error).__name__
            if isinstance(error, BaseException)
            else "Erreur inconnue"
        )
    for pattern in _HEALTH_SECRET_PATTERNS:
        message = pattern.sub("[masqué]", message)
    message = message.splitlines()[0]  # one line only, never a multi-line traceback
    return message[:300]


@dataclass
class HealthSourceResult:
    """What a single source's collection attempt produced this run, fed into
    record_health_results() at commit time. `started_at` is stamped once per attempt (via
    health_mark_running(), or manually for sources that don't use it) and doubles as the
    ordering key that keeps an older run's result from clobbering a newer one.
    """

    status: str
    started_at: str
    duration_seconds: float
    items_collected: int | None = None
    error: BaseException | str | None = None


def _merge_health_source(
    existing: dict[str, Any], result: HealthSourceResult
) -> dict[str, Any]:
    # An older/slower run's result must never clobber what a later attempt already recorded --
    # lastAttemptAt is the ordering key (this run's own started_at vs whatever's on disk).
    # Compared as parsed datetimes, not raw strings: started_at now carries microsecond
    # resolution (see utc_now_precise()) so two attempts beginning within the same whole second
    # are still distinguishable, but a handful of pre-existing records on disk may still be at
    # the old whole-second precision -- as plain strings, "...:00Z" sorts AFTER "...:00.5...Z"
    # ('.' < 'Z' in ASCII) even though .0 is chronologically earlier than .5, which would wrongly
    # reject a legitimate same-second update. Parsing both sides sidesteps that entirely.
    existing_attempt_at = existing.get("lastAttemptAt")
    if existing_attempt_at and parse_health_timestamp(
        existing_attempt_at
    ) > parse_health_timestamp(result.started_at):
        return existing

    record = dict(existing)
    record["status"] = result.status
    record["lastAttemptAt"] = result.started_at
    record["durationSeconds"] = result.duration_seconds
    if result.items_collected is not None:
        record["itemsCollected"] = result.items_collected

    if result.status == HEALTH_STATUS_OK:
        record["lastSuccessAt"] = result.started_at
        record["consecutiveFailures"] = 0
        record["lastError"] = None
    elif result.status == HEALTH_STATUS_WARNING:
        # Succeeded technically, but the result looked abnormal (e.g. an empty result where one
        # wasn't expected, or a handful of items skipped out of a much larger batch) -- still
        # counts as a success for lastSuccessAt/consecutiveFailures purposes (the run did
        # complete and produce data), but the anomaly stays visible via status/lastError so the
        # UI still renders it orange rather than green.
        record["lastSuccessAt"] = result.started_at
        record["consecutiveFailures"] = 0
        record["lastErrorAt"] = result.started_at
        record["lastError"] = sanitize_health_error(result.error)
    elif result.status == HEALTH_STATUS_ERROR:
        record["lastErrorAt"] = result.started_at
        record["lastError"] = sanitize_health_error(result.error)
        record["consecutiveFailures"] = existing.get("consecutiveFailures", 0) + 1
        # lastSuccessAt is deliberately never touched here.
    elif result.status == HEALTH_STATUS_SKIPPED:
        # Deliberately not run this time (--skip-network, or the corresponding --*-catalog flag
        # left off) -- distinct from a failure: never touch consecutiveFailures, lastSuccessAt,
        # or lastError.
        record.setdefault("consecutiveFailures", existing.get("consecutiveFailures", 0))
    return record


def health_mark_running(health_path: Path, source_id: str) -> str:
    """Stamp `source_id` as currently running, written immediately (not batched with the rest of
    the run's results) so a process that dies mid-collection leaves a visibly stuck "running"
    status with a stale lastAttemptAt, rather than silently vanishing with no trace at all.
    Returns the started_at timestamp — reuse it when building this source's HealthSourceResult
    so both writes agree on the same attempt's identity.
    """
    started_at = utc_now_precise()
    try:
        with cross_process_lock(health_path):
            state = read_health_state(health_path)
            sources = state.setdefault("sources", {})
            existing = sources.get(source_id, {})
            record = dict(existing)
            record["status"] = HEALTH_STATUS_RUNNING
            record["lastAttemptAt"] = started_at
            sources[source_id] = record
            state["updatedAt"] = utc_now()
            write_json(health_path, state)
    except OSError:
        pass  # health tracking is best-effort -- never let it block the actual collection
    return started_at


def record_health_results(
    health_path: Path, results: dict[str, HealthSourceResult]
) -> None:
    """Apply a batch of this run's HealthSourceResults to the health-state file, atomically and
    under the same cross-process lock as every other writer.
    """
    with cross_process_lock(health_path):
        state = read_health_state(health_path)
        sources = state.setdefault("sources", {})
        for source_id, result in results.items():
            sources[source_id] = _merge_health_source(
                sources.get(source_id, {}), result
            )
        state["updatedAt"] = utc_now()
        write_json(health_path, state)


def parse_health_timestamp(value: str) -> dt.datetime:
    """Always returns a timezone-aware datetime normalized to UTC -- raises ValueError for
    anything that isn't unambiguously one (a naive timestamp with no "Z"/explicit offset, e.g.
    "2026-07-17T07:00:00", or a bare date like "2026-07-17"), rather than silently guessing what
    timezone a naive value meant. Every comparison in this module (classify_source_severity(),
    _merge_health_source()'s clobber-guard) works against dt.datetime.now(dt.UTC) -- an aware
    value -- and comparing that to a naive one raises TypeError deep inside those functions
    instead of the much-earlier, already-handled ValueError this raises here. Both
    _is_valid_health_timestamp() (fortios_watch.py) and outbox timestamp validation
    (fortios_notify.py, via this same function) rely on that ValueError to reject a bad value up
    front.
    """
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"Horodatage sans fuseau horaire : {value!r}")
    return parsed.astimezone(dt.UTC)


def classify_source_severity(
    record: dict[str, Any],
    *,
    now: str | None = None,
    max_age_hours: float = 48,
    repeated_failure_threshold: int = 2,
) -> str:
    """One of "ok" (green), "warning" (orange), or "error" (red), combining status, consecutive
    failures, and data age into the single traffic-light signal the UI shows per source:
    - red: repeated failures, or data older than `max_age_hours` (or never succeeded at all);
    - orange: aging-but-not-stale, a single recent failure, a warning result, or a deliberate skip;
    - green: a recent, clean success.
    """
    now_dt = parse_health_timestamp(now) if now else dt.datetime.now(dt.UTC)
    consecutive_failures = record.get("consecutiveFailures") or 0
    last_success_at = record.get("lastSuccessAt")
    status = record.get("status")

    if consecutive_failures >= repeated_failure_threshold:
        return "error"
    if not last_success_at:
        # No confirmed success yet is only a hard error when the source actually finished with a
        # real error. A source mid-collection (running), deliberately skipped, or that finished
        # with a mere warning (succeeded, just flagged as suspicious — see
        # _merge_health_source()) is not a failure and must never render as full red just because
        # this happens to be its first-ever attempt.
        return "error" if status == HEALTH_STATUS_ERROR else "warning"
    age_hours = (
        now_dt - parse_health_timestamp(last_success_at)
    ).total_seconds() / 3600
    if age_hours > max_age_hours:
        return "error"
    if (
        status in (HEALTH_STATUS_WARNING, HEALTH_STATUS_SKIPPED)
        or consecutive_failures > 0
    ):
        return "warning"
    return "ok"


def count_firmwares(state: dict[str, Any]) -> int:
    return sum(
        len(model.get("firmwares", []))
        for product in state.get("products", [])
        for model in product.get("models", [])
    )


def count_firmwares_for_product(state: dict[str, Any], product_id: str) -> int:
    return sum(
        len(model.get("firmwares", []))
        for product in state.get("products", [])
        if product.get("id") == product_id
        for model in product.get("models", [])
    )


def versions_by_product(state: dict[str, Any]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for product in state.get("products", []):
        product_id = product.get("id")
        if not product_id:
            continue
        versions = result.setdefault(product_id, set())
        for model in product.get("models", []):
            for firmware in model.get("firmwares", []):
                if firmware.get("version"):
                    versions.add(firmware["version"])
    return result


def release_notes_by_product(state: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Map product id -> version -> Fortinet release-notes URL from the collected catalog.

    Only what the catalog really publishes is returned: a firmware without a release-notes
    link contributes no entry, and the notification renderer then simply shows no link.
    """
    result: dict[str, dict[str, str]] = {}
    for product in state.get("products", []):
        product_id = product.get("id")
        if not product_id:
            continue
        versions = result.setdefault(product_id, {})
        for model in product.get("models", []):
            for firmware in model.get("firmwares", []):
                version = firmware.get("version")
                if not version or version in versions:
                    continue
                link = (firmware.get("links") or {}).get("release-notes")
                if isinstance(link, str) and link.strip():
                    versions[version] = link.strip()
    return result


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def is_fortios_version(version: str) -> bool:
    parts = version_key(version)
    return len(parts) >= 3 and parts[0] in {5, 6, 7, 8}


def model_sort_key(model_id: str) -> tuple[str, tuple[int, ...], str]:
    family = re.match(r"^[A-Z]+", model_id)
    family_id = family.group(0) if family else model_id
    family_rank = {"FGT": "0", "FWF": "1", "FGR": "2", "FFW": "3"}.get(family_id, "9")
    numbers = tuple(int(part) for part in re.findall(r"\d+", model_id))
    return (family_rank, numbers, model_id)


def unique_in_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            output.append(item)
    return output


def normalize_state(payload: dict[str, Any] | None) -> dict[str, Any]:
    payload = payload or {}
    return {
        "generatedAt": payload.get("generatedAt") or utc_now(),
        "products": payload.get("products")
        if isinstance(payload.get("products"), list)
        else [],
        "paths": payload.get("paths") if isinstance(payload.get("paths"), list) else [],
        "advisories": payload.get("advisories")
        if isinstance(payload.get("advisories"), list)
        else [],
        "compatibilities": payload.get("compatibilities")
        if isinstance(payload.get("compatibilities"), list)
        else [],
        "cves": payload.get("cves") if isinstance(payload.get("cves"), list) else [],
        "fortiosLifecycle": payload.get("fortiosLifecycle")
        if isinstance(payload.get("fortiosLifecycle"), dict)
        else {},
        "searchHistory": payload.get("searchHistory")
        if isinstance(payload.get("searchHistory"), list)
        else [],
    }


def ensure_product(
    state: dict[str, Any], product_id: str, label: str
) -> dict[str, Any]:
    for product in state["products"]:
        if product.get("id") == product_id:
            product.setdefault("label", label)
            product.setdefault("models", [])
            return product

    product = {"id": product_id, "label": label, "models": []}
    state["products"].append(product)
    return product


def ensure_model(
    state: dict[str, Any], product_id: str, model_id: str
) -> dict[str, Any]:
    product = ensure_product(
        state, product_id, PRODUCT_LABELS.get(product_id, DEFAULT_PRODUCT_LABEL)
    )
    for model in product["models"]:
        if model.get("id") == model_id:
            model.setdefault("label", model_id)
            model.setdefault("firmwares", [])
            return model

    model = {"id": model_id, "label": model_label(model_id), "firmwares": []}
    product["models"].append(model)
    product["models"].sort(key=lambda item: model_sort_key(item.get("id", "")))
    return model


def upsert_firmware(state: dict[str, Any], item: Firmware) -> bool:
    model = ensure_model(state, item.product, item.model)
    for existing in model["firmwares"]:
        if existing.get("version") == item.version:
            before = dict(existing)
            if item.build and item.build != "-":
                existing["build"] = item.build
            if item.notes:
                existing["notes"] = sorted(
                    set(existing.get("notes", [])) | set(item.notes)
                )
            if item.links:
                existing["links"] = {**existing.get("links", {}), **item.links}
            return existing != before

    entry = {
        "version": item.version,
        "build": item.build,
        "notes": list(item.notes),
        # Stamped only here, at first sight of this version — lets the frontend show a
        # "new" badge for a couple weeks. Never touched again once the entry exists, so a
        # daily rescan of an already-known version doesn't reset it.
        "discoveredAt": dt.datetime.now(dt.timezone.utc).date().isoformat(),
    }
    if item.links:
        entry["links"] = dict(item.links)
    model["firmwares"].append(entry)
    model["firmwares"].sort(key=lambda firmware: version_key(firmware["version"]))
    return True


def model_label(model_id: str) -> str:
    if model_id.startswith("FGT"):
        return f"FortiGate-{model_id[3:]}"
    if model_id.startswith("FWF"):
        return f"FortiWiFi-{model_id[3:]}"
    if model_id.startswith("FGR"):
        return f"FortiGate Rugged-{model_id[3:]}"
    if model_id.startswith("FFW"):
        return f"FortiFirewall-{model_id[3:]}"
    return model_id


def normalize_doc_model(doc_model: str) -> str:
    prefix, value = doc_model.split("-", 1)
    compact = value.replace("-", "")
    if prefix == "FG":
        return f"FGT{compact}"
    return f"{prefix}{compact}"


class UnsafeRedirectError(urllib.error.URLError):
    """A redirect target was refused before any connection to it was opened."""


class _RedirectValidatingHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that vets every Location before it is ever opened.

    Validating only the initial URL would not actually constrain where a
    request ends up: the stdlib's default handler happily follows a redirect
    from an allowed host to any other host, and even downgrades https to
    http/ftp. Every hop therefore goes through ``validator`` first, and a
    refused hop raises UnsafeRedirectError before any connection to it.
    """

    def __init__(self, validator: Callable[[str], bool]) -> None:
        super().__init__()
        self._validator = validator

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        if not self._validator(newurl):
            raise UnsafeRedirectError(f"redirection refusée : {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def read_url_with_retry(
    request: urllib.request.Request,
    timeout: int,
    retries: int = 3,
    redirect_validator: Callable[[str], bool] | None = None,
) -> bytes:
    """Open and fully read one HTTP response, retrying transient failures at either stage.

    A server/proxy may close the response halfway through ``read()``
    (``http.client.IncompleteRead``), which is exactly what happened to the daily FortiClient/EMS
    scrape on 2026-07-30.  A partial response is never usable: close it and replay the complete
    request with bounded exponential backoff.  Retry only HTTP statuses commonly used for
    transient throttling or server/gateway failures; definitive responses such as 404 fail fast.

    With ``redirect_validator``, every HTTP redirect target (Location) is checked against it
    *before* it is opened: an admitted URL must not be able to turn into a request to an
    unexpected host, port or scheme via a 30x response. A refused target raises
    UnsafeRedirectError at once — never retried, and no connection is ever made to it.
    """
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            if redirect_validator is None:
                response = urllib.request.urlopen(request, timeout=timeout)
            else:
                opener = urllib.request.build_opener(
                    _RedirectValidatingHandler(redirect_validator)
                )
                response = opener.open(request, timeout=timeout)
            with response:
                return response.read()
        except UnsafeRedirectError:
            raise  # definitive refusal: retrying could only repeat the same refusal
        except urllib.error.HTTPError as error:
            if error.code not in {408, 429} and not 500 <= error.code < 600:
                raise
            last_error = error
            if attempt < retries - 1:
                time.sleep((2**attempt) + random.uniform(0, 1))
        except (
            urllib.error.URLError,
            TimeoutError,
            ConnectionError,
            OSError,
            http.client.IncompleteRead,
            http.client.RemoteDisconnected,
        ) as error:
            last_error = error
            if attempt < retries - 1:
                time.sleep((2**attempt) + random.uniform(0, 1))
    assert (
        last_error is not None
    )  # retries >= 1 and every successful attempt returns above
    raise last_error


def fetch_text(
    url: str, timeout: int, redirect_validator: Callable[[str], bool] | None = None
) -> str:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "sns-fortios-upgrade-watch/0.1"},
    )
    return read_url_with_retry(
        request, timeout, redirect_validator=redirect_validator
    ).decode("utf-8", errors="ignore")


def html_to_text(raw_html: str) -> str:
    text = re.sub(
        r"<script\b[^>]*>.*?</script>", " ", raw_html, flags=re.IGNORECASE | re.DOTALL
    )
    text = re.sub(
        r"<style\b[^>]*>.*?</style>", " ", text, flags=re.IGNORECASE | re.DOTALL
    )
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def _discover_published_versions(
    product_slug: str,
    doc_slug: str,
    label: str,
    major_versions: tuple[str, ...],
    timeout: int,
) -> tuple[list[str], list[str]]:
    """Versions listed on each train page, plus the trains Fortinet has no page for (yet).

    Fortinet only publishes `<base>/product/<slug>/<train>` once that train exists: a 404 means
    "nothing published on this train yet, try the others", never a reason to abort the whole
    catalog (that's how the 8.4/8.2 pages took the FortiOS and FortiClient/EMS sources down in
    2026-09 — the first train of DEFAULT_DOCS_MAJOR_VERSIONS had no page at all). Every other
    failure (timeout, DNS, 5xx, 403...) still fails the source, and a run where no train could be
    read *at all* raises: an empty catalog must never masquerade as a successful, genuinely
    empty scan. Idem when a page answers 200 but carries none of the expected release-notes links
    (a parsing breakage, not an empty train).
    """
    versions: set[str] = set()
    missing: list[str] = []
    for major in major_versions:
        url = f"{FORTINET_DOCS_BASE_URL}/product/{product_slug}/{major}"
        try:
            raw_html = fetch_text(url, timeout)
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            missing.append(f"{product_slug}/{major}")
            continue
        versions.update(
            re.findall(
                rf"/document/{re.escape(product_slug)}/(\d+\.\d+\.\d+)/{re.escape(doc_slug)}",
                raw_html,
            )
        )
    if not versions:
        details = (
            f"branches absentes (HTTP 404) : {', '.join(missing)}"
            if missing
            else "aucune version publiée trouvée sur les pages testées"
        )
        raise ValueError(
            f"Aucune branche {label} exploitable sur docs.fortinet.com ({details})"
        )
    return sorted(versions, key=version_key), missing


def discover_docs_versions(
    major_versions: tuple[str, ...], timeout: int
) -> tuple[list[str], list[str]]:
    return _discover_published_versions(
        "fortigate", "fortios-release-notes", "FortiOS", major_versions, timeout
    )


def parse_docs_release(version: str, timeout: int) -> DocsRelease | None:
    source_url = (
        f"{FORTINET_DOCS_BASE_URL}/document/fortigate/{version}/fortios-release-notes"
    )
    raw_html = fetch_text(source_url, timeout)
    text = html_to_text(raw_html)

    build_match = re.search(
        rf"This guide provides release information for FortiOS\s+{re.escape(version)}\s+build\s+([0-9]+)",
        text,
        flags=re.IGNORECASE,
    )
    build = build_match.group(1) if build_match else "-"

    marker = f"FortiOS {version} supports the following models."
    start = text.find(marker)
    if start == -1:
        return None

    end_candidates = [
        text.find("FortiGate 6000 and 7000 support", start),
        text.find("Special branch supported models", start),
        text.find("Previous", start),
    ]
    end_candidates = [index for index in end_candidates if index != -1]
    end = min(end_candidates) if end_candidates else start + 12000
    block = text[start:end]

    models = tuple(
        sorted(
            {normalize_doc_model(item) for item in DOC_MODEL_RE.findall(block)},
            key=model_sort_key,
        )
    )
    if not models:
        return None
    return DocsRelease(
        version=version, build=build, models=models, source_url=source_url
    )


def collect_docs_catalog(
    major_versions: tuple[str, ...], timeout: int
) -> tuple[dict[str, Any], list[str]]:
    state = normalize_state({})
    versions, missing_branches = discover_docs_versions(major_versions, timeout)
    # A train with no published page is reported as a skip, not as an error: the other trains are
    # still collected (see _discover_published_versions). It shows up in the run report so a
    # genuinely new train (e.g. 8.4 before Fortinet publishes it) stays visible.
    skipped: list[str] = [
        f"{branch} (page absente, HTTP 404)" for branch in missing_branches
    ]

    for version in versions:
        try:
            release = parse_docs_release(version, timeout)
        except (urllib.error.URLError, TimeoutError, OSError):
            skipped.append(version)
            continue
        if not release:
            skipped.append(version)
            continue

        for model_id in release.models:
            firmware = Firmware(
                product=DEFAULT_PRODUCT_ID,
                model=model_id,
                version=release.version,
                build=release.build,
                notes=("release-notes",),
                links={
                    "release-notes": release_notes_url(
                        DEFAULT_PRODUCT_ID, release.version
                    )
                },
            )
            upsert_firmware(state, firmware)

    return state, skipped


# The Upgrade Path Tool's own availability items carry a maturity code per version ("M" = Mature,
# "F" = Feature, "" = the tool doesn't classify that old version) that release-notes scraping
# (collect_docs_catalog above) never sees. This is a property of the FortiOS version itself, not
# of the hardware model, so one reference model is enough to read every version's status — no need
# to repeat this call per model.
FORTIOS_MATURITY_REFERENCE_MODEL = "FGT60F"

# Translation to the two maturity labels the catalog and the UI have always stored, plus the
# "None" the UI already treats as "not classified". Any other token is a vocabulary we don't
# understand: fail closed rather than invent a classification (the caller treats maturity as a
# soft enrichment, so a future Fortinet change degrades to "no maturity", never to wrong data).
MATURITY_TYPE_LABELS = {
    "M": "Mature",
    "F": "Feature",
    "Mature": "Mature",
    "Feature": "Feature",
    "": "None",
    None: "None",
}


def _availability_entry(item: Any, context: str) -> tuple[str, str, str]:
    """One version item of a payload (path hop or availability entry) -> (version, build, type).

    Every usable field is read from the new response keys (`version`, `build`, `type`); a missing
    or non-string version — the one field the whole catalog is keyed on — fails closed instead of
    silently producing a gap-free-looking hop list.
    """
    if not isinstance(item, dict):
        raise UpgradeToolResponseError(
            f"Réponse Upgrade Path Tool invalide ({context}) : entrée de version attendue, "
            f"reçu {item!r}."
        )
    version = item.get("version")
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise UpgradeToolResponseError(
            f"Réponse Upgrade Path Tool invalide ({context}) : version manquante ou invalide "
            f"({item!r})."
        )
    build = item.get("build")
    if build is not None and not isinstance(build, str):
        raise UpgradeToolResponseError(
            f"Réponse Upgrade Path Tool invalide ({context}) : build non textuel "
            f"({item!r})."
        )
    item_type = item.get("type")
    if item_type not in MATURITY_TYPE_LABELS:
        raise UpgradeToolResponseError(
            f"Réponse Upgrade Path Tool invalide ({context}) : maturité inconnue "
            f"({item_type!r})."
        )
    return version, (build or "-"), MATURITY_TYPE_LABELS[item_type]


def fetch_fortios_version_maturity(timeout: int) -> dict[str, str]:
    payload = fetch_upgrade_tool_payload(
        PRODUCTS[DEFAULT_PRODUCT_ID]["slug"],
        FORTIOS_MATURITY_REFERENCE_MODEL,
        timeout,
    )
    context = f"{PRODUCTS[DEFAULT_PRODUCT_ID]['slug']}/{FORTIOS_MATURITY_REFERENCE_MODEL}"
    maturity: dict[str, str] = {}
    for item in _payload_list(payload, "availableFrom", context) + _payload_list(
        payload, "availableTo", context
    ):
        version, _build, label = _availability_entry(item, context)
        maturity[version] = label
    return maturity


def apply_fortios_maturity(state: dict[str, Any], maturity: dict[str, str]) -> None:
    if not maturity:
        return
    for product in state["products"]:
        if product.get("id") != DEFAULT_PRODUCT_ID:
            continue
        for model in product.get("models", []):
            for firmware in model.get("firmwares", []):
                version = firmware.get("version")
                if version in maturity:
                    firmware["maturity"] = maturity[version]


# endoflife.date is a community-maintained tracker, not Fortinet itself, but it's the only public,
# no-account source for FortiOS support/EOL dates we found — the official page
# (support.fortinet.com/Information/ProductLifeCycle.aspx) requires a FortiCloud login. Per-train
# only (e.g. "7.6"), not per patch version — Fortinet's own support windows are per major train.
FORTIOS_EOL_API_URL = "https://endoflife.date/api/fortios.json"


def fetch_fortios_lifecycle(timeout: int) -> dict[str, dict[str, str | None]]:
    entries = json.loads(fetch_text(FORTIOS_EOL_API_URL, timeout))
    lifecycle: dict[str, dict[str, str | None]] = {}
    for entry in entries:
        train = entry.get("cycle")
        if not train:
            continue
        lifecycle[str(train)] = {
            "releaseDate": entry.get("releaseDate"),
            "support": entry.get("support"),
            "eol": entry.get("eol"),
        }
    return lifecycle


# FortiClient has no hardware "models" — the three OS installers are close enough to that concept
# (each ships its own build number, tracked in its own release notes) to reuse the same model
# slot. FortiClient EMS has a single implicit model.
FORTICLIENT_PLATFORM_DOC_SLUGS = {
    "windows": "windows-release-notes",
    "macos": "macos-release-notes",
    "linux": "linux-release-notes",
}
FORTICLIENT_PLATFORM_LABELS = {
    "windows": "FortiClient (Windows)",
    "macos": "FortiClient (macOS)",
    "linux": "FortiClient (Linux)",
}
FORTICLIENT_EMS_DOC_SLUG = "ems-release-notes"
FORTICLIENT_EMS_MODEL_ID = "ems"


def discover_forticlient_versions(
    major_versions: tuple[str, ...], doc_slug: str, timeout: int
) -> tuple[list[str], list[str]]:
    return _discover_published_versions(
        "forticlient", doc_slug, "FortiClient", major_versions, timeout
    )


def parse_forticlient_build(version: str, doc_slug: str, timeout: int) -> str | None:
    url = f"{FORTINET_DOCS_BASE_URL}/document/forticlient/{version}/{doc_slug}"
    raw_html = fetch_text(url, timeout)
    text = html_to_text(raw_html)
    match = re.search(
        rf"{re.escape(version)}\s+build\s+(\S+)\s*[.:]", text, flags=re.IGNORECASE
    )
    return match.group(1) if match else None


def collect_forticlient_catalog(
    major_versions: tuple[str, ...], timeout: int
) -> tuple[dict[str, Any], list[str]]:
    """FortiClient (one model per OS) + FortiClient EMS catalogs, scraped from release notes.

    Neither product is in Fortinet's Upgrade Path Tool, so there's no products.json/upgrade-path
    endpoint to use like collect_tool_catalog does for FortiAnalyzer/FortiManager — this falls
    back to the same release-notes scraping as collect_docs_catalog, just without a "Supported
    models" section to parse (the model here is simply which release-notes doc we found it in).
    """
    state = normalize_state({})
    skipped: list[str] = []
    skipped_branches: list[str] = []

    fc_product = ensure_product(
        state, FORTICLIENT_PRODUCT_ID, PRODUCT_LABELS[FORTICLIENT_PRODUCT_ID]
    )
    for platform, doc_slug in FORTICLIENT_PLATFORM_DOC_SLUGS.items():
        if not any(model.get("id") == platform for model in fc_product["models"]):
            fc_product["models"].append(
                {
                    "id": platform,
                    "label": FORTICLIENT_PLATFORM_LABELS[platform],
                    "firmwares": [],
                }
            )

        versions, missing_branches = discover_forticlient_versions(
            major_versions, doc_slug, timeout
        )
        skipped_branches.extend(
            f"{branch} (page absente, HTTP 404)" for branch in missing_branches
        )
        for version in versions:
            try:
                build = parse_forticlient_build(version, doc_slug, timeout)
            except (urllib.error.URLError, TimeoutError, OSError):
                build = None
            if not build:
                skipped.append(f"forticlient/{platform}/{version}")
                continue
            upsert_firmware(
                state,
                Firmware(
                    product=FORTICLIENT_PRODUCT_ID,
                    model=platform,
                    version=version,
                    build=build,
                    notes=("release-notes",),
                    links={
                        "release-notes": f"{FORTINET_DOCS_BASE_URL}/document/forticlient/{version}/{doc_slug}"
                    },
                ),
            )

    ems_product = ensure_product(
        state, FORTICLIENT_EMS_PRODUCT_ID, PRODUCT_LABELS[FORTICLIENT_EMS_PRODUCT_ID]
    )
    if not any(
        model.get("id") == FORTICLIENT_EMS_MODEL_ID for model in ems_product["models"]
    ):
        ems_product["models"].append(
            {
                "id": FORTICLIENT_EMS_MODEL_ID,
                "label": "FortiClient EMS",
                "firmwares": [],
            }
        )

    ems_versions, ems_missing_branches = discover_forticlient_versions(
        major_versions, FORTICLIENT_EMS_DOC_SLUG, timeout
    )
    skipped_branches.extend(
        f"{branch} (page absente, HTTP 404)" for branch in ems_missing_branches
    )
    for version in ems_versions:
        try:
            build = parse_forticlient_build(version, FORTICLIENT_EMS_DOC_SLUG, timeout)
        except (urllib.error.URLError, TimeoutError, OSError):
            build = None
        if not build:
            skipped.append(f"forticlient-ems/{version}")
            continue
        upsert_firmware(
            state,
            Firmware(
                product=FORTICLIENT_EMS_PRODUCT_ID,
                model=FORTICLIENT_EMS_MODEL_ID,
                version=version,
                build=build,
                notes=("release-notes",),
                links={
                    "release-notes": f"{FORTINET_DOCS_BASE_URL}/document/forticlient/{version}/{FORTICLIENT_EMS_DOC_SLUG}"
                },
            ),
        )

    return state, unique_in_order(skipped_branches + skipped)


# The Upgrade Path Tool's per-item `links` map is keyed by the release-notes section slug; the
# catalog and the UI have always named those same sections with short keys (the R/K/U/B badges,
# plus "release-notes" for the general page / D badge). One mapping for both notes and links so a
# section can never be listed as a badge without its deep link, or the other way around.
OFFICIAL_NOTE_LINK_SLUGS = {
    "resolved-issues": "resolved",
    "known-issues": "known",
    "upgrade-information": "upgrade",
    "changes-in-default-behavior": "behavior",
    "special-notices": "special",
}


def _official_links(item: dict[str, Any]) -> dict[str, Any]:
    links = item.get("links")
    if links is None:
        return {}
    if not isinstance(links, dict):
        raise UpgradeToolResponseError(
            f"Réponse Upgrade Path Tool invalide : 'links' doit être un objet "
            f"(version {item.get('version')!r})."
        )
    return links


def official_note_keys(item: dict[str, Any]) -> tuple[str, ...]:
    notes = [
        OFFICIAL_NOTE_LINK_SLUGS[slug]
        for slug in _official_links(item)
        if slug in OFFICIAL_NOTE_LINK_SLUGS
    ]
    return tuple(unique_in_order(notes))


def release_notes_url(product_id: str, version: str) -> str:
    product_slug = PRODUCTS.get(product_id, PRODUCTS[DEFAULT_PRODUCT_ID])["slug"]
    doc_slug = RELEASE_NOTES_DOC_SLUGS.get(product_id, "release-notes")
    return f"{FORTINET_DOCS_BASE_URL}/document/{product_slug}/{version}/{doc_slug}"


def official_note_links(
    item: dict[str, Any], product_id: str, version: str
) -> dict[str, str]:
    """Deep links into the version's release notes, one per section badge (R/K/U/B), plus a
    "release-notes" entry for the general page (the D badge).

    Fortinet now returns those deep links directly in the item's `links` map. Only absolute
    https:// URLs are kept: they end up as hrefs in the UI, so anything else is dropped rather
    than trusted blind.
    """
    links: dict[str, str] = {"release-notes": release_notes_url(product_id, version)}
    for slug, url in _official_links(item).items():
        note = OFFICIAL_NOTE_LINK_SLUGS.get(slug)
        if note and isinstance(url, str) and url.startswith("https://"):
            links[note] = url
    return links


def _decode_upgrade_tool_payload(raw: bytes, context: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError as error:
        raise UpgradeToolResponseError(
            f"Réponse Upgrade Path Tool illisible ({context}) : {error}"
        ) from error
    if not isinstance(payload, dict):
        raise UpgradeToolResponseError(
            f"Réponse Upgrade Path Tool invalide ({context}) : objet JSON attendu."
        )
    return payload


def _payload_list(payload: dict[str, Any], key: str, context: str) -> list[Any]:
    """One list field of an upgrade-path payload — fail closed when it isn't a list at all."""
    value = payload.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise UpgradeToolResponseError(
            f"Réponse Upgrade Path Tool invalide ({context}) : '{key}' doit être une liste."
        )
    return value


def fetch_upgrade_tool_payload(
    product_slug: str,
    model: str,
    timeout: int,
    from_version: str | None = None,
    to_version: str | None = None,
) -> dict[str, Any]:
    """GET the Upgrade Path Tool's JSON for one product/model, optionally between two versions.

    This is the endpoint the tool's own pages call since 2026-09, when the previous
    `/upgrade-tool/products/<slug>.json` + `POST /upgrade-tool/upgrade-path` pair was retired
    (both now answer 404). It is observed on a public page's JS bundle, not a contractually
    guaranteed API — so an unexpected shape raises UpgradeToolResponseError instead of being
    mistaken for "no versions". `from`/`to` are only sent as a pair: a path is only meaningful
    between an explicit source and target, so a lone bound is dropped rather than sent alone.
    """
    params = {"product": product_slug, "model": model}
    if from_version and to_version:
        params["from"] = from_version
        params["to"] = to_version
    request = urllib.request.Request(
        f"{FORTINET_UPGRADE_TOOL_API_URL}?{urllib.parse.urlencode(params)}",
        headers={
            "User-Agent": "sns-fortios-upgrade-watch/0.1",
            "Referer": f"{FORTINET_DOCS_BASE_URL}/upgrade-tool/{product_slug}",
        },
    )
    return _decode_upgrade_tool_payload(
        read_url_with_retry(request, timeout), f"{product_slug}/{model}"
    )


_FORTINET_MODEL_ALIASES: dict[str, dict[str, str]] = {}


def normalize_model_key(value: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", value.upper())


def fortinet_model_alias_map(product_slug: str, timeout: int) -> dict[str, str]:
    """Normalized product_name -> hardware_model_name for one Fortinet product.

    Our own FortiGate catalog builds model ids from a hand-rolled prefix
    convention (FGT/FWF/FGR/FFW + suffix) derived from release-notes scraping,
    which only coincidentally matches the id the Upgrade Path Tool actually
    expects (its own hardware_model_name) for simple models like FGT60F. As
    soon as a model has a qualifier (POE, DSL, SFP, BP, 3G4G...), Fortinet's
    real id uses its own abbreviation (e.g. FortiGate-100F is FG100F, not
    FGT100F) and the coincidence breaks — silently returning no path. This
    resolves our id through the tool's own product list instead of guessing.
    """
    if product_slug not in _FORTINET_MODEL_ALIASES:
        alias_map: dict[str, str] = {}
        for entry in fetch_product_models(product_slug, timeout):
            name = entry.get("product_name")
            hardware_model_name = entry.get("hardware_model_name")
            if name and hardware_model_name:
                alias_map[normalize_model_key(name)] = hardware_model_name
        _FORTINET_MODEL_ALIASES[product_slug] = alias_map
    return _FORTINET_MODEL_ALIASES[product_slug]


def resolve_fortinet_model(product_id: str, model_id: str, timeout: int) -> str:
    if product_id != DEFAULT_PRODUCT_ID:
        return model_id
    try:
        alias_map = fortinet_model_alias_map(PRODUCTS[product_id]["slug"], timeout)
    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        json.JSONDecodeError,
        UpgradeToolResponseError,
    ):
        return model_id
    return alias_map.get(normalize_model_key(model_label(model_id)), model_id)


def fetch_official_upgrade_path(
    requested: OfficialPathRequest, timeout: int
) -> tuple[UpgradePath, list[Firmware]] | None:
    if requested.product not in PRODUCTS:
        return None  # not in Fortinet's Upgrade Path Tool (e.g. FortiClient/EMS) — no path to fetch.
    if version_key(requested.to_version) <= version_key(requested.from_version):
        raise ValueError(UPGRADE_DIRECTION_ERROR)
    product_slug = PRODUCTS[requested.product]["slug"]
    # Alias resolution only concerns FortiGate: its catalog model ids come from release-notes
    # scraping (FGT60F...) and must be translated to the tool's own hardware ids through the
    # models endpoint. FortiAnalyzer/FortiManager catalogs are built from that same tool list, so
    # their model ids already are the ids the tool expects — never rewrite them.
    api_model = (
        resolve_fortinet_model(requested.product, requested.model, timeout)
        if requested.product == DEFAULT_PRODUCT_ID
        else requested.model
    )
    payload = fetch_upgrade_tool_payload(
        product_slug,
        api_model,
        timeout,
        from_version=requested.from_version,
        to_version=requested.to_version,
    )
    context = f"{product_slug}/{api_model} {requested.from_version}->{requested.to_version}"
    path_items = _payload_list(payload, "path", context)
    if len(path_items) < 2:
        return None

    parsed = [_availability_entry(item, context) for item in path_items]
    hops = tuple(version for version, _build, _type in parsed)
    # Trust the endpoints we asked for over whatever Fortinet's response claims only once we've
    # confirmed the hops themselves actually start/end there — otherwise a stored path's title
    # (from -> to) could contradict its own hop list. Treat a mismatch the same as "no path".
    if hops[0] != requested.from_version or hops[-1] != requested.to_version:
        return None

    path = UpgradePath(
        product=requested.product,
        model=requested.model,
        from_version=requested.from_version,
        to_version=requested.to_version,
        hops=hops,
        source="Fortinet Upgrade Path Tool public service",
    )
    firmwares = [
        Firmware(
            product=requested.product,
            model=requested.model,
            version=version,
            build=build,
            notes=official_note_keys(item),
            links=official_note_links(item, requested.product, version),
        )
        for item, (version, build, _type) in zip(path_items, parsed)
    ]
    return path, firmwares


def _model_entry(entry: Any, product_slug: str) -> dict[str, str]:
    """One {name, value} entry of the models endpoint -> the catalog's own field names."""
    name = entry.get("name") if isinstance(entry, dict) else None
    value = entry.get("value") if isinstance(entry, dict) else None
    if not isinstance(name, str) or not name or not isinstance(value, str) or not value:
        raise UpgradeToolResponseError(
            f"Réponse Upgrade Path Tool invalide : modèle inexploitable pour {product_slug} "
            f"({entry!r})."
        )
    return {"product_name": name, "hardware_model_name": value}


def fetch_product_models(product_slug: str, timeout: int) -> list[dict[str, str]]:
    """List of {product_name, hardware_model_name} the Upgrade Path Tool knows for this product.

    This is the same JSON the tool's own product dropdown fetches on selection change, so it's a
    more reliable model source than scraping release notes for a "Supported models" section (which
    FortiAnalyzer/FortiManager release notes don't reliably have in the same format as FortiOS).
    """
    url = f"{FORTINET_UPGRADE_TOOL_MODELS_URL}?{urllib.parse.urlencode({'product': product_slug})}"
    request = urllib.request.Request(
        url, headers={"User-Agent": "sns-fortios-upgrade-watch/0.1"}
    )
    # Use the same three-total-attempt budget as transport retries. A syntactically valid but empty
    # payload is not usable catalog data, so give Fortinet's endpoint two bounded chances to recover.
    for attempt in range(3):
        try:
            payload = json.loads(
                read_url_with_retry(request, timeout).decode("utf-8", errors="ignore")
            )
        except json.JSONDecodeError as error:
            raise UpgradeToolResponseError(
                f"Réponse Upgrade Path Tool illisible ({product_slug}/models) : {error}"
            ) from error
        if not isinstance(payload, list):
            raise UpgradeToolResponseError(
                f"Réponse Upgrade Path Tool invalide ({product_slug}/models) : liste attendue."
            )
        models = [_model_entry(entry, product_slug) for entry in payload]
        if models:
            return models
        if attempt < 2:
            time.sleep((2**attempt) + random.uniform(0, 1))
    return []


def fetch_model_firmwares(
    product_slug: str, hardware_model_name: str, timeout: int
) -> list[dict[str, str]]:
    """Version/build catalog for one model, from the tool's own availability lists.

    A model the tool answers nothing for fails closed instead of reading as "this model has no
    version": every model coming from the tool's own list does have versions in practice, so an
    empty answer means a degraded API or an unknown model id, never a legitimate empty catalog.
    """
    payload = fetch_upgrade_tool_payload(product_slug, hardware_model_name, timeout)
    context = f"{product_slug}/{hardware_model_name}"
    by_version: dict[str, dict[str, str]] = {}
    for item in _payload_list(payload, "availableFrom", context) + _payload_list(
        payload, "availableTo", context
    ):
        version, build, _type = _availability_entry(item, context)
        by_version[version] = {"version": version, "build": build}
    if not by_version:
        raise UpgradeToolResponseError(
            f"Réponse Upgrade Path Tool vide pour {context} : aucune version disponible "
            f"(modèle inconnu ou réponse dégradée)."
        )
    return list(by_version.values())


def collect_tool_catalog(product_id: str, timeout: int) -> dict[str, Any]:
    """Model + version/build catalog for a product, sourced from the Upgrade Path Tool itself."""
    meta = PRODUCTS[product_id]
    state = normalize_state({})
    product = ensure_product(state, product_id, meta["label"])

    model_entries = fetch_product_models(meta["slug"], timeout)
    if not model_entries:
        raise UpgradeToolResponseError(
            f"Upgrade Path Tool : aucun modèle retourné pour {product_id}."
        )
    for entry in model_entries:
        model_id = entry.get("hardware_model_name")
        if not model_id:
            continue
        model_label_value = entry.get("product_name") or model_id
        model = next(
            (item for item in product["models"] if item.get("id") == model_id), None
        )
        if model is None:
            model = {"id": model_id, "label": model_label_value, "firmwares": []}
            product["models"].append(model)

        for firmware_info in fetch_model_firmwares(meta["slug"], model_id, timeout):
            upsert_firmware(
                state,
                Firmware(
                    product=product_id,
                    model=model_id,
                    version=firmware_info["version"],
                    build=firmware_info.get("build") or "-",
                    links={
                        "release-notes": release_notes_url(
                            product_id, firmware_info["version"]
                        )
                    },
                ),
            )

    product["models"].sort(key=lambda item: model_sort_key(item.get("id", "")))
    return state


def parse_official_path_spec(spec: str) -> OfficialPathRequest:
    parts = [part.strip() for part in re.split(r"[:,]", spec) if part.strip()]
    if len(parts) != 3:
        raise ValueError(f"Format attendu MODEL:FROM:TO, reçu: {spec}")
    return OfficialPathRequest(
        model=parts[0], from_version=parts[1], to_version=parts[2]
    )


def read_official_path_requests(path: Path) -> list[OfficialPathRequest]:
    if not path.exists():
        return []

    requests: list[OfficialPathRequest] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            model = row.get("model") or row.get("Model")
            from_version = (
                row.get("from") or row.get("current") or row.get("from_version")
            )
            to_version = row.get("to") or row.get("target") or row.get("to_version")
            if model and from_version and to_version:
                requests.append(
                    OfficialPathRequest(
                        model=model.strip(),
                        from_version=from_version.strip(),
                        to_version=to_version.strip(),
                    )
                )
    return requests


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "advisory"


def upsert_advisory(state: dict[str, Any], advisory: dict[str, Any]) -> bool:
    for index, existing in enumerate(state["advisories"]):
        if existing.get("id") == advisory.get("id"):
            if existing == advisory:
                return False
            state["advisories"][index] = advisory
            return True
    state["advisories"].append(advisory)
    return True


def upsert_compatibility(state: dict[str, Any], item: dict[str, Any]) -> bool:
    for index, existing in enumerate(state["compatibilities"]):
        if existing.get("id") == item.get("id"):
            if existing == item:
                return False
            state["compatibilities"][index] = item
            return True
    state["compatibilities"].append(item)
    return True


def upsert_path(state: dict[str, Any], item: UpgradePath) -> bool:
    path_id = f"path-{item.model}-{item.from_version}-{item.to_version}"
    next_path = {
        "id": path_id,
        "product": item.product,
        "model": item.model,
        "from": item.from_version,
        "to": item.to_version,
        "hops": list(item.hops),
        "source": item.source,
        "fetchedAt": utc_now(),
    }

    for index, existing in enumerate(state["paths"]):
        if (
            existing.get("product") == item.product
            and existing.get("model") == item.model
            and existing.get("from") == item.from_version
            and existing.get("to") == item.to_version
        ):
            if existing == next_path:
                return False
            state["paths"][index] = next_path
            return True

    state["paths"].append(next_path)
    return True


# Shared across everyone hitting the live /api/official-path endpoint (see fortios_server.py) —
# no per-user accounts exist, so this is intentionally anonymous: just what was searched and
# when, not who searched it. Re-searching the same model/from/to bumps it to the top instead of
# duplicating.
SEARCH_HISTORY_LIMIT = 50


def record_search_history(
    state: dict[str, Any],
    product: str,
    model: str,
    from_version: str,
    to_version: str,
    hops: tuple[str, ...],
) -> None:
    history = [
        entry
        for entry in state.get("searchHistory", [])
        if not (
            entry.get("product") == product
            and entry.get("model") == model
            and entry.get("from") == from_version
            and entry.get("to") == to_version
        )
    ]
    history.insert(
        0,
        {
            "product": product,
            "model": model,
            "from": from_version,
            "to": to_version,
            "hops": list(hops),
            "requestedAt": utc_now(),
        },
    )
    state["searchHistory"] = history[:SEARCH_HISTORY_LIMIT]


def merge_state(base: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    state = normalize_state(base)
    incoming = normalize_state(incoming)

    for product in incoming["products"]:
        product_id = product.get("id") or DEFAULT_PRODUCT_ID
        target_product = ensure_product(
            state, product_id, product.get("label") or DEFAULT_PRODUCT_LABEL
        )
        model_by_id = {model.get("id"): model for model in target_product["models"]}
        for model in product.get("models", []):
            model_id = model.get("id")
            if not model_id:
                continue
            target_model = model_by_id.get(model_id)
            if not target_model:
                target_product["models"].append(model)
                model_by_id[model_id] = model
                continue
            firmware_by_version = {
                firmware.get("version"): firmware
                for firmware in target_model.get("firmwares", [])
            }
            for firmware in model.get("firmwares", []):
                version = firmware.get("version")
                if not version:
                    continue
                existing_firmware = firmware_by_version.get(version)
                merged_firmware = {**(existing_firmware or {}), **firmware}
                # notes/links are collections, not scalars — a plain dict-spread REPLACES them
                # wholesale rather than merging their contents, so a version enriched by a live
                # official-path fetch (rich notes: behavior/known/resolved/special/upgrade, and
                # matching links) would lose all of that the next time collect_docs_catalog()
                # re-scrapes it with just notes=("release-notes",). Union notes, merge links key
                # by key — the same non-destructive merge upsert_firmware() already does for a
                # single live upsert; build/maturity/anything else stay simple last-writer-wins.
                if existing_firmware is not None:
                    if "notes" in firmware:
                        merged_firmware["notes"] = sorted(
                            set(existing_firmware.get("notes", []))
                            | set(firmware.get("notes") or [])
                        )
                    if "links" in firmware:
                        merged_firmware["links"] = {
                            **existing_firmware.get("links", {}),
                            **(firmware.get("links") or {}),
                        }
                # The incoming side is usually a throwaway collector state (collect_docs_catalog()
                # etc. start from a blank state, so every version it touches looks "brand new" to
                # it and gets stamped with today's date). If the base already knew this version
                # before this run, it can never be newly discovered today, full stop — whether or
                # not it already carried a discoveredAt (~14k pre-migration entries don't; the
                # frontend already treats a missing discoveredAt as "not new", so there's nothing
                # to backfill). Only a version genuinely absent from the base keeps incoming's
                # fresh stamp.
                if existing_firmware is not None:
                    if "discoveredAt" in existing_firmware:
                        merged_firmware["discoveredAt"] = existing_firmware[
                            "discoveredAt"
                        ]
                    else:
                        merged_firmware.pop("discoveredAt", None)
                firmware_by_version[version] = merged_firmware
            target_model["firmwares"] = sorted(
                firmware_by_version.values(),
                key=lambda firmware: version_key(firmware["version"]),
            )
        target_product["models"].sort(
            key=lambda item: model_sort_key(item.get("id", ""))
        )

    path_keys = {
        (
            path.get("product"),
            path.get("model"),
            path.get("from"),
            path.get("to"),
        ): index
        for index, path in enumerate(state["paths"])
    }
    for path in incoming["paths"]:
        key = (path.get("product"), path.get("model"), path.get("from"), path.get("to"))
        if key in path_keys:
            state["paths"][path_keys[key]] = path
        else:
            state["paths"].append(path)

    advisory_by_id = {item.get("id"): item for item in state["advisories"]}
    for advisory in incoming["advisories"]:
        advisory_id = advisory.get("id")
        if advisory_id:
            advisory_by_id[advisory_id] = advisory
    state["advisories"] = list(advisory_by_id.values())

    compatibility_by_id = {item.get("id"): item for item in state["compatibilities"]}
    for compatibility in incoming["compatibilities"]:
        compatibility_id = compatibility.get("id")
        if compatibility_id:
            compatibility_by_id[compatibility_id] = compatibility
    state["compatibilities"] = list(compatibility_by_id.values())

    cve_by_id = {item.get("id"): item for item in state["cves"]}
    for cve in incoming["cves"]:
        cve_id = cve.get("id")
        if cve_id:
            cve_by_id[cve_id] = cve
    state["cves"] = list(cve_by_id.values())

    # Fetched wholesale from endoflife.date each time, so incoming (fresher) wins per train.
    state["fortiosLifecycle"] = {
        **state["fortiosLifecycle"],
        **incoming["fortiosLifecycle"],
    }

    # Same product/model/from/to key as record_search_history — keep the most recent
    # requestedAt per key, then re-sort and cap, so a merge never resurrects a stale entry
    # above a newer one.
    history_by_key = {
        (item.get("product"), item.get("model"), item.get("from"), item.get("to")): item
        for item in state["searchHistory"]
    }
    for item in incoming["searchHistory"]:
        key = (item.get("product"), item.get("model"), item.get("from"), item.get("to"))
        existing = history_by_key.get(key)
        if not existing or (item.get("requestedAt") or "") > (
            existing.get("requestedAt") or ""
        ):
            history_by_key[key] = item
    state["searchHistory"] = sorted(
        history_by_key.values(),
        key=lambda item: item.get("requestedAt") or "",
        reverse=True,
    )[:SEARCH_HISTORY_LIMIT]

    state["generatedAt"] = utc_now()
    return state


def fetch_psirt_versions(timeout: int) -> set[str]:
    request = urllib.request.Request(
        PSIRT_RSS_URL,
        headers={"User-Agent": "sns-fortios-upgrade-watch/0.1"},
    )
    try:
        xml_bytes = read_url_with_retry(request, timeout)
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException):
        return set()

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return set()

    versions: set[str] = set()
    for node in root.iter():
        if node.text:
            versions.update(
                version
                for version in VERSION_RE.findall(node.text)
                if is_fortios_version(version)
            )
    return versions


# --- PSIRT CVE tracking -------------------------------------------------
#
# Fortinet publishes two machine-readable exports per PSIRT advisory: a CVRF
# (Common Vulnerability Reporting Framework) XML feed and a CSAF 2.0 JSON
# export. The CVRF feed is coarse — it lists whole version trains ("FortiOS
# 7.6", "FortiOS 7.2") as "Known Affected" with no bounds, which the UI reads
# as "every version of that train is vulnerable". That is exactly what made
# FG-IR-26-174 flag FortiOS 7.2/7.4/8.0, while the official CSAF export
# restricts the impact to ">=7.6.1|<=7.6.6" and lists 7.2/7.4/7.6.7/8.0 as NOT
# affected. CSAF is therefore the single authoritative applicability source:
# product_status.known_affected carries the exact ranges, known_not_affected /
# fixed the exclusions. There is deliberately NO silent fallback to the CVRF
# ranges when CSAF is unavailable (that would re-introduce those false
# positives): an unreachable, anti-bot-challenged or unvalidated response
# makes the advisory "unresolved" — previous entries are preserved untouched
# and the run reports the skip — never "no more CVEs".
PSIRT_BASE_URL = "https://fortiguard.fortinet.com"
ADVISORY_LINK_RE = re.compile(r"location\.href\s*=\s*'/psirt/(FG-IR-[\w-]+)'")
# The CSAF export's file name embeds a slugified advisory title, so it cannot
# be guessed: one HTML fetch of the advisory page is still needed to discover
# it. Its target is strictly re-validated (see _validated_csaf_url) — only
# Fortinet's own file store over https — so an upstream-tampered link can
# never turn the collector into an open fetcher (no SSRF via upstream links).
CSAF_HOST = "filestore.fortinet.com"
CSAF_PATH_PREFIX = "/fortiguard/psirt/"
CSAF_HREF_RE = re.compile(r'href\s*=\s*"([^"]+)"', re.IGNORECASE)
CSAF_VERSION_RE_TEXT = r"\d+(?:\.\d+){1,3}"

# CSAF product name -> (our internal product id, model id or None when the product
# has no FortiClient-style per-platform model).
CVE_PRODUCT_MAP: dict[str, tuple[str, str | None]] = {
    "FortiOS": (DEFAULT_PRODUCT_ID, None),
    "FortiAnalyzer": ("fortianalyzer", None),
    "FortiManager": ("fortimanager", None),
    "FortiClientWindows": (FORTICLIENT_PRODUCT_ID, "windows"),
    "FortiClientMac": (FORTICLIENT_PRODUCT_ID, "macos"),
    "FortiClientLinux": (FORTICLIENT_PRODUCT_ID, "linux"),
    "FortiClientEMS": (FORTICLIENT_EMS_PRODUCT_ID, FORTICLIENT_EMS_MODEL_ID),
}
# Product filter values PSIRT's own listing page accepts, used only for --cve-backfill —
# the RSS feed used for the daily incremental refresh isn't filterable by product and only
# covers the last ~50 advisories across every Fortinet product line.
CVE_LISTING_PRODUCT_FILTERS = tuple(CVE_PRODUCT_MAP)

# Longest-first so "FortiClientWindows" wins over any shorter prefix, and unknown product
# names (FortiWeb, FortiMail, FortiADC...) are simply not tracked here at all.
CSAF_PRODUCT_NAMES = tuple(sorted(CVE_PRODUCT_MAP, key=len, reverse=True))


def discover_advisory_ids_from_rss(timeout: int) -> list[str]:
    request = urllib.request.Request(
        PSIRT_RSS_URL, headers={"User-Agent": "sns-fortios-upgrade-watch/0.1"}
    )
    root = ET.fromstring(read_url_with_retry(request, timeout))

    ids: list[str] = []
    for item in root.iter("item"):
        link = item.findtext("link") or ""
        match = re.search(r"(FG-IR-[\w-]+)", link)
        if match:
            ids.append(match.group(1))
    return unique_in_order(ids)


def discover_advisory_ids_from_listing(
    product_filter: str, max_pages: int, timeout: int
) -> list[str]:
    ids: list[str] = []
    for page in range(1, max_pages + 1):
        url = f"{PSIRT_BASE_URL}/psirt?product={urllib.parse.quote(product_filter)}&page={page}"
        raw_html = fetch_text(url, timeout)
        page_ids = unique_in_order(ADVISORY_LINK_RE.findall(raw_html))
        if not page_ids:
            break
        ids.extend(page_ids)
        time.sleep(0.3)
    return unique_in_order(ids)


class CsafResolutionError(RuntimeError):
    """An advisory's CSAF data could not be established definitively.

    Callers must treat it as "cannot confirm anything for this advisory":
    preserve the previously stored entries and report a diagnostic — never as
    a confirmed empty CVE list.
    """


def _validated_csaf_url(candidate: str) -> str | None:
    """Return `candidate` restricted to Fortinet's CSAF file host, or None.

    Accepts only https://filestore.fortinet.com/fortiguard/psirt/*.json with
    no credentials, no fragment and a normal https port; anything else (other
    host, http, smuggled destination) is refused rather than fetched.
    """
    candidate = candidate.strip()
    if not candidate:
        return None
    try:
        parsed = urllib.parse.urlsplit(candidate)
    except ValueError:
        return None
    if parsed.scheme != "https" or parsed.hostname != CSAF_HOST:
        return None
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        return None
    if parsed.fragment:
        return None
    if not parsed.path.startswith(CSAF_PATH_PREFIX) or not parsed.path.endswith(".json"):
        return None
    return urllib.parse.urlunsplit(("https", CSAF_HOST, parsed.path, parsed.query, ""))


def _psirt_page_redirect_allowed(candidate: str) -> bool:
    """Advisory pages may only ever redirect within the https PSIRT site.

    Same rules as the initial advisory URL: no credential smuggling, no port
    trickery, no downgrade to http/ftp, no departure from the PSIRT host.
    """
    try:
        parsed = urllib.parse.urlsplit(candidate)
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname == urllib.parse.urlsplit(PSIRT_BASE_URL).hostname
        and parsed.port in (None, 443)
        and not parsed.username
        and not parsed.password
        and parsed.path.startswith("/psirt/")
    )


def _csaf_redirect_allowed(candidate: str) -> bool:
    """CSAF downloads may only redirect to another validated CSAF destination."""
    return _validated_csaf_url(candidate) is not None


def discover_csaf_url(advisory_id: str, raw_html: str) -> str | None:
    """Find and validate the CSAF export URL advertised by an advisory page.

    The page links ``/psirt/csaf/<advisory_id>?csaf_url=<file-store URL>``;
    the parameter is re-validated here instead of trusted (see
    _validated_csaf_url). Returns None when no usable link exists — including
    an anti-bot challenge page, which callers turn into an unresolved
    advisory, never into an empty result.
    """
    page_url = f"{PSIRT_BASE_URL}/psirt/{advisory_id}"
    psirt_host = urllib.parse.urlsplit(PSIRT_BASE_URL).hostname
    for raw_href in CSAF_HREF_RE.findall(raw_html):
        resolved = urllib.parse.urljoin(page_url, html.unescape(raw_href.strip()))
        direct = _validated_csaf_url(resolved)
        if direct:
            return direct
        parsed = urllib.parse.urlsplit(resolved)
        if (
            parsed.scheme == "https"
            and parsed.hostname == psirt_host
            and parsed.path == f"/psirt/csaf/{advisory_id}"
        ):
            relayed = urllib.parse.parse_qs(parsed.query).get("csaf_url", [""])[0]
            validated = _validated_csaf_url(relayed)
            if validated:
                return validated
    return None


def csaf_branch(version: str) -> str:
    return ".".join(version.split(".")[:2])


def split_csaf_product_value(value: Any) -> tuple[str, str] | None:
    """Split one product_status value into (tracked product, version clause).

    Returns None for values that are *definitively* statements about a product
    this tool does not track. That includes entirely different Fortinet lines
    (FortiWeb, FortiMail, FortiPAM, FortiProxy...) and names that merely
    *start with* a tracked one — "FortiManager Cloud 7.2 all versions" is a
    distinct cloud product, not on-prem FortiManager, so it is ignored like
    any other untracked product.

    Anything else is uninterpretable rather than "out of scope": a non-string
    or null entry, an empty value, or an opaque identifier (CSAF product id,
    stray token) that names no Fortinet product at all. Those raise — treating
    them as an untracked product let a partially-invalid export look like a
    confirmed "no longer affected" and delete the previously stored entries.
    Raising suspends the advisory instead, preserving previous data.
    """
    if not isinstance(value, str):
        raise CsafResolutionError(f"product_status value is not a string: {value!r}")
    compact = " ".join(value.split())
    if not compact:
        raise CsafResolutionError("product_status value is empty")
    for product_name in CSAF_PRODUCT_NAMES:
        if not compact.startswith(product_name):
            continue
        rest = compact[len(product_name):]
        stripped = rest.strip().lstrip("-/").strip()
        if stripped and stripped[0].isupper():
            return None  # a different product sharing the prefix ("FortiManager Cloud")
        return product_name, rest
    if compact.startswith("Forti"):
        # A recognizable, untracked Fortinet product line (FortiWeb, FortiPAM,
        # FortiProxy...): explicitly out of scope, whatever its version clause.
        return None
    raise CsafResolutionError(
        f"unresolved product_status value (no recognizable product): {value!r}"
    )


def parse_csaf_version_clause(rest: str) -> dict[str, Any] | None:
    """Parse the version part of one CSAF product_status value.

    Shapes observed in Fortinet's exports:
      ">=7.6.1|<=7.6.6"      bounded range ("FortiOS >=7.6.1|<=7.6.6")
      ">=7.6.1" / "<=7.6.6"  half-open range
      "8.0 all versions"     whole train, no bounds
      "7.6.7" / "-7.6.7"     one exact version
      "upcoming  7.6.7"      one exact (not yet released) version

    Returns {"branch", "from", "to"} — or None when the clause matches none
    of these; callers then suspend the advisory (for a tracked product)
    instead of guessing or silently dropping the claim.

    The WHOLE normalized clause must match one of the shapes above. A bound
    embedded in unknown or contradictory text (">=7.6.1|<7.6.7", "version
    >=7.6.1", ">=7.6.1 or later") is deliberately NOT accepted: partially
    consuming the clause used to reinterpret it as a smaller claim — e.g. a
    malformed ">=7.6.1|<7.6.7" silently became a lower bound with no upper
    bound — which is exactly how a non-probative value could weaken a stored
    range instead of suspending the advisory.
    """
    rest = " ".join(rest.split()).lstrip("-/").strip()
    if not rest:
        return None
    all_versions = re.fullmatch(r"(\d+\.\d+)\s+all versions", rest, re.IGNORECASE)
    if all_versions:
        return {"branch": all_versions.group(1), "from": None, "to": None}
    bounded = re.fullmatch(
        rf">=\s*({CSAF_VERSION_RE_TEXT})\s*\|\s*<=\s*({CSAF_VERSION_RE_TEXT})", rest
    )
    if bounded:
        from_version = bounded.group(1)
        to_version = bounded.group(2)
        if csaf_branch(from_version) != csaf_branch(to_version):
            return None  # a cross-train range cannot be represented per-branch
        if version_key(from_version) > version_key(to_version):
            return None
        return {
            "branch": csaf_branch(from_version),
            "from": from_version,
            "to": to_version,
        }
    from_only = re.fullmatch(rf">=\s*({CSAF_VERSION_RE_TEXT})", rest)
    if from_only:
        version = from_only.group(1)
        return {"branch": csaf_branch(version), "from": version, "to": None}
    to_only = re.fullmatch(rf"<=\s*({CSAF_VERSION_RE_TEXT})", rest)
    if to_only:
        version = to_only.group(1)
        return {"branch": csaf_branch(version), "from": None, "to": version}
    exact = re.fullmatch(
        rf"(?:upcoming\s+)?({CSAF_VERSION_RE_TEXT})", rest, re.IGNORECASE
    )
    if exact:
        version = exact.group(1)
        return {"branch": csaf_branch(version), "from": version, "to": version}
    return None


def cvss_severity(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def _csaf_range_sort_key(range_entry: dict[str, Any]) -> tuple[Any, ...]:
    """Stable ordering for affected ranges (deterministic diffs across runs)."""
    return (
        range_entry["product"],
        version_key(range_entry["branch"]),
        version_key(range_entry["from"] or "0"),
        version_key(range_entry["to"] or "0"),
    )


def _csaf_status_list(advisory_id: str, status: dict[str, Any], key: str) -> list[Any]:
    """One product_status entry list, distinguishing "absent" from "invalid".

    An absent optional key is simply no claim at all ([]). A key that exists
    but is null or not a list is malformed data — never silently read as "no
    claim", which would let an invalid export remove stored entries.
    """
    if key not in status:
        return []
    values = status[key]
    if values is None:
        raise CsafResolutionError(f"{advisory_id}: CSAF product_status.{key} is null")
    if not isinstance(values, list):
        raise CsafResolutionError(
            f"{advisory_id}: CSAF product_status.{key} is not a list"
        )
    return values


def validate_csaf_document(advisory_id: str, doc: Any) -> dict[str, Any]:
    """Refuse anything that is not the tracked advisory's own CSAF export.

    A successful download is not proof of anything on its own: the response
    must parse as a CSAF 2.x object whose publisher is Fortinet PSIRT and
    whose tracking id is exactly the advisory being fetched. A captive
    portal, a truncated file or a mixed-up document fails here — loudly.
    """
    if not isinstance(doc, dict):
        raise CsafResolutionError(f"{advisory_id}: CSAF document is not a JSON object")
    document = doc.get("document")
    if not isinstance(document, dict):
        raise CsafResolutionError(f"{advisory_id}: CSAF document has no document section")
    if not str(document.get("csaf_version") or "").startswith("2."):
        raise CsafResolutionError(
            f"{advisory_id}: unexpected CSAF version {document.get('csaf_version')!r}"
        )
    tracking = document.get("tracking")
    if not isinstance(tracking, dict) or tracking.get("id") != advisory_id:
        raise CsafResolutionError(f"{advisory_id}: CSAF tracking id does not match")
    publisher = document.get("publisher")
    if not isinstance(publisher, dict) or publisher.get("name") != "Fortinet PSIRT":
        raise CsafResolutionError(f"{advisory_id}: CSAF publisher is not Fortinet PSIRT")
    if not isinstance(doc.get("vulnerabilities"), list):
        raise CsafResolutionError(f"{advisory_id}: CSAF vulnerabilities is not a list")
    for vulnerability in doc["vulnerabilities"]:
        if not isinstance(vulnerability, dict):
            raise CsafResolutionError(
                f"{advisory_id}: a vulnerabilities element is not an object"
            )
        if not isinstance(vulnerability.get("cve"), str) or not vulnerability["cve"]:
            raise CsafResolutionError(
                f"{advisory_id}: a vulnerability has no cve identifier"
            )
        product_status = vulnerability.get("product_status")
        if not isinstance(product_status, dict):
            raise CsafResolutionError(
                f"{advisory_id}: a vulnerability has no product_status object"
            )
        # An absent/null/empty known_affected asserts nothing. Reading it as
        # "no longer affected" is what would let a truncated or partial export
        # delete every stored entry of the CVE; skip-with-diagnostic instead.
        known_affected = product_status.get("known_affected")
        if not isinstance(known_affected, list) or not known_affected:
            raise CsafResolutionError(
                f"{advisory_id}: a vulnerability has no usable known_affected list"
            )
    return doc


def parse_csaf_document(advisory_id: str, doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Translate a validated CSAF export into catalogue CVE entries.

    Only product_status drives applicability: known_affected gives the exact
    per-train ranges (or "all versions" / single-version claims), while
    known_not_affected and fixed give exclusions — a version listed there is
    never reported as affected, even inside an otherwise affected range. One
    CVE can appear as several vulnerability entries in a single export (one
    per product/platform); they are merged into one entry, like the previous
    collector did.

    Raises CsafResolutionError as soon as a value *about a tracked product*
    uses an unrecognized shape, or when a product/train is claimed both
    affected and fully unaffected: such an advisory keeps its last confirmed
    data and surfaces in the run diagnostic instead of being silently
    dropped or degraded to "not affected".
    """
    document = doc.get("document") or {}
    tracking = document.get("tracking") or {}
    title = str(document.get("title") or advisory_id)
    published_at = str(tracking.get("initial_release_date") or "")[:10]
    updated_at = str(tracking.get("current_release_date") or "")[:10]
    url = f"{PSIRT_BASE_URL}/psirt/{advisory_id}"

    entries_by_cve: dict[str, dict[str, Any]] = {}
    for vulnerability in doc.get("vulnerabilities") or []:
        if not isinstance(vulnerability, dict):
            raise CsafResolutionError(
                f"{advisory_id}: a vulnerabilities element is not an object"
            )
        cve_id = vulnerability.get("cve")
        if not isinstance(cve_id, str) or not cve_id:
            raise CsafResolutionError(
                f"{advisory_id}: a vulnerability has no usable cve identifier"
            )

        cvss_score: float | None = None
        severity: str | None = None
        for score in vulnerability.get("scores") or []:
            if not isinstance(score, dict):
                continue
            metrics = score.get("cvss_v3") or score.get("cvss_v4")
            if isinstance(metrics, dict):
                cvss_score = metrics.get("baseScore")
                severity = str(metrics.get("baseSeverity") or "").lower() or None
                break
        severity = severity or cvss_severity(cvss_score)

        status = vulnerability.get("product_status")
        if not isinstance(status, dict):
            raise CsafResolutionError(
                f"{advisory_id}: {cve_id} has no product_status object"
            )
        known_affected = _csaf_status_list(advisory_id, status, "known_affected")
        if not known_affected:
            raise CsafResolutionError(
                f"{advisory_id}: {cve_id} has no known_affected status"
            )

        affected_by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
        # Exclusions are scoped to product AND platform (model) AND branch:
        # FortiClientWindows/Mac/Linux share the same tracked product id, so
        # keying them by product+branch alone would let a Mac exclusion also
        # exclude Windows (or even suspend a coherent Windows-only bulletin).
        exclusions: dict[tuple[str, str | None, str], set[str]] = {}
        for value in known_affected:
            split = split_csaf_product_value(value)
            if split is None:
                continue  # not a tracked product — out of scope by design.
            product_name, rest = split
            clause = parse_csaf_version_clause(rest)
            if clause is None:
                raise CsafResolutionError(
                    f"{advisory_id}: {cve_id} has an unrecognized known_affected "
                    f"value for {product_name}: {value!r}"
                )
            product_id, model_id = CVE_PRODUCT_MAP[product_name]
            key = (product_id, model_id, clause["branch"], clause["from"], clause["to"])
            affected_by_key[key] = {
                "product": product_id,
                "models": [model_id] if model_id else [],
                "branch": clause["branch"],
                "from": clause["from"],
                "to": clause["to"],
            }
        for status_key in ("known_not_affected", "fixed"):
            for value in _csaf_status_list(advisory_id, status, status_key):
                split = split_csaf_product_value(value)
                if split is None:
                    continue
                product_name, rest = split
                clause = parse_csaf_version_clause(rest)
                if clause is None:
                    raise CsafResolutionError(
                        f"{advisory_id}: {cve_id} has an unrecognized {status_key} "
                        f"value for {product_name}: {value!r}"
                    )
                product_id, model_id = CVE_PRODUCT_MAP[product_name]
                bucket = exclusions.setdefault(
                    (product_id, model_id, clause["branch"]), set()
                )
                if clause["from"] is not None and clause["from"] == clause["to"]:
                    bucket.add(clause["from"])
                elif clause["from"] is None and clause["to"] is None:
                    bucket.add("*")
                else:
                    raise CsafResolutionError(
                        f"{advisory_id}: {cve_id} has an unusable {status_key} range "
                        f"for {product_name}: {value!r}"
                    )

        for key, range_entry in affected_by_key.items():
            product_id, model_id = key[0], key[1]
            excluded: set[str] = set()
            for version in exclusions.get(
                (product_id, model_id, range_entry["branch"]), set()
            ):
                if version == "*":
                    raise CsafResolutionError(
                        f"{advisory_id}: {cve_id} claims {range_entry['product']} "
                        f"{range_entry['branch']} both affected and fully unaffected"
                    )
                if (
                    range_entry["from"] is not None
                    and version_key(version) < version_key(range_entry["from"])
                ):
                    continue
                if (
                    range_entry["to"] is not None
                    and version_key(version) > version_key(range_entry["to"])
                ):
                    continue
                excluded.add(version)
            if excluded:
                range_entry["excluded"] = sorted(excluded, key=version_key)

        if not affected_by_key:
            continue  # this vulnerability entry touches no tracked product.

        entry = entries_by_cve.setdefault(
            cve_id,
            {
                "id": cve_id,
                "advisoryId": advisory_id,
                "title": title,
                "severity": severity,
                "cvssScore": cvss_score,
                "url": url,
                "publishedAt": published_at,
                "updatedAt": updated_at,
                "affected": [],
            },
        )
        entry["affected"].extend(affected_by_key.values())

    for entry in entries_by_cve.values():
        entry["affected"] = sorted(entry["affected"], key=_csaf_range_sort_key)
    return list(entries_by_cve.values())


def collect_cve_entries_for_advisory(
    advisory_id: str, timeout: int
) -> list[dict[str, Any]]:
    """Return the definitive CVE list for one advisory, from its CSAF export.

    The advisory page is fetched once to discover the (unguessable) CSAF URL,
    which is re-validated before use; the export itself is validated
    (Fortinet PSIRT, CSAF 2.x, tracking.id == advisory_id) and then translated
    with its exact ranges and exclusions. Every failure — transport, anti-bot
    challenge without a usable link, invalid or foreign JSON, unknown value
    shapes for a tracked product — is raised to the caller, which records the
    advisory as skipped and preserves its previous data. An empty list is
    reserved for a genuinely confirmed case: a validated export that names no
    tracked product for this advisory.
    """
    raw_html = fetch_text(
        f"{PSIRT_BASE_URL}/psirt/{advisory_id}",
        timeout,
        redirect_validator=_psirt_page_redirect_allowed,
    )
    csaf_url = discover_csaf_url(advisory_id, raw_html)
    if csaf_url is None:
        raise CsafResolutionError(
            f"{advisory_id}: no validated CSAF link on the advisory page"
        )
    doc = json.loads(
        fetch_text(csaf_url, timeout, redirect_validator=_csaf_redirect_allowed)
    )
    validate_csaf_document(advisory_id, doc)
    return parse_csaf_document(advisory_id, doc)


def upsert_cve(state: dict[str, Any], item: dict[str, Any]) -> bool:
    for index, existing in enumerate(state["cves"]):
        if existing.get("id") == item.get("id"):
            if existing == item:
                return False
            state["cves"][index] = item
            return True
    state["cves"].append(item)
    return True


@dataclass
class CveReconciliationStats:
    added: int = 0
    updated: int = 0
    removed: int = 0

    def __add__(self, other: CveReconciliationStats) -> CveReconciliationStats:
        return CveReconciliationStats(
            added=self.added + other.added,
            updated=self.updated + other.updated,
            removed=self.removed + other.removed,
        )


def replace_cves_for_advisory(
    state: dict[str, Any], advisory_id: str, new_entries: list[dict[str, Any]]
) -> CveReconciliationStats:
    """Replace every CVE previously recorded under `advisory_id` with exactly `new_entries` —
    only ever call this with a DEFINITIVE, successfully-parsed CVRF result (never for an advisory
    that was skipped due to a network/parse failure), since a
    transient PSIRT hiccup must never be allowed to wipe real, previously-confirmed CVE data.
    Returns distinct added/updated/removed counts — a removal must never be reported as if it
    were a new addition.
    """
    existing_for_advisory = {
        item.get("id"): item
        for item in state["cves"]
        if item.get("advisoryId") == advisory_id
    }
    new_ids = {entry["id"] for entry in new_entries}
    stale_ids = set(existing_for_advisory) - new_ids
    if stale_ids:
        state["cves"] = [
            item for item in state["cves"] if item.get("id") not in stale_ids
        ]

    added = 0
    updated = 0
    for entry in new_entries:
        if entry["id"] in existing_for_advisory:
            if upsert_cve(state, entry):
                updated += 1
        elif upsert_cve(state, entry):
            added += 1
    return CveReconciliationStats(added=added, updated=updated, removed=len(stale_ids))


def collect_cve_catalog(
    existing_advisory_ids: set[str],
    timeout: int,
    backfill: bool = False,
    backfill_max_pages: int = 30,
    reconcile_existing: bool = False,
) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    """Per-advisory CVE entries to reconcile (keyed by advisory_id), plus a skipped-id list.

    An advisory_id present in the returned dict got a DEFINITIVE, successfully-parsed CSAF
    result this run (see collect_cve_entries_for_advisory()) — its entries are the complete,
    current set of CVEs for that advisory among our tracked products, so the caller should
    replace whatever it previously had for that advisory_id, dropping anything no longer
    present (see replace_cves_for_advisory()). An advisory_id in `skipped` (or simply absent
    because it wasn't looked at this run) must have its existing CVEs left completely alone.

    Daily use (backfill=False) only looks at the PSIRT RSS feed (last ~50 advisories across all
    Fortinet products) — cheap, and plenty since real advisories publish far slower than that.
    Re-fetches every advisory from that feed every time, even already-known ones: Fortinet
    regularly revises severity/CVSS/affected versions (or drops a product's relevance entirely)
    on an advisory well after first publishing it, so re-checking ~50 advisories a day is worth
    the trivial extra cost to avoid silently freezing stale data forever.
    reconcile_existing=True (maintenance pass, `--cve-reconcile-existing`) additionally
    re-fetches every advisory the catalogue already references, including ones the current RSS
    window no longer covers — that is what lets a corrected collector repair ranges stored by
    an older one instead of leaving pre-RSS-window entries frozen with stale data. Idempotent
    (same upstream ⇒ same entries ⇒ zero deltas) and interruptible (nothing is written until
    the run's single final commit, under the usual cross-process lock). Without --cve-backfill;
    backfill=True instead walks the paginated, per-product PSIRT listing to seed deep history —
    hundreds of advisories worth of requests, so it's still bounded to genuinely new ids there;
    meant to be run manually/occasionally, not from the daily timer.
    """
    if backfill:
        advisory_ids: list[str] = []
        for product_filter in CVE_LISTING_PRODUCT_FILTERS:
            advisory_ids.extend(
                discover_advisory_ids_from_listing(
                    product_filter, backfill_max_pages, timeout
                )
            )
        advisory_ids = unique_in_order(advisory_ids)
        advisory_ids = [
            advisory_id
            for advisory_id in advisory_ids
            if advisory_id not in existing_advisory_ids
        ]
    else:
        advisory_ids = discover_advisory_ids_from_rss(timeout)
        if reconcile_existing:
            advisory_ids = unique_in_order(
                [*advisory_ids, *sorted(existing_advisory_ids)]
            )

    return fetch_cve_entries_for_advisories(advisory_ids, timeout)


def fetch_cve_entries_for_advisories(
    advisory_ids: list[str], timeout: int
) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    """Fetch the definitive CSAF result for each id in `advisory_ids`, split into resolved
    results and a skipped list (see collect_cve_catalog's docstring for what each side means to
    callers). Factored out of collect_cve_catalog() so main() can call it a second time with just
    the skipped ids after a delay, without re-running RSS/listing discovery.
    """
    results: dict[str, list[dict[str, Any]]] = {}
    skipped: list[str] = []
    for advisory_id in advisory_ids:
        try:
            entries = collect_cve_entries_for_advisory(advisory_id, timeout)
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            http.client.HTTPException,
            json.JSONDecodeError,
            CsafResolutionError,
        ):
            entries = None
        if entries is None:
            skipped.append(advisory_id)
        else:
            results[advisory_id] = entries
        time.sleep(0.2)
    return results, skipped


def read_forticare_json(path: Path) -> dict[str, Any]:
    """Read a FortiCare/FNDN JSON export in either native or UI schema form.

    Accepted compact shape:
    {
      "firmwares": [
        {"product": "fortigate-fortios", "model": "FGT90G", "version": "7.4.11", "build": "2878"}
      ]
    }
    """
    payload = read_json(path, {})
    if "products" in payload:
        return normalize_state(payload)

    state = normalize_state({})
    for item in payload.get("firmwares", []):
        firmware = Firmware(
            product=item.get("product") or DEFAULT_PRODUCT_ID,
            model=item["model"],
            version=item["version"],
            build=item.get("build") or "-",
            notes=tuple(item.get("notes", [])),
        )
        upsert_firmware(state, firmware)
    return state


class UnsupportedExportShape(ValueError):
    """Raised when `text` parses as JSON but doesn't match any explicitly recognized export
    shape — the signal to reject the file outright rather than silently falling back to the
    regex scan (which is exactly how a decoy version number in an unrelated field like "note"
    used to get mistaken for a hop)."""


def is_valid_version_string(value: Any) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"\d+\.\d+\.\d+(?:\.\d+)?", value) is not None
    )


def validated_hops_from_path_items(path_items: list[Any]) -> list[str]:
    """Extract and validate every element of a recognized path array. Every element must be
    either a valid version string, or a dict with a "version" key that's a valid version string
    — anything else (a dict missing "version", a non-string/malformed version like the int 123,
    a bare number, a stray note...) raises rather than being silently dropped, since silently
    skipping one bad element would delete a real mandatory hop without any signal (exactly what
    {"path": ["7.2.10", {"note": "hop manquant"}, "7.4.11"]} used to do, turning into
    7.2.10 -> 7.4.11). Also requires at least two valid hops.
    """
    hops: list[str] = []
    for item in path_items:
        if isinstance(item, str):
            version = item
        elif isinstance(item, dict):
            version = item.get("version")
        else:
            raise UnsupportedExportShape(f"Élément de chemin invalide : {item!r}")
        if not is_valid_version_string(version):
            raise UnsupportedExportShape(
                f"Version invalide dans le chemin : {version!r}"
            )
        hops.append(version)
    if len(hops) < 2:
        raise UnsupportedExportShape("Chemin JSON avec moins de deux versions valides.")
    return hops


def parse_upgrade_export_json(text: str) -> list[str] | None:
    """Extract hops from `text` if it's JSON in one of two explicitly recognized shapes:
    - the raw Fortinet Upgrade Path Tool API response, result.path[].version (the same shape
      fetch_official_upgrade_path() parses from a live call);
    - a plain "path" array, of either version strings or {"version": ...} objects.

    Returns None (not []) when `text` isn't valid JSON at all, so the caller falls back to the
    loose regex scan — still needed for the .csv/.txt exports this same import also accepts (see
    README "Ajouter un export Fortinet Upgrade Path Tool"). Raises UnsupportedExportShape when
    `text` IS valid JSON but matches neither shape, or matches a shape with an invalid element:
    that case must never fall back to the regex scan over the same document, since a real path
    field sitting next to an unrelated field like "note": "fixed since 6.4.15" would otherwise
    both get scanned indiscriminately, and a partially-invalid path must never be silently
    trimmed down to whatever elements happened to look valid.
    """
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None

    if isinstance(payload, dict):
        result = payload.get("result")
        if isinstance(result, dict) and isinstance(result.get("path"), list):
            return validated_hops_from_path_items(result["path"])

        path_field = payload.get("path")
        if isinstance(path_field, list):
            return validated_hops_from_path_items(path_field)

    raise UnsupportedExportShape(
        "JSON valide mais structure non reconnue (attendu result.path[].version ou path[])."
    )


def parse_upgrade_export(
    text: str, expected_from: str | None = None, expected_to: str | None = None
) -> list[str] | None:
    """Returns hops, or None if the file should be rejected outright: unsupported-but-valid JSON
    shape, or extracted endpoints that contradict the from/to versions encoded in the filename
    (see parse_export_filename) — a mismatch there means something is wrong with the file's
    content, not just noisy, so the whole path is discarded rather than trusted partially.
    """
    try:
        json_hops = parse_upgrade_export_json(text)
    except UnsupportedExportShape:
        return None
    if json_hops is not None:
        hops = unique_in_order(json_hops)
    else:
        # Not JSON at all — loose fallback for .csv/.txt exports with no fixed structure: scan
        # for version-looking substrings anywhere in the text.
        hops = unique_in_order(VERSION_RE.findall(text))

    if hops and expected_from and hops[0] != expected_from:
        return None
    if hops and expected_to and hops[-1] != expected_to:
        return None
    return hops


def read_upgrade_exports(directory: Path) -> list[UpgradePath]:
    paths: list[UpgradePath] = []
    if not directory.exists():
        return paths

    for file_path in sorted(directory.iterdir()):
        if not file_path.is_file():
            continue
        model, from_version, to_version = parse_export_filename(file_path)
        if not model:
            continue

        text = file_path.read_text(encoding="utf-8", errors="ignore")
        hops = parse_upgrade_export(
            text, expected_from=from_version, expected_to=to_version
        )
        if not hops or len(hops) < 2:
            continue

        paths.append(
            UpgradePath(
                product=DEFAULT_PRODUCT_ID,
                model=model,
                from_version=from_version or hops[0],
                to_version=to_version or hops[-1],
                hops=tuple(hops),
                source=f"Fortinet Upgrade Path Tool export: {file_path.name}",
            )
        )
    return paths


def parse_export_filename(path: Path) -> tuple[str | None, str | None, str | None]:
    """Parse names like FGT90G__7.2.10__7.4.11.json."""
    stem = path.stem
    parts = stem.split("__")
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 1 and parts[0].startswith("FG"):
        return parts[0], None, None
    return None, None, None


def import_csv_advisories(path: Path) -> list[dict[str, Any]]:
    """Import optional internal advisories from CSV.

    Columns:
    id,product,models,version,from,to,severity,title,description,command,source
    """
    if not path.exists():
        return []

    advisories: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            advisory = {key: value for key, value in row.items() if value}
            if "models" in advisory:
                advisory["models"] = [
                    item.strip()
                    for item in advisory["models"].split(",")
                    if item.strip()
                ]
            if advisory.get("id"):
                advisories.append(advisory)
    return advisories


def build_report(
    before: dict[str, Any],
    after: dict[str, Any],
    psirt_versions: set[str],
    changed_paths: int,
    docs_catalog_enabled: bool = False,
    skipped_docs_versions: list[str] | None = None,
    forticlient_catalog_enabled: bool = False,
    skipped_forticlient: list[str] | None = None,
    cve_catalog_enabled: bool = False,
    cve_stats: CveReconciliationStats | None = None,
    skipped_cves: list[str] | None = None,
) -> str:
    before_versions = all_versions(before)
    after_versions = all_versions(after)
    new_versions = sorted(after_versions - before_versions, key=version_key)
    product = next(
        (
            item
            for item in after.get("products", [])
            if item.get("id") == DEFAULT_PRODUCT_ID
        ),
        {},
    )
    model_count = len(product.get("models", []))
    skipped_docs_versions = skipped_docs_versions or []

    lines = [
        "# Rapport FortiOS Upgrade Intelligence",
        "",
        f"- Généré le : {after['generatedAt']}",
        f"- Modèles FortiGate/FortiWiFi dans la base : {model_count}",
        f"- Versions FortiOS dans la base : {len(after_versions)}",
        f"- Nouvelles versions dans la base : {', '.join(new_versions) if new_versions else 'aucune'}",
        f"- Versions vues dans le flux PSIRT : {', '.join(sorted(psirt_versions, key=version_key)) if psirt_versions else 'aucune ou source indisponible'}",
        f"- Chemins ajoutés/mis à jour : {changed_paths}",
        "",
        "## Prochaine étape FortiCare/FNDN",
        "",
        "Le script accepte déjà un export JSON authentifié via `--forticare-json` ou `FORTICARE_FIRMWARE_JSON`.",
        "Quand le mécanisme d'authentification FortiCare/FNDN sera confirmé, il faudra remplacer cet export par un connecteur API documenté, ou par une automatisation navigateur contrôlée si aucune API n'existe.",
        "",
    ]
    if docs_catalog_enabled:
        lines.extend(
            [
                "## Catalogue public Fortinet Docs",
                "",
                "Le catalogue modèles/versions a été enrichi depuis les release notes publiques `docs.fortinet.com`.",
                f"- Versions non intégrées faute de section modèles exploitable : {', '.join(skipped_docs_versions) if skipped_docs_versions else 'aucune'}",
                "",
            ]
        )
    if forticlient_catalog_enabled:
        lines.extend(
            [
                "## Catalogue FortiClient / FortiClient EMS",
                "",
                "Le catalogue FortiClient (Windows/macOS/Linux) et FortiClient EMS a été enrichi depuis leurs release notes publiques.",
                f"- Versions non intégrées faute de numéro de build exploitable : {', '.join(skipped_forticlient) if skipped_forticlient else 'aucune'}",
                "",
            ]
        )
    if cve_catalog_enabled:
        skipped_cves = skipped_cves or []
        stats = cve_stats or CveReconciliationStats()
        lines.extend(
            [
                "## CVE PSIRT Fortinet",
                "",
                f"- CVE ajoutées : {stats.added} · mises à jour : {stats.updated} · supprimées : {stats.removed}",
                f"- Advisories PSIRT ignorées (erreur réseau) : {', '.join(skipped_cves) if skipped_cves else 'aucune'}",
                "",
            ]
        )
    return "\n".join(lines)


def all_versions(state: dict[str, Any]) -> set[str]:
    versions: set[str] = set()
    for product in state.get("products", []):
        for model in product.get("models", []):
            for firmware in model.get("firmwares", []):
                if firmware.get("version"):
                    versions.add(firmware["version"])
    return versions


def parse_retry_delays(raw: str) -> list[int]:
    return [int(chunk) for chunk in raw.split(",") if chunk.strip()]


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate FortiOS upgrade UI data.")
    parser.add_argument(
        "--base", type=Path, default=Path("data/fortios-data.sample.json")
    )
    parser.add_argument(
        "--output", type=Path, default=Path("data/fortios-data.generated.json")
    )
    parser.add_argument("--report", type=Path, default=Path("docs/last_report.md"))
    parser.add_argument(
        "--upgrade-exports", type=Path, default=Path("data/upgrade_exports")
    )
    parser.add_argument(
        "--advisories-csv", type=Path, default=Path("data/advisories.csv")
    )
    parser.add_argument(
        "--forticare-json", type=Path, default=os.environ.get("FORTICARE_FIRMWARE_JSON")
    )
    parser.add_argument(
        "--official-path",
        action="append",
        default=[],
        help="Récupérer un chemin officiel Fortinet au format MODEL:FROM:TO, ex: FGT40F:7.0.15:7.4.11.",
    )
    parser.add_argument(
        "--official-paths-csv",
        type=Path,
        default=Path("data/official-path-requests.csv"),
        help="CSV optionnel avec les colonnes model,from,to pour récupérer des chemins officiels Fortinet.",
    )
    parser.add_argument(
        "--docs-catalog",
        action="store_true",
        help="Enrichir les modèles et versions depuis les release notes publiques docs.fortinet.com.",
    )
    parser.add_argument(
        "--docs-major-versions",
        default=",".join(DEFAULT_DOCS_MAJOR_VERSIONS),
        help="Trains FortiOS à parcourir sur docs.fortinet.com, séparés par des virgules.",
    )
    parser.add_argument(
        "--tool-products",
        default="",
        help=(
            "Produits (séparés par des virgules) à enrichir depuis les endpoints publics de "
            "l'Upgrade Path Tool Fortinet, ex: fortianalyzer,fortimanager. Identifiants valides : "
            + ", ".join(PRODUCTS)
        ),
    )
    parser.add_argument(
        "--forticlient-catalog",
        action="store_true",
        help="Enrichir les catalogues FortiClient (Windows/macOS/Linux) et FortiClient EMS depuis leurs release notes publiques.",
    )
    parser.add_argument(
        "--cve-catalog",
        action="store_true",
        help="Rafraîchir le catalogue de CVE PSIRT Fortinet (flux RSS, incrémental) pour FortiOS/FAZ/FMG/FortiClient/EMS.",
    )
    parser.add_argument(
        "--cve-backfill",
        action="store_true",
        help="Backfill historique complet des CVE PSIRT via la liste paginée par produit (usage ponctuel, plus lent que --cve-catalog).",
    )
    parser.add_argument(
        "--cve-backfill-max-pages",
        type=int,
        default=30,
        help="Pages max à parcourir par produit lors du --cve-backfill.",
    )
    parser.add_argument(
        "--cve-reconcile-existing",
        action="store_true",
        help=(
            "Passe de maintenance : re-récupère aussi chaque advisory déjà référencé par le "
            "catalogue (y compris ceux sortis du dernier RSS) pour recalculer ses CVE depuis "
            "l'export CSAF précis. Idempotente et interruptible ; rien n'est écrit avant le "
            "commit final. À lancer manuellement avec --cve-catalog."
        ),
    )
    parser.add_argument(
        "--cve-retry-delays-seconds",
        type=parse_retry_delays,
        default="300,900",
        help=(
            "Délais successifs (secondes, séparés par des virgules) avant de retenter les "
            "advisories PSIRT en échec réseau -- une relance par délai, dans l'ordre, tant qu'il "
            'en reste en échec. Défaut : deux relances (5 min puis 15 min). Vide ("") pour désactiver.'
        ),
    )
    parser.add_argument(
        "--health-output",
        type=Path,
        default=DEFAULT_HEALTH_PATH,
        help="Fichier d'état de santé des collectes (séparé du catalogue principal).",
    )
    parser.add_argument(
        "--notify-history-output",
        type=Path,
        default=DEFAULT_NOTIFY_HISTORY_PATH,
        help="Fichier d'historique de déduplication des notifications email.",
    )
    parser.add_argument(
        "--notification-settings-output",
        type=Path,
        default=DEFAULT_NOTIFICATION_SETTINGS_PATH,
        help="Préférences fonctionnelles persistantes des notifications email.",
    )
    parser.add_argument(
        "--test-email",
        action="store_true",
        help="Envoie un email de test (vérifie la config SMTP), ne lance aucune collecte.",
    )
    parser.add_argument("--timeout", type=int, default=12)
    parser.add_argument("--skip-network", action="store_true")
    return parser.parse_args(argv)


def commit_collected_state(
    output_path: Path,
    state: dict[str, Any],
    advisory_deltas: list[dict[str, Any]],
    path_deltas: list[UpgradePath],
    cve_results_by_advisory: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    """Merge this run's collected deltas into the catalogue under the process lock.

    `state` is this run's own snapshot, read before potentially minutes of network collection —
    another writer (fortios_server.py, import_forticlient_compat.py) or a concurrent maintenance
    pass may have changed the file since. The lock serializes writes, not snapshot freshness, so
    nothing stale may be written back wholesale:

    - firmwares/lifecycle are this script's own exclusive domain: bulk-merged (incoming wins);
    - advisories/paths are applied as precise upserts from the deltas tracked by the caller;
    - compatibilities are never touched by this script and are left completely alone;
    - CVEs are NEVER bulk-merged from the snapshot. Only this run's definitive per-advisory
      results (cve_results_by_advisory) are applied with replace_cves_for_advisory(), so a run
      that never re-fetched an advisory cannot resurrect the stale ranges it read at the top of
      its own run over a concurrent --cve-reconcile-existing correction — and its own fresh,
      probative results still win over the disk for the advisories it did fetch.
    """
    with cross_process_lock(output_path):
        latest_from_disk = normalize_state(read_json(output_path, {}))
        state_for_bulk_merge = {
            **state,
            "advisories": [],
            "paths": [],
            "compatibilities": [],
            "cves": [],
        }
        final_state = merge_state(latest_from_disk, state_for_bulk_merge)
        for advisory in advisory_deltas:
            upsert_advisory(final_state, advisory)
        for path in path_deltas:
            upsert_path(final_state, path)
        for advisory_id, entries in cve_results_by_advisory.items():
            replace_cves_for_advisory(final_state, advisory_id, entries)
        final_state["generatedAt"] = utc_now()
        write_json(output_path, final_state)
    return final_state


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    if args.test_email:
        # Deliberately short-circuits before touching anything else: no collection, no catalog
        # read/write, no dedup history — this is purely a "does SMTP actually work" check.
        import fortios_notify

        config = fortios_notify.load_email_config(
            settings_path=args.notification_settings_output
        )
        return 0 if fortios_notify.send_test_email(config) else 1

    run_started_at_monotonic = time.monotonic()
    before = normalize_state(read_json(args.base, {}))
    state = normalize_state(read_json(args.base, {}))

    # Snapshots taken before any collection runs, purely for the email notification step at the
    # very end (see the "Notifications" block below) — every event is a diff against these, never
    # a re-scan of the whole catalog, which is what keeps a first activation or a --cve-backfill
    # from spamming years of pre-existing history.
    health_before = read_health_state(args.health_output).get("sources", {})
    cves_before_by_id = {
        item["id"]: item for item in before.get("cves", []) if item.get("id")
    }

    # Establish the notify checkpoint BEFORE any collection below can change the catalog --
    # not merely when it happens to still be missing once the notification block at the end of
    # this function runs. Picture the very first run ever with email enabled, which also happens
    # to be the run that discovers a new CVE, and then crashes before ever reaching that later
    # block: if the checkpoint were only established there, the next run would fall back to
    # reading `before` fresh off disk -- but that `before` would already reflect this run's own
    # (successful) catalog write, so the diff would find nothing new and the notification would
    # be lost exactly like before this fix existed. Bootstrapping immediately, before collection
    # can change anything, closes that crack: even if literally everything after this fails, the
    # pre-collection baseline is already safely anchored (see
    # fortios_notify.ensure_checkpoint()'s docstring for the full reasoning).
    notify_checkpoint: dict[str, Any] | None = None
    notification_settings: Any = None
    try:
        import fortios_notify

        notification_settings = fortios_notify.load_notification_settings(
            args.notification_settings_output
        )
        if (
            notification_settings.enabled
            or notification_settings.release_notifications_enabled
            or args.notification_settings_output.exists()
            or args.notify_history_output.exists()
        ):
            notify_checkpoint = fortios_notify.ensure_checkpoint(
                args.notify_history_output,
                {
                    "versionsByProduct": {
                        product: sorted(versions)
                        for product, versions in versions_by_product(before).items()
                    },
                    "cvesById": cves_before_by_id,
                    "health": health_before,
                },
            )
    except Exception as error:  # noqa: BLE001 - notification bookkeeping must never block collection.
        sys.stderr.write(
            f"Avertissement : initialisation du point de contrôle des notifications impossible ({error}).\n"
        )

    # Populated as each source below finishes (success, failure, or deliberate skip), then
    # applied to args.health_output in one batch near the end — same delta pattern as the
    # advisories/paths/CVE deltas, and for the same reason: never write partial health state
    # sprinkled across the run when one atomic commit at the end is just as easy and safer.
    health_results: dict[str, HealthSourceResult] = {}

    def record_source(
        source_id: str,
        started_at: str,
        t0: float,
        *,
        status: str,
        items: int | None = None,
        error: Any = None,
    ) -> None:
        health_results[source_id] = HealthSourceResult(
            status=status,
            started_at=started_at,
            duration_seconds=round(time.monotonic() - t0, 3),
            items_collected=items,
            error=error,
        )

    forticare_json = args.forticare_json
    if forticare_json:
        state = merge_state(state, read_forticare_json(Path(forticare_json)))

    skipped_docs_versions: list[str] = []
    if args.docs_catalog and not args.skip_network:
        t0 = time.monotonic()
        started_at = health_mark_running(args.health_output, SOURCE_FORTIOS_DOCS)
        try:
            major_versions = tuple(
                item.strip()
                for item in args.docs_major_versions.split(",")
                if item.strip()
            )
            docs_state, skipped_docs_versions = collect_docs_catalog(
                major_versions, args.timeout
            )
            items = count_firmwares(docs_state)
            state = merge_state(state, docs_state)
            try:
                apply_fortios_maturity(
                    state, fetch_fortios_version_maturity(args.timeout)
                )
            except (
                urllib.error.URLError,
                TimeoutError,
                OSError,
                json.JSONDecodeError,
                UpgradeToolResponseError,
            ):
                pass  # maturity is a soft enrichment on top of the docs catalog, not its core success
            record_source(
                SOURCE_FORTIOS_DOCS,
                started_at,
                t0,
                status=HEALTH_STATUS_OK if items > 0 else HEALTH_STATUS_WARNING,
                items=items,
                error=None
                if items > 0
                else "Aucune version collectée depuis docs.fortinet.com",
            )
        except Exception as error:  # noqa: BLE001 - any failure here must still be recorded, then re-raised is NOT desired: a docs-catalog hiccup shouldn't abort the whole run either.
            record_source(
                SOURCE_FORTIOS_DOCS,
                started_at,
                t0,
                status=HEALTH_STATUS_ERROR,
                error=error,
            )

        t0 = time.monotonic()
        started_at = health_mark_running(args.health_output, SOURCE_FORTIOS_LIFECYCLE)
        try:
            state["fortiosLifecycle"] = fetch_fortios_lifecycle(args.timeout)
            record_source(
                SOURCE_FORTIOS_LIFECYCLE,
                started_at,
                t0,
                status=HEALTH_STATUS_OK,
                items=len(state["fortiosLifecycle"]),
            )
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            json.JSONDecodeError,
        ) as error:
            record_source(
                SOURCE_FORTIOS_LIFECYCLE,
                started_at,
                t0,
                status=HEALTH_STATUS_ERROR,
                error=error,
            )
    else:
        skip_reason = (
            "collecte ignorée avec --skip-network" if args.docs_catalog else None
        )
        if skip_reason:
            skipped_docs_versions = [skip_reason]
        if args.skip_network:
            for source_id in (SOURCE_FORTIOS_DOCS, SOURCE_FORTIOS_LIFECYCLE):
                record_source(
                    source_id,
                    utc_now_precise(),
                    time.monotonic(),
                    status=HEALTH_STATUS_SKIPPED,
                )
        # else: --docs-catalog simply wasn't requested this run at all (a narrower invocation,
        # e.g. the afternoon CVE-only retry pass) -- leave these sources' health record exactly
        # as an earlier, more complete run left it, rather than clobbering a still-fresh real
        # success with a misleading "ignorée" every single afternoon.

    tool_products = [
        item.strip() for item in args.tool_products.split(",") if item.strip()
    ]
    tool_product_health_sources = {
        "fortianalyzer": SOURCE_FORTIANALYZER,
        "fortimanager": SOURCE_FORTIMANAGER,
    }
    if tool_products and not args.skip_network:
        for product_id in tool_products:
            if product_id not in PRODUCTS:
                continue
            source_id = tool_product_health_sources.get(product_id)
            t0 = time.monotonic()
            started_at = (
                health_mark_running(args.health_output, source_id)
                if source_id
                else utc_now_precise()
            )
            try:
                product_state = collect_tool_catalog(product_id, args.timeout)
                items = count_firmwares_for_product(product_state, product_id)
                state = merge_state(state, product_state)
                if source_id:
                    record_source(
                        source_id,
                        started_at,
                        t0,
                        status=HEALTH_STATUS_OK if items > 0 else HEALTH_STATUS_WARNING,
                        items=items,
                        error=None
                        if items > 0
                        else f"Aucune version collectée pour {product_id}",
                    )
            except Exception as error:  # noqa: BLE001 - one product's failure shouldn't abort the others.
                if source_id:
                    record_source(
                        source_id,
                        started_at,
                        t0,
                        status=HEALTH_STATUS_ERROR,
                        error=error,
                    )
    elif args.skip_network:
        for source_id in tool_product_health_sources.values():
            record_source(
                source_id,
                utc_now_precise(),
                time.monotonic(),
                status=HEALTH_STATUS_SKIPPED,
            )
    # else (no --tool-products, not --skip-network): not requested this run at all -- leave
    # these sources' health record untouched, same reasoning as the docs-catalog branch above.

    skipped_forticlient: list[str] = []
    if args.forticlient_catalog and not args.skip_network:
        t0 = time.monotonic()
        started_at_fc = health_mark_running(args.health_output, SOURCE_FORTICLIENT)
        started_at_ems = health_mark_running(args.health_output, SOURCE_FORTICLIENT_EMS)
        try:
            major_versions = tuple(
                item.strip()
                for item in args.docs_major_versions.split(",")
                if item.strip()
            )
            forticlient_state, skipped_forticlient = collect_forticlient_catalog(
                major_versions, args.timeout
            )
            items_fc = count_firmwares_for_product(
                forticlient_state, FORTICLIENT_PRODUCT_ID
            )
            items_ems = count_firmwares_for_product(
                forticlient_state, FORTICLIENT_EMS_PRODUCT_ID
            )
            state = merge_state(state, forticlient_state)
            # One HTTP/scraping flow covers both products together, so they succeed/fail as a
            # pair — only the item counts are tracked per product.
            record_source(
                SOURCE_FORTICLIENT,
                started_at_fc,
                t0,
                status=HEALTH_STATUS_OK if items_fc > 0 else HEALTH_STATUS_WARNING,
                items=items_fc,
                error=None if items_fc > 0 else "Aucune version FortiClient collectée",
            )
            record_source(
                SOURCE_FORTICLIENT_EMS,
                started_at_ems,
                t0,
                status=HEALTH_STATUS_OK if items_ems > 0 else HEALTH_STATUS_WARNING,
                items=items_ems,
                error=None
                if items_ems > 0
                else "Aucune version FortiClient EMS collectée",
            )
        except Exception as error:  # noqa: BLE001 - recorded, not re-raised: doesn't abort the rest of the run.
            record_source(
                SOURCE_FORTICLIENT,
                started_at_fc,
                t0,
                status=HEALTH_STATUS_ERROR,
                error=error,
            )
            record_source(
                SOURCE_FORTICLIENT_EMS,
                started_at_ems,
                t0,
                status=HEALTH_STATUS_ERROR,
                error=error,
            )
    else:
        if args.forticlient_catalog:
            skipped_forticlient = ["collecte ignorée avec --skip-network"]
        if args.skip_network:
            for source_id in (SOURCE_FORTICLIENT, SOURCE_FORTICLIENT_EMS):
                record_source(
                    source_id,
                    utc_now_precise(),
                    time.monotonic(),
                    status=HEALTH_STATUS_SKIPPED,
                )
        # else: --forticlient-catalog simply wasn't requested this run -- leave untouched.

    # Advisories and paths are the two fields a live user can create/edit/delete through
    # fortios_server.py at any moment, including during this run's multi-minute network
    # collection — so unlike everything else `state` accumulates below (firmwares, CVEs,
    # lifecycle: this script's own exclusive domain, safe to bulk-merge), these two are tracked
    # separately as precise deltas and applied as targeted upserts onto a freshly re-read state
    # at commit time, never as a wholesale replace of a possibly-stale full copy (see the commit
    # section below for why that distinction matters).
    advisory_deltas: list[dict[str, Any]] = []
    path_deltas: list[UpgradePath] = []

    for advisory in import_csv_advisories(args.advisories_csv):
        state["advisories"] = [
            item for item in state["advisories"] if item.get("id") != advisory["id"]
        ]
        state["advisories"].append(advisory)
        advisory_deltas.append(advisory)

    changed_paths = 0
    official_requests = read_official_path_requests(args.official_paths_csv)
    official_requests.extend(
        parse_official_path_spec(spec) for spec in args.official_path
    )
    if official_requests and not args.skip_network:
        for official_request in official_requests:
            try:
                official_result = fetch_official_upgrade_path(
                    official_request, args.timeout
                )
            except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
                continue
            if not official_result:
                continue
            official_path, firmwares = official_result
            for firmware in firmwares:
                upsert_firmware(state, firmware)
            if upsert_path(state, official_path):
                changed_paths += 1
            path_deltas.append(official_path)

    for path in read_upgrade_exports(args.upgrade_exports):
        for version in path.hops:
            upsert_firmware(state, Firmware(path.product, path.model, version))
        if upsert_path(state, path):
            changed_paths += 1
        path_deltas.append(path)

    psirt_versions: set[str] = set()
    if not args.skip_network:
        psirt_versions = fetch_psirt_versions(args.timeout)

    cve_stats = CveReconciliationStats()
    cve_results_by_advisory: dict[str, list[dict[str, Any]]] = {}
    skipped_cves: list[str] = []
    # Set when the maintenance pass cannot make its silence intent durable (see the staging block
    # below): the reconciled results are then withheld from the commit and the health record says
    # so, instead of committing history corrections nothing would keep silent.
    reconcile_aborted = False
    if (args.cve_catalog or args.cve_backfill or args.cve_reconcile_existing) and not args.skip_network:
        t0 = time.monotonic()
        started_at = health_mark_running(args.health_output, SOURCE_CVE_PSIRT)
        try:
            existing_advisory_ids = {
                item.get("advisoryId") for item in state.get("cves", [])
            }
            cve_results_by_advisory, skipped_cves = collect_cve_catalog(
                existing_advisory_ids,
                args.timeout,
                backfill=args.cve_backfill,
                backfill_max_pages=args.cve_backfill_max_pages,
                reconcile_existing=args.cve_reconcile_existing,
            )
            # A handful of advisories failing out of the ~50 fetched daily is almost always a
            # transient PSIRT hiccup (rate limiting, brief outage) that clears up within minutes
            # on its own -- retrying seconds later (the per-request backoff in read_url_with_retry)
            # mostly doesn't help with that, so wait for real before giving the still-failing ones
            # another shot. Bounded and spaced out (not "retry forever until green"): an advisory
            # can be legitimately without a usable CSAF link (see collect_cve_entries_for_advisory's
            # docstring),
            # indistinguishable here from a real failure, so an unbounded loop would spin on it
            # forever every single day; and hammering PSIRT harder/faster when it's already
            # struggling only makes the rate limiting worse, not better (observed directly: 1
            # skip left completely alone, vs 3 after two manual back-to-back re-runs).
            for delay in args.cve_retry_delays_seconds:
                if not skipped_cves:
                    break
                time.sleep(delay)
                retried_results, skipped_cves = fetch_cve_entries_for_advisories(
                    skipped_cves, args.timeout
                )
                cve_results_by_advisory.update(retried_results)

            # Durable silence intent, written BEFORE the catalogue commit further below: the
            # corrected historical entries are declared "not news" on disk first, so even if this
            # process dies between the catalogue commit and the notification work, every later run
            # — a normal collection included — can still confirm and absorb them instead of
            # deriving them as brand-new notifications (see
            # fortios_notify.stage_pending_cve_baseline()). If this intent cannot be made durable,
            # the reconciliation is abandoned for this run: committing corrections that nothing
            # would keep silent is exactly the historical-replay window this pass exists to close.
            # Skipped only when no notification state exists at all — nothing to protect, since a
            # future first activation bootstraps its baseline silently from whatever the catalogue
            # holds then.
            if args.cve_reconcile_existing and cve_results_by_advisory and (
                notify_checkpoint is not None
                or os.path.lexists(args.notify_history_output)
            ):
                try:
                    import fortios_notify

                    fortios_notify.stage_pending_cve_baseline(
                        args.notify_history_output,
                        {
                            entry["id"]: entry
                            for entries in cve_results_by_advisory.values()
                            for entry in entries
                            if entry.get("id")
                        },
                    )
                except Exception as error:  # noqa: BLE001 - recorded below, never fatal here.
                    reconcile_aborted = True
                    cve_results_by_advisory = {}
                    sys.stderr.write(
                        "Avertissement : réconciliation CVE abandonnée, intention durable de "
                        f"silence non enregistrable ({error}) — les corrections historiques de "
                        "ce run ne sont pas committées.\n"
                    )
            # Each advisory here got a definitive CVRF result this run: replace (not just upsert)
            # whatever we had for it, so a CVE Fortinet has since removed/reattributed away from
            # our tracked products actually disappears instead of lingering forever. Advisories
            # in skipped_cves are left completely untouched. Reconciling `state` here (in
            # addition to `final_state` below) is what makes the numbers in the report accurate;
            # the actual persisted removal only really takes effect at the final commit.
            for advisory_id, entries in cve_results_by_advisory.items():
                cve_stats += replace_cves_for_advisory(state, advisory_id, entries)

            total_considered = len(cve_results_by_advisory) + len(skipped_cves)
            if reconcile_aborted:
                cve_health_status = HEALTH_STATUS_ERROR
                cve_health_error = (
                    "Réconciliation CVE abandonnée : intention durable de silence "
                    "non enregistrable"
                )
            elif total_considered > 0 and not cve_results_by_advisory:
                cve_health_status = HEALTH_STATUS_ERROR
                cve_health_error = (
                    f"{len(skipped_cves)} advisorie(s) PSIRT injoignable(s)"
                )
            elif skipped_cves:
                cve_health_status = HEALTH_STATUS_WARNING
                cve_health_error = f"{len(skipped_cves)} advisorie(s) PSIRT ignorée(s) (réseau/parsing)"
            else:
                cve_health_status = HEALTH_STATUS_OK
                cve_health_error = None
            record_source(
                SOURCE_CVE_PSIRT,
                started_at,
                t0,
                status=cve_health_status,
                items=cve_stats.added + cve_stats.updated,
                error=cve_health_error,
            )
        except Exception as error:  # noqa: BLE001 - recorded, not re-raised.
            record_source(
                SOURCE_CVE_PSIRT,
                started_at,
                t0,
                status=HEALTH_STATUS_ERROR,
                error=error,
            )
    elif args.skip_network:
        record_source(
            SOURCE_CVE_PSIRT,
            utc_now_precise(),
            time.monotonic(),
            status=HEALTH_STATUS_SKIPPED,
        )
    # else (no --cve-catalog/--cve-backfill, not --skip-network): not requested this run -- leave
    # untouched (see the docs-catalog branch above for why).

    # This run started from a read of args.output taken potentially minutes ago (network
    # scraping in between) — fortios_server.py or import_forticlient_compat.py may have written
    # to that same file since, and the maintenance reconciliation (--cve-reconcile-existing) may
    # even have repaired CVEs of advisories this run never fetched. commit_collected_state()
    # applies this run's deltas onto a freshly re-read state under the lock (see its docstring:
    # firmwares/lifecycle bulk-merged, advisories/paths as precise upserts, CVEs only per fetched
    # advisory) so nothing stale is written back wholesale.
    final_state = commit_collected_state(
        args.output, state, advisory_deltas, path_deltas, cve_results_by_advisory
    )

    # Maintenance reconciliation and notifications: the corrected historical entries this pass
    # just committed must be part of the notification baseline from this very commit on. The
    # durable intent was staged BEFORE the commit above (stage_pending_cve_baseline); this step
    # confirms it against the just-committed catalogue right here, so even a crash that skips
    # everything below leaves the corrections un-replayable: any later run — normal collection
    # included — resolves the same staged intent before deriving anything (see
    # consume_pending_cve_baseline() and the notification block below). Outbox, sentKeys,
    # preferences and the version/health baselines (a combined run must still be able to notify
    # them) are untouched.
    if args.cve_reconcile_existing and notify_checkpoint is not None:
        try:
            import fortios_notify

            fortios_notify.consume_pending_cve_baseline(
                args.notify_history_output,
                {
                    item["id"]: item
                    for item in final_state.get("cves", [])
                    if item.get("id")
                },
            )
        except Exception as error:  # noqa: BLE001 - notification bookkeeping only.
            sys.stderr.write(
                "Avertissement : consommation de l'intention de réconciliation CVE "
                f"impossible ({error}).\n"
            )

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        build_report(
            before,
            final_state,
            psirt_versions,
            changed_paths,
            docs_catalog_enabled=args.docs_catalog,
            skipped_docs_versions=skipped_docs_versions,
            forticlient_catalog_enabled=args.forticlient_catalog,
            skipped_forticlient=skipped_forticlient,
            cve_catalog_enabled=args.cve_catalog
            or args.cve_backfill
            or args.cve_reconcile_existing,
            cve_stats=cve_stats,
            skipped_cves=skipped_cves,
        ),
        encoding="utf-8",
    )

    # Overall summary across every source touched this run: red if anything hard-failed, orange
    # if only warnings/skips, green otherwise. Computed from health_results rather than any
    # separate bookkeeping, so it can never drift from what's actually being reported per source.
    failed_sources = sorted(
        sid
        for sid, result in health_results.items()
        if result.status == HEALTH_STATUS_ERROR
    )
    warned_sources = sorted(
        sid
        for sid, result in health_results.items()
        if result.status == HEALTH_STATUS_WARNING
    )
    if failed_sources:
        daily_run_status = HEALTH_STATUS_ERROR
        daily_run_error = f"En échec : {', '.join(failed_sources)}"
    elif warned_sources:
        daily_run_status = HEALTH_STATUS_WARNING
        daily_run_error = f"Avertissement : {', '.join(warned_sources)}"
    else:
        daily_run_status = HEALTH_STATUS_OK
        daily_run_error = None
    health_results[SOURCE_DAILY_RUN] = HealthSourceResult(
        status=daily_run_status,
        started_at=utc_now_precise(),
        duration_seconds=round(time.monotonic() - run_started_at_monotonic, 3),
        items_collected=count_firmwares(final_state),
        error=daily_run_error,
    )
    # Health tracking is entirely best-effort: a problem writing it (disk full, permissions...)
    # must never be treated as if the actual collection above had failed. ValueError is caught
    # too, defensively: read_health_state()'s validator already rejects a record with a
    # non-timezone-aware timestamp before _merge_health_source() ever sees it, but this is cheap
    # insurance against that guarantee ever developing a gap.
    try:
        record_health_results(args.health_output, health_results)
    except (OSError, ValueError) as error:
        sys.stderr.write(
            f"Avertissement : échec de l'écriture de l'état de santé ({error}).\n"
        )

    # Email notifications: entirely best-effort and additive, never touching the catalog or the
    # exit code.
    #
    # Checkpoint architecture (closes the catalog-vs-outbox loss window): final_state was already
    # committed to args.output above, well before this block runs. If this process died right
    # after that commit but before the events derived from it ever reached the outbox, naively
    # diffing against `before` (this run's own pre-collection snapshot) would be wrong on the
    # NEXT run -- `before` would then be read fresh from the now-already-updated catalog, so the
    # version/CVE that was never actually notified about would no longer look new at all. Instead,
    # every catalog/health-derived event below is diffed against `notify_checkpoint`: a snapshot
    # of versions/CVEs/health as of the last run whose events genuinely made it into the outbox,
    # established BEFORE collection even started (see the "Establish the notify checkpoint" block
    # near the top of this function, and fortios_notify.ensure_checkpoint()'s docstring for why it
    # can't simply be bootstrapped here instead). commit_events_with_checkpoint() then advances it
    # and queues the events it produced in one single atomic write -- exactly the same "state +
    # events together, or neither" guarantee commit_eol_transition() already gives EOL crossings.
    # A crash between the catalog commit and this commit simply leaves the checkpoint where it
    # was: the next run's diff (old checkpoint vs current catalog) still finds the version/CVE
    # "new" and re-derives the same event, which the existing outbox/sentKeys dedup (keyed by a
    # stable dedup_key, not by which run happened to derive it) makes safe to attempt again from
    # a different, later run.
    #
    # A crashed maintenance pass (--cve-reconcile-existing) is the exception that must NOT
    # re-derive: its corrections are not news, they are the state the pass itself staged as
    # baseline before committing the catalogue (see the staging block above and
    # stage_pending_cve_baseline()). This block resolves any staged intent against the
    # just-committed catalogue before deriving anything — applied entries are diffed against
    # themselves, and only entries the catalogue has not actually reached yet stay pending for a
    # later run — so a normal resume can never turn corrected history back into notifications.
    try:
        import uuid

        import fortios_notify  # deferred: avoids a load-time circular import with this module

        email_config = fortios_notify.load_email_config(
            settings=notification_settings,
            settings_path=args.notification_settings_output,
        )
        # Three independent category gates. `enabled` is the CVE switch alone;
        # releaseNotificationsEnabled adds/removes the "nouvelle version" category; system
        # alerts (EOL, repeated collection failures, recoveries, technical events) have their
        # own switch and their own recipient list, with no sharing or fallback in either
        # direction. Every category keeps its own derivation gate below.
        cve_notifications = email_config.enabled
        release_notifications = email_config.release_notifications_enabled
        system_notifications = bool(
            notification_settings is not None
            and notification_settings.system_notifications_enabled
            and notification_settings.system_recipients
        )
        if (
            notification_settings is not None
            and notify_checkpoint is not None
            and not cve_notifications
            and not release_notifications
            and not system_notifications
        ):
            health_after = read_health_state(args.health_output).get("sources", {})
            cves_after_by_id = {
                item["id"]: item
                for item in final_state.get("cves", [])
                if item.get("id")
            }
            notify_state = fortios_notify.load_notify_state(args.notify_history_output)
            _, eol_state_after = fortios_notify.derive_eol_events(
                final_state.get("fortiosLifecycle", {}),
                notify_state.get("eolState", {}),
                now=final_state["generatedAt"],
            )
            fortios_notify.commit_disabled_notification_state(
                args.notify_history_output,
                eol_state_after,
                {
                    "versionsByProduct": {
                        product: sorted(versions)
                        for product, versions in versions_by_product(final_state).items()
                    },
                    "cvesById": cves_after_by_id,
                    "health": health_after,
                },
            )
        if (
            notification_settings is not None
            and notify_checkpoint is not None
            and (
                cve_notifications
                or release_notifications
                or system_notifications
            )
        ):
            health_after = read_health_state(args.health_output).get("sources", {})
            notify_state = fortios_notify.load_notify_state(args.notify_history_output)
            pending_observed = notify_state.get(fortios_notify.PENDING_CVE_BASELINE_KEY)

            # The derivation baseline is the checkpoint as it stands RIGHT NOW -- freshly
            # re-read -- not the one this run bootstrapped at start-up. A maintenance pass (or any
            # other writer) that completed while this run was still collecting has already
            # consumed its historical corrections into that fresher checkpoint; deriving against
            # the stale start-up capture would replay them (the B3 "checkpoint périmé" case), so
            # the durable state -- never an in-flight run's memory -- is the reference that stays
            # opposable to it. The same freshness contract is enforced again, under the write
            # lock, by commit_events_with_checkpoint(derivation_checkpoint=...): a correction
            # certified by someone else is never overwritten by this run's older snapshot.
            checkpoint_state = notify_state.get("checkpoint") or notify_checkpoint

            # cves_after_by_id feeds the new checkpoint below regardless of --cve-backfill, so a
            # normal run right after a backfill still sees those CVEs as already-known rather
            # than spamming all of them as "new".
            cves_after_by_id = {
                item["id"]: item
                for item in final_state.get("cves", [])
                if item.get("id")
            }

            # A maintenance pass that crashed between its catalogue commit and its baseline
            # advance leaves a durable intent on disk (stage_pending_cve_baseline). Confirm it
            # against the catalogue this run just committed: entries the catalogue already
            # carries with the same notification-relevant severity become part of the diff
            # baseline, so no run can derive them as brand-new history; anything the catalogue
            # has not actually reached yet stays staged (it must never be silently advanced to a
            # state the catalogue does not back). The resolution is certified, not imposed: the
            # final commit below only retires the ids this run actually observed and resolved, in
            # the same atomic write that advances the checkpoint.
            pending_applied, pending_remaining = fortios_notify.resolve_pending_cve_baseline(
                pending_observed,
                cves_after_by_id,
            )

            checkpoint_versions = {
                product: set(versions)
                for product, versions in checkpoint_state["versionsByProduct"].items()
            }
            checkpoint_cves_by_id = {**checkpoint_state["cvesById"], **pending_applied}
            checkpoint_health = checkpoint_state["health"]

            events: list[Any] = []
            # Historical ingestion (--cve-backfill) and the maintenance reconciliation
            # (--cve-reconcile-existing) never derive notifications: the entries they import or
            # correct are not news. The checkpoint below still advances to the final catalogue
            # (and the staged CVE-baseline intent — consumed right after the commit above, and
            # re-confirmed by every later run — already covers an interruption before this
            # block), so a later normal run cannot replay any of it as new.
            if not (args.cve_backfill or args.cve_reconcile_existing):
                product_labels = {
                    p.get("id"): p.get("label", p.get("id"))
                    for p in final_state.get("products", [])
                }
                if release_notifications:
                    events += fortios_notify.derive_version_events(
                        checkpoint_versions,
                        versions_by_product(final_state),
                        product_labels,
                        detected_at=final_state["generatedAt"],
                        release_links=release_notes_by_product(final_state),
                    )
                if cve_notifications:
                    newly_added_cves = [
                        item
                        for item in final_state.get("cves", [])
                        if item.get("id") and item["id"] not in checkpoint_cves_by_id
                    ]
                    events += fortios_notify.derive_new_cve_events(
                        newly_added_cves, notification_settings
                    )
                    events += fortios_notify.derive_cve_modification_events(
                        checkpoint_cves_by_id,
                        cves_after_by_id,
                        notification_settings,
                    )

            # A CVE backfill must not consume a real EOL crossing while system alerts are on:
            # the next normal collection must still be able to notify it. While the category is
            # off, however, its baseline keeps advancing silently even during a backfill so a
            # later activation cannot replay historical transitions.
            if not args.cve_backfill or not system_notifications:
                eol_events, eol_state_after = fortios_notify.derive_eol_events(
                    final_state.get("fortiosLifecycle", {}),
                    notify_state.get("eolState", {}),
                    now=final_state["generatedAt"],
                )
                fortios_notify.commit_eol_transition(
                    args.notify_history_output,
                    eol_state_after,
                    eol_events if system_notifications else [],
                    now=final_state["generatedAt"],
                )

            # System alerts (EOL above, collection health here) follow their own switch: while
            # it is off, the health baseline still advances through the checkpoint committed
            # below, so re-enabling never replays an older failure or recovery.
            if system_notifications:
                events += fortios_notify.derive_source_health_events(
                    checkpoint_health, health_after, HEALTH_SOURCE_LABELS
                )

            # Container image security (Trivy) — a category of its own, ingested from the report the
            # VPS sync downloaded next to the notification state. It commits its OWN state
            # atomically (baseline + outbox in one write, see
            # commit_container_security_transition) and therefore runs here, before the claim
            # below, so a fresh finding is delivered in this same pass. Deliberately NOT gated by
            # `cve_notifications`: the scan state is recorded either way (disabling is a pause,
            # not a buffer) and the administration displays it regardless of the switch.
            container_settings_path = (
                args.notification_settings_output.parent
                / fortios_notify.CONTAINER_SECURITY_SETTINGS_FILENAME
            )
            container_settings, container_settings_error = (
                fortios_notify.load_container_security_settings(container_settings_path)
            )
            if container_settings_error:
                print(
                    f"Sécurité conteneur : {container_settings_error}",
                    file=sys.stderr,
                    flush=True,
                )
            container_events, container_error = (
                fortios_notify.ingest_container_security_report(
                    args.notification_settings_output.parent / "trivy-report.json",
                    args.notification_settings_output.parent / "trivy-report.meta.json",
                    container_settings,
                    history_path=args.notify_history_output,
                    now=final_state["generatedAt"],
                )
            )
            if container_error:
                print(
                    f"Sécurité conteneur : {container_error}",
                    file=sys.stderr,
                    flush=True,
                )
            if container_events:
                print(
                    f"Sécurité conteneur : {len(container_events)} nouvel(aux) événement(s).",
                    flush=True,
                )

            if args.cve_reconcile_existing:
                # A maintenance pass may only absorb what it actually resolved: the corrections
                # its own staged intent confirmed against the catalogue it just committed
                # (checkpoint_cves_by_id = durable baseline + confirmed corrections), plus the
                # version baseline unchanged. Advancing CVE/version baselines to the WHOLE merged
                # catalogue would silently absorb a novelty this pass never derived an event for
                # -- a concurrent collector's new CVE, a newly collected version -- and the next
                # normal run would then find nothing left to report (the B3 "absorption globale"
                # case). Anything beyond its own corrections stays diffable; the next normal run
                # still derives and delivers it exactly once. Health is this run's own source
                # observation, not catalogue-derived, and keeps advancing as before.
                new_checkpoint = {
                    "versionsByProduct": {
                        product: sorted(versions)
                        for product, versions in checkpoint_state["versionsByProduct"].items()
                    },
                    "cvesById": dict(checkpoint_cves_by_id),
                    "health": health_after,
                }
            else:
                new_checkpoint = {
                    "versionsByProduct": {
                        product: sorted(versions)
                        for product, versions in versions_by_product(final_state).items()
                    },
                    "cvesById": cves_after_by_id,
                    "health": health_after,
                }
            claimant = f"{os.getpid()}-{uuid.uuid4().hex[:8]}"
            pending = fortios_notify.commit_events_with_checkpoint(
                args.notify_history_output,
                new_checkpoint,
                events,
                claimant=claimant,
                transport=email_config.transport,
                settings=notification_settings,
                pending_cve_baseline=fortios_notify.PendingCveBaselineResolution(
                    observed=pending_observed,
                    remaining=pending_remaining,
                ),
                derivation_checkpoint=checkpoint_state,
            )
            fortios_notify.deliver_notification_batches(
                args.notify_history_output,
                pending,
                claimant=claimant,
                settings=notification_settings,
                config=email_config,
                run_timestamp=final_state["generatedAt"],
                container_security=container_settings,
            )
    except Exception as error:  # noqa: BLE001 - a broken notification path must never fail the run.
        sys.stderr.write(f"Avertissement : notification email non envoyée ({error}).\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
