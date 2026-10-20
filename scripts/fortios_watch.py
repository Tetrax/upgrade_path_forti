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
import dataclasses
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
# CISA Known Exploited Vulnerabilities: public JSON catalogue of CVEs with confirmed in-the-wild
# exploitation. Only used to flag CVEs already in our catalogue; never a source of new CVEs.
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
# The full KEV catalogue holds well over a thousand entries; a much shorter document is a
# truncated or substituted response, never "nothing is exploited any more".
KEV_MIN_ENTRIES = 100
CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}")
# Bounded history of detected RSS discontinuities kept in the catalogue's cveCoverage.
CVE_COVERAGE_MAX_GAPS = 20
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


# Sentinel for read_coherent_notification_observation(): it is never a valid catalogue, so "the
# durable catalogue could not be read" can never be confused with any real payload.
_COHERENT_OBSERVATION_UNAVAILABLE = object()


def _notification_catalogue_invalid_reason(catalogue: dict[str, Any]) -> str | None:
    """Why `catalogue` cannot feed the notification block -- None when it can.

    The notification block derives every baseline (CVE ids/severities, versions, EOL, health)
    from this catalogue BEFORE writing any of them, and each consumer treats a missing or
    wrong-typed collection as an empty one ({} iterates as nothing, a missing key falls back
    to []). That silent equivalence is the danger: an invalid catalogue would REPLACE healthy
    baselines with nothing and the next runs would replay the whole history as new. Missing
    data is not a valid empty list, so every field the block actually reads is checked against
    its real contract here, and only for the shapes those paths use:

    - ``cves``: list of entry dicts carrying a non-empty string ``id`` (the baseline is keyed
      by it);
    - ``products``: list of product dicts whose ``models``/``firmwares`` lists carry the
      version strings the version baseline is built from;
    - ``fortiosLifecycle``: branch -> dict map (derive_eol_events() iterates .items()).

    A genuinely empty list (``cves: []``, no model/firmware) stays valid: this rejects
    structures, never contents -- extra keys, absent optional fields and entries the consumers
    already tolerate are left to the consumers.
    """
    cves = catalogue.get("cves")
    if not isinstance(cves, list):
        return "cves : liste attendue"
    for entry in cves:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("id"), str)
            or not entry["id"].strip()
        ):
            return "cves : entrées mal formées"
    products = catalogue.get("products")
    if not isinstance(products, list):
        return "products : liste attendue"
    for product in products:
        if not isinstance(product, dict):
            return "products : entrées mal formées"
        models = product.get("models", [])
        if not isinstance(models, list) or not all(
            isinstance(model, dict) for model in models
        ):
            return "products : modèles mal formés"
        for model in models:
            firmwares = model.get("firmwares", [])
            if not isinstance(firmwares, list) or not all(
                isinstance(firmware, dict) for firmware in firmwares
            ):
                return "products : firmwares mal formés"
            if any(
                firmware.get("version") is not None
                and not isinstance(firmware.get("version"), str)
                for firmware in firmwares
            ):
                return "products : versions mal formées"
    lifecycle = catalogue.get("fortiosLifecycle")
    if not isinstance(lifecycle, dict) or not all(
        isinstance(info, dict) for info in lifecycle.values()
    ):
        return "fortiosLifecycle : objet attendu"
    return None


def read_coherent_notification_observation(
    history_path: Path, catalogue_path: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read the committed catalogue AND the notify state as ONE coherent observation.

    Both reads happen inside a single short cross_process_lock(history_path) section. Every
    writer of the checkpoint, the staged CVE-baseline intents and the rest of the notify state
    goes through that very lock, so none of them can advance between the two reads; the
    catalogue is replaced atomically, so the image read next to that state is the one the
    notification work will diff against it. A maintenance pass (or any other writer) completing
    while a run was still collecting can therefore only be observed entirely before this
    snapshot (its advance is already the baseline) or entirely after it (its stage/consume/
    commit steps are still excluded by the lock) -- never as a stale catalogue image paired
    with a freshly certified baseline, the shape that used to let an older run regress that
    advance and replay the correction as a historical notification (the B3 review's remaining
    window).

    The lock is released before any derivation, network or SMTP work: it only ever covers the
    two reads, never the whole notification pass (whose helpers take this same non-reentrant
    lock themselves).

    Never falls back silently: an absent, unreadable or structurally invalid catalogue raises
    (the caller isolates the failure by suspending the notification work -- state preserved,
    cleaned diagnostic, collection unaffected) instead of deriving from this run's own older
    `final_state` image, which nothing durable backs anymore. Structural validity covers the
    fields the notification block actually consumes -- checked BEFORE it can write any
    baseline, see _notification_catalogue_invalid_reason() -- so a wrong-typed or missing
    collection can never be iterated as if it were empty and silently replace a healthy
    baseline with nothing.
    """
    import fortios_notify  # deferred: avoids a load-time circular import with this module

    with cross_process_lock(history_path):
        try:
            catalogue = read_json(catalogue_path, _COHERENT_OBSERVATION_UNAVAILABLE)
        except (OSError, UnicodeDecodeError, ValueError) as error:
            raise RuntimeError(
                f"Catalogue durable illisible ({type(error).__name__})."
            ) from error
        if catalogue is _COHERENT_OBSERVATION_UNAVAILABLE or not isinstance(
            catalogue, dict
        ):
            raise RuntimeError(
                "Catalogue durable absent ou invalide pour l'observation des notifications"
            )
        invalid_reason = _notification_catalogue_invalid_reason(catalogue)
        if invalid_reason is not None:
            raise RuntimeError(
                "Catalogue durable structurellement invalide pour l'observation des "
                f"notifications ({invalid_reason})."
            )
        notify_state = fortios_notify.load_notify_state(history_path)
    return catalogue, notify_state


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
SOURCE_CISA_KEV = "cisa-kev"
# The weekly --cve-backfill (full PSIRT history check), kept apart from the daily RSS collection
# so neither can reset the other's failure count or recovery alert.
SOURCE_CVE_HISTORY = "cve-psirt-history"
# CVE.org and NVD cross-check of the PSIRT data (--cve-crosscheck), its own record so an outage of
# either reference never turns the PSIRT collection itself orange.
SOURCE_CVE_CROSSCHECK = "cve-crosscheck"
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
    SOURCE_CISA_KEV,
    SOURCE_CVE_HISTORY,
    SOURCE_CVE_CROSSCHECK,
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
    SOURCE_CISA_KEV: "CISA KEV (exploitation active)",
    SOURCE_CVE_HISTORY: "Historique CVE PSIRT (hebdomadaire)",
    SOURCE_CVE_CROSSCHECK: "Contre-vérification CVE (CVE.org, NVD)",
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
    parsed = dt.datetime.fromisoformat(value)
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
        # Continuity of the PSIRT RSS observation (see update_cve_coverage()), only present once
        # a run has observed the feed. An older image simply drops this key on its next write:
        # the coverage restarts, nothing else is lost.
        **(
            {"cveCoverage": payload["cveCoverage"]}
            if isinstance(payload.get("cveCoverage"), dict)
            else {}
        ),
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
        "discoveredAt": dt.datetime.now(dt.UTC).date().isoformat(),
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
# and the run reports the skip — never "no more CVEs". The one exception is
# narrow: an advisory older than Fortinet's CSAF exports (<= FG-IR-23) that has
# none at all is read from a CVRF that enumerates exact affected versions,
# never from a train-level one (see parse_legacy_cvrf_document()).
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
# First word after a tracked name that makes it a different product line, whatever its case:
# "FortiManager cloud 7.0 all versions", "FortiOS-6K7K 7.0.10" (chassis builds, own numbering).
CSAF_DISTINCT_PRODUCT_WORDS = frozenset({"cloud", "6k7k"})
# Fortinet components named without the "Forti" prefix, never tracked here (FortiGuard engines).
CSAF_UNTRACKED_COMPONENT_PREFIXES = ("IPS Engine", "AV Engine")


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


class KevFeedError(ValueError):
    """The CISA KEV document is not the catalogue it should be (shape, size)."""


def parse_cisa_kev(payload: Any) -> dict[str, dict[str, Any]]:
    """Fortinet entries of the CISA KEV catalogue, keyed by upper-case CVE id.

    Each value is ``{"dateAdded": "YYYY-MM-DD" | None, "ransomware": bool}``. A malformed or
    suspiciously short document raises KevFeedError: the caller then keeps the flags it already
    had instead of clearing every CVE's exploitation status on a bad response.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise KevFeedError("format du catalogue CISA KEV inattendu")
    vulnerabilities = payload["vulnerabilities"]
    if len(vulnerabilities) < KEV_MIN_ENTRIES:
        raise KevFeedError(
            f"catalogue CISA KEV anormalement court ({len(vulnerabilities)} entrées)"
        )
    listed: dict[str, dict[str, Any]] = {}
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        if str(item.get("vendorProject") or "").strip().casefold() != "fortinet":
            continue
        cve_id = str(item.get("cveID") or "").strip().upper()
        if not CVE_ID_RE.fullmatch(cve_id):
            continue
        date_added = str(item.get("dateAdded") or "").strip()
        listed[cve_id] = {
            "dateAdded": date_added if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_added) else None,
            "ransomware": str(item.get("knownRansomwareCampaignUse") or "").strip().casefold()
            == "known",
        }
    # Fortinet has had dozens of listed CVEs for years: none at all is a filtered or substituted
    # document, never "nothing Fortinet is exploited any more".
    if not listed:
        raise KevFeedError("catalogue CISA KEV sans aucune entrée Fortinet")
    return listed


def fetch_cisa_kev(timeout: int) -> dict[str, dict[str, Any]]:
    request = urllib.request.Request(
        CISA_KEV_URL, headers={"User-Agent": "sns-fortios-upgrade-watch/0.1"}
    )
    return parse_cisa_kev(json.loads(read_url_with_retry(request, timeout)))


def apply_kev_annotations(
    state: dict[str, Any], kev_by_id: dict[str, dict[str, Any]]
) -> int:
    """Set every catalogued CVE's ``kev`` flag from a freshly read KEV catalogue.

    ``kev`` is the listing (dateAdded, ransomware) when CISA lists the CVE, ``False`` when it was
    checked and is not listed. An entry without the key has simply never been checked: the
    notification engine treats that as an unknown baseline, never as "newly exploited", so the
    first deployment (or a rollback that dropped the flags) cannot replay the whole KEV history.

    A listing is definitive: a CVE CISA no longer lists keeps its flag. Confirmed exploitation
    does not expire, and a document that briefly lost entries can therefore never turn known
    listings back to False and have the next correct document replay them as new.
    Returns how many catalogued CVEs are listed.
    """
    listed = 0
    for cve in state["cves"]:
        entry = kev_by_id.get(str(cve.get("id") or "").strip().upper())
        if entry:
            cve["kev"] = dict(entry)
        elif not isinstance(cve.get("kev"), dict):
            cve["kev"] = False
        listed += isinstance(cve["kev"], dict)
    return listed


def update_cve_coverage(
    previous: Any, rss_ids: list[str], now: str
) -> tuple[dict[str, Any], bool]:
    """Advance the PSIRT RSS continuity record; returns ``(coverage, gap_detected)``.

    The RSS feed is a sliding window of the ~50 most recent advisories (revised old advisories
    keep their original pubDate, so dates cannot bound the window). Two consecutive collections
    whose windows share no advisory at all mean the feed moved by more than its whole size in
    between: advisories published in that interval may never have been seen. That is recorded as
    a gap, and ``continuousSince`` restarts at this collection.
    """
    prev = previous if isinstance(previous, dict) else {}
    prev_ids = prev.get("rssSeenIds") if isinstance(prev.get("rssSeenIds"), list) else []
    prev_ids = [item for item in prev_ids if isinstance(item, str)]
    gaps = prev.get("gaps") if isinstance(prev.get("gaps"), list) else []
    gaps = [item for item in gaps if isinstance(item, dict)]
    since = prev.get("continuousSince") if isinstance(prev.get("continuousSince"), str) else None
    gap_detected = bool(prev_ids) and not (set(prev_ids) & set(rss_ids))
    if gap_detected:
        gaps = [
            *gaps,
            {"detectedAt": now, "previousCheckAt": prev.get("lastCheckAt")},
        ][-CVE_COVERAGE_MAX_GAPS:]
        since = now
    coverage: dict[str, Any] = {
        "continuousSince": since or now,
        "lastCheckAt": now,
        "rssSeenIds": sorted(set(rss_ids)),
        "gaps": gaps,
    }
    if isinstance(prev.get("history"), dict):
        coverage["history"] = prev["history"]  # owned by the backfill (see commit below)
    if isinstance(prev.get("crossCheck"), dict):
        coverage["crossCheck"] = prev["crossCheck"]  # owned by the NVD cross-check (commit below)
    return coverage, gap_detected


class CsafResolutionError(RuntimeError):
    """An advisory's CSAF data could not be established definitively.

    Callers must treat it as "cannot confirm anything for this advisory":
    preserve the previously stored entries and report a diagnostic — never as
    a confirmed empty CVE list.
    """


class CsafUnavailableError(CsafResolutionError):
    """The advisory page is genuine but Fortinet publishes no CSAF export for it.

    Older advisories only carry the legacy CVRF export (``/psirt/cvrf/<id>``),
    deliberately not used as an applicability source (see the PSIRT section
    comment). Retrying cannot help: the advisory is left untouched like any
    other unresolved one, but reported as "sans export CSAF", not as a failure.
    """


class CsafLinkMissingError(CsafResolutionError):
    """The advisory page offers no usable CSAF link (anti-bot page, moved file store, or a
    recent advisory whose export is not out yet): a real failure, retried."""


# Every advisory numbered from this year on has a CSAF export (audit of the 318 PSIRT advisories
# of the tracked products, 2026-10-15: the 46 without one are FG-IR-20 to FG-IR-23). A newer
# page without a CSAF link is therefore never "legacy": it stays a retried failure.
LEGACY_CVRF_ONLY_LAST_YEAR = 23


def is_legacy_advisory_id(advisory_id: str) -> bool:
    match = re.fullmatch(r"FG-IR-(\d{2})-\d+", advisory_id)
    return bool(match) and int(match.group(1)) <= LEGACY_CVRF_ONLY_LAST_YEAR


# Why an advisory stayed unresolved, as shown in the run report and the health message.
SKIP_REASON_NO_CSAF = "sans export CSAF"
SKIP_REASON_NO_LINK = "page sans lien CSAF"
SKIP_REASON_INVALID = "CSAF invalide"
SKIP_REASON_NETWORK = "réseau"


def skip_reason(error: BaseException) -> str:
    if isinstance(error, CsafUnavailableError):
        return SKIP_REASON_NO_CSAF
    if isinstance(error, CsafLinkMissingError):
        return SKIP_REASON_NO_LINK
    if isinstance(error, CsafResolutionError):
        return SKIP_REASON_INVALID
    if isinstance(error, json.JSONDecodeError):
        return SKIP_REASON_INVALID
    return SKIP_REASON_NETWORK


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
        if stripped and (
            stripped[0].isupper()
            or re.split(r"[\s-]", stripped, maxsplit=1)[0].lower() in CSAF_DISTINCT_PRODUCT_WORDS
        ):
            return None  # a different product sharing the prefix ("FortiManager Cloud")
        return product_name, rest
    if compact.startswith("Forti") or compact.startswith(CSAF_UNTRACKED_COMPONENT_PREFIXES):
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
      "7.0.6 and above"      half-open range, same as ">=7.0.6"
    A single trailing parenthesized note is dropped after a whole-train claim only ("6.0 all
    versions (need to be authenticated)"): nothing can be broader, so the note can never turn it
    into a weaker claim. After any bound, a note still makes the clause unrecognized.

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
    noted = re.fullmatch(r"(\d+\.\d+\s+all versions)\s*\([^()]*\)", rest, re.IGNORECASE)
    if noted:
        rest = noted.group(1)
    if not rest:
        return None
    and_above = re.fullmatch(r"(\d+\.\d+\.\d+)\s+and above", rest, re.IGNORECASE)
    if and_above:
        version = and_above.group(1)
        return {"branch": csaf_branch(version), "from": version, "to": None}
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


def _csaf_product_tree_out_of_scope(doc: dict[str, Any]) -> bool:
    """True only when the product tree names at least one product, all recognizably
    untracked Fortinet lines. A tracked or uninterpretable name keeps the export invalid."""
    names: list[Any] = []

    def walk(node: Any) -> None:
        if isinstance(node, list):
            for child in node:
                walk(child)
        elif isinstance(node, dict):
            if node.get("category") in ("product", "product_name", "product_family"):
                names.append(node.get("name"))
            product = node.get("product")
            if isinstance(product, dict):
                names.append(product.get("name"))
            for key in ("branches", "full_product_names"):
                walk(node.get(key))
            if "product_id" in node and "name" in node and "category" not in node:
                names.append(node.get("name"))

    walk(doc.get("product_tree"))
    if not names:
        return False
    try:
        return all(split_csaf_product_value(name) is None for name in names)
    except CsafResolutionError:
        return False


def _csaf_status_out_of_scope(status: dict[str, Any]) -> bool:
    """An explicitly empty known_affected whose other statements only name untracked products
    (FG-IR-24-221: "FortiAuthenticator/ 6.6 all versions" not affected) asserts nothing about a
    tracked product: that vulnerability entry is out of scope, not a truncated export."""
    if status.get("known_affected") != []:
        return False
    values: list[Any] = []
    # Every other status (known_not_affected, fixed, under_investigation, first_affected...):
    # one naming a tracked product keeps the entry in scope, hence invalid without known_affected.
    for key, listed in status.items():
        if key == "known_affected":
            continue
        if not isinstance(listed, list):
            return False
        values.extend(listed)
    if not values:
        return False
    try:
        return all(split_csaf_product_value(value) is None for value in values)
    except CsafResolutionError:
        return False


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
    if "vulnerabilities" not in doc and _csaf_product_tree_out_of_scope(doc):
        # Fortinet omits the section on some exports that only name products this tool does
        # not track (FG-IR-26-144: FortiSOAR only) — a confirmed "nothing tracked here".
        return doc
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
        if _csaf_status_out_of_scope(product_status):
            continue
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
        if not known_affected and _csaf_status_out_of_scope(status):
            continue  # this vulnerability entry only speaks about untracked products.
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


def _xml_local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_children(node: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in node if _xml_local(child.tag) == name]


def _xml_find(node: ET.Element, *path: str) -> ET.Element | None:
    for name in path:
        found = _xml_children(node, name)
        if not found:
            return None
        node = found[0]
    return node


def parse_legacy_cvrf_document(advisory_id: str, raw_xml: str) -> list[dict[str, Any]]:
    """Catalogue entries of an advisory Fortinet never exported to CSAF, from its CVRF export.

    Strictly narrower than the CVRF reading dropped for FG-IR-26-174: accepted only when every
    tracked "Known Affected" product is ONE exact version ("FortiOS 7.0.12"), as in Fortinet's
    pre-CSAF advisories, which enumerate each affected release. A train-level claim ("FortiOS
    7.6") or any other shape for a tracked product cannot be read exactly, so the advisory stays
    "sans export CSAF" (CsafUnavailableError) — as does one naming no tracked product at all:
    a legacy export is never a confirmed empty result. A malformed or foreign document is a
    failure (CsafResolutionError), like an invalid CSAF export.

    Per branch, the enumerated versions become one range from the lowest to the highest, with
    every patch number in between that is not listed recorded as excluded.
    """
    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as error:
        raise CsafResolutionError(f"{advisory_id}: CVRF export is not XML ({error})") from None
    if _xml_local(root.tag) != "cvrfdoc":
        raise CsafResolutionError(f"{advisory_id}: CVRF export has no cvrfdoc root")
    tracking_id = _xml_find(root, "DocumentTracking", "Identification", "ID")
    if tracking_id is None or (tracking_id.text or "").strip() != advisory_id:
        raise CsafResolutionError(f"{advisory_id}: CVRF tracking id does not match")
    title_node = _xml_find(root, "DocumentTitle")
    title = " ".join((title_node.text or "").split()) if title_node is not None else ""
    published_node = _xml_find(root, "DocumentTracking", "InitialReleaseDate")
    updated_node = _xml_find(root, "DocumentTracking", "CurrentReleaseDate")
    published_at = (published_node.text or "").strip()[:10] if published_node is not None else ""
    updated_at = (updated_node.text or "").strip()[:10] if updated_node is not None else ""

    names_by_id: dict[str, str] = {}
    for node in root.iter():
        if _xml_local(node.tag) == "FullProductName":
            product_id = (node.get("ProductID") or "").strip()
            if product_id:
                names_by_id[product_id] = " ".join((node.text or "").split())

    entries_by_cve: dict[str, dict[str, Any]] = {}
    for vulnerability in _xml_children(root, "Vulnerability"):
        cve_ids = [
            (node.text or "").strip()
            for node in _xml_children(vulnerability, "CVE")
            if (node.text or "").strip()
        ]
        if not cve_ids:
            raise CsafResolutionError(f"{advisory_id}: a CVRF vulnerability has no CVE")
        versions: dict[tuple[str, str | None, str], set[str]] = {}
        statuses = _xml_find(vulnerability, "ProductStatuses")
        status_nodes = _xml_children(statuses, "Status") if statuses is not None else []
        if not any(status.get("Type") == "Known Affected" for status in status_nodes):
            # Nothing exact to read for this CVE: never let it silently drop out of a document
            # whose other vulnerabilities are readable.
            raise CsafUnavailableError(
                f"{advisory_id}: CVRF vulnerability {cve_ids[0]} has no Known Affected status"
            )
        for status in status_nodes:
            if status.get("Type") != "Known Affected":
                continue
            for product_ref in _xml_children(status, "ProductID"):
                name = names_by_id.get((product_ref.text or "").strip())
                if name is None:
                    raise CsafResolutionError(
                        f"{advisory_id}: CVRF status references an unknown product"
                    )
                split = split_csaf_product_value(name)
                if split is None:
                    continue
                product_name, rest = split
                exact = re.fullmatch(r"\s*(\d+\.\d+\.\d+)", rest)
                if exact is None:
                    raise CsafUnavailableError(
                        f"{advisory_id}: CVRF names {name!r}, not one exact version"
                    )
                product_id, model_id = CVE_PRODUCT_MAP[product_name]
                version = exact.group(1)
                versions.setdefault((product_id, model_id, csaf_branch(version)), set()).add(
                    version
                )
        if not versions:
            continue
        score_node = _xml_find(vulnerability, "CVSSScoreSets", "ScoreSetV3", "BaseScoreV3")
        try:
            cvss_score = float((score_node.text or "").strip()) if score_node is not None else None
        except ValueError:
            cvss_score = None
        affected = []
        for (product_id, model_id, branch), listed in versions.items():
            ordered = sorted(listed, key=version_key)
            low, high = ordered[0], ordered[-1]
            prefix = branch + "."
            excluded = [
                f"{prefix}{patch}"
                for patch in range(int(low.rsplit(".", 1)[1]), int(high.rsplit(".", 1)[1]))
                if f"{prefix}{patch}" not in listed
            ]
            range_entry: dict[str, Any] = {
                "product": product_id,
                "models": [model_id] if model_id else [],
                "branch": branch,
                "from": low,
                "to": high,
            }
            if excluded:
                range_entry["excluded"] = excluded
            affected.append(range_entry)
        for cve_id in cve_ids:
            entry = entries_by_cve.setdefault(
                cve_id,
                {
                    "id": cve_id,
                    "advisoryId": advisory_id,
                    "title": title or advisory_id,
                    "severity": cvss_severity(cvss_score),
                    "cvssScore": cvss_score,
                    "url": f"{PSIRT_BASE_URL}/psirt/{advisory_id}",
                    "publishedAt": published_at,
                    "updatedAt": updated_at,
                    "affected": [],
                },
            )
            entry["affected"].extend(dict(item) for item in affected)
    if not entries_by_cve:
        raise CsafUnavailableError(f"{advisory_id}: CVRF names no tracked product version")
    for entry in entries_by_cve.values():
        entry["affected"] = sorted(entry["affected"], key=_csaf_range_sort_key)
    return list(entries_by_cve.values())


# Second, independent reading of an advisory's applicability: the "Affected" table of its public
# page (or, on pages older than that table, the "Affected Products" text block). Fortinet's
# exports are sometimes narrower than the page they describe — a train the CSAF never lists
# (FG-IR-26-123: FortiOS 6.0-7.0), a product it omits (FG-IR-18-292: FortiOS), or an on-prem
# version it declares "not affected" because the Cloud rows lost their name (FG-IR-24-463,
# FortiManager 7.2.8). Audit of 2026-10-18: 308 of 317 advisories agree version for version.
PSIRT_PAGE_SOURCE = "psirt-page"
_PSIRT_PAGE_TABLE_RE = re.compile(
    r"<table[^>]*>(?:(?!</table>).)*?Affected(?:(?!</table>).)*?</table>", re.DOTALL | re.IGNORECASE
)


def _psirt_page_text(fragment: str) -> str:
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", fragment)).split())


def _psirt_page_rows(raw_html: str, *, complete: bool = False) -> list[tuple[str, str, str]] | None:
    """(tracked product name, train, affected text) for each row naming a tracked product.

    A row label must be exactly "<product> <train>": a qualified label ("FortiOS (only
    FGT_VM64) 7.4", "FortiOS-6K7K 7.0", "FortiManager Cloud 7.2") is another product or a
    narrower claim, ignored like CSAF's distinct product lines. None when the page has no
    affected section at all (anti-bot or changed page).

    `complete` is for a page read as the only statement of a CVE's versions: a narrower claim
    ("FortiOS (only FGT_VM64) 7.4") or a prose line about a tracked product in another wording
    ("FortiOS versions 6.4.6 and below.") makes the whole page unreadable (None) instead of
    being skipped, since the rows read would then be only part of what the page states.
    """
    table = _PSIRT_PAGE_TABLE_RE.search(raw_html)
    rows: list[tuple[str, str, str]] = []
    if table:
        for row in re.findall(r"<tr[^>]*>(.*?)</tr>", table.group(0), re.DOTALL | re.IGNORECASE):
            cells = [
                _psirt_page_text(cell)
                for cell in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row, re.DOTALL | re.IGNORECASE)
            ]
            if len(cells) < 2:
                continue
            label = re.fullmatch(r"(\S+) (\d+\.\d+)", cells[0])
            if label and label.group(1) in CVE_PRODUCT_MAP:
                rows.append((label.group(1), label.group(2), cells[1]))
            elif complete and _names_tracked_product_or_fortigate(cells[0]):
                return None  # "FortiOS (only FGT_VM64) 7.2", "FortiOS 7.4 (...)", "FortiGate 7.0"
        return rows
    start = raw_html.find("Affected Products")
    if start < 0:
        return None
    end = raw_html.find("Solutions", start)
    for line in re.split(r"<[^>]+>", raw_html[start : end if end > 0 else start + 8000]):
        text = " ".join(html.unescape(line).split())
        legacy = re.fullmatch(r"(\S+) (?:version )?((\d+\.\d+)\b.*)", text)
        if legacy and legacy.group(1) in CVE_PRODUCT_MAP:
            rows.append((legacy.group(1), legacy.group(3), legacy.group(2)))
        elif complete and _names_tracked_product_or_fortigate(text):
            # "FortiOS versions 6.4.6 and below.", "FortiGate version 6.4.2 to 6.4.4", "Please
            # note that FortiManager 6.4.3 and below are NOT impacted": not read, so not complete.
            return None
    return rows


def _names_tracked_product_or_fortigate(text: str) -> bool:
    return _names_tracked_product(text) or "fortigate" in text.lower()


def _psirt_page_clause(train: str, text: str) -> dict[str, Any] | None:
    """{"from", "to"} of one affected cell (both None for the whole train), {} when the train is
    not affected, None when the wording is not recognized."""
    claim = re.sub(r"^version ", "", text.strip()).replace(" though ", " through ")
    # A note is dropped only after a whole-train claim ("6.0 all versions (Need to be
    # authenticated...)"): nothing is broader. After a bound ("7.4.0 through 7.4.3 (only
    # FGT_VM64)") it may narrow the claim, so the wording is not recognized.
    claim = re.sub(r"^(\d+\.\d+ all versions)\s*\([^()]*\)$", r"\1", claim)
    if re.search(r"\bnot affected\b", claim, re.IGNORECASE) or claim.startswith("Cloud "):
        # "Cloud 7.4.1 through 7.4.2" in a FortiManager row is about FortiManager Cloud.
        return {}
    if re.fullmatch(rf"{re.escape(train)} all versions", claim, re.IGNORECASE):
        return {"from": None, "to": None}
    version = rf"{re.escape(train)}(?:\.\d+)?"
    bounded = re.fullmatch(rf"({version}) through ({version})", claim)
    if bounded:
        start = bounded.group(1) if bounded.group(1) != train else f"{train}.0"
        if bounded.group(2) == train or version_key(start) > version_key(bounded.group(2)):
            return None
        return {"from": start, "to": bounded.group(2)}
    above = re.fullmatch(rf"({re.escape(train)}\.\d+) and above", claim)
    if above:
        return {"from": above.group(1), "to": None}
    exact = re.fullmatch(rf"{re.escape(train)}\.\d+", claim)
    if exact:
        return {"from": claim, "to": claim}
    return None


def parse_psirt_page_affected(raw_html: str, *, complete: bool = False) -> list[dict[str, Any]] | None:
    """Affected ranges of the tracked products as the advisory's public page states them.

    None when the page has no affected section or when any row about a tracked product uses a
    wording this reader does not recognize: the page is then not trusted at all, rather than
    read partially. An empty list is a page that names no affected tracked product. See
    _psirt_page_rows() for `complete`.
    """
    rows = _psirt_page_rows(raw_html, complete=complete)
    if rows is None:
        return None
    ranges: dict[tuple[Any, ...], dict[str, Any]] = {}
    for product_name, train, text in rows:
        clause = _psirt_page_clause(train, text)
        if clause is None:
            return None
        if not clause:
            continue
        product_id, model_id = CVE_PRODUCT_MAP[product_name]
        key = (product_id, model_id, train, clause["from"], clause["to"])
        ranges[key] = {
            "product": product_id,
            "models": [model_id] if model_id else [],
            "branch": train,
            "from": clause["from"],
            "to": clause["to"],
        }
    return sorted(ranges.values(), key=_csaf_range_sort_key)


def _range_covers(outer: dict[str, Any], start: str, end: str | None) -> bool:
    if outer["from"] is not None and version_key(outer["from"]) > version_key(start):
        return False
    if outer["to"] is not None and (end is None or version_key(outer["to"]) < version_key(end)):
        return False
    # A bounded page claim that names a version the export excludes is the page's explicit word
    # on that version (FG-IR-24-463): this range does not cover it.
    return not any(
        version_key(version) >= version_key(start)
        and (end is None or version_key(version) <= version_key(end))
        for version in outer.get("excluded") or []
    )


def merge_psirt_page_ranges(
    entry: dict[str, Any], page_ranges: list[dict[str, Any]], source: str = PSIRT_PAGE_SOURCE
) -> int:
    """Add to `entry` the page claims its export-derived ranges do not already cover.

    Also used for the CVE.org record (`source` = "cve-org"), which only ever states bounded
    ranges: the same precedences apply.

    A train the export never mentions is taken from the page as stated. On a train the export
    does describe, a page "all versions" claim adds nothing: the export is the precise one there
    (exact versions enumerated by a CVRF, a fix declared after the page kept its wording --
    FG-IR-22-255, 6.2.13). A bounded page claim is explicit and is added wherever the export
    does not cover it, including a version the export excludes. Added ranges carry
    "source": `source`. Returns the number of ranges added.
    """
    added = 0
    for page_range in page_ranges:
        same_train = [
            existing
            for existing in entry["affected"]
            if existing["product"] == page_range["product"]
            and list(existing.get("models") or []) == page_range["models"]
            and existing["branch"] == page_range["branch"]
        ]
        if page_range["from"] is None:
            if same_train:
                continue
        elif any(
            _range_covers(existing, page_range["from"], page_range["to"])
            for existing in same_train
        ):
            continue
        entry["affected"].append({**page_range, "source": source})
        added += 1
    if added:
        entry["affected"] = sorted(entry["affected"], key=_csaf_range_sort_key)
    return added


def apply_psirt_page_crosscheck(
    advisory_id: str,
    entries: list[dict[str, Any]],
    raw_html: str,
    export_cve_ids: set[str],
) -> list[dict[str, Any]]:
    """Widen the export-derived entries with what the public page states, when attributable.

    The page has one table per advisory, not per CVE: it is applied only when the export names
    exactly one CVE in all (untracked products included -- a second CVE about FortiProxy only
    would otherwise lend its rows to the first) and that CVE is the entry. A page that cannot be
    read leaves the entries untouched: the export stays the only source, never an advisory
    failure.
    """
    if len(entries) != 1 or export_cve_ids != {entries[0]["id"]}:
        return entries
    try:
        page_ranges = parse_psirt_page_affected(raw_html)
        if page_ranges is None:
            print(
                f"{advisory_id}: page PSIRT non contre-vérifiée (tableau illisible), "
                "export seul retenu",
                file=sys.stderr,
            )
            return entries
        widened = json.loads(json.dumps(entries[0]))
        merge_psirt_page_ranges(widened, page_ranges)
    except Exception as error:  # noqa: BLE001 -- the export must survive any page surprise.
        print(
            f"{advisory_id}: contre-vérification de la page PSIRT ignorée ({type(error).__name__})",
            file=sys.stderr,
        )
        return entries
    return [widened]


def _csaf_cve_ids(doc: dict[str, Any]) -> set[str]:
    return {
        str(vulnerability.get("cve"))
        for vulnerability in doc.get("vulnerabilities") or []
        if isinstance(vulnerability, dict) and vulnerability.get("cve")
    }


def _cvrf_cve_ids(raw_xml: str) -> set[str]:
    return set(re.findall(r"<(?:\w+:)?CVE>\s*(CVE-\d+-\d+)\s*</(?:\w+:)?CVE>", raw_xml))


# Cross-check of the PSIRT data with the two other public references (`--cve-crosscheck`).
# Audit of 2026-10-20 (331 CVEs, version by version): the CVE.org record, written by Fortinet as
# CNA but published through another channel than its CSAF, filled real PSIRT gaps on 20 CVEs
# (CVE-2024-26013: no FortiOS range at all in the CSAF; CVE-2026-71408: only the maintained
# trains); NVD, an independent analysis, agrees on 85 % of the versions but two thirds of what
# it alone reports comes from ranges spanning several trains ("6.4.0 -> 7.0.16"). Hence: CVE.org
# widens what is shown, like the advisory page; NVD only confirms and feeds the coverage report,
# a version NVD alone reports is never shown.
CVE_ORG_SOURCE = "cve-org"
CVE_ORG_API_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
NVD_FORTINET_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
    "?sourceIdentifier=psirt%40fortinet.com&resultsPerPage={per_page}&startIndex={start}"
)
NVD_PAGE_SIZE = 2000
# Fortinet had ~1970 CVEs in NVD on 2026-10-20: far fewer is a filtered or substituted answer.
NVD_MIN_FORTINET_CVES = 1000
# NVD asks clients without an API key for ~6 s between requests.
NVD_PAGE_DELAY_SECONDS = 6
CVE_ORG_STATUS_CONFIRMED = "confirmed"  # structured ranges for a tracked product
CVE_ORG_STATUS_UNSTRUCTURED = "unstructured"  # names a tracked product in free text only
CVE_ORG_STATUS_ABSENT = "absent"  # no record, or no tracked product in it
NVD_STATUS_CONFIRMED = "confirmed"
NVD_STATUS_ABSENT = "absent"
# Report lists stay bounded in the catalogue; the counts stay exact.
CVE_CROSSCHECK_MAX_LISTED = 200
CVE_CROSSCHECK_MAX_VERSIONS = 8
_CVE_ORG_PRODUCTS = {name.lower(): name for name in CVE_PRODUCT_MAP}
# CPE product names NVD uses for the tracked products, and its FortiClient target platforms.
NVD_CPE_PRODUCTS: dict[str, str] = {
    "fortios": DEFAULT_PRODUCT_ID,
    "fortimanager": "fortimanager",
    "fortianalyzer": "fortianalyzer",
    "forticlient": FORTICLIENT_PRODUCT_ID,
    "forticlient_enterprise_management_server": FORTICLIENT_EMS_PRODUCT_ID,
    "forticlient_endpoint_management_server": FORTICLIENT_EMS_PRODUCT_ID,
    "forticlientems": FORTICLIENT_EMS_PRODUCT_ID,
}
NVD_CPE_PLATFORMS = {"windows": "windows", "mac_os": "macos", "mac_os_x": "macos", "macos": "macos", "linux": "linux"}
_EXACT_VERSION_RE = re.compile(r"\d+\.\d+\.\d+")


class NvdFeedError(RuntimeError):
    """The NVD answer cannot be trusted as Fortinet's complete CVE list."""


def _cve_org_product(name: Any) -> str | None:
    compact = re.sub(r"^Fortinet\s+", "", str(name or "").strip()).replace(" ", "").lower()
    return _CVE_ORG_PRODUCTS.get(compact)


def _names_tracked_product(name: Any) -> bool:
    """A free-text product list naming a tracked product ("Fortinet FortiOS, FortiProxy")."""
    compact = str(name or "").lower().replace(" ", "")
    for product in ("fortios", "fortimanager", "fortianalyzer", "forticlient"):
        for match in re.finditer(product, compact):
            following = compact[match.end() : match.end() + 8]
            # "FortiManager Cloud", "FortiOS-6K7K", "FortiAnalyzer-BigData", "FortiClientiOS"...
            if not re.match(r"(cloud|-6k7k|-bigdata|ios|android)", following):
                return True
    return False


def _cve_org_range(entry: dict[str, Any]) -> tuple[str, str] | None:
    """(from, to) of one structured "affected" version entry, None when not exactly readable."""
    start = str(entry.get("version") or "").strip()
    if not _EXACT_VERSION_RE.fullmatch(start):
        return None
    if entry.get("lessThanOrEqual") is not None:
        end = str(entry["lessThanOrEqual"]).strip()
    elif entry.get("lessThan") is not None:
        bound = str(entry["lessThan"]).strip()
        if not _EXACT_VERSION_RE.fullmatch(bound):
            return None
        major, minor, patch = (int(part) for part in bound.split("."))
        if patch == 0:
            return None  # "< 7.4.0" says nothing exact about the 7.2 train it ends
        end = f"{major}.{minor}.{patch - 1}"
    else:
        end = start
    if not _EXACT_VERSION_RE.fullmatch(end) or csaf_branch(start) != csaf_branch(end):
        return None
    if version_key(start) > version_key(end):
        return None
    return start, end


def parse_cve_org_record(doc: Any, *, complete: bool = False) -> tuple[str, list[dict[str, Any]]]:
    """(status, ranges) of the tracked products in one CVE.org record (CVE JSON 5).

    Only the CNA container (Fortinet's own statement) is read. A product entry is used only when
    it names exactly one tracked product and each affected version is exact or an exact range
    within one train; free-text records ("6.0.10 and below, 6.2.2 and below", common before
    2022) are reported as unstructured, never interpreted. With `complete` (the record is the
    only statement of a CVE's versions), a record mixing structured ranges with free text about
    a tracked product is unstructured as a whole: its ranges would be only part of the claim.
    """
    containers = doc.get("containers") if isinstance(doc, dict) else None
    cna = containers.get("cna") if isinstance(containers, dict) else None
    if not isinstance(cna, dict):
        return CVE_ORG_STATUS_ABSENT, []
    ranges: dict[tuple[Any, ...], dict[str, Any]] = {}
    unstructured = False
    for product_entry in cna.get("affected") or []:
        if not isinstance(product_entry, dict):
            continue
        product_name = _cve_org_product(product_entry.get("product"))
        if product_name is None:
            unstructured = unstructured or _names_tracked_product(product_entry.get("product"))
            continue
        product_id, model_id = CVE_PRODUCT_MAP[product_name]
        for version_entry in product_entry.get("versions") or []:
            if not isinstance(version_entry, dict) or version_entry.get("status") != "affected":
                continue
            bounds = _cve_org_range(version_entry)
            if bounds is None:
                unstructured = True
                continue
            key = (product_id, model_id, *bounds)
            ranges[key] = {
                "product": product_id,
                "models": [model_id] if model_id else [],
                "branch": csaf_branch(bounds[0]),
                "from": bounds[0],
                "to": bounds[1],
            }
    if ranges and not (complete and unstructured):
        return CVE_ORG_STATUS_CONFIRMED, sorted(ranges.values(), key=_csaf_range_sort_key)
    return (CVE_ORG_STATUS_UNSTRUCTURED if unstructured else CVE_ORG_STATUS_ABSENT), []


def fetch_cve_org_record(cve_id: str, timeout: int) -> Any:
    """The CVE.org record, or None when CVE.org has none (404). Network errors raise."""
    request = urllib.request.Request(
        CVE_ORG_API_URL.format(cve_id=urllib.parse.quote(cve_id)),
        headers={"User-Agent": "sns-fortios-upgrade-watch/0.1", "Accept": "application/json"},
    )
    try:
        return json.loads(read_url_with_retry(request, timeout))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def apply_cve_org_crosscheck(
    entries: list[dict[str, Any]],
    timeout: int,
    fetch: Callable[[str, int], Any] | None = None,
    *,
    second_opinion: Callable[[str], set[tuple[str, str | None]]] | None = None,
) -> list[str]:
    """Widen each entry with its CVE.org record; returns the CVE ids CVE.org could not answer.

    Per CVE, so no attribution problem across an advisory. A train CVE.org adds to a product the
    PSIRT already names is taken as is (CVE-2026-71408: PSIRT lists the maintained trains only).
    A product the PSIRT does not name at all is taken only if `second_opinion(cve_id)` (the
    products NVD states for that CVE) also names it: CVE-2024-26013's FortiOS is confirmed, while
    CVE-2023-42791's FortiAnalyzer -- in the structured record only, not in its own description,
    the advisory page nor NVD -- is not shown. An entry CVE.org could not answer keeps no
    "cveOrg" key: the caller restores what the catalogue already holds for it
    (restore_cve_org_crosscheck()), so an outage never removes a range shown before.
    """
    fetch = fetch or fetch_cve_org_record
    failed: list[str] = []
    for entry in entries:
        try:
            status, ranges = parse_cve_org_record(fetch(entry["id"], timeout))
        except Exception:  # noqa: BLE001 -- one record must never fail the advisory.
            failed.append(entry["id"])
            continue
        named = {_cve_product_key(item) for item in entry["affected"]}
        confirmed = second_opinion(entry["id"]) if second_opinion else set()
        kept = [
            item
            for item in ranges
            if _cve_product_key(item) in named
            or _cve_product_key(item) in confirmed
            or (item["product"], None) in confirmed
        ]
        # "confirmed" only when the record speaks about a product actually shown.
        if status == CVE_ORG_STATUS_CONFIRMED and not kept:
            status = CVE_ORG_STATUS_ABSENT
        entry["cveOrg"] = status
        if kept:
            merge_psirt_page_ranges(entry, kept, CVE_ORG_SOURCE)
    return failed


def _cve_product_key(item: dict[str, Any]) -> tuple[str, str | None]:
    """(product, FortiClient platform): FortiClientMac and FortiClientWindows are distinct
    Fortinet products for the "product the PSIRT does not name" rule."""
    if item.get("product") == FORTICLIENT_PRODUCT_ID:
        models = list(item.get("models") or [])
        return FORTICLIENT_PRODUCT_ID, models[0] if len(models) == 1 else None
    return str(item.get("product")), None


def nvd_second_opinion(
    nvd_by_id: dict[str, dict[str, Any]] | None, previous_by_id: dict[str, dict[str, Any]]
) -> Callable[[str], set[tuple[str, str | None]]]:
    """Products a CVE.org-only product addition may use: those NVD states for the CVE or, when
    NVD could not be read this run, those such an addition already brought to the catalogue."""

    def products(cve_id: str) -> set[tuple[str, str | None]]:
        if nvd_by_id is not None:
            record = nvd_by_id.get(str(cve_id).upper())
            # A FortiClient CPE without target platform covers every platform: (product, None).
            return {(claim["product"], claim.get("platform")) for claim in record["claims"]} if record else set()
        previous = previous_by_id.get(cve_id) or {}
        return {
            _cve_product_key(item)
            for item in previous.get("affected") or []
            if isinstance(item, dict) and item.get("source") == CVE_ORG_SOURCE
        }

    return products


def restore_cve_org_crosscheck(entry: dict[str, Any], previous: dict[str, Any] | None) -> None:
    """Give an entry CVE.org could not answer this run what the catalogue held from it."""
    if not isinstance(previous, dict) or "cveOrg" not in previous:
        return
    entry["cveOrg"] = previous["cveOrg"]
    kept = [
        dict(item)
        for item in previous.get("affected") or []
        if isinstance(item, dict) and item.get("source") == CVE_ORG_SOURCE
    ]
    if kept:
        merge_psirt_page_ranges(
            entry, [{key: value for key, value in item.items() if key != "source"} for item in kept],
            CVE_ORG_SOURCE,
        )


def _nvd_claims(cve: dict[str, Any]) -> list[dict[str, Any]]:
    claims = []
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                parts = str(match.get("criteria") or "").split(":")
                if len(parts) < 11 or parts[4] not in NVD_CPE_PRODUCTS:
                    continue
                product = NVD_CPE_PRODUCTS[parts[4]]
                platform = None
                if product == FORTICLIENT_PRODUCT_ID and parts[10] not in ("*", "-"):
                    platform = NVD_CPE_PLATFORMS.get(parts[10])
                    if platform is None:
                        continue  # iOS, Android...: untracked FortiClient platforms
                claims.append(
                    {
                        "product": product,
                        "platform": platform,
                        "version": parts[5] if parts[5] not in ("*", "-") else None,
                        **{
                            key: match[key]
                            for key in (
                                "versionStartIncluding",
                                "versionStartExcluding",
                                "versionEndIncluding",
                                "versionEndExcluding",
                            )
                            if match.get(key)
                        },
                    }
                )
    return claims


def parse_nvd_fortinet(pages: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """{cve id: {"claims", "published", "severity"}} for the tracked products, from NVD pages."""
    total = pages[0].get("totalResults") if pages else None
    vulnerabilities = [item for page in pages for item in page.get("vulnerabilities") or []]
    if not isinstance(total, int) or total < NVD_MIN_FORTINET_CVES or len(vulnerabilities) < total:
        raise NvdFeedError(
            f"liste NVD Fortinet incomplète ({len(vulnerabilities)} sur {total!r})"
        )
    tracked: dict[str, dict[str, Any]] = {}
    for item in vulnerabilities:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict) or not cve.get("id"):
            continue
        claims = _nvd_claims(cve)
        if not claims:
            continue
        severity = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
            for metric in (cve.get("metrics") or {}).get(key) or []:
                if metric.get("type") == "Primary":
                    severity = str(metric.get("cvssData", {}).get("baseSeverity") or "").lower() or None
                    break
            if severity:
                break
        tracked[str(cve["id"]).upper()] = {
            "claims": claims,
            "published": str(cve.get("published") or "")[:10],
            "severity": severity,
        }
    return tracked


def fetch_nvd_fortinet(timeout: int) -> dict[str, dict[str, Any]]:
    """Every Fortinet-assigned CVE NVD knows (one request per 2000), kept for tracked products."""
    pages: list[dict[str, Any]] = []
    start = 0
    while True:
        request = urllib.request.Request(
            NVD_FORTINET_URL.format(per_page=NVD_PAGE_SIZE, start=start),
            headers={"User-Agent": "sns-fortios-upgrade-watch/0.1"},
        )
        page = json.loads(read_url_with_retry(request, timeout))
        pages.append(page)
        start += NVD_PAGE_SIZE
        if start >= int(page.get("totalResults") or 0):
            break
        time.sleep(NVD_PAGE_DELAY_SECONDS)
    return parse_nvd_fortinet(pages)


def _nvd_claim_single_train(claim: dict[str, Any]) -> bool:
    """An exact version, or both bounds within one train. "<= 6.2.0", ">= 7.0.0", "*" alone or
    "6.4.0 -> 7.0.16" reach every older (or newer) train: too coarse to point at versions."""
    if claim.get("version"):
        return True
    low = claim.get("versionStartIncluding") or claim.get("versionStartExcluding")
    high = claim.get("versionEndIncluding") or claim.get("versionEndExcluding")
    return bool(low and high) and csaf_branch(low) == csaf_branch(high)


def nvd_claim_matches(claim: dict[str, Any], product: str, platform: str | None, version: str) -> bool:
    if claim["product"] != product or (claim.get("platform") and claim["platform"] != platform):
        return False
    try:
        key = version_key(version)
        if claim.get("version"):
            return version_key(claim["version"]) == key
        if claim.get("versionStartIncluding") and key < version_key(claim["versionStartIncluding"]):
            return False
        if claim.get("versionStartExcluding") and key <= version_key(claim["versionStartExcluding"]):
            return False
        if claim.get("versionEndIncluding") and key > version_key(claim["versionEndIncluding"]):
            return False
        if claim.get("versionEndExcluding") and key >= version_key(claim["versionEndExcluding"]):
            return False
    except ValueError:
        return False  # "6.0.0-b1234"-style CPE versions: not comparable, not claimed here
    return True


def cve_shows_version(cve: dict[str, Any], product: str, platform: str | None, version: str) -> bool:
    """Whether the interface shows `cve` on this version (same rule as cveMatchesVersion())."""
    for item in cve.get("affected") or []:
        if not isinstance(item, dict) or item.get("product") != product:
            continue
        models = [model for model in item.get("models") or [] if model != FORTICLIENT_EMS_MODEL_ID]
        # FortiClient ranges are per platform; a FortiOS range restricted to some models
        # (FGT_VM64...) is shown for those models, so the version counts as shown.
        if models and platform is not None and platform not in models:
            continue
        if csaf_branch(version) != item.get("branch") or version in (item.get("excluded") or []):
            continue
        if item.get("from") and version_key(version) < version_key(item["from"]):
            continue
        if item.get("to") and version_key(version) > version_key(item["to"]):
            continue
        return True
    return False


def _catalogue_versions(state: dict[str, Any]) -> list[tuple[str, str | None, str]]:
    versions: set[tuple[str, str | None, str]] = set()
    for product in state.get("products") or []:
        for model in product.get("models") or []:
            platform = model.get("id") if product.get("id") == FORTICLIENT_PRODUCT_ID else None
            for firmware in model.get("firmwares") or []:
                version = str(firmware.get("version") or "")
                if _EXACT_VERSION_RE.fullmatch(version):
                    versions.add((product.get("id"), platform, version))
    return sorted(versions)


def apply_nvd_crosscheck(
    state: dict[str, Any], nvd_by_id: dict[str, dict[str, Any]], now: str
) -> dict[str, Any]:
    """Mark each catalogued CVE confirmed (or not) by NVD; return the coverage report.

    Nothing NVD alone states is shown. The report lists, against the catalogue's real versions:
    CVEs whose NVD ranges reach versions no Fortinet source declares affected ("nvdOnly"), and
    NVD CVEs of a tracked product missing from the catalogue ("missing"). NVD ranges spanning
    several trains ("6.4.0 -> 7.0.16") are too coarse to point at versions: only counted.
    """
    versions = _catalogue_versions(state)
    catalogued = set()
    nvd_only: list[dict[str, Any]] = []
    cross_train = 0
    for cve in state.get("cves") or []:
        cve_id = str(cve.get("id") or "").upper()
        catalogued.add(cve_id)
        record = nvd_by_id.get(cve_id)
        cve["nvd"] = NVD_STATUS_CONFIRMED if record else NVD_STATUS_ABSENT
        if not record:
            continue
        usable = [claim for claim in record["claims"] if _nvd_claim_single_train(claim)]
        cross_train += len(record["claims"]) - len(usable)
        only = sorted(
            {
                (product, platform, version)
                for product, platform, version in versions
                if any(nvd_claim_matches(claim, product, platform, version) for claim in usable)
                and not cve_shows_version(cve, product, platform, version)
            }
        )
        if only:
            labels = [f"{product}{'/' + platform if platform else ''} {version}" for product, platform, version in only]
            nvd_only.append(
                {"id": cve_id, "versionCount": len(labels), "versions": labels[:CVE_CROSSCHECK_MAX_VERSIONS]}
            )
    missing = nvd_missing_cves(catalogued, nvd_by_id, versions)
    nvd_only.sort(key=lambda item: item["id"])
    return {
        "checkedAt": now,
        "nvdOnlyCount": len(nvd_only),
        "nvdOnly": nvd_only[:CVE_CROSSCHECK_MAX_LISTED],
        "missingCount": len(missing),
        "missing": missing[:CVE_CROSSCHECK_MAX_LISTED],
        "crossTrainIgnored": cross_train,
    }


def nvd_missing_cves(
    catalogued: set[str],
    nvd_by_id: dict[str, dict[str, Any]],
    versions: list[tuple[str, str | None, str]],
) -> list[dict[str, Any]]:
    """NVD CVEs absent from `catalogued` whose single-train ranges reach a catalogued version,
    most severe and most recent first."""
    missing = []
    for cve_id, record in nvd_by_id.items():
        if cve_id in catalogued:
            continue
        usable = [claim for claim in record["claims"] if _nvd_claim_single_train(claim)]
        products = sorted(
            {
                product
                for product, platform, version in versions
                if any(nvd_claim_matches(claim, product, platform, version) for claim in usable)
            }
        )
        if products:
            missing.append(
                {"id": cve_id, "published": record["published"], "severity": record["severity"], "products": products}
            )
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    missing.sort(key=lambda item: item["published"], reverse=True)
    missing.sort(key=lambda item: severity_rank.get(item["severity"] or "", 4))
    return missing


# Recovery of the CVEs the PSIRT collection never brought (weekly --cve-backfill with
# --cve-crosscheck). Audit of 2026-10-20: 90 NVD CVEs reach a catalogued version without being in
# the catalogue, nearly all from FG-IR-16 to FG-IR-21 advisories the per-product PSIRT listing no
# longer shows. Each is traced back to its advisory through the FG-IR link of Fortinet's own CVE
# record: an advisory whose export reads exactly is imported like any other; an older one, without
# such an export, gives a CVE only when Fortinet's other statements (the structured CVE.org record,
# the advisory page's table) and NVD agree on at least one catalogued version. What NVD alone
# states is still never shown; the rest stays listed in the coverage report.
CVE_RECOVERY_MAX_CANDIDATES = 150
RECOVERED_CVE_MARK = "recovered"
_FORTIGUARD_ADVISORY_URL_RE = re.compile(
    r"https?://(?:www\.)?fortiguard\.(?:fortinet\.)?com/(?:psirt|advisory)/(FG-IR-\d{2}-\d{3,})(?![\w-])",
    re.IGNORECASE,
)
_PSIRT_PAGE_META_ROW_RE = re.compile(
    r"<tr[^>]*>\s*<td[^>]*>(.*?)</td>\s*<td[^>]*>(.*?)</td>", re.DOTALL | re.IGNORECASE
)
_PSIRT_PAGE_TITLE_RE = re.compile(r"<h1[^>]*\bclass=\"title\"[^>]*>(.*?)</h1>", re.DOTALL | re.IGNORECASE)


def cve_org_advisory_ids(doc: Any) -> list[str]:
    """The FG-IR advisories Fortinet's CVE record links to."""
    containers = doc.get("containers") if isinstance(doc, dict) else None
    cna = containers.get("cna") if isinstance(containers, dict) else None
    advisory_ids: set[str] = set()
    for reference in (cna.get("references") if isinstance(cna, dict) else None) or []:
        if isinstance(reference, dict):
            match = _FORTIGUARD_ADVISORY_URL_RE.match(str(reference.get("url") or "").strip())
            if match:
                advisory_ids.add(match.group(1).upper())
    return sorted(advisory_ids)


def parse_psirt_page_meta(raw_html: str) -> dict[str, Any] | None:
    """Title, IR number, publication date, severity, CVSS and CVE ids of an advisory page, or
    None when the page is not an advisory page (no title or IR number: anti-bot, error page)."""
    fields: dict[str, str] = {}
    for label, value in _PSIRT_PAGE_META_ROW_RE.findall(raw_html):
        fields.setdefault(_psirt_page_text(label), value)
    title_match = _PSIRT_PAGE_TITLE_RE.search(raw_html)
    title = _psirt_page_text(title_match.group(1)) if title_match else ""
    advisory_id = _psirt_page_text(fields.get("IR Number", ""))
    if not title or not re.fullmatch(r"FG-IR-\d{2}-\d{3,}", advisory_id):
        return None
    try:
        published_at = (
            dt.datetime.strptime(_psirt_page_text(fields.get("Published Date", "")), "%b %d, %Y").date().isoformat()
        )
    except ValueError:
        published_at = ""
    severity = _psirt_page_text(fields.get("Severity", "")).lower()
    try:
        cvss_score: float | None = float(_psirt_page_text(fields.get("CVSSv3 Score", "")))
    except ValueError:
        cvss_score = None
    return {
        "advisoryId": advisory_id,
        "title": title,
        "publishedAt": published_at,
        "severity": severity if severity in ("critical", "high", "medium", "low") else None,
        "cvssScore": cvss_score,
        "cveIds": sorted(set(CVE_ID_RE.findall(fields.get("CVE ID", "")))),
    }


def _cve_org_cvss(doc: Any) -> tuple[float | None, str | None]:
    """(score, severity) Fortinet gives the CVE in its CVE record."""
    containers = doc.get("containers") if isinstance(doc, dict) else None
    cna = containers.get("cna") if isinstance(containers, dict) else None
    for metric in (cna.get("metrics") if isinstance(cna, dict) else None) or []:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
            data = metric.get(key) if isinstance(metric, dict) else None
            score = data.get("baseScore") if isinstance(data, dict) else None
            if isinstance(score, (int, float)) and not isinstance(score, bool):
                severity = str(data.get("baseSeverity") or "").lower()
                return float(score), severity if severity in ("critical", "high", "medium", "low") else cvss_severity(score)
    return None, None


def recovered_cve_entry(
    advisory_id: str,
    cve_id: str,
    record: Any,
    raw_html: str,
    nvd_record: dict[str, Any],
    versions: list[tuple[str, str | None, str]],
) -> dict[str, Any] | None:
    """The catalogue entry of a CVE an advisory without exact export never gave, or None.

    - attribution: the page is the advisory's own (its IR number) and lists the CVE;
    - ranges: Fortinet's, never NVD's -- the structured CVE.org record, plus the page table when
      the page lists this CVE alone (the table is per advisory) -- for the products NVD names;
    - agreement: at least one catalogued version is affected according to both these ranges and
      an NVD range within one train;
    - severity: Fortinet's CVE record, or the page's when the page lists this CVE alone.
    """
    meta = parse_psirt_page_meta(raw_html)
    if meta is None or meta["advisoryId"] != advisory_id or cve_id not in meta["cveIds"] or not meta["publishedAt"]:
        return None
    alone = meta["cveIds"] == [cve_id]
    nvd_products = {(claim["product"], claim.get("platform")) for claim in nvd_record["claims"]}

    def named_by_nvd(item: dict[str, Any]) -> bool:
        return _cve_product_key(item) in nvd_products or (item["product"], None) in nvd_products

    candidate: dict[str, Any] = {"affected": []}
    # Each statement is used only if read in full: a partial read would under-state the CVE.
    _status, cve_org_ranges = parse_cve_org_record(record, complete=True)
    merge_psirt_page_ranges(candidate, [item for item in cve_org_ranges if named_by_nvd(item)], CVE_ORG_SOURCE)
    if alone:
        page_ranges = parse_psirt_page_affected(raw_html, complete=True) or []
        merge_psirt_page_ranges(candidate, [item for item in page_ranges if named_by_nvd(item)], PSIRT_PAGE_SOURCE)
    usable = [claim for claim in nvd_record["claims"] if _nvd_claim_single_train(claim)]
    if not any(
        cve_shows_version(candidate, product, platform, version)
        and any(nvd_claim_matches(claim, product, platform, version) for claim in usable)
        for product, platform, version in versions
    ):
        return None
    cvss_score, severity = _cve_org_cvss(record)
    if severity is None and alone:
        cvss_score = meta["cvssScore"]
        severity = meta["severity"] or (cvss_severity(cvss_score) if cvss_score is not None else None)
    if severity is None:
        return None
    return {
        "id": cve_id,
        "advisoryId": advisory_id,
        "title": meta["title"],
        "severity": severity,
        "cvssScore": cvss_score,
        "url": f"{PSIRT_BASE_URL}/psirt/{advisory_id}",
        "publishedAt": meta["publishedAt"],
        "updatedAt": meta["publishedAt"],
        "affected": candidate["affected"],
        RECOVERED_CVE_MARK: True,
    }


def _fetch_psirt_page(advisory_id: str, timeout: int) -> str:
    return fetch_text(
        f"{PSIRT_BASE_URL}/psirt/{advisory_id}", timeout, redirect_validator=_psirt_page_redirect_allowed
    )


def recover_missing_cves(
    state: dict[str, Any],
    nvd_by_id: dict[str, dict[str, Any]],
    known_advisory_ids: set[str],
    timeout: int,
    *,
    fetch_record: Callable[[str, int], Any] | None = None,
    fetch_page: Callable[[str, int], str] | None = None,
    collect_advisory: Callable[[str, int], list[dict[str, Any]]] | None = None,
    limit: int = CVE_RECOVERY_MAX_CANDIDATES,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any], list[str]]:
    """(definitive results by advisory, CVE.org records read, problems) for the NVD CVEs missing
    from `state` on a catalogued version.

    Only advisories absent from `known_advisory_ids` are looked at: an advisory the catalogue
    already reads has its definitive set of CVEs, and replacing it with one recovered CVE would
    drop the others. The exception is an advisory known only through earlier recoveries (every
    entry "recovered"): its other CVEs are carried over, so a CVE an earlier pass could not read
    is still tried again. An advisory whose export reads exactly is returned whole, like a
    backfill import; one Fortinet never exported exactly (CsafUnavailableError) gives the CVEs
    recovered_cve_entry() accepts. A read failure is a problem for the health record, never a
    result: the CVE stays in the coverage report and the next weekly pass tries again.
    """
    fetch_record = fetch_record or fetch_cve_org_record
    fetch_page = fetch_page or _fetch_psirt_page
    collect_advisory = collect_advisory or collect_cve_entries_for_advisory
    versions = _catalogue_versions(state)
    catalogued = {str(item.get("id") or "").upper() for item in state.get("cves") or []}
    candidates = nvd_missing_cves(catalogued, nvd_by_id, versions)[:limit]
    recovered_before: dict[str, list[dict[str, Any]]] = {}
    for item in state.get("cves") or []:
        recovered_before.setdefault(str(item.get("advisoryId") or ""), []).append(item)
    recovered_before = {
        advisory_id: entries
        for advisory_id, entries in recovered_before.items()
        if all(entry.get(RECOVERED_CVE_MARK) for entry in entries)
    }
    records: dict[str, Any] = {}
    problems: list[str] = []
    cves_by_advisory: dict[str, list[str]] = {}
    for item in candidates:
        try:
            records[item["id"]] = fetch_record(item["id"], timeout)
        except Exception as error:  # noqa: BLE001 -- one record must never stop the recovery.
            problems.append(f"{item['id']} (fiche CVE.org, {type(error).__name__})")
            continue
        advisory_ids = cve_org_advisory_ids(records[item["id"]])
        # One advisory, never read by the catalogue: anything else cannot be attributed safely.
        if len(advisory_ids) == 1 and (
            advisory_ids[0] not in known_advisory_ids or advisory_ids[0] in recovered_before
        ):
            cves_by_advisory.setdefault(advisory_ids[0], []).append(item["id"])
    results: dict[str, list[dict[str, Any]]] = {}
    for advisory_id, cve_ids in sorted(cves_by_advisory.items()):
        time.sleep(0.2)
        try:
            entries = collect_advisory(advisory_id, timeout)
        except CsafUnavailableError:
            entries = None
        except (OSError, http.client.HTTPException, json.JSONDecodeError, CsafResolutionError) as error:
            problems.append(f"{advisory_id} ({skip_reason(error)})")  # retried next week
            continue
        except Exception as error:  # noqa: BLE001 -- an unexpected export never fails the pass.
            problems.append(f"{advisory_id} ({type(error).__name__})")
            continue
        if entries is not None:
            if entries:
                results[advisory_id] = entries
            continue
        try:
            raw_html = fetch_page(advisory_id, timeout)
        except Exception as error:  # noqa: BLE001 -- recorded, retried next week.
            problems.append(f"{advisory_id} (page PSIRT, {type(error).__name__})")
            continue
        recovered = []
        for cve_id in cve_ids:
            try:
                entry = recovered_cve_entry(
                    advisory_id, cve_id, records[cve_id], raw_html, nvd_by_id[cve_id], versions
                )
            except Exception as error:  # noqa: BLE001 -- an unexpected page never fails the pass.
                problems.append(f"{cve_id} ({type(error).__name__})")
                continue
            if entry is not None:
                recovered.append(entry)
        if recovered:
            new_ids = {entry["id"] for entry in recovered}
            carried = [
                json.loads(json.dumps(entry))
                for entry in recovered_before.get(advisory_id, [])
                if entry.get("id") not in new_ids
            ]
            results[advisory_id] = sorted([*carried, *recovered], key=lambda entry: entry["id"])
    return results, records, problems


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
    if (
        csaf_url is None
        and is_legacy_advisory_id(advisory_id)
        and f"/psirt/cvrf/{advisory_id}" in raw_html
        and "csaf" not in raw_html.lower()
    ):
        # The advisory's own page (it links its legacy CVRF export) that never mentions CSAF, for
        # an advisory older than Fortinet's CSAF exports: one that was never exported. An
        # anti-bot page carries no CVRF link, a CSAF link that fails validation (moved host,
        # tampered URL) stays a failure, and so does a recent page whose export is not out yet.
        # Its CVRF export is read only when it enumerates exact versions.
        raw_xml = fetch_text(
            f"{PSIRT_BASE_URL}/psirt/cvrf/{advisory_id}",
            timeout,
            redirect_validator=_psirt_page_redirect_allowed,
        )
        return apply_psirt_page_crosscheck(
            advisory_id,
            parse_legacy_cvrf_document(advisory_id, raw_xml),
            raw_html,
            _cvrf_cve_ids(raw_xml),
        )
    if csaf_url is None:
        raise CsafLinkMissingError(
            f"{advisory_id}: no validated CSAF link on the advisory page"
        )
    doc = json.loads(
        fetch_text(csaf_url, timeout, redirect_validator=_csaf_redirect_allowed)
    )
    validate_csaf_document(advisory_id, doc)
    return apply_psirt_page_crosscheck(
        advisory_id, parse_csaf_document(advisory_id, doc), raw_html, _csaf_cve_ids(doc)
    )


def upsert_cve(state: dict[str, Any], item: dict[str, Any]) -> bool:
    for index, existing in enumerate(state["cves"]):
        if existing.get("id") == item.get("id"):
            # A freshly parsed CSAF entry never carries the KEV flag: keep the one already
            # established (apply_kev_annotations() refreshes it whenever the KEV feed is read), so
            # a re-fetch neither erases it nor counts as an update by itself.
            if "kev" not in item and "kev" in existing:
                item = {**item, "kev": existing["kev"]}
            # Same for the NVD confirmation mark, refreshed only by a run that read NVD.
            if "nvd" not in item and "nvd" in existing:
                item = {**item, "nvd": existing["nvd"]}
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


# A backfill absorbs silently only what is history: an advisory first published at least this long
# ago. A more recent one it imports stays out of the notification baseline, so the next normal
# pass derives and notifies it like any new CVE (it may have been missed by the RSS window).
BACKFILL_HISTORY_MIN_AGE_DAYS = 30


def is_backfill_history(entry: dict[str, Any], now: dt.datetime) -> bool:
    try:
        published = dt.date.fromisoformat(str(entry.get("publishedAt") or "")[:10])
    except ValueError:
        # Unknown age: never silenced -- except an advisory older than Fortinet's CSAF exports,
        # whose number alone dates it years back.
        return is_legacy_advisory_id(str(entry.get("advisoryId") or ""))
    return published <= (now - dt.timedelta(days=BACKFILL_HISTORY_MIN_AGE_DAYS)).date()


def collect_cve_catalog(
    existing_advisory_ids: set[str],
    timeout: int,
    backfill: bool = False,
    backfill_max_pages: int = 30,
    reconcile_existing: bool = False,
    *,
    reasons: dict[str, str] | None = None,
    listed: list[str] | None = None,
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
    meant to be run manually/occasionally (the scheduler runs it weekly), not daily. When given,
    `listed` receives every advisory id the listing returned. What the backfill may absorb
    silently is decided by the caller from each advisory's age (see is_backfill_history()).
    """
    if backfill:
        advisory_ids: list[str] = []
        for product_filter in CVE_LISTING_PRODUCT_FILTERS:
            product_ids = discover_advisory_ids_from_listing(
                product_filter, backfill_max_pages, timeout
            )
            if not product_ids:
                # Every tracked product has advisories: an empty listing is an anti-bot or
                # changed page, never "nothing to import" (which would look like a full check).
                raise CsafResolutionError(
                    f"liste PSIRT vide pour {product_filter} (page anti-bot ou format modifié)"
                )
            advisory_ids.extend(product_ids)
        advisory_ids = unique_in_order(advisory_ids)
        if listed is not None:
            listed.extend(advisory_ids)
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

    return fetch_cve_entries_for_advisories(advisory_ids, timeout, reasons=reasons)


def format_skipped_advisories(advisory_ids: list[str], reasons: dict[str, str]) -> str:
    """'FG-IR-26-144 (CSAF invalide), FG-IR-26-150 (réseau)' — ids grouped by reason."""
    by_reason: dict[str, list[str]] = {}
    for advisory_id in advisory_ids:
        by_reason.setdefault(reasons.get(advisory_id, SKIP_REASON_NETWORK), []).append(advisory_id)
    return ", ".join(f"{', '.join(ids)} ({reason})" for reason, ids in by_reason.items())


def fetch_cve_entries_for_advisories(
    advisory_ids: list[str], timeout: int, *, reasons: dict[str, str] | None = None
) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    """Fetch the definitive CSAF result for each id in `advisory_ids`, split into resolved
    results and a skipped list (see collect_cve_catalog's docstring for what each side means to
    callers). Factored out of collect_cve_catalog() so main() can call it a second time with just
    the skipped ids after a delay, without re-running RSS/listing discovery. When given,
    `reasons` receives each skipped id's SKIP_REASON_* (a resolved id's stale reason is dropped).
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
        ) as error:
            entries = None
            if reasons is not None:
                reasons[advisory_id] = skip_reason(error)
        if entries is None:
            skipped.append(advisory_id)
        else:
            results[advisory_id] = entries
            if reasons is not None:
                reasons.pop(advisory_id, None)
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
    skip_reasons: dict[str, str] | None = None,
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
        skip_reasons = skip_reasons or {}
        stats = cve_stats or CveReconciliationStats()
        failing = [i for i in skipped_cves if skip_reasons.get(i) != SKIP_REASON_NO_CSAF]
        no_csaf = [i for i in skipped_cves if skip_reasons.get(i) == SKIP_REASON_NO_CSAF]
        lines.extend(
            [
                "## CVE PSIRT Fortinet",
                "",
                f"- CVE ajoutées : {stats.added} · mises à jour : {stats.updated} · supprimées : {stats.removed}",
                "- Advisories PSIRT non résolues : "
                + (format_skipped_advisories(failing, skip_reasons) if failing else "aucune"),
                "- Advisories sans export CSAF (non analysées, à vérifier sur la page PSIRT) : "
                + (", ".join(no_csaf) if no_csaf else "aucune"),
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
        "--kev-catalog",
        action="store_true",
        help="Avec une passe CVE, marquer les CVE du catalogue listées par CISA KEV (exploitation active confirmée).",
    )
    parser.add_argument(
        "--cve-crosscheck",
        action="store_true",
        help=(
            "Avec une passe CVE, compléter les plages par la fiche CVE.org de chaque CVE collectée "
            "et contre-vérifier tout le catalogue avec NVD (rapport de couverture, jamais affiché)."
        ),
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
    *,
    kev_by_id: dict[str, dict[str, Any]] | None = None,
    rss_ids: list[str] | None = None,
    history: dict[str, Any] | None = None,
    nvd_by_id: dict[str, dict[str, Any]] | None = None,
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
    - KEV flags (``kev_by_id``, when this run read the CISA catalogue) are applied to every CVE
      of the merged result, after the per-advisory replacement, so no CVE is left unchecked;
      without a fresh KEV read the flags already on disk are kept (see upsert_cve()).
    - ``rss_ids``, when this run observed the RSS window, advance the stored continuity record
      (update_cve_coverage()) against the record on disk, so two overlapping collections chain
      their observations instead of the last one erasing a gap the other detected.
    - ``history``, from a backfill that walked the whole per-product PSIRT listing, replaces the
      record of that verification (``cveCoverage.history``); the RSS record is left as is.
    - ``nvd_by_id``, when this run read NVD, marks every CVE of the merged result confirmed or
      not by NVD and replaces the cross-check report (``cveCoverage.crossCheck``), computed on
      the merged catalogue itself (apply_nvd_crosscheck()).
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
        if kev_by_id is not None:
            apply_kev_annotations(final_state, kev_by_id)
        if rss_ids:
            final_state["cveCoverage"], _ = update_cve_coverage(
                latest_from_disk.get("cveCoverage"), rss_ids, utc_now()
            )
        if history is not None:
            final_state["cveCoverage"] = {**(final_state.get("cveCoverage") or {}), "history": history}
        if nvd_by_id is not None:
            report = apply_nvd_crosscheck(final_state, nvd_by_id, utc_now())
            final_state["cveCoverage"] = {**(final_state.get("cveCoverage") or {}), "crossCheck": report}
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
    skip_reasons: dict[str, str] = {}
    # Every advisory id the per-product listing returned (backfill only), and the resulting
    # record of that full history verification for cveCoverage.history.
    listed_ids: list[str] = []
    cve_history: dict[str, Any] | None = None
    # Set when the maintenance pass cannot make its silence intent durable (see the staging block
    # below): the reconciled results are then withheld from the commit and the health record says
    # so, instead of committing history corrections nothing would keep silent.
    reconcile_aborted = False
    # Fresh CISA KEV flags and observed RSS window for the final commit; None = keep what the
    # catalogue already holds (feed unavailable, or not observed by this kind of run).
    kev_by_id: dict[str, dict[str, Any]] | None = None
    rss_ids: list[str] | None = None
    # NVD's Fortinet CVEs for the final commit (--cve-crosscheck); None = not read this run, the
    # marks and report already on disk are kept.
    nvd_by_id: dict[str, dict[str, Any]] | None = None
    cve_org_failed: list[str] = []
    cve_org_widened = 0
    cve_recovered = 0
    cross_problems: list[str] = []
    cross_started_at: str | None = None
    cross_t0 = 0.0
    if (args.cve_catalog or args.cve_backfill or args.cve_reconcile_existing) and not args.skip_network:
        t0 = time.monotonic()
        cve_source = SOURCE_CVE_HISTORY if args.cve_backfill else SOURCE_CVE_PSIRT
        started_at = health_mark_running(args.health_output, cve_source)
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
                reasons=skip_reasons,
                listed=listed_ids,
            )
            # A handful of advisories failing out of the ~50 fetched daily is almost always a
            # transient PSIRT hiccup (rate limiting, brief outage) that clears up within minutes
            # on its own -- retrying seconds later (the per-request backoff in read_url_with_retry)
            # mostly doesn't help with that, so wait for real before giving the still-failing ones
            # another shot. Bounded and spaced out (not "retry forever until green"): an advisory
            # can stay without a usable CSAF link for days (see collect_cve_entries_for_advisory's
            # docstring), so an unbounded loop would spin on it forever every single day; and
            # hammering PSIRT harder/faster when it's already struggling only makes the rate
            # limiting worse, not better (observed directly: 1
            # skip left completely alone, vs 3 after two manual back-to-back re-runs). An advisory
            # whose genuine page publishes no CSAF export at all is never retried: no wait helps.
            for delay in args.cve_retry_delays_seconds:
                retryable = [
                    advisory_id
                    for advisory_id in skipped_cves
                    if skip_reasons.get(advisory_id) != SKIP_REASON_NO_CSAF
                ]
                if not retryable:
                    break
                time.sleep(delay)
                retried_results, still_skipped = fetch_cve_entries_for_advisories(
                    retryable, args.timeout, reasons=skip_reasons
                )
                cve_results_by_advisory.update(retried_results)
                skipped_cves = [
                    advisory_id
                    for advisory_id in skipped_cves
                    if advisory_id not in retryable or advisory_id in still_skipped
                ]

            # CVE.org widens each definitive result before anything is staged or committed, so the
            # silence intent and the commit both carry the cross-checked entries. A record CVE.org
            # could not give keeps what the catalogue already held from it.
            if args.cve_crosscheck:
                cross_t0 = time.monotonic()
                # Isolated from the PSIRT pass: whatever goes wrong here, the PSIRT results stay
                # exactly as collected and still reach the silence intent and the commit below.
                untouched = json.loads(json.dumps(cve_results_by_advisory))
                try:
                    cross_started_at = health_mark_running(args.health_output, SOURCE_CVE_CROSSCHECK)
                    try:
                        nvd_by_id = fetch_nvd_fortinet(args.timeout)
                    except Exception as error:  # noqa: BLE001 - recorded below, marks on disk kept.
                        nvd_by_id = None
                        cross_problems.append(f"NVD indisponible ({type(error).__name__}: {error})")
                    cve_org_records: dict[str, Any] = {}
                    # The weekly history pass also brings the CVEs NVD places on a catalogued
                    # version that no PSIRT pass ever collected (recover_missing_cves()). They join
                    # this run's definitive results, so the silence intent below covers them like
                    # any backfill import: history is absorbed, a recent advisory stays notifiable.
                    # Never with --cve-reconcile-existing, which silences everything it stages: a
                    # recent advisory recovered there would never be notified.
                    if args.cve_backfill and not args.cve_reconcile_existing and nvd_by_id is not None:
                        collected = [entry for entries in cve_results_by_advisory.values() for entry in entries]
                        recovered, cve_org_records, recovery_problems = recover_missing_cves(
                            {**state, "cves": [*state.get("cves", []), *collected]},
                            nvd_by_id,
                            {item.get("advisoryId") for item in state.get("cves", [])}
                            | set(cve_results_by_advisory),
                            args.timeout,
                        )
                        cve_results_by_advisory.update(recovered)
                        # CVEs carried over from an earlier recovery of the same advisory are not new.
                        catalogued_ids = {item.get("id") for item in state.get("cves", [])}
                        cve_recovered = sum(
                            1 for entries in recovered.values() for entry in entries if entry["id"] not in catalogued_ids
                        )
                        if recovery_problems:
                            cross_problems.append(
                                f"{len(recovery_problems)} CVE ou bulletin(s) non lu(s) pour la récupération : "
                                + ", ".join(recovery_problems[:10])
                            )
                        print(f"Contre-vérification : {cve_recovered} CVE absente(s) du PSIRT récupérée(s).")

                    def cve_org_record(cve_id: str, timeout: int) -> Any:
                        if cve_id in cve_org_records:
                            return cve_org_records[cve_id]
                        return fetch_cve_org_record(cve_id, timeout)

                    previous_by_id = {item.get("id"): item for item in state.get("cves", [])}
                    second_opinion = nvd_second_opinion(nvd_by_id, previous_by_id)
                    for entries in cve_results_by_advisory.values():
                        failed = apply_cve_org_crosscheck(
                            entries, args.timeout, cve_org_record, second_opinion=second_opinion
                        )
                        for entry in entries:
                            if entry["id"] in failed:
                                restore_cve_org_crosscheck(entry, previous_by_id.get(entry["id"]))
                            if not entry.get(RECOVERED_CVE_MARK) and any(
                                item.get("source") == CVE_ORG_SOURCE for item in entry["affected"]
                            ):
                                cve_org_widened += 1
                        cve_org_failed.extend(failed)
                except Exception as error:  # noqa: BLE001 - the PSIRT results are restored.
                    cve_results_by_advisory = untouched
                    cve_org_widened = 0
                    cve_recovered = 0
                    cross_problems.append(
                        f"contre-vérification interrompue ({type(error).__name__}: {error})"
                    )
                    cross_started_at = cross_started_at or utc_now_precise()

            # Durable silence intent, written BEFORE the catalogue commit further below: the
            # corrected historical entries are declared "not news" on disk first, so even if this
            # process dies between the catalogue commit and the notification work, every later run
            # — a normal collection included — can still confirm and absorb them instead of
            # deriving them as brand-new notifications (see
            # fortios_notify.stage_pending_cve_baseline()). If this intent cannot be made durable,
            # the reconciliation is abandoned for this run: committing corrections that nothing
            # would keep silent is exactly the historical-replay window this pass exists to close.
            # A --cve-backfill import is history too, and the weekly pass can be killed by any
            # redeploy: the same intent keeps its imported CVEs silent across such a crash.
            # Skipped only when no notification state exists at all — nothing to protect, since a
            # future first activation bootstraps its baseline silently from whatever the catalogue
            # holds then.
            if (args.cve_reconcile_existing or args.cve_backfill) and cve_results_by_advisory and (
                notify_checkpoint is not None
                or os.path.lexists(args.notify_history_output)
            ):
                try:
                    import fortios_notify

                    staging_now = dt.datetime.now(dt.UTC)
                    fortios_notify.stage_pending_cve_baseline(
                        args.notify_history_output,
                        {
                            entry["id"]: entry
                            for entries in cve_results_by_advisory.values()
                            for entry in entries
                            if entry.get("id")
                            and (
                                args.cve_reconcile_existing
                                or is_backfill_history(entry, staging_now)
                            )
                        },
                    )
                except Exception as error:  # noqa: BLE001 - recorded below, never fatal here.
                    reconcile_aborted = True
                    cve_results_by_advisory = {}
                    cve_recovered = 0
                    sys.stderr.write(
                        "Avertissement : import ou réconciliation CVE abandonné, intention durable "
                        f"de silence non enregistrable ({error}) — les entrées historiques de "
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
            # Only a real failure turns the source orange: a page without any CSAF export is a
            # known, permanent state, listed in the run report instead.
            failing_cves = [
                advisory_id
                for advisory_id in skipped_cves
                if skip_reasons.get(advisory_id) != SKIP_REASON_NO_CSAF
            ]
            if reconcile_aborted:
                cve_health_status = HEALTH_STATUS_ERROR
                cve_health_error = (
                    "Import ou réconciliation CVE abandonné : intention durable de silence "
                    "non enregistrable"
                )
            elif total_considered > 0 and not cve_results_by_advisory and failing_cves:
                # Only legacy no-CSAF advisories left (a weekly backfill once history is in) is
                # not an outage; a site-wide failure would also fail every FG-IR-24+ advisory.
                cve_health_status = HEALTH_STATUS_ERROR
                cve_health_error = (
                    f"{len(skipped_cves)} advisorie(s) PSIRT non résolue(s), aucune résolue : "
                    + format_skipped_advisories(skipped_cves, skip_reasons)
                )
            elif failing_cves:
                cve_health_status = HEALTH_STATUS_WARNING
                cve_health_error = (
                    f"{len(failing_cves)} advisorie(s) PSIRT non résolue(s) : "
                    + format_skipped_advisories(failing_cves, skip_reasons)
                )
            else:
                cve_health_status = HEALTH_STATUS_OK
                cve_health_error = None
            # RSS continuity, only observable on a plain RSS run: backfill walks the listing and
            # a maintenance pass mixes the catalogue's own ids into the same list. Evaluated at
            # the commit below, under the catalogue lock; a gap is reported on this source then.
            if not (args.cve_backfill or args.cve_reconcile_existing):
                rss_ids = sorted(set(cve_results_by_advisory) | set(skipped_cves)) or None
            if args.cve_backfill and listed_ids and not reconcile_aborted:
                cve_history = {
                    "checkedAt": utc_now(),
                    "listedAdvisories": len(listed_ids),
                    # Unresolved for a reason a later pass can fix (network, invalid export...):
                    # the check is incomplete, not just a few legacy advisories without data.
                    "failed": len(failing_cves),
                    "unresolved": [
                        {"id": advisory_id, "reason": skip_reasons.get(advisory_id, SKIP_REASON_NETWORK)}
                        for advisory_id in skipped_cves
                    ],
                }
            record_source(
                cve_source,
                started_at,
                t0,
                status=cve_health_status,
                items=cve_stats.added + cve_stats.updated,
                error=cve_health_error,
            )
        except Exception as error:  # noqa: BLE001 - recorded, not re-raised.
            record_source(
                cve_source,
                started_at,
                t0,
                status=HEALTH_STATUS_ERROR,
                error=error,
            )
        # CISA KEV (--kev-catalog, set by the scheduled passes): an enrichment of the CVEs already
        # catalogued, with its own health record so a CISA outage never marks the PSIRT
        # collection itself as failed. Read even when PSIRT failed: existing CVEs still get their
        # exploitation status.
        if args.kev_catalog:
            kev_t0 = time.monotonic()
            kev_started_at = health_mark_running(args.health_output, SOURCE_CISA_KEV)
            try:
                kev_by_id = fetch_cisa_kev(args.timeout)
                record_source(
                    SOURCE_CISA_KEV,
                    kev_started_at,
                    kev_t0,
                    status=HEALTH_STATUS_OK,
                    items=len(kev_by_id),
                )
            except Exception as error:  # noqa: BLE001 - recorded, flags on disk are kept.
                kev_by_id = None
                record_source(
                    SOURCE_CISA_KEV,
                    kev_started_at,
                    kev_t0,
                    status=HEALTH_STATUS_ERROR,
                    error=error,
                )
        # CVE.org (read above, per CVE) and NVD (one bulk read here) never decide what PSIRT
        # collected: their own health record, and an outage keeps what the catalogue holds.
        if args.cve_crosscheck and cross_started_at is not None:
            problems = list(cross_problems)
            if cve_org_failed:
                problems.append(
                    f"{len(cve_org_failed)} fiche(s) CVE.org non lue(s) : "
                    + ", ".join(sorted(cve_org_failed)[:10])
                )
            record_source(
                SOURCE_CVE_CROSSCHECK,
                cross_started_at,
                cross_t0,
                status=HEALTH_STATUS_WARNING if problems else HEALTH_STATUS_OK,
                items=cve_org_widened + cve_recovered,
                error="; ".join(problems) or None,
            )
    elif args.skip_network:
        skipped_sources = (
            [SOURCE_CVE_PSIRT]
            + ([SOURCE_CISA_KEV] if args.kev_catalog else [])
            + ([SOURCE_CVE_CROSSCHECK] if args.cve_crosscheck else [])
        )
        for skipped_source in skipped_sources:
            record_source(
                skipped_source,
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
        args.output,
        state,
        advisory_deltas,
        path_deltas,
        cve_results_by_advisory,
        kev_by_id=kev_by_id,
        rss_ids=rss_ids,
        history=cve_history,
        nvd_by_id=nvd_by_id,
    )
    coverage = final_state.get("cveCoverage") or {}
    last_gap = (coverage.get("gaps") or [{}])[-1]
    psirt_result = health_results.get(SOURCE_CVE_PSIRT)
    if (
        rss_ids
        and psirt_result is not None
        and isinstance(last_gap, dict)
        and last_gap.get("detectedAt") == coverage.get("lastCheckAt")
    ):
        gap_text = (
            "trou possible dans le flux RSS PSIRT : aucun bulletin commun avec la collecte "
            "précédente, des bulletins ont pu être manqués"
        )
        previous_error = sanitize_health_error(psirt_result.error)
        health_results[SOURCE_CVE_PSIRT] = dataclasses.replace(
            psirt_result,
            status=(
                HEALTH_STATUS_WARNING
                if psirt_result.status == HEALTH_STATUS_OK
                else psirt_result.status
            ),
            error=(
                f"{previous_error} ; {gap_text}"
                if previous_error
                else gap_text[0].upper() + gap_text[1:]
            ),
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
    if (args.cve_reconcile_existing or args.cve_backfill) and notify_checkpoint is not None:
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
            skip_reasons=skip_reasons,
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
    # The weekly history check alone is not a daily collection: it leaves the daily summary as is.
    history_check_only = args.cve_backfill and not (
        args.cve_catalog or args.docs_catalog or args.forticlient_catalog or args.tool_products
    )
    if not history_check_only:
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
        # The catalogue observation every baseline below is built from is read HERE, as ONE
        # coherent snapshot together with the notify state (checkpoint, staged intents, EOL
        # state) -- never as two separate reads, and never from the `final_state` image this run
        # committed earlier. See read_coherent_notification_observation(): both reads share one
        # short section of the history lock every notify-state writer already takes, so a writer
        # that completed while this run was still collecting (a maintenance pass finishing right
        # before this block, for instance) is observed either entirely before the snapshot (its
        # advance is already the baseline diffed below) or entirely after it (its stage/consume/
        # commit steps are still excluded by the lock) -- never as a stale catalogue image
        # paired with a freshly certified baseline, the shape that used to let an older run
        # regress that advance and replay the correction as a historical low->high notification
        # (the B3 review's remaining window). An absent or unreadable catalogue aborts this
        # best-effort block (caught below) instead of silently falling back to the stale
        # final_state image: the next run re-observes the durable pair from scratch.
        notify_observation = None
        if notification_settings is not None and notify_checkpoint is not None:
            notify_observation = read_coherent_notification_observation(
                args.notify_history_output, args.output
            )
        if (
            notify_observation is not None
            and not cve_notifications
            and not release_notifications
            and not system_notifications
        ):
            # Notifications disabled: every baseline below still advances silently, but each
            # proposal is conditioned (under the write lock, on the baseline this observation
            # read) so an older disabled run can never regress an advance another writer
            # certified since -- which a later reactivation would otherwise replay.
            notify_catalog, notify_state = notify_observation
            health_after = read_health_state(args.health_output).get("sources", {})
            cves_after_by_id = {
                item["id"]: item
                for item in notify_catalog.get("cves", [])
                if item.get("id")
            }
            _, eol_state_after = fortios_notify.derive_eol_events(
                notify_catalog.get("fortiosLifecycle", {}),
                notify_state.get("eolState", {}),
                now=final_state["generatedAt"],
            )
            fortios_notify.commit_disabled_notification_state(
                args.notify_history_output,
                eol_state_after,
                {
                    "versionsByProduct": {
                        product: sorted(versions)
                        for product, versions in versions_by_product(notify_catalog).items()
                    },
                    "cvesById": cves_after_by_id,
                    "health": health_after,
                },
                observed_checkpoint=notify_state.get("checkpoint"),
                observed_eol_state=notify_state.get("eolState"),
            )
        if notify_observation is not None and (
            cve_notifications
            or release_notifications
            or system_notifications
        ):
            notify_catalog, notify_state = notify_observation
            health_after = read_health_state(args.health_output).get("sources", {})
            pending_observed = notify_state.get(fortios_notify.PENDING_CVE_BASELINE_KEY)

            # The derivation baseline is the checkpoint as it stands RIGHT NOW, from the
            # coherent observation above -- not the one this run bootstrapped at start-up. A
            # maintenance pass (or any other writer) that completed while this run was still
            # collecting has already consumed its historical corrections into that fresher
            # checkpoint; deriving against the stale start-up capture would replay them (the B3
            # "checkpoint périmé" case), so the durable state -- never an in-flight run's
            # memory -- is the reference that stays opposable to it. The same freshness contract
            # is enforced again, under the write lock, by
            # commit_events_with_checkpoint(derivation_checkpoint=...): a correction certified
            # by someone else is never overwritten by this run's older snapshot, and
            # pre-derived events are revalidated against the fresh durable state before entering
            # the outbox. The catalogue side of the observation was read in the same protected
            # section (read_coherent_notification_observation above), so the proposed baseline
            # and the catalogue it is diffed against always belong to one coordinated
            # observation of the durable pair.
            checkpoint_state = notify_state.get("checkpoint") or notify_checkpoint

            # cves_after_by_id feeds the new checkpoint below regardless of --cve-backfill, so a
            # normal run right after a backfill still sees those CVEs as already-known rather
            # than spamming all of them as "new".
            cves_after_by_id = {
                item["id"]: item
                for item in notify_catalog.get("cves", [])
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
            # A staged correction never resets (or forges) a CVE's KEV baseline: see
            # fortios_notify.with_durable_kev(), also applied by consume_pending_cve_baseline().
            checkpoint_cves_by_id = {
                **checkpoint_state["cvesById"],
                **fortios_notify.with_durable_kev(
                    pending_applied, checkpoint_state["cvesById"]
                ),
            }
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
                    for p in notify_catalog.get("products", [])
                }
                if release_notifications:
                    events += fortios_notify.derive_version_events(
                        checkpoint_versions,
                        versions_by_product(notify_catalog),
                        product_labels,
                        detected_at=final_state["generatedAt"],
                        release_links=release_notes_by_product(notify_catalog),
                    )
                if cve_notifications:
                    newly_added_cves = [
                        item
                        for item in notify_catalog.get("cves", [])
                        if item.get("id") and item["id"] not in checkpoint_cves_by_id
                    ]
                    new_cve_events = fortios_notify.derive_new_cve_events(
                        newly_added_cves, notification_settings
                    )
                    modification_events = fortios_notify.derive_cve_modification_events(
                        checkpoint_cves_by_id,
                        cves_after_by_id,
                        notification_settings,
                    )
                    events += new_cve_events
                    events += modification_events
                    # A CVE announced by another event of this run (new, or escalated) carries its
                    # KEV flag in that event: no second section for it. Only an event that will
                    # really be queued counts -- one whose key was already sent or is already
                    # pending is dropped at enqueue time and must not swallow the KEV listing.
                    known_keys = set(notify_state.get("sentKeys") or {}) | {
                        entry.get("dedupKey")
                        for entry in notify_state.get("outbox") or []
                        if isinstance(entry, dict)
                    }
                    events += fortios_notify.derive_kev_events(
                        checkpoint_cves_by_id,
                        cves_after_by_id,
                        notification_settings,
                        already_notified_ids={
                            event.details["id"]
                            for event in (*new_cve_events, *modification_events)
                            if "kev" in event.details and event.dedup_key not in known_keys
                        },
                    )

            # A CVE backfill must not consume a real EOL crossing while system alerts are on:
            # the next normal collection must still be able to notify it. While the category is
            # off, however, its baseline keeps advancing silently even during a backfill so a
            # later activation cannot replay historical transitions.
            if not args.cve_backfill or not system_notifications:
                eol_events, eol_state_after = fortios_notify.derive_eol_events(
                    notify_catalog.get("fortiosLifecycle", {}),
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

            if args.cve_reconcile_existing or args.cve_backfill:
                # A history import (--cve-backfill, weekly) is bound by the same rule: only the
                # historical entries it staged and the catalogue confirmed join the baseline.
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
                # A CVE entering the baseline in this very run without a KEV verdict (KEV feed
                # unavailable, or a recovery pass) is genuinely new, not history: record it as
                # "checked, not listed" so the next KEV read can still derive its listing once.
                # Only the checkpoint gets this baseline, the catalogue keeps the truth (no flag).
                # A --cve-backfill never reaches this branch: its history enters the baseline
                # through the staged intent above, without any KEV flag (unknown baseline).
                new_checkpoint = {
                    "versionsByProduct": {
                        product: sorted(versions)
                        for product, versions in versions_by_product(notify_catalog).items()
                    },
                    "cvesById": {
                        cve_id: (
                            entry
                            if "kev" in entry or cve_id in checkpoint_cves_by_id
                            else {**entry, "kev": False}
                        )
                        for cve_id, entry in cves_after_by_id.items()
                    },
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
