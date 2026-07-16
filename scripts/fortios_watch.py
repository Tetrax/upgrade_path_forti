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
FORTINET_UPGRADE_PATH_URL = f"{FORTINET_DOCS_BASE_URL}/upgrade-tool/upgrade-path"
DEFAULT_DOCS_MAJOR_VERSIONS = (
    "8.4", "8.2", "8.0", "7.6", "7.4", "7.2", "7.0", "6.4", "6.2", "6.0", "5.6", "5.4", "5.2", "5.0",
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
RELEASE_NOTES_DOC_SLUGS = {
    DEFAULT_PRODUCT_ID: "fortios-release-notes",
    "fortianalyzer": "release-notes",
    "fortimanager": "release-notes",
}


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
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


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
        "products": payload.get("products") if isinstance(payload.get("products"), list) else [],
        "paths": payload.get("paths") if isinstance(payload.get("paths"), list) else [],
        "advisories": payload.get("advisories") if isinstance(payload.get("advisories"), list) else [],
        "compatibilities": payload.get("compatibilities") if isinstance(payload.get("compatibilities"), list) else [],
        "cves": payload.get("cves") if isinstance(payload.get("cves"), list) else [],
        "fortiosLifecycle": payload.get("fortiosLifecycle") if isinstance(payload.get("fortiosLifecycle"), dict) else {},
        "searchHistory": payload.get("searchHistory") if isinstance(payload.get("searchHistory"), list) else [],
    }


def ensure_product(state: dict[str, Any], product_id: str, label: str) -> dict[str, Any]:
    for product in state["products"]:
        if product.get("id") == product_id:
            product.setdefault("label", label)
            product.setdefault("models", [])
            return product

    product = {"id": product_id, "label": label, "models": []}
    state["products"].append(product)
    return product


def ensure_model(state: dict[str, Any], product_id: str, model_id: str) -> dict[str, Any]:
    product = ensure_product(state, product_id, PRODUCT_LABELS.get(product_id, DEFAULT_PRODUCT_LABEL))
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
                existing["notes"] = sorted(set(existing.get("notes", [])) | set(item.notes))
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
        "discoveredAt": dt.date.today().isoformat(),
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


def urlopen_with_retry(request: urllib.request.Request, timeout: int, retries: int = 3):
    """urlopen with exponential backoff for transient connection failures.

    The daily cron run has repeatedly died partway through (ConnectionRefusedError, SSL
    handshake timeout) after dozens of prior successful requests in the same run — that pattern
    (fails after a long streak of successes, works again standalone seconds later) points at
    transient connection drops rather than Fortinet actually being down, so it's worth a few
    retries before giving up. A real HTTP error response (404, 500...) means the server did
    answer, so that's not retried — another attempt would just get the same answer.
    """
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            return urllib.request.urlopen(request, timeout=timeout)
        except urllib.error.HTTPError:
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as error:
            last_error = error
            if attempt < retries - 1:
                time.sleep((2 ** attempt) + random.uniform(0, 1))
    raise last_error


def fetch_text(url: str, timeout: int) -> str:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "sns-fortios-upgrade-watch/0.1"},
    )
    with urlopen_with_retry(request, timeout) as response:
        return response.read().decode("utf-8", errors="ignore")


def html_to_text(raw_html: str) -> str:
    text = re.sub(r"<script\b[^>]*>.*?</script>", " ", raw_html, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<style\b[^>]*>.*?</style>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def discover_docs_versions(major_versions: tuple[str, ...], timeout: int) -> list[str]:
    versions: set[str] = set()
    for major in major_versions:
        product_url = f"{FORTINET_DOCS_BASE_URL}/product/fortigate/{major}"
        raw_html = fetch_text(product_url, timeout)
        versions.update(re.findall(r"/document/fortigate/(\d+\.\d+\.\d+)/fortios-release-notes", raw_html))
    return sorted(versions, key=version_key)


def parse_docs_release(version: str, timeout: int) -> DocsRelease | None:
    source_url = f"{FORTINET_DOCS_BASE_URL}/document/fortigate/{version}/fortios-release-notes"
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
    return DocsRelease(version=version, build=build, models=models, source_url=source_url)


def collect_docs_catalog(major_versions: tuple[str, ...], timeout: int) -> tuple[dict[str, Any], list[str]]:
    state = normalize_state({})
    skipped: list[str] = []

    for version in discover_docs_versions(major_versions, timeout):
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
                links={"release-notes": release_notes_url(DEFAULT_PRODUCT_ID, release.version)},
            )
            upsert_firmware(state, firmware)

    return state, skipped


# The Upgrade Path Tool's own available_from/to_extended items carry a "type": "Mature"|"Feature"
# per version that release-notes scraping (collect_docs_catalog above) never sees. This is a
# property of the FortiOS version itself, not of the hardware model, so one reference model is
# enough to read every version's status — no need to repeat this call per model.
FORTIOS_MATURITY_REFERENCE_MODEL = "FGT60F"


def fetch_fortios_version_maturity(timeout: int) -> dict[str, str]:
    payload_json = post_official_upgrade_tool(
        {"product_slug": PRODUCTS[DEFAULT_PRODUCT_ID]["slug"], "model": FORTIOS_MATURITY_REFERENCE_MODEL}, timeout
    )
    result = payload_json.get("result")
    if not isinstance(result, dict):
        return {}

    maturity: dict[str, str] = {}
    for item in (result.get("available_from_extended") or []) + (result.get("available_to_extended") or []):
        version = item.get("version")
        item_type = item.get("type")
        if version and item_type:
            maturity[version] = item_type
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


def discover_forticlient_versions(major_versions: tuple[str, ...], doc_slug: str, timeout: int) -> list[str]:
    versions: set[str] = set()
    for major in major_versions:
        url = f"{FORTINET_DOCS_BASE_URL}/product/forticlient/{major}"
        raw_html = fetch_text(url, timeout)
        versions.update(re.findall(rf"/document/forticlient/(\d+\.\d+\.\d+)/{re.escape(doc_slug)}", raw_html))
    return sorted(versions, key=version_key)


def parse_forticlient_build(version: str, doc_slug: str, timeout: int) -> str | None:
    url = f"{FORTINET_DOCS_BASE_URL}/document/forticlient/{version}/{doc_slug}"
    raw_html = fetch_text(url, timeout)
    text = html_to_text(raw_html)
    match = re.search(rf"{re.escape(version)}\s+build\s+(\S+)\s*[.:]", text, flags=re.IGNORECASE)
    return match.group(1) if match else None


def collect_forticlient_catalog(major_versions: tuple[str, ...], timeout: int) -> tuple[dict[str, Any], list[str]]:
    """FortiClient (one model per OS) + FortiClient EMS catalogs, scraped from release notes.

    Neither product is in Fortinet's Upgrade Path Tool, so there's no products.json/upgrade-path
    endpoint to use like collect_tool_catalog does for FortiAnalyzer/FortiManager — this falls
    back to the same release-notes scraping as collect_docs_catalog, just without a "Supported
    models" section to parse (the model here is simply which release-notes doc we found it in).
    """
    state = normalize_state({})
    skipped: list[str] = []

    fc_product = ensure_product(state, FORTICLIENT_PRODUCT_ID, PRODUCT_LABELS[FORTICLIENT_PRODUCT_ID])
    for platform, doc_slug in FORTICLIENT_PLATFORM_DOC_SLUGS.items():
        if not any(model.get("id") == platform for model in fc_product["models"]):
            fc_product["models"].append({"id": platform, "label": FORTICLIENT_PLATFORM_LABELS[platform], "firmwares": []})

        for version in discover_forticlient_versions(major_versions, doc_slug, timeout):
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
                    links={"release-notes": f"{FORTINET_DOCS_BASE_URL}/document/forticlient/{version}/{doc_slug}"},
                ),
            )

    ems_product = ensure_product(state, FORTICLIENT_EMS_PRODUCT_ID, PRODUCT_LABELS[FORTICLIENT_EMS_PRODUCT_ID])
    if not any(model.get("id") == FORTICLIENT_EMS_MODEL_ID for model in ems_product["models"]):
        ems_product["models"].append({"id": FORTICLIENT_EMS_MODEL_ID, "label": "FortiClient EMS", "firmwares": []})

    for version in discover_forticlient_versions(major_versions, FORTICLIENT_EMS_DOC_SLUG, timeout):
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

    return state, skipped


def official_note_keys(item: dict[str, Any]) -> tuple[str, ...]:
    slug_to_note = {
        "resolved-issues": "resolved",
        "known-issues": "known",
        "upgrade-information": "upgrade",
        "changes-in-default-behavior": "behavior",
        "special-notices": "special",
    }
    notes: list[str] = []
    for permalink in item.get("permalinks") or []:
        note = slug_to_note.get(permalink.get("slug"))
        if note:
            notes.append(note)
    return tuple(unique_in_order(notes))


def release_notes_url(product_id: str, version: str) -> str:
    product_slug = PRODUCTS.get(product_id, PRODUCTS[DEFAULT_PRODUCT_ID])["slug"]
    doc_slug = RELEASE_NOTES_DOC_SLUGS.get(product_id, "release-notes")
    return f"{FORTINET_DOCS_BASE_URL}/document/{product_slug}/{version}/{doc_slug}"


def official_note_links(item: dict[str, Any], product_id: str, version: str) -> dict[str, str]:
    """Deep links into the version's release notes, one per section badge (R/K/U/B), plus a
    "release-notes" entry for the general page (the D badge)."""
    slug_to_note = {
        "resolved-issues": "resolved",
        "known-issues": "known",
        "upgrade-information": "upgrade",
        "changes-in-default-behavior": "behavior",
    }
    base_url = release_notes_url(product_id, version)
    links: dict[str, str] = {"release-notes": base_url}
    for permalink in item.get("permalinks") or []:
        slug = permalink.get("slug")
        note = slug_to_note.get(slug)
        permanent_id = permalink.get("permanent_id")
        if note and permanent_id:
            links[note] = f"{base_url}/{permanent_id}/{slug}"
    return links


def post_official_upgrade_tool(payload: dict[str, str], timeout: int) -> dict[str, Any]:
    product_slug = payload.get("product_slug", "fortigate")
    body = urllib.parse.urlencode(payload).encode("utf-8")
    request = urllib.request.Request(
        FORTINET_UPGRADE_PATH_URL,
        data=body,
        headers={
            "User-Agent": "sns-fortios-upgrade-watch/0.1",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": FORTINET_DOCS_BASE_URL,
            "Referer": f"{FORTINET_DOCS_BASE_URL}/upgrade-tool/{product_slug}",
        },
    )
    with urlopen_with_retry(request, timeout) as response:
        return json.loads(response.read().decode("utf-8", errors="ignore"))


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
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return model_id
    return alias_map.get(normalize_model_key(model_label(model_id)), model_id)


def fetch_official_upgrade_path(requested: OfficialPathRequest, timeout: int) -> tuple[UpgradePath, list[Firmware]] | None:
    if requested.product not in PRODUCTS:
        return None  # not in Fortinet's Upgrade Path Tool (e.g. FortiClient/EMS) — no path to fetch.
    product_slug = PRODUCTS[requested.product]["slug"]
    api_model = resolve_fortinet_model(requested.product, requested.model, timeout)
    payload = {
        "product_slug": product_slug,
        "model": api_model,
        "current_version": requested.from_version,
        "target_version": requested.to_version,
    }
    payload_json = post_official_upgrade_tool(payload, timeout)
    result = payload_json.get("result")
    path_items = result.get("path") if isinstance(result, dict) else None
    path_items = path_items or []
    if len(path_items) < 2:
        return None

    hops = tuple(item["version"] for item in path_items if item.get("version"))
    if len(hops) < 2:
        return None
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
            version=item["version"],
            build=item.get("build_number") or "-",
            notes=official_note_keys(item),
            links=official_note_links(item, requested.product, item["version"]),
        )
        for item in path_items
        if item.get("version")
    ]
    return path, firmwares


def fetch_product_models(product_slug: str, timeout: int) -> list[dict[str, str]]:
    """List of {product_name, hardware_model_name} the Upgrade Path Tool knows for this product.

    This is the same JSON the tool's own product dropdown fetches on selection change, so it's a
    more reliable model source than scraping release notes for a "Supported models" section (which
    FortiAnalyzer/FortiManager release notes don't reliably have in the same format as FortiOS).
    """
    url = f"{FORTINET_DOCS_BASE_URL}/upgrade-tool/products/{product_slug}.json"
    request = urllib.request.Request(url, headers={"User-Agent": "sns-fortios-upgrade-watch/0.1"})
    with urlopen_with_retry(request, timeout) as response:
        data = json.loads(response.read().decode("utf-8", errors="ignore"))
    return data.get("products", [])


def fetch_model_firmwares(product_slug: str, hardware_model_name: str, timeout: int) -> list[dict[str, str]]:
    """Version/build catalog for one model, from the tool's own available_from/to_extended lists."""
    payload_json = post_official_upgrade_tool(
        {"product_slug": product_slug, "model": hardware_model_name}, timeout
    )
    result = payload_json.get("result")
    if not isinstance(result, dict):
        return []

    by_version: dict[str, dict[str, str]] = {}
    for item in (result.get("available_from_extended") or []) + (result.get("available_to_extended") or []):
        version = item.get("version")
        if version:
            by_version[version] = item
    return list(by_version.values())


def collect_tool_catalog(product_id: str, timeout: int) -> dict[str, Any]:
    """Model + version/build catalog for a product, sourced from the Upgrade Path Tool itself."""
    meta = PRODUCTS[product_id]
    state = normalize_state({})
    product = ensure_product(state, product_id, meta["label"])

    for entry in fetch_product_models(meta["slug"], timeout):
        model_id = entry.get("hardware_model_name")
        if not model_id:
            continue
        model_label_value = entry.get("product_name") or model_id
        model = next((item for item in product["models"] if item.get("id") == model_id), None)
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
                    build=firmware_info.get("build_number") or "-",
                    links={"release-notes": release_notes_url(product_id, firmware_info["version"])},
                ),
            )

    product["models"].sort(key=lambda item: model_sort_key(item.get("id", "")))
    return state


def parse_official_path_spec(spec: str) -> OfficialPathRequest:
    parts = [part.strip() for part in re.split(r"[:,]", spec) if part.strip()]
    if len(parts) != 3:
        raise ValueError(f"Format attendu MODEL:FROM:TO, reçu: {spec}")
    return OfficialPathRequest(model=parts[0], from_version=parts[1], to_version=parts[2])


def read_official_path_requests(path: Path) -> list[OfficialPathRequest]:
    if not path.exists():
        return []

    requests: list[OfficialPathRequest] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            model = row.get("model") or row.get("Model")
            from_version = row.get("from") or row.get("current") or row.get("from_version")
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
    state: dict[str, Any], product: str, model: str, from_version: str, to_version: str, hops: tuple[str, ...]
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
        target_product = ensure_product(state, product_id, product.get("label") or DEFAULT_PRODUCT_LABEL)
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
            firmware_by_version = {firmware.get("version"): firmware for firmware in target_model.get("firmwares", [])}
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
                            set(existing_firmware.get("notes", [])) | set(firmware.get("notes") or [])
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
                        merged_firmware["discoveredAt"] = existing_firmware["discoveredAt"]
                    else:
                        merged_firmware.pop("discoveredAt", None)
                firmware_by_version[version] = merged_firmware
            target_model["firmwares"] = sorted(
                firmware_by_version.values(),
                key=lambda firmware: version_key(firmware["version"]),
            )
        target_product["models"].sort(key=lambda item: model_sort_key(item.get("id", "")))

    path_keys = {
        (path.get("product"), path.get("model"), path.get("from"), path.get("to")): index
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
    state["fortiosLifecycle"] = {**state["fortiosLifecycle"], **incoming["fortiosLifecycle"]}

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
        if not existing or (item.get("requestedAt") or "") > (existing.get("requestedAt") or ""):
            history_by_key[key] = item
    state["searchHistory"] = sorted(
        history_by_key.values(), key=lambda item: item.get("requestedAt") or "", reverse=True
    )[:SEARCH_HISTORY_LIMIT]

    state["generatedAt"] = utc_now()
    return state


def fetch_psirt_versions(timeout: int) -> set[str]:
    request = urllib.request.Request(
        PSIRT_RSS_URL,
        headers={"User-Agent": "sns-fortios-upgrade-watch/0.1"},
    )
    try:
        with urlopen_with_retry(request, timeout) as response:
            xml_bytes = response.read()
    except (urllib.error.URLError, TimeoutError, OSError):
        return set()

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return set()

    versions: set[str] = set()
    for node in root.iter():
        if node.text:
            versions.update(version for version in VERSION_RE.findall(node.text) if is_fortios_version(version))
    return versions


# --- PSIRT CVE tracking -------------------------------------------------
#
# Fortinet publishes a CSAF (Common Security Advisory Framework — a standard,
# machine-readable JSON format) export for every PSIRT advisory. Its
# vulnerabilities[].product_status.known_affected list gives exact per-branch
# version ranges (e.g. "FortiOS >=7.6.0|<=7.6.4" or "FortiClientEMS 7.0 all
# versions"), far more reliable than parsing the human-readable advisory page.
# The CSAF file's own URL isn't guessable (it embeds a slugified title), so a
# single HTML fetch per new advisory is still needed to find it.
PSIRT_BASE_URL = "https://fortiguard.fortinet.com"
CSAF_URL_RE = re.compile(r'csaf_url=([^"&]+\.json)')
ADVISORY_LINK_RE = re.compile(r"location\.href\s*=\s*'/psirt/(FG-IR-[\w-]+)'")
KNOWN_AFFECTED_RE = re.compile(r"^(?P<product>Forti\w+)\s+(?P<rest>.+)$")
ALL_VERSIONS_RE = re.compile(r"^(?P<branch>\d+\.\d+)\s+all versions$", re.IGNORECASE)

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


def discover_advisory_ids_from_rss(timeout: int) -> list[str]:
    request = urllib.request.Request(PSIRT_RSS_URL, headers={"User-Agent": "sns-fortios-upgrade-watch/0.1"})
    with urlopen_with_retry(request, timeout) as response:
        root = ET.fromstring(response.read())

    ids: list[str] = []
    for item in root.iter("item"):
        link = item.findtext("link") or ""
        match = re.search(r"(FG-IR-[\w-]+)", link)
        if match:
            ids.append(match.group(1))
    return unique_in_order(ids)


def discover_advisory_ids_from_listing(product_filter: str, max_pages: int, timeout: int) -> list[str]:
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


def fetch_csaf_url(advisory_id: str, timeout: int) -> str | None:
    raw_html = fetch_text(f"{PSIRT_BASE_URL}/psirt/{advisory_id}", timeout)
    match = CSAF_URL_RE.search(raw_html)
    return match.group(1) if match else None


def parse_known_affected_value(value: str) -> tuple[str, str | None, str | None, str | None] | None:
    """Parse one product_status.known_affected string.

    Returns (csaf_product_name, from_version, to_version, all_versions_branch) — the last
    element is set instead of from/to when the whole train is affected (e.g. "FortiClientEMS
    7.0 all versions"). Returns None if the string doesn't match a recognized shape.
    """
    match = KNOWN_AFFECTED_RE.match(value.strip())
    if not match:
        return None
    product_name = match.group("product")
    rest = match.group("rest").strip()

    all_match = ALL_VERSIONS_RE.match(rest)
    if all_match:
        return product_name, None, None, all_match.group("branch")

    from_match = re.search(r">=([\d.]+)", rest)
    to_match = re.search(r"<=([\d.]+)", rest)
    from_version = from_match.group(1) if from_match else None
    to_version = to_match.group(1) if to_match else None
    if not from_version and not to_version:
        return None
    return product_name, from_version, to_version, None


def parse_csaf_document(advisory_id: str, doc: dict[str, Any]) -> list[dict[str, Any]]:
    document = doc.get("document") or {}
    tracking = document.get("tracking") or {}
    title = document.get("title") or advisory_id
    published_at = (tracking.get("initial_release_date") or "")[:10]
    updated_at = (tracking.get("current_release_date") or "")[:10]
    url = f"{PSIRT_BASE_URL}/psirt/{advisory_id}"

    # A single CVE can show up as several vulnerabilities[] entries in one CSAF document —
    # e.g. FG-IR-22-230 has one entry per FortiClient platform, all under CVE-2022-45856.
    # Merge them into one entry per CVE with a combined `affected` list, otherwise later
    # entries would silently clobber earlier ones once upserted by id.
    entries_by_cve: dict[str, dict[str, Any]] = {}
    for vuln in doc.get("vulnerabilities") or []:
        cve_id = vuln.get("cve")
        if not cve_id:
            continue

        severity = None
        cvss_score = None
        for score in vuln.get("scores") or []:
            metrics = score.get("cvss_v3") or score.get("cvss_v4")
            if metrics:
                severity = (metrics.get("baseSeverity") or "").lower() or None
                cvss_score = metrics.get("baseScore")
                break

        affected: list[dict[str, Any]] = []
        for value in (vuln.get("product_status") or {}).get("known_affected") or []:
            parsed = parse_known_affected_value(value)
            if not parsed:
                continue
            product_name, from_version, to_version, all_versions_branch = parsed
            mapping = CVE_PRODUCT_MAP.get(product_name)
            if not mapping:
                continue
            product_id, model_id = mapping
            branch = all_versions_branch or ".".join((from_version or to_version).split(".")[:2])
            affected.append(
                {
                    "product": product_id,
                    "models": [model_id] if model_id else [],
                    "branch": branch,
                    "from": from_version,
                    "to": to_version,
                }
            )

        if not affected:
            continue  # this vulnerability entry doesn't touch any product this tool tracks.

        entry = entries_by_cve.setdefault(
            cve_id,
            {
                "id": cve_id,
                "advisoryId": advisory_id,
                "title": title,
                "severity": severity or "unknown",
                "cvssScore": cvss_score,
                "url": url,
                "publishedAt": published_at,
                "updatedAt": updated_at,
                "affected": [],
            },
        )
        entry["affected"].extend(affected)

    return list(entries_by_cve.values())


def collect_cve_entries_for_advisory(advisory_id: str, timeout: int) -> list[dict[str, Any]] | None:
    """Returns the definitive, current list of CVEs for this advisory (each already filtered to
    tracked products by parse_csaf_document — possibly empty if none apply anymore), or None if
    we can't confirm one way or another: no CSAF url found for this advisory could mean a
    transient PSIRT hiccup, or a legitimately CSAF-less legacy advisory — since those aren't
    distinguishable here, callers must never treat None as "confirmed zero CVEs" (see
    replace_cves_for_advisory()).
    """
    csaf_url = fetch_csaf_url(advisory_id, timeout)
    if not csaf_url:
        return None
    doc = json.loads(fetch_text(csaf_url, timeout))
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


def replace_cves_for_advisory(state: dict[str, Any], advisory_id: str, new_entries: list[dict[str, Any]]) -> int:
    """Replace every CVE previously recorded under `advisory_id` with exactly `new_entries` —
    only ever call this with a DEFINITIVE, successfully-parsed CSAF result (never for an advisory
    that was skipped due to a network/parse failure or an unresolved CSAF lookup), since a
    transient PSIRT hiccup must never be allowed to wipe real, previously-confirmed CVE data.
    Returns how many entries actually changed (added, updated in place, or removed).
    """
    new_ids = {entry["id"] for entry in new_entries}
    stale_ids = {
        item.get("id") for item in state["cves"]
        if item.get("advisoryId") == advisory_id and item.get("id") not in new_ids
    }
    changed = len(stale_ids)
    if stale_ids:
        state["cves"] = [item for item in state["cves"] if item.get("id") not in stale_ids]
    for entry in new_entries:
        if upsert_cve(state, entry):
            changed += 1
    return changed


def collect_cve_catalog(
    existing_advisory_ids: set[str],
    timeout: int,
    backfill: bool = False,
    backfill_max_pages: int = 30,
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
    backfill=True instead walks the paginated, per-product PSIRT listing to seed deep history —
    hundreds of advisories worth of requests, so it's still bounded to genuinely new ids there;
    meant to be run manually/occasionally, not from the daily timer.
    """
    if backfill:
        advisory_ids: list[str] = []
        for product_filter in CVE_LISTING_PRODUCT_FILTERS:
            advisory_ids.extend(discover_advisory_ids_from_listing(product_filter, backfill_max_pages, timeout))
        advisory_ids = unique_in_order(advisory_ids)
        advisory_ids = [advisory_id for advisory_id in advisory_ids if advisory_id not in existing_advisory_ids]
    else:
        advisory_ids = discover_advisory_ids_from_rss(timeout)

    results: dict[str, list[dict[str, Any]]] = {}
    skipped: list[str] = []
    for advisory_id in advisory_ids:
        try:
            entries = collect_cve_entries_for_advisory(advisory_id, timeout)
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
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
    return isinstance(value, str) and re.fullmatch(r"\d+\.\d+\.\d+(?:\.\d+)?", value) is not None


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
            raise UnsupportedExportShape(f"Version invalide dans le chemin : {version!r}")
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
        hops = parse_upgrade_export(text, expected_from=from_version, expected_to=to_version)
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
                advisory["models"] = [item.strip() for item in advisory["models"].split(",") if item.strip()]
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
    added_cves: int = 0,
    skipped_cves: list[str] | None = None,
) -> str:
    before_versions = all_versions(before)
    after_versions = all_versions(after)
    new_versions = sorted(after_versions - before_versions, key=version_key)
    product = next((item for item in after.get("products", []) if item.get("id") == DEFAULT_PRODUCT_ID), {})
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
        lines.extend(
            [
                "## CVE PSIRT Fortinet",
                "",
                f"- Nouvelles CVE ajoutées : {added_cves}",
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


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate FortiOS upgrade UI data.")
    parser.add_argument("--base", type=Path, default=Path("data/fortios-data.sample.json"))
    parser.add_argument("--output", type=Path, default=Path("data/fortios-data.generated.json"))
    parser.add_argument("--report", type=Path, default=Path("docs/last_report.md"))
    parser.add_argument("--upgrade-exports", type=Path, default=Path("data/upgrade_exports"))
    parser.add_argument("--advisories-csv", type=Path, default=Path("data/advisories.csv"))
    parser.add_argument("--forticare-json", type=Path, default=os.environ.get("FORTICARE_FIRMWARE_JSON"))
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
    parser.add_argument("--cve-backfill-max-pages", type=int, default=30, help="Pages max à parcourir par produit lors du --cve-backfill.")
    parser.add_argument("--timeout", type=int, default=12)
    parser.add_argument("--skip-network", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    before = normalize_state(read_json(args.base, {}))
    state = normalize_state(read_json(args.base, {}))

    forticare_json = args.forticare_json
    if forticare_json:
        state = merge_state(state, read_forticare_json(Path(forticare_json)))

    skipped_docs_versions: list[str] = []
    if args.docs_catalog and not args.skip_network:
        major_versions = tuple(item.strip() for item in args.docs_major_versions.split(",") if item.strip())
        docs_state, skipped_docs_versions = collect_docs_catalog(major_versions, args.timeout)
        state = merge_state(state, docs_state)
        try:
            apply_fortios_maturity(state, fetch_fortios_version_maturity(args.timeout))
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            pass
        try:
            state["fortiosLifecycle"] = fetch_fortios_lifecycle(args.timeout)
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            pass
    elif args.docs_catalog:
        skipped_docs_versions = ["collecte ignorée avec --skip-network"]

    tool_products = [item.strip() for item in args.tool_products.split(",") if item.strip()]
    if tool_products and not args.skip_network:
        for product_id in tool_products:
            if product_id not in PRODUCTS:
                continue
            state = merge_state(state, collect_tool_catalog(product_id, args.timeout))

    skipped_forticlient: list[str] = []
    if args.forticlient_catalog and not args.skip_network:
        major_versions = tuple(item.strip() for item in args.docs_major_versions.split(",") if item.strip())
        forticlient_state, skipped_forticlient = collect_forticlient_catalog(major_versions, args.timeout)
        state = merge_state(state, forticlient_state)
    elif args.forticlient_catalog:
        skipped_forticlient = ["collecte ignorée avec --skip-network"]

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
        state["advisories"] = [item for item in state["advisories"] if item.get("id") != advisory["id"]]
        state["advisories"].append(advisory)
        advisory_deltas.append(advisory)

    changed_paths = 0
    official_requests = read_official_path_requests(args.official_paths_csv)
    official_requests.extend(parse_official_path_spec(spec) for spec in args.official_path)
    if official_requests and not args.skip_network:
        for official_request in official_requests:
            try:
                official_result = fetch_official_upgrade_path(official_request, args.timeout)
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

    added_cves = 0
    skipped_cves: list[str] = []
    if (args.cve_catalog or args.cve_backfill) and not args.skip_network:
        existing_advisory_ids = {item.get("advisoryId") for item in state.get("cves", [])}
        cve_results_by_advisory, skipped_cves = collect_cve_catalog(
            existing_advisory_ids,
            args.timeout,
            backfill=args.cve_backfill,
            backfill_max_pages=args.cve_backfill_max_pages,
        )
        # Each advisory here got a definitive CSAF result this run: replace (not just upsert)
        # whatever we had for it, so a CVE Fortinet has since removed/reattributed away from our
        # tracked products actually disappears instead of lingering forever. Advisories in
        # skipped_cves are left completely untouched.
        for advisory_id, entries in cve_results_by_advisory.items():
            added_cves += replace_cves_for_advisory(state, advisory_id, entries)

    # This run started from a read of args.output taken potentially minutes ago (network
    # scraping in between) — fortios_server.py or import_forticlient_compat.py may have written
    # to that same file since. The lock below closes the race with those other writers; what it
    # doesn't do on its own is stop THIS run's own stale copy from clobbering what they wrote:
    # `state` still carries the advisories/paths/compatibilities exactly as they were at the top
    # of this function; blindly merging that in would replace a concurrent edit with our stale
    # pre-collection copy, or resurrect something a user deleted while we were scraping. So the
    # bulk merge below only ever carries firmwares/CVEs/lifecycle (this script's own exclusive
    # domain — no other process writes those) onto a freshly re-read state, while advisories and
    # paths are applied as precise upserts from the deltas tracked above, and compatibilities
    # (never touched by this script at all) are left completely alone.
    with cross_process_lock(args.output):
        latest_from_disk = normalize_state(read_json(args.output, {}))
        state_for_bulk_merge = {**state, "advisories": [], "paths": [], "compatibilities": []}
        final_state = merge_state(latest_from_disk, state_for_bulk_merge)
        for advisory in advisory_deltas:
            upsert_advisory(final_state, advisory)
        for path in path_deltas:
            upsert_path(final_state, path)
        final_state["generatedAt"] = utc_now()
        write_json(args.output, final_state)

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
            cve_catalog_enabled=args.cve_catalog or args.cve_backfill,
            added_cves=added_cves,
            skipped_cves=skipped_cves,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
