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
import html
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any


VERSION_RE = re.compile(r"\b\d+\.\d+\.\d+(?:\.\d+)?\b")
DOC_MODEL_RE = re.compile(r"\b(?:FG|FWF|FGR|FFW)-[A-Z0-9][A-Z0-9-]*\b")
DEFAULT_PRODUCT_ID = "fortigate-fortios"
DEFAULT_PRODUCT_LABEL = "FortiGate / FortiOS"
PSIRT_RSS_URL = "https://www.fortiguard.com/rss/ir.xml"
FORTINET_DOCS_BASE_URL = "https://docs.fortinet.com"
FORTINET_UPGRADE_PATH_URL = f"{FORTINET_DOCS_BASE_URL}/upgrade-tool/upgrade-path"
DEFAULT_DOCS_MAJOR_VERSIONS = ("8.0", "7.6", "7.4", "7.2", "7.0", "6.4", "6.2", "6.0", "5.6", "5.4", "5.2", "5.0")


@dataclass(frozen=True)
class Firmware:
    product: str
    model: str
    version: str
    build: str = "-"
    notes: tuple[str, ...] = ()


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
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


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
    product = ensure_product(state, product_id, DEFAULT_PRODUCT_LABEL)
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
            return existing != before

    model["firmwares"].append(
        {
            "version": item.version,
            "build": item.build,
            "notes": list(item.notes),
        }
    )
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


def fetch_text(url: str, timeout: int) -> str:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "sns-fortios-upgrade-watch/0.1"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
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
            )
            upsert_firmware(state, firmware)

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


def post_official_upgrade_tool(payload: dict[str, str], timeout: int) -> dict[str, Any]:
    body = urllib.parse.urlencode(payload).encode("utf-8")
    request = urllib.request.Request(
        FORTINET_UPGRADE_PATH_URL,
        data=body,
        headers={
            "User-Agent": "sns-fortios-upgrade-watch/0.1",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": FORTINET_DOCS_BASE_URL,
            "Referer": f"{FORTINET_DOCS_BASE_URL}/upgrade-tool/fortigate",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", errors="ignore"))


def fetch_official_upgrade_path(requested: OfficialPathRequest, timeout: int) -> tuple[UpgradePath, list[Firmware]] | None:
    payload = {
        "product_slug": "fortigate",
        "model": requested.model,
        "current_version": requested.from_version,
        "target_version": requested.to_version,
    }
    payload_json = post_official_upgrade_tool(payload, timeout)
    path_items = payload_json.get("result", {}).get("path") or []
    if len(path_items) < 2:
        return None

    hops = tuple(item["version"] for item in path_items if item.get("version"))
    if len(hops) < 2:
        return None

    path = UpgradePath(
        product=DEFAULT_PRODUCT_ID,
        model=requested.model,
        from_version=requested.from_version,
        to_version=requested.to_version,
        hops=hops,
        source="Fortinet Upgrade Path Tool public service",
    )
    firmwares = [
        Firmware(
            product=DEFAULT_PRODUCT_ID,
            model=requested.model,
            version=item["version"],
            build=item.get("build_number") or "-",
            notes=official_note_keys(item),
        )
        for item in path_items
        if item.get("version")
    ]
    return path, firmwares


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
                firmware_by_version[version] = {**firmware_by_version.get(version, {}), **firmware}
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
    state["generatedAt"] = utc_now()
    return state


def fetch_psirt_versions(timeout: int) -> set[str]:
    request = urllib.request.Request(
        PSIRT_RSS_URL,
        headers={"User-Agent": "sns-fortios-upgrade-watch/0.1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
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


def parse_upgrade_export(text: str) -> list[str]:
    return unique_in_order(VERSION_RE.findall(text))


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
        hops = parse_upgrade_export(text)
        if len(hops) < 2:
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
    id,product,models,version,from,to,severity,timing,title,description,command,source
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
    elif args.docs_catalog:
        skipped_docs_versions = ["collecte ignorée avec --skip-network"]

    for advisory in import_csv_advisories(args.advisories_csv):
        state["advisories"] = [item for item in state["advisories"] if item.get("id") != advisory["id"]]
        state["advisories"].append(advisory)

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

    for path in read_upgrade_exports(args.upgrade_exports):
        for version in path.hops:
            upsert_firmware(state, Firmware(path.product, path.model, version))
        if upsert_path(state, path):
            changed_paths += 1

    psirt_versions: set[str] = set()
    if not args.skip_network:
        psirt_versions = fetch_psirt_versions(args.timeout)

    state["generatedAt"] = utc_now()
    write_json(args.output, state)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        build_report(
            before,
            state,
            psirt_versions,
            changed_paths,
            docs_catalog_enabled=args.docs_catalog,
            skipped_docs_versions=skipped_docs_versions,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
