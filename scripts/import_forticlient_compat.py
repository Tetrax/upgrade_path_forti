#!/usr/bin/env python3
"""One-time/manual import of Fortinet's official FortiClient <-> EMS compatibility matrix.

Not part of the daily catalog refresh: Fortinet only publishes this matrix as a PDF with
sideways column headers, which extracts as reversed text (pdfplumber reads it character-by-
character in the wrong direction) — parseable, but fragile enough that a human should review
the result before it lands in production data. Run without --commit first to preview.

Requires pdfplumber, which isn't part of this project's normal (stdlib-only) dependencies:

    python3 -m venv /tmp/pdfenv && /tmp/pdfenv/bin/pip install pdfplumber
    /tmp/pdfenv/bin/python3 scripts/import_forticlient_compat.py --commit

Usage:
    python3 scripts/import_forticlient_compat.py                # preview only
    python3 scripts/import_forticlient_compat.py --commit        # write into the generated JSON
    python3 scripts/import_forticlient_compat.py --major 7.4     # older snapshot instead of latest
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import sys
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fortios_watch import normalize_state, read_json, upsert_compatibility, utc_now, write_json  # noqa: E402

FORTINET_DOCS_BASE_URL = "https://docs.fortinet.com"
DEFAULT_MAJORS_TO_TRY = ("8.0", "7.4", "7.2")
SOURCE_LABEL = "FortiClient EMS Compatibility Matrix (Fortinet, officielle)"
ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "fortios-data.generated.json"
SAMPLE_PATH = ROOT / "data" / "fortios-data.sample.json"


def fetch_url(url: str, timeout: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "sns-fortios-upgrade-watch/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def find_pdf_url(major: str, timeout: int) -> str | None:
    url = f"{FORTINET_DOCS_BASE_URL}/document/forticlient/{major}.0/ems-compatibility-chart"
    html = fetch_url(url, timeout).decode("utf-8", errors="ignore")
    match = re.search(r'href="(https://fortinetweb\.s3\.amazonaws\.com/[^"]+ems-compatibility-matrix\.pdf)"', html)
    return match.group(1) if match else None


def parse_matrix(pdf_path: Path) -> list[dict[str, Any]]:
    import pdfplumber  # deferred import: optional dependency, see module docstring.

    with pdfplumber.open(pdf_path) as pdf:
        table = pdf.pages[0].extract_tables()[0]

    # Row 0 is a title row ("FortiClient Windows, macOS, Linux*" / "FortiClient EMS"), row 1
    # holds the actual EMS version tokens — extracted reversed since the PDF renders them as
    # sideways text (e.g. "7.2.10" comes out as "01.2.7").
    header = [cell[::-1] if cell else cell for cell in table[1][1:]]
    client_by_ems: dict[str, list[str]] = {ems: [] for ems in header if ems}

    for row in table[2:]:
        client_version = row[0]
        if not client_version or not re.match(r"^\d+\.\d+\.\d+$", client_version):
            continue
        for ems_version, cell in zip(header, row[1:]):
            if ems_version and cell and cell.strip().upper() == "P":
                client_by_ems[ems_version].append(client_version)

    return [
        {"emsVersion": ems, "clientVersions": clients}
        for ems, clients in client_by_ems.items()
        if clients
    ]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--major", help="Train FortiClient à utiliser pour trouver le PDF (ex: 8.0). Sinon, essaie 8.0, 7.4, 7.2 dans l'ordre.")
    parser.add_argument("--commit", action="store_true", help="Écrire le résultat dans data/fortios-data.generated.json (sinon, aperçu seulement).")
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args(argv)

    majors = (args.major,) if args.major else DEFAULT_MAJORS_TO_TRY
    pdf_url = None
    for major in majors:
        pdf_url = find_pdf_url(major, args.timeout)
        if pdf_url:
            break
    if not pdf_url:
        print("Impossible de trouver le PDF de compatibilité sur docs.fortinet.com.", file=sys.stderr)
        return 1
    print(f"PDF trouvé : {pdf_url}")

    pdf_bytes = fetch_url(pdf_url, args.timeout)
    tmp_pdf = Path("/tmp") / "forticlient_ems_compat.pdf"
    tmp_pdf.write_bytes(pdf_bytes)

    entries = parse_matrix(tmp_pdf)
    if not entries:
        print("Aucune combinaison extraite — le format du PDF a peut-être changé.", file=sys.stderr)
        return 1

    print(f"\n{len(entries)} versions EMS trouvées :\n")
    for entry in sorted(entries, key=lambda e: e["emsVersion"]):
        print(f"  EMS {entry['emsVersion']:<10} -> FortiClient {', '.join(entry['clientVersions'])}")

    if not args.commit:
        print("\nAperçu seulement. Relancer avec --commit pour écrire dans data/fortios-data.generated.json.")
        return 0

    state = normalize_state(read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {}))
    added = 0
    for entry in entries:
        item = {
            "id": f"compat-official-{entry['emsVersion']}",
            "emsVersion": entry["emsVersion"],
            "clientVersions": entry["clientVersions"],
            "note": "",
            "source": SOURCE_LABEL,
            "createdAt": utc_now(),
        }
        if upsert_compatibility(state, item):
            added += 1
    state["generatedAt"] = utc_now()
    write_json(DATA_PATH, state)
    print(f"\n{added} combinaison(s) officielle(s) ajoutée(s)/mise(s) à jour dans {DATA_PATH}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
