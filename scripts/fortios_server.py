#!/usr/bin/env python3
"""Serve the FortiOS UI and fetch official Fortinet upgrade paths on demand."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import secrets
import sys
import urllib.parse
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from fortios_watch import (
    DEFAULT_PRODUCT_ID,
    PRODUCTS,
    OfficialPathRequest,
    fetch_official_upgrade_path,
    normalize_state,
    read_json,
    slugify,
    upsert_advisory,
    upsert_firmware,
    upsert_path,
    utc_now,
    write_json,
)

VALID_SEVERITIES = {"critical", "important", "warning", "info"}
ADVISORIES_PREFIX = "/api/advisories/"
IMAGE_EXTENSIONS = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
}
MAX_IMAGE_BYTES = 8 * 1024 * 1024
IMAGE_URL_PREFIX = "/data/advisory-images/"
IMAGE_REF_RE = re.compile(r"!\[[^\]]*\]\(/data/advisory-images/([^)\s]+)\)")


def parse_advisory_fields(payload: dict[str, Any]) -> dict[str, Any]:
    title = str(payload.get("title", "")).strip()
    description = str(payload.get("description", "")).strip()
    versions = [str(item).strip() for item in payload.get("versions") or [] if str(item).strip()]
    min_versions = [str(item).strip() for item in payload.get("minVersions") or [] if str(item).strip()]
    if not title or not description:
        raise ValueError("Titre et description sont obligatoires.")
    if not versions and not min_versions:
        raise ValueError("Indiquer au moins une version, ou au moins un point de départ.")

    product = str(payload.get("product") or DEFAULT_PRODUCT_ID).strip()
    if product not in PRODUCTS:
        raise ValueError(f"Produit invalide : {product}")
    severity = str(payload.get("severity") or "important").strip()
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"Sévérité invalide : {severity}")

    models = [str(item).strip() for item in payload.get("models") or [] if str(item).strip()]
    command = str(payload.get("command") or "").strip()
    bug_id = str(payload.get("bugId") or "").strip()
    bug_version = str(payload.get("bugVersion") or "").strip()
    behavior_change = bool(payload.get("behaviorChange"))
    source = str(payload.get("source") or "Ingénieur SNS").strip()

    fields: dict[str, Any] = {
        "product": product,
        "severity": severity,
        "title": title,
        "description": description,
        "source": source,
    }
    if min_versions:
        fields["minVersions"] = min_versions
    else:
        fields["versions"] = versions
    if models:
        fields["models"] = models
    if command:
        fields["command"] = command
    if behavior_change:
        fields["behaviorChange"] = True
    if bug_id:
        fields["bugId"] = bug_id
    if bug_version:
        fields["bugVersion"] = bug_version
    return fields


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "fortios-data.generated.json"
SAMPLE_PATH = ROOT / "data" / "fortios-data.sample.json"
IMAGE_DIR = ROOT / "data" / "advisory-images"


def delete_referenced_images(description: str) -> None:
    for match in IMAGE_REF_RE.finditer(description or ""):
        path = IMAGE_DIR / match.group(1)
        try:
            if path.is_file() and path.resolve().parent == IMAGE_DIR.resolve():
                path.unlink()
        except OSError:
            pass


class FortiosHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, timeout: int = 20, **kwargs: Any) -> None:
        self.timeout = timeout
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_POST(self) -> None:
        if self.path == "/api/official-path":
            self.handle_official_path()
        elif self.path == "/api/advisories":
            self.handle_create_advisory()
        elif self.path == "/api/advisory-images":
            self.handle_upload_image()
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint inconnu")

    def do_PUT(self) -> None:
        if self.path.startswith(ADVISORIES_PREFIX) and len(self.path) > len(ADVISORIES_PREFIX):
            self.handle_update_advisory(self.path[len(ADVISORIES_PREFIX):])
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint inconnu")

    def do_DELETE(self) -> None:
        if self.path.startswith(ADVISORIES_PREFIX) and len(self.path) > len(ADVISORIES_PREFIX):
            self.handle_delete_advisory(self.path[len(ADVISORIES_PREFIX):])
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint inconnu")

    def handle_official_path(self) -> None:
        try:
            payload = self.read_json_body()
            product = str(payload.get("product") or DEFAULT_PRODUCT_ID).strip()
            if product not in PRODUCTS:
                raise ValueError(f"Produit invalide : {product}")
            request = OfficialPathRequest(
                product=product,
                model=str(payload["model"]).strip(),
                from_version=str(payload["from"]).strip(),
                to_version=str(payload["to"]).strip(),
            )
            result = fetch_official_upgrade_path(request, self.timeout)
            if not result:
                self.write_json_response(
                    {"error": "Fortinet n'a pas retourné de chemin pour cette requête."},
                    HTTPStatus.NOT_FOUND,
                )
                return

            official_path, firmwares = result
            state = normalize_state(read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {}))
            for firmware in firmwares:
                upsert_firmware(state, firmware)
            upsert_path(state, official_path)
            state["generatedAt"] = utc_now()
            write_json(DATA_PATH, state)

            path_payload = next(
                path
                for path in state["paths"]
                if path.get("product") == request.product
                and path.get("model") == request.model
                and path.get("from") == request.from_version
                and path.get("to") == request.to_version
            )
            self.write_json_response({"state": state, "path": path_payload})
        except ValueError as error:
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        except KeyError as error:
            self.write_json_response({"error": f"Champ manquant : {error.args[0]}"}, HTTPStatus.BAD_REQUEST)
        except Exception as error:  # noqa: BLE001 - surface a readable local API error.
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_GATEWAY)

    def handle_create_advisory(self) -> None:
        try:
            payload = self.read_json_body()
            fields = parse_advisory_fields(payload)
            advisory: dict[str, Any] = {
                "id": f"adv-{slugify(fields['title'])}-{secrets.token_hex(4)}",
                "createdAt": utc_now(),
                **fields,
            }

            state = normalize_state(read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {}))
            upsert_advisory(state, advisory)
            state["generatedAt"] = utc_now()
            write_json(DATA_PATH, state)

            self.write_json_response({"state": state, "advisory": advisory})
        except ValueError as error:
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        except Exception as error:  # noqa: BLE001 - surface a readable local API error.
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_GATEWAY)

    def handle_update_advisory(self, raw_id: str) -> None:
        try:
            advisory_id = urllib.parse.unquote(raw_id)
            state = normalize_state(read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {}))
            existing = next((item for item in state["advisories"] if item.get("id") == advisory_id), None)
            if existing is None:
                self.write_json_response({"error": "Alerte introuvable."}, HTTPStatus.NOT_FOUND)
                return

            payload = self.read_json_body()
            fields = parse_advisory_fields(payload)
            advisory: dict[str, Any] = {
                "id": advisory_id,
                "createdAt": existing.get("createdAt") or utc_now(),
                "updatedAt": utc_now(),
                **fields,
            }

            upsert_advisory(state, advisory)
            state["generatedAt"] = utc_now()
            write_json(DATA_PATH, state)

            self.write_json_response({"state": state, "advisory": advisory})
        except ValueError as error:
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        except Exception as error:  # noqa: BLE001 - surface a readable local API error.
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_GATEWAY)

    def handle_delete_advisory(self, raw_id: str) -> None:
        try:
            advisory_id = urllib.parse.unquote(raw_id)
            state = normalize_state(read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {}))
            target = next((item for item in state["advisories"] if item.get("id") == advisory_id), None)
            if target is None:
                self.write_json_response({"error": "Alerte introuvable."}, HTTPStatus.NOT_FOUND)
                return

            state["advisories"] = [item for item in state["advisories"] if item.get("id") != advisory_id]
            state["generatedAt"] = utc_now()
            write_json(DATA_PATH, state)
            delete_referenced_images(target.get("description", ""))

            self.write_json_response({"state": state})
        except Exception as error:  # noqa: BLE001 - surface a readable local API error.
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_GATEWAY)

    def handle_upload_image(self) -> None:
        try:
            payload = self.read_json_body()
            content_type = str(payload.get("contentType") or "").strip().lower()
            data_base64 = str(payload.get("dataBase64") or "").strip()
            if content_type not in IMAGE_EXTENSIONS:
                raise ValueError(f"Format d'image non supporté : {content_type or 'inconnu'}")
            if not data_base64:
                raise ValueError("Image manquante.")

            try:
                raw = base64.b64decode(data_base64, validate=True)
            except (binascii.Error, ValueError) as error:
                raise ValueError("Image mal encodée.") from error
            if len(raw) > MAX_IMAGE_BYTES:
                raise ValueError("Image trop volumineuse (8 Mo max).")

            IMAGE_DIR.mkdir(parents=True, exist_ok=True)
            filename = f"{secrets.token_hex(8)}{IMAGE_EXTENSIONS[content_type]}"
            (IMAGE_DIR / filename).write_bytes(raw)

            self.write_json_response({"url": f"{IMAGE_URL_PREFIX}{filename}"})
        except ValueError as error:
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        except Exception as error:  # noqa: BLE001 - surface a readable local API error.
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_GATEWAY)

    def read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def write_json_response(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write("%s - %s\n" % (self.log_date_time_string(), format % args))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Serve FortiOS Upgrade Intelligence.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--timeout", type=int, default=20)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    def handler(*handler_args: Any, **handler_kwargs: Any) -> FortiosHandler:
        return FortiosHandler(*handler_args, timeout=args.timeout, **handler_kwargs)

    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"FortiOS Upgrade Intelligence: http://{args.host}:{args.port}/app/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt du serveur.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
