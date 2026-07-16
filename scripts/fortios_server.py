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
import threading
import traceback
import urllib.parse
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from fortios_watch import (
    DEFAULT_PRODUCT_ID,
    PRODUCTS,
    PRODUCT_LABELS,
    OfficialPathRequest,
    fetch_official_upgrade_path,
    normalize_state,
    read_json,
    record_search_history,
    slugify,
    upsert_advisory,
    upsert_compatibility,
    upsert_firmware,
    upsert_path,
    utc_now,
    write_json,
)

VALID_SEVERITIES = {"critical", "important", "warning", "info"}
ADVISORIES_PREFIX = "/api/advisories/"
COMPATIBILITIES_PREFIX = "/api/compatibilities/"
IMAGE_EXTENSIONS = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
}
MAX_IMAGE_BYTES = 8 * 1024 * 1024
IMAGE_URL_PREFIX = "/data/advisory-images/"
IMAGE_REF_RE = re.compile(r"!\[[^\]]*\]\(/data/advisory-images/([^)\s]+)\)")
# 1 MB is generously above any legitimate JSON body this API accepts (the image upload payload is
# base64, so 8 MB of image data becomes ~11 MB on the wire — bump the ceiling for that one route).
MAX_JSON_BODY_BYTES = 1 * 1024 * 1024
MAX_IMAGE_UPLOAD_BODY_BYTES = 12 * 1024 * 1024
# Only these two directories are anything the UI actually needs served over HTTP — ROOT is the
# whole repo checkout, which also holds scripts/, deploy/, docs/ and .git/.
ALLOWED_STATIC_PREFIXES = ("/app/", "/data/")

# ThreadingHTTPServer runs every request on its own thread, but all the POST/PUT/DELETE handlers
# below do read-JSON -> mutate -> write-JSON against the same file with no isolation of their
# own — this serializes that whole sequence so two concurrent requests can't race and silently
# clobber one another's changes (a "lost update").
STATE_LOCK = threading.Lock()


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
    if product not in PRODUCT_LABELS:
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


def parse_compatibility_fields(payload: dict[str, Any]) -> dict[str, Any]:
    ems_version = str(payload.get("emsVersion") or "").strip()
    client_versions = [str(item).strip() for item in payload.get("clientVersions") or [] if str(item).strip()]
    if not ems_version:
        raise ValueError("La version FortiClient EMS est obligatoire.")
    if not client_versions:
        raise ValueError("Indiquer au moins une version FortiClient compatible.")

    note = str(payload.get("note") or "").strip()
    source = str(payload.get("source") or "Ingénieur SNS").strip()

    return {
        "emsVersion": ems_version,
        "clientVersions": client_versions,
        "note": note,
        "source": source,
    }


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "fortios-data.generated.json"
SAMPLE_PATH = ROOT / "data" / "fortios-data.sample.json"
IMAGE_DIR = ROOT / "data" / "advisory-images"


def referenced_image_filenames(description: str) -> set[str]:
    return {match.group(1) for match in IMAGE_REF_RE.finditer(description or "")}


def prune_unreferenced_images(candidates: set[str], state: dict[str, Any]) -> None:
    """Delete image files in `candidates` unless still referenced by any advisory in `state`."""
    if not candidates:
        return
    still_used: set[str] = set()
    for advisory in state["advisories"]:
        still_used |= referenced_image_filenames(advisory.get("description", ""))

    for filename in candidates - still_used:
        path = IMAGE_DIR / filename
        try:
            if path.is_file() and path.resolve().parent == IMAGE_DIR.resolve():
                path.unlink()
        except OSError:
            pass


class FortiosHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, timeout: int = 20, **kwargs: Any) -> None:
        self.timeout = timeout
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def translate_path(self, path: str) -> str:
        # SimpleHTTPRequestHandler already blocks ".." traversal outside `directory`, but that
        # still leaves every other file under the repo root (scripts/, deploy/, docs/, .git/)
        # readable over plain HTTP by anyone who can reach this server — restrict to what the UI
        # actually needs.
        url_path = urllib.parse.urlsplit(path).path
        if not any(url_path.startswith(prefix) for prefix in ALLOWED_STATIC_PREFIXES):
            return str(ROOT / "__not_served__")
        return super().translate_path(path)

    def is_safe_origin(self) -> bool:
        """Lightweight CSRF guard for the state-mutating routes: the request must claim to come
        from this same host. Not a full token-based scheme, but it closes off the "any page the
        browser visits can silently fetch() this API" hole a bare Content-Type check leaves open,
        since a Content-Type of text/plain would otherwise sail through as a CORS-simple request.

        Compared on hostname only (not port): behind the nginx reverse proxy, the forwarded Host
        header loses the original port (nginx's $host strips it) while the browser's Origin keeps
        it (valdev.me:3001 is not the default HTTPS port) — comparing full netloc rejected every
        single legitimate request.
        """
        host = self.headers.get("Host", "").split(":", 1)[0]
        origin = self.headers.get("Origin")
        if origin is not None:
            return urllib.parse.urlsplit(origin).hostname == host
        referer = self.headers.get("Referer")
        if referer is not None:
            return urllib.parse.urlsplit(referer).hostname == host
        return True  # neither header present — a same-origin browser navigation, not fetch()

    def do_POST(self) -> None:
        if not self.is_safe_origin():
            self.send_error(HTTPStatus.FORBIDDEN, "Origin invalide")
            return
        if self.path == "/api/official-path":
            self.handle_official_path()
        elif self.path == "/api/advisories":
            self.handle_create_advisory()
        elif self.path == "/api/advisory-images":
            self.handle_upload_image()
        elif self.path == "/api/compatibilities":
            self.handle_create_compatibility()
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint inconnu")

    def do_PUT(self) -> None:
        if not self.is_safe_origin():
            self.send_error(HTTPStatus.FORBIDDEN, "Origin invalide")
            return
        if self.path.startswith(ADVISORIES_PREFIX) and len(self.path) > len(ADVISORIES_PREFIX):
            self.handle_update_advisory(self.path[len(ADVISORIES_PREFIX):])
        elif self.path.startswith(COMPATIBILITIES_PREFIX) and len(self.path) > len(COMPATIBILITIES_PREFIX):
            self.handle_update_compatibility(self.path[len(COMPATIBILITIES_PREFIX):])
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint inconnu")

    def do_DELETE(self) -> None:
        if not self.is_safe_origin():
            self.send_error(HTTPStatus.FORBIDDEN, "Origin invalide")
            return
        if self.path.startswith(ADVISORIES_PREFIX) and len(self.path) > len(ADVISORIES_PREFIX):
            self.handle_delete_advisory(self.path[len(ADVISORIES_PREFIX):])
        elif self.path.startswith(COMPATIBILITIES_PREFIX) and len(self.path) > len(COMPATIBILITIES_PREFIX):
            self.handle_delete_compatibility(self.path[len(COMPATIBILITIES_PREFIX):])
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint inconnu")

    def handle_official_path(self) -> None:
        try:
            payload = self.read_json_body()
            product = str(payload.get("product") or DEFAULT_PRODUCT_ID).strip()
            if product not in PRODUCT_LABELS:
                raise ValueError(f"Produit invalide : {product}")
            if product not in PRODUCTS:
                raise ValueError(f"{PRODUCT_LABELS[product]} n'a pas de chemin d'upgrade automatique Fortinet.")
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
            with STATE_LOCK:
                state = normalize_state(read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {}))
                for firmware in firmwares:
                    upsert_firmware(state, firmware)
                upsert_path(state, official_path)
                record_search_history(
                    state, request.product, request.model, request.from_version, request.to_version, official_path.hops
                )
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
            self.log_exception("handle_official_path")
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

            with STATE_LOCK:
                state = normalize_state(read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {}))
                upsert_advisory(state, advisory)
                state["generatedAt"] = utc_now()
                write_json(DATA_PATH, state)

            self.write_json_response({"state": state, "advisory": advisory})
        except ValueError as error:
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        except Exception as error:  # noqa: BLE001 - surface a readable local API error.
            self.log_exception("handle_create_advisory")
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_GATEWAY)

    def handle_update_advisory(self, raw_id: str) -> None:
        try:
            advisory_id = urllib.parse.unquote(raw_id)
            with STATE_LOCK:
                state = normalize_state(read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {}))
                existing = next((item for item in state["advisories"] if item.get("id") == advisory_id), None)
                if existing is None:
                    self.write_json_response({"error": "Alerte introuvable."}, HTTPStatus.NOT_FOUND)
                    return

                old_images = referenced_image_filenames(existing.get("description", ""))

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
                prune_unreferenced_images(old_images, state)

            self.write_json_response({"state": state, "advisory": advisory})
        except ValueError as error:
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        except Exception as error:  # noqa: BLE001 - surface a readable local API error.
            self.log_exception("handle_update_advisory")
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_GATEWAY)

    def handle_delete_advisory(self, raw_id: str) -> None:
        try:
            advisory_id = urllib.parse.unquote(raw_id)
            with STATE_LOCK:
                state = normalize_state(read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {}))
                target = next((item for item in state["advisories"] if item.get("id") == advisory_id), None)
                if target is None:
                    self.write_json_response({"error": "Alerte introuvable."}, HTTPStatus.NOT_FOUND)
                    return

                state["advisories"] = [item for item in state["advisories"] if item.get("id") != advisory_id]
                state["generatedAt"] = utc_now()
                write_json(DATA_PATH, state)
                prune_unreferenced_images(referenced_image_filenames(target.get("description", "")), state)

            self.write_json_response({"state": state})
        except Exception as error:  # noqa: BLE001 - surface a readable local API error.
            self.log_exception("handle_delete_advisory")
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_GATEWAY)

    def handle_create_compatibility(self) -> None:
        try:
            payload = self.read_json_body()
            fields = parse_compatibility_fields(payload)
            item: dict[str, Any] = {
                "id": f"compat-{slugify(fields['emsVersion'])}-{secrets.token_hex(4)}",
                "createdAt": utc_now(),
                **fields,
            }

            with STATE_LOCK:
                state = normalize_state(read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {}))
                upsert_compatibility(state, item)
                state["generatedAt"] = utc_now()
                write_json(DATA_PATH, state)

            self.write_json_response({"state": state, "compatibility": item})
        except ValueError as error:
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        except Exception as error:  # noqa: BLE001 - surface a readable local API error.
            self.log_exception("handle_create_compatibility")
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_GATEWAY)

    def handle_update_compatibility(self, raw_id: str) -> None:
        try:
            item_id = urllib.parse.unquote(raw_id)
            with STATE_LOCK:
                state = normalize_state(read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {}))
                existing = next((item for item in state["compatibilities"] if item.get("id") == item_id), None)
                if existing is None:
                    self.write_json_response({"error": "Combinaison introuvable."}, HTTPStatus.NOT_FOUND)
                    return

                payload = self.read_json_body()
                fields = parse_compatibility_fields(payload)
                item: dict[str, Any] = {
                    "id": item_id,
                    "createdAt": existing.get("createdAt") or utc_now(),
                    "updatedAt": utc_now(),
                    **fields,
                }

                upsert_compatibility(state, item)
                state["generatedAt"] = utc_now()
                write_json(DATA_PATH, state)

            self.write_json_response({"state": state, "compatibility": item})
        except ValueError as error:
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        except Exception as error:  # noqa: BLE001 - surface a readable local API error.
            self.log_exception("handle_update_compatibility")
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_GATEWAY)

    def handle_delete_compatibility(self, raw_id: str) -> None:
        try:
            item_id = urllib.parse.unquote(raw_id)
            with STATE_LOCK:
                state = normalize_state(read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {}))
                remaining = [item for item in state["compatibilities"] if item.get("id") != item_id]
                if len(remaining) == len(state["compatibilities"]):
                    self.write_json_response({"error": "Combinaison introuvable."}, HTTPStatus.NOT_FOUND)
                    return

                state["compatibilities"] = remaining
                state["generatedAt"] = utc_now()
                write_json(DATA_PATH, state)

            self.write_json_response({"state": state})
        except Exception as error:  # noqa: BLE001 - surface a readable local API error.
            self.log_exception("handle_delete_compatibility")
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_GATEWAY)

    def handle_upload_image(self) -> None:
        try:
            payload = self.read_json_body(max_bytes=MAX_IMAGE_UPLOAD_BODY_BYTES)
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
            self.log_exception("handle_upload_image")
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_GATEWAY)

    def read_json_body(self, max_bytes: int = MAX_JSON_BODY_BYTES) -> dict[str, Any]:
        # Requiring the exact Content-Type also closes the "CORS-simple request" loophole a
        # cross-origin fetch() could otherwise use (e.g. text/plain) to reach this endpoint
        # without a preflight — paired with is_safe_origin() above.
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type != "application/json":
            raise ValueError("Content-Type doit être application/json.")
        length = int(self.headers.get("Content-Length", "0"))
        if length > max_bytes:
            raise ValueError(f"Corps de requête trop volumineux ({length} octets, max {max_bytes}).")
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def log_exception(self, context: str) -> None:
        sys.stderr.write(f"{self.log_date_time_string()} - unhandled error in {context}\n")
        traceback.print_exc(file=sys.stderr)

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
