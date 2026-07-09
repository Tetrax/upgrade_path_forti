#!/usr/bin/env python3
"""Serve the FortiOS UI and fetch official Fortinet upgrade paths on demand."""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from fortios_watch import (
    DEFAULT_PRODUCT_ID,
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
VALID_TIMINGS = {"pre-upgrade", "during-upgrade", "post-upgrade"}


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "fortios-data.generated.json"
SAMPLE_PATH = ROOT / "data" / "fortios-data.sample.json"


class FortiosHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, timeout: int = 20, **kwargs: Any) -> None:
        self.timeout = timeout
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_POST(self) -> None:
        if self.path == "/api/official-path":
            self.handle_official_path()
        elif self.path == "/api/advisories":
            self.handle_create_advisory()
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint inconnu")

    def handle_official_path(self) -> None:
        try:
            payload = self.read_json_body()
            request = OfficialPathRequest(
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
                if path.get("product") == DEFAULT_PRODUCT_ID
                and path.get("model") == request.model
                and path.get("from") == request.from_version
                and path.get("to") == request.to_version
            )
            self.write_json_response({"state": state, "path": path_payload})
        except KeyError as error:
            self.write_json_response({"error": f"Champ manquant : {error.args[0]}"}, HTTPStatus.BAD_REQUEST)
        except Exception as error:  # noqa: BLE001 - surface a readable local API error.
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_GATEWAY)

    def handle_create_advisory(self) -> None:
        try:
            payload = self.read_json_body()
            title = str(payload.get("title", "")).strip()
            description = str(payload.get("description", "")).strip()
            versions = [str(item).strip() for item in payload.get("versions") or [] if str(item).strip()]
            if not title or not description or not versions:
                raise ValueError("Titre, description et au moins une version sont obligatoires.")

            severity = str(payload.get("severity") or "important").strip()
            if severity not in VALID_SEVERITIES:
                raise ValueError(f"Sévérité invalide : {severity}")
            timing = str(payload.get("timing") or "post-upgrade").strip()
            if timing not in VALID_TIMINGS:
                raise ValueError(f"Timing invalide : {timing}")

            models = [str(item).strip() for item in payload.get("models") or [] if str(item).strip()]
            command = str(payload.get("command") or "").strip()
            source = str(payload.get("source") or "Ingénieur SNS").strip()

            advisory: dict[str, Any] = {
                "id": f"adv-{slugify(title)}-{secrets.token_hex(4)}",
                "product": DEFAULT_PRODUCT_ID,
                "versions": versions,
                "severity": severity,
                "timing": timing,
                "title": title,
                "description": description,
                "source": source,
                "createdAt": utc_now(),
            }
            if models:
                advisory["models"] = models
            if command:
                advisory["command"] = command

            state = normalize_state(read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {}))
            upsert_advisory(state, advisory)
            state["generatedAt"] = utc_now()
            write_json(DATA_PATH, state)

            self.write_json_response({"state": state, "advisory": advisory})
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
