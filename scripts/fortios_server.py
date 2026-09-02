#!/usr/bin/env python3
"""Serve the FortiOS UI and fetch official Fortinet upgrade paths on demand."""

from __future__ import annotations

import argparse
import base64
import binascii
import hmac
import ipaddress
import json
import os
import re
import secrets
import ssl
import sys
import threading
import traceback
import urllib.error
import urllib.parse
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import certctl
import fortios_notify
from cert_admin import (
    DEFAULT_CREDENTIALS,
    MAX_PASSWORD_LENGTH,
    CredentialError,
    authenticate_credentials,
    credential_lock,
    credentials_revision,
)
from cert_helper_protocol import HelperError, install_via_helper
from cert_web import (
    ActionRateLimiter,
    AdminSession,
    EmailPreviewStore,
    LoginRateLimiter,
    SessionStore,
    ValidationTicketStore,
    install_uploaded_certificate,
    validate_uploaded_certificate,
)
from fortios_watch import (
    DEFAULT_PRODUCT_ID,
    PRODUCT_LABELS,
    PRODUCTS,
    UPGRADE_DIRECTION_ERROR,
    Firmware,
    OfficialPathRequest,
    UpgradePath,
    cross_process_lock,
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
    version_key,
    write_json,
)
from tls_lock import managed_pair_lock

if os.environ.get("FORTIOS_E2E_MOCK_NETWORK") == "1":
    # Inert unless this exact env var is set — never touched in production, only by the
    # isolated E2E test fixture, which is also the only thing that ever points
    # FORTIOS_E2E_MOCK_RESPONSE_FILE somewhere real. Lets tests simulate a successful Fortinet
    # fetch (a hops[] list) or an outage (an "error" message, raised as a URLError so the
    # existing offline/cache-fallback code path in handle_official_path() runs unmodified) with
    # zero real network calls.
    def _mock_fetch_official_upgrade_path(request: OfficialPathRequest, timeout: int):
        response_path = Path(os.environ["FORTIOS_E2E_MOCK_RESPONSE_FILE"])
        payload = (
            json.loads(response_path.read_text()) if response_path.exists() else {}
        )
        if payload.get("error"):
            raise urllib.error.URLError(payload["error"])
        hops = payload.get("hops")
        if not hops:
            return None
        path = UpgradePath(
            product=request.product,
            model=request.model,
            from_version=request.from_version,
            to_version=request.to_version,
            hops=tuple(hops),
            source="Simulation E2E (FORTIOS_E2E_MOCK_NETWORK)",
        )
        firmwares = [
            Firmware(product=request.product, model=request.model, version=version)
            for version in hops
        ]
        return path, firmwares

    fetch_official_upgrade_path = _mock_fetch_official_upgrade_path

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
MAX_CERT_UPLOAD_BODY_BYTES = 56 * 1024 * 1024
REQUEST_SOCKET_TIMEOUT_SECONDS = 15
EMAIL_PREVIEW_RENDER_PREFIX = "/api/cert/notifications/preview/render/"
EMAIL_PREVIEW_CSP = (
    "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; "
    "img-src 'none'; frame-ancestors 'self'; base-uri 'none'; form-action 'none'"
)

# Persisted user-controlled text is deliberately bounded well above the current UI/data sizes,
# while preventing accidental multi-megabyte records from turning the JSON catalog into an
# unbounded storage sink. These limits apply at every HTTP mutation parser below.
MAX_VERSION_LENGTH = 32
MAX_MODEL_LENGTH = 64
MAX_ADVISORY_TITLE_LENGTH = 200
MAX_ADVISORY_DESCRIPTION_LENGTH = 20_000
MAX_ADVISORY_COMMAND_LENGTH = 8_000
MAX_ADVISORY_SOURCE_LENGTH = 200
MAX_ADVISORY_BUG_ID_LENGTH = 64
MAX_ADVISORY_VERSION_ITEMS = 128
MAX_ADVISORY_MODEL_ITEMS = 512
MAX_COMPAT_CLIENT_VERSION_ITEMS = 128
MAX_COMPAT_NOTE_LENGTH = 4_000
MAX_COMPAT_SOURCE_LENGTH = 200

# ThreadingHTTPServer creates one handler per request. This semaphore is process-global (and thus
# shared by all anonymous callers of this server) and bounds only the expensive live Fortinet call.
# Set FORTIOS_OFFICIAL_PATH_MAX_CONCURRENCY before starting the server to tune it without adding
# an identity/account system. Invalid or extreme values fall back to a small safe range.
DEFAULT_OFFICIAL_PATH_MAX_CONCURRENCY = 2
MAX_OFFICIAL_PATH_MAX_CONCURRENCY = 32
try:
    OFFICIAL_PATH_MAX_CONCURRENCY = int(
        os.environ.get(
            "FORTIOS_OFFICIAL_PATH_MAX_CONCURRENCY",
            str(DEFAULT_OFFICIAL_PATH_MAX_CONCURRENCY),
        )
    )
except ValueError:
    OFFICIAL_PATH_MAX_CONCURRENCY = DEFAULT_OFFICIAL_PATH_MAX_CONCURRENCY
OFFICIAL_PATH_MAX_CONCURRENCY = min(
    max(1, OFFICIAL_PATH_MAX_CONCURRENCY), MAX_OFFICIAL_PATH_MAX_CONCURRENCY
)
OFFICIAL_PATH_SEMAPHORE = threading.BoundedSemaphore(OFFICIAL_PATH_MAX_CONCURRENCY)
INTERNAL_ERROR_MESSAGE = "Erreur interne du serveur."
OFFICIAL_PATH_BUSY_MESSAGE = "Trop de requêtes Fortinet en cours."
# Only these two directories are anything the UI actually needs served over HTTP — ROOT is the
# whole repo checkout, which also holds scripts/, deploy/, docs/ and .git/. Defined next to ROOT
# below at import time (module globals resolve at call time regardless of source order).

# ThreadingHTTPServer runs every request on its own thread, and this script's daily batch
# counterpart (fortios_watch.py) and import_forticlient_compat.py both write the same file from
# entirely separate processes — all read-JSON -> mutate -> write-JSON critical sections use
# cross_process_lock(DATA_PATH) (see fortios_watch.py) rather than an in-process threading.Lock,
# which would do nothing to stop those other processes from interleaving a conflicting write.


def _bounded_text(
    value: object,
    label: str,
    maximum: int,
    *,
    required: bool = False,
) -> str:
    if value is None:
        text = ""
    elif isinstance(value, str):
        text = value.strip()
    else:
        raise ValueError(f"{label} invalide.")
    if required and not text:
        raise ValueError(f"{label} obligatoire.")
    if len(text) > maximum:
        raise ValueError(f"{label} trop long ({maximum} caractères maximum).")
    return text


def _bounded_text_list(
    value: object,
    label: str,
    *,
    maximum_items: int,
    maximum_length: int,
) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise TypeError(f"{label} doit être une liste.")
    if len(value) > maximum_items:
        raise ValueError(f"{label} contient trop d'éléments ({maximum_items} maximum).")

    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"Chaque élément de {label} doit être du texte.")
        text = item.strip()
        if not text:
            continue
        if len(text) > maximum_length:
            raise ValueError(
                f"Un élément de {label} est trop long ({maximum_length} caractères maximum)."
            )
        result.append(text)
    return result


def parse_official_path_request(payload: dict[str, Any]) -> OfficialPathRequest:
    product = _bounded_text(
        payload.get("product") or DEFAULT_PRODUCT_ID,
        "Produit",
        MAX_MODEL_LENGTH,
        required=True,
    )
    if product not in PRODUCT_LABELS:
        raise ValueError(f"Produit invalide : {product}")
    if product not in PRODUCTS:
        raise ValueError(
            f"{PRODUCT_LABELS[product]} n'a pas de chemin d'upgrade automatique Fortinet."
        )
    missing = [name for name in ("model", "from", "to") if name not in payload]
    if missing:
        raise KeyError(missing[0])
    model = _bounded_text(payload["model"], "Modèle", MAX_MODEL_LENGTH, required=True)
    from_version = _bounded_text(
        payload["from"], "Version de départ", MAX_VERSION_LENGTH, required=True
    )
    to_version = _bounded_text(
        payload["to"], "Version cible", MAX_VERSION_LENGTH, required=True
    )
    if version_key(to_version) <= version_key(from_version):
        raise ValueError(UPGRADE_DIRECTION_ERROR)
    return OfficialPathRequest(
        product=product,
        model=model,
        from_version=from_version,
        to_version=to_version,
    )


def parse_advisory_fields(payload: dict[str, Any]) -> dict[str, Any]:
    title = _bounded_text(
        payload.get("title"),
        "Titre",
        MAX_ADVISORY_TITLE_LENGTH,
        required=True,
    )
    description = _bounded_text(
        payload.get("description"),
        "Description",
        MAX_ADVISORY_DESCRIPTION_LENGTH,
        required=True,
    )
    versions = _bounded_text_list(
        payload.get("versions"),
        "Versions",
        maximum_items=MAX_ADVISORY_VERSION_ITEMS,
        maximum_length=MAX_VERSION_LENGTH,
    )
    min_versions = _bounded_text_list(
        payload.get("minVersions"),
        "Versions minimales",
        maximum_items=MAX_ADVISORY_VERSION_ITEMS,
        maximum_length=MAX_VERSION_LENGTH,
    )
    from_version = _bounded_text(
        payload.get("from"), "Version de départ", MAX_VERSION_LENGTH
    )
    to_version = _bounded_text(payload.get("to"), "Version cible", MAX_VERSION_LENGTH)
    if bool(from_version) != bool(to_version):
        raise ValueError(
            "Une bascule précise nécessite une version de départ et une version cible."
        )
    if from_version and to_version and from_version == to_version:
        raise ValueError(
            "La version de départ et la version cible doivent être différentes."
        )
    targeting_modes = sum(
        (
            bool(versions),
            bool(min_versions),
            bool(from_version and to_version),
        ),
    )
    if targeting_modes > 1:
        raise ValueError("Choisir un seul mode de ciblage des versions.")
    if not versions and not min_versions and not (from_version and to_version):
        raise ValueError(
            "Indiquer au moins une version, un point de départ, ou une bascule précise."
        )

    product = _bounded_text(
        payload.get("product") or DEFAULT_PRODUCT_ID,
        "Produit",
        MAX_MODEL_LENGTH,
        required=True,
    )
    if product not in PRODUCT_LABELS:
        raise ValueError(f"Produit invalide : {product}")
    severity = _bounded_text(
        payload.get("severity") or "important",
        "Sévérité",
        MAX_ADVISORY_SOURCE_LENGTH,
        required=True,
    )
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"Sévérité invalide : {severity}")

    models = _bounded_text_list(
        payload.get("models"),
        "Modèles",
        maximum_items=MAX_ADVISORY_MODEL_ITEMS,
        maximum_length=MAX_MODEL_LENGTH,
    )
    command = _bounded_text(
        payload.get("command"), "Commande", MAX_ADVISORY_COMMAND_LENGTH
    )
    bug_id = _bounded_text(
        payload.get("bugId"), "Bug ID", MAX_ADVISORY_BUG_ID_LENGTH
    )
    bug_version = _bounded_text(
        payload.get("bugVersion"), "Version du bug", MAX_VERSION_LENGTH
    )
    behavior_change = bool(payload.get("behaviorChange"))
    source = _bounded_text(
        payload.get("source") or "Ingénieur SNS",
        "Source",
        MAX_ADVISORY_SOURCE_LENGTH,
        required=True,
    )

    fields: dict[str, Any] = {
        "product": product,
        "severity": severity,
        "title": title,
        "description": description,
        "source": source,
    }
    if from_version and to_version:
        fields["from"] = from_version
        fields["to"] = to_version
    elif min_versions:
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
    ems_version = _bounded_text(
        payload.get("emsVersion"), "La version FortiClient EMS", MAX_VERSION_LENGTH
    )
    client_versions = _bounded_text_list(
        payload.get("clientVersions"),
        "Versions FortiClient",
        maximum_items=MAX_COMPAT_CLIENT_VERSION_ITEMS,
        maximum_length=MAX_VERSION_LENGTH,
    )
    if not ems_version:
        raise ValueError("La version FortiClient EMS est obligatoire.")
    if not client_versions:
        raise ValueError("Indiquer au moins une version FortiClient compatible.")

    note = _bounded_text(payload.get("note"), "Note", MAX_COMPAT_NOTE_LENGTH)
    source = _bounded_text(
        payload.get("source") or "Ingénieur SNS",
        "Source",
        MAX_COMPAT_SOURCE_LENGTH,
        required=True,
    )

    return {
        "emsVersion": ems_version,
        "clientVersions": client_versions,
        "note": note,
        "source": source,
    }


def activate_uploaded_certificate(
    payload: dict[str, Any],
    hostname: str,
    output_dir: Path,
    *,
    helper_socket: Path | None,
    credentials_revision: str,
) -> dict[str, Any]:
    if helper_socket is not None:
        return install_via_helper(
            helper_socket,
            payload,
            credentials_revision=credentials_revision,
        )
    return install_uploaded_certificate(payload, hostname, output_dir)


ROOT = Path(__file__).resolve().parents[1]
ALLOWED_STATIC_DIR_APP = (ROOT / "app").resolve()
ALLOWED_STATIC_DIR_CERT = (ROOT / "app" / "cert").resolve()

# DATA_DIR is overridable via FORTIOS_TEST_DATA_DIR — unset in production (default: ROOT/data,
# identical to before this existed), set only by the isolated E2E test fixture so tests never
# read or write the real data/fortios-data.generated.json, advisory-images/, etc. app/ always
# still resolves against the fixed ROOT below, regardless of this override.
_test_data_dir = os.environ.get("FORTIOS_TEST_DATA_DIR")
DATA_DIR = Path(_test_data_dir).resolve() if _test_data_dir else (ROOT / "data")
ALLOWED_STATIC_DIR_DATA = DATA_DIR.resolve()
DATA_PATH = DATA_DIR / "fortios-data.generated.json"
SAMPLE_PATH = DATA_DIR / "fortios-data.sample.json"
IMAGE_DIR = DATA_DIR / "advisory-images"
NOTIFICATION_SETTINGS_PATH = DATA_DIR / "notification-settings.json"
SMTP_SETTINGS_PATH = DATA_DIR / "smtp-settings.json"


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
    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(REQUEST_SOCKET_TIMEOUT_SECONDS)

    def __init__(
        self,
        *args: Any,
        timeout: int = 20,
        tls_active: bool = False,
        allow_insecure_localhost: bool = False,
        cert_trusted_proxy_networks: tuple[
            ipaddress.IPv4Network | ipaddress.IPv6Network, ...
        ] = (),
        cert_admin_file: Path = DEFAULT_CREDENTIALS,
        cert_sessions: SessionStore | None = None,
        cert_hostname: str = "",
        cert_output_dir: Path = Path("certificates/active"),
        cert_direct_install: bool = False,
        cert_helper_socket: Path | None = None,
        cert_login_limiter: LoginRateLimiter | None = None,
        cert_test_email_limiter: ActionRateLimiter | None = None,
        cert_preview_limiter: ActionRateLimiter | None = None,
        cert_validation_tickets: ValidationTicketStore | None = None,
        email_previews: EmailPreviewStore | None = None,
        **kwargs: Any,
    ) -> None:
        self.timeout = timeout
        self.tls_active = tls_active
        self.allow_insecure_localhost = allow_insecure_localhost
        self.cert_trusted_proxy_networks = cert_trusted_proxy_networks
        self.cert_admin_file = cert_admin_file
        self.cert_sessions = cert_sessions or SessionStore()
        self.cert_hostname = cert_hostname
        self.cert_output_dir = cert_output_dir
        self.cert_direct_install = cert_direct_install
        self.cert_helper_socket = cert_helper_socket
        self.cert_login_limiter = cert_login_limiter or LoginRateLimiter()
        self.cert_test_email_limiter = (
            cert_test_email_limiter or ActionRateLimiter()
        )
        self.cert_preview_limiter = cert_preview_limiter or ActionRateLimiter(
            max_actions=30
        )
        self.cert_validation_tickets = (
            cert_validation_tickets or ValidationTicketStore()
        )
        self.email_previews = email_previews or EmailPreviewStore()
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def request_from_trusted_proxy(self) -> bool:
        try:
            client = ipaddress.ip_address(self.client_address[0])
        except ValueError:
            return False
        networks = getattr(self, "cert_trusted_proxy_networks", ())
        return any(client in network for network in networks)

    def request_is_secure(self) -> bool:
        if self.tls_active:
            return True
        return (
            self.request_from_trusted_proxy()
            and self.headers.get("X-Forwarded-Proto", "").strip().lower() == "https"
        )

    def cert_client_identity(self) -> str:
        direct_client = self.client_address[0]
        if not self.request_from_trusted_proxy():
            return direct_client
        try:
            return str(ipaddress.ip_address(self.headers.get("X-Real-IP", "")))
        except ValueError:
            return direct_client

    def certificate_ui_available(self) -> bool:
        if self.request_is_secure():
            return True
        if not self.allow_insecure_localhost:
            return False
        try:
            return ipaddress.ip_address(self.client_address[0]).is_loopback
        except ValueError:
            return False

    def end_headers(self) -> None:
        url_path = urllib.parse.urlsplit(self.path).path
        if self.request_is_secure():
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        if url_path.startswith(EMAIL_PREVIEW_RENDER_PREFIX):
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", EMAIL_PREVIEW_CSP)
        elif url_path in ("/cert", "/app/cert") or url_path.startswith(
            ("/cert/", "/app/cert/", "/api/cert/")
        ):
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self'; connect-src 'self'; base-uri 'none'; "
                "frame-ancestors 'none'; form-action 'self'",
            )
        super().end_headers()

    def is_safe_cert_origin(self) -> bool:
        origin = self.headers.get("Origin")
        host = self.headers.get("Host")
        if not origin or not host:
            return False
        parsed = urllib.parse.urlsplit(origin)
        expected_scheme = "https" if self.request_is_secure() else "http"
        return (
            parsed.scheme == expected_scheme
            and parsed.netloc == host
            and parsed.path in ("", "/")
            and not parsed.query
            and not parsed.fragment
        )

    def do_GET(self) -> None:
        url_path = urllib.parse.urlsplit(self.path).path
        if url_path.startswith("/api/cert/"):
            if not self.certificate_ui_available():
                self.send_error(HTTPStatus.NOT_FOUND, "Endpoint inconnu")
                return
            if url_path == "/api/cert/status":
                self.handle_cert_status()
            elif url_path == "/api/cert/notifications":
                self.handle_notification_settings_read()
            elif url_path == "/api/cert/smtp":
                self.handle_smtp_settings_read()
            elif url_path.startswith(EMAIL_PREVIEW_RENDER_PREFIX):
                self.handle_notification_email_preview_render(url_path)
            else:
                self.send_error(HTTPStatus.NOT_FOUND, "Endpoint inconnu")
            return
        if (
            url_path in ("/cert", "/app/cert")
            or url_path.startswith(("/cert/", "/app/cert/"))
        ) and not self.certificate_ui_available():
            self.send_error(HTTPStatus.NOT_FOUND, "Page introuvable")
            return
        super().do_GET()

    def authenticated_cert_session(self) -> AdminSession | None:
        session_id = self.cert_session_id()
        session = self.cert_sessions.get(session_id) if session_id else None
        if session_id is None or session is None:
            return None
        try:
            current_revision = credentials_revision(self.cert_admin_file)
        except CredentialError:
            self.cert_sessions.revoke(session_id)
            return None
        if not hmac.compare_digest(session.credentials_revision, current_revision):
            self.cert_sessions.revoke(session_id)
            return None
        return session

    def cert_session_id(self) -> str | None:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except CookieError:
            return None
        morsel = cookie.get("fortios_cert_session")
        if morsel is None:
            return None
        return morsel.value

    def handle_cert_status(self) -> None:
        session = self.authenticated_cert_session()
        if session is None:
            self.write_json_response(
                {"authenticated": False},
                HTTPStatus.UNAUTHORIZED,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        self.write_json_response(
            {
                "authenticated": True,
                "username": session.username,
                "csrfToken": session.csrf_token,
                "hostname": self.cert_hostname,
                "canInstall": self.cert_direct_install,
                "tlsActive": self.request_is_secure(),
            },
            extra_headers={"Cache-Control": "no-store"},
        )

    def require_admin_session(self, *, csrf: bool) -> AdminSession | None:
        session = self.authenticated_cert_session()
        if session is None:
            self.write_json_response(
                {"error": "Session administrateur requise."},
                HTTPStatus.UNAUTHORIZED,
                extra_headers={"Cache-Control": "no-store"},
            )
            return None
        if csrf and not hmac.compare_digest(
            session.csrf_token, self.headers.get("X-CSRF-Token", "")
        ):
            self.write_json_response(
                {"error": "Jeton CSRF invalide."},
                HTTPStatus.FORBIDDEN,
                extra_headers={"Cache-Control": "no-store"},
            )
            return None
        return session

    def notification_settings_response(
        self, settings: fortios_notify.NotificationSettings
    ) -> dict[str, Any]:
        config = fortios_notify.load_email_config(
            settings=settings,
            settings_path=NOTIFICATION_SETTINGS_PATH,
            smtp_settings_path=SMTP_SETTINGS_PATH,
        )
        return {
            "settings": settings.to_payload(),
            "smtp": fortios_notify.smtp_public_status(config),
        }

    def handle_notification_settings_read(self) -> None:
        if self.require_admin_session(csrf=False) is None:
            return
        settings = fortios_notify.load_notification_settings(
            NOTIFICATION_SETTINGS_PATH
        )
        self.write_json_response(
            self.notification_settings_response(settings),
            extra_headers={"Cache-Control": "no-store"},
        )

    def handle_notification_settings_write(self) -> None:
        if self.require_admin_session(csrf=True) is None:
            return
        try:
            payload = self.read_json_body(max_bytes=64 * 1024)
            settings = fortios_notify.save_notification_settings(
                NOTIFICATION_SETTINGS_PATH, payload
            )
        except (TypeError, ValueError, OSError) as error:
            self.write_json_response(
                {"error": str(error)[:500]},
                HTTPStatus.BAD_REQUEST,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        self.write_json_response(
            self.notification_settings_response(settings),
            extra_headers={"Cache-Control": "no-store"},
        )

    def smtp_settings_response(self) -> dict[str, Any]:
        notification_settings = fortios_notify.load_notification_settings(
            NOTIFICATION_SETTINGS_PATH
        )
        smtp_settings, config = fortios_notify.load_smtp_snapshot(
            settings=notification_settings,
            settings_path=NOTIFICATION_SETTINGS_PATH,
            smtp_settings_path=SMTP_SETTINGS_PATH,
        )
        return {
            "smtp": fortios_notify.smtp_public_settings(smtp_settings, config)
        }

    def handle_smtp_settings_read(self) -> None:
        if self.require_admin_session(csrf=False) is None:
            return
        self.write_json_response(
            self.smtp_settings_response(),
            extra_headers={"Cache-Control": "no-store"},
        )

    def handle_smtp_settings_write(self) -> None:
        if self.require_admin_session(csrf=True) is None:
            return
        try:
            payload = self.read_json_body(max_bytes=64 * 1024)
            password = payload.pop("password", None)
            if password is not None and not isinstance(password, str):
                raise TypeError("Le mot de passe SMTP doit être une chaîne.")
            fortios_notify.save_smtp_settings(
                SMTP_SETTINGS_PATH,
                payload,
                password=password,
            )
            response = self.smtp_settings_response()
        except (TypeError, ValueError, OSError) as error:
            self.write_json_response(
                {"error": str(error)[:500]},
                HTTPStatus.BAD_REQUEST,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        self.write_json_response(
            response,
            extra_headers={"Cache-Control": "no-store"},
        )

    def handle_smtp_password_delete(self) -> None:
        if self.require_admin_session(csrf=True) is None:
            return
        try:
            fortios_notify.delete_smtp_password(SMTP_SETTINGS_PATH)
            response = self.smtp_settings_response()
        except OSError as error:
            self.write_json_response(
                {"error": str(error)[:500]},
                HTTPStatus.BAD_REQUEST,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        self.write_json_response(
            response,
            extra_headers={"Cache-Control": "no-store"},
        )

    @staticmethod
    def compose_notification_email_preview(
        payload: dict[str, Any], *, app_url: str, run_timestamp: str
    ) -> dict[str, str]:
        if set(payload) != {"scenario", "appearance"}:
            raise ValueError("Paramètres d'aperçu invalides.")
        return fortios_notify.compose_email_preview(
            payload["scenario"],
            app_url=app_url or "/app/",
            run_timestamp=run_timestamp,
            appearance=fortios_notify.validate_email_appearance(payload["appearance"]),
        )

    def handle_notification_email_preview(self) -> None:
        if self.require_admin_session(csrf=True) is None:
            return
        session_id = self.cert_session_id()
        if session_id is None:
            self.write_json_response(
                {"error": "Session administrateur requise."},
                HTTPStatus.UNAUTHORIZED,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        if not self.cert_preview_limiter.try_record(session_id):
            self.write_json_response(
                {"error": "Limite de trente aperçus par minute atteinte."},
                HTTPStatus.TOO_MANY_REQUESTS,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        try:
            payload = self.read_json_body(max_bytes=16 * 1024)
            smtp_settings = fortios_notify.load_smtp_settings(SMTP_SETTINGS_PATH)
            preview = self.compose_notification_email_preview(
                payload,
                app_url=smtp_settings.app_url,
                run_timestamp=utc_now(),
            )
        except (TypeError, ValueError, OSError) as error:
            self.write_json_response(
                {"error": str(error)[:500]},
                HTTPStatus.BAD_REQUEST,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        html = preview.pop("html")
        token = self.email_previews.issue(session_id, html)
        preview["renderUrl"] = f"{EMAIL_PREVIEW_RENDER_PREFIX}{token}"
        self.write_json_response(preview, extra_headers={"Cache-Control": "no-store"})

    def handle_notification_email_preview_render(self, url_path: str) -> None:
        if self.require_admin_session(csrf=False) is None:
            return
        session_id = self.cert_session_id()
        token = url_path.removeprefix(EMAIL_PREVIEW_RENDER_PREFIX)
        if session_id is None or not token or "/" in token:
            self.send_error(HTTPStatus.NOT_FOUND, "Aperçu introuvable")
            return
        html = self.email_previews.get(token, session_id)
        if html is None:
            self.send_error(HTTPStatus.NOT_FOUND, "Aperçu introuvable")
            return
        body = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_notification_email_preview_send(self) -> None:
        if self.require_admin_session(csrf=True) is None:
            return
        session_id = self.cert_session_id()
        if session_id is None or not self.cert_test_email_limiter.try_record(session_id):
            self.write_json_response(
                {"error": "Limite de trois emails de test par minute atteinte."},
                HTTPStatus.TOO_MANY_REQUESTS,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        try:
            payload = self.read_json_body(max_bytes=16 * 1024)
            if set(payload) != {"scenario", "appearance", "runTimestamp", "recipient"}:
                raise ValueError("Paramètres d'envoi de l'aperçu invalides.")
            recipient = payload["recipient"]
            if not isinstance(recipient, str):
                raise TypeError("Destinataire de test invalide.")
            _smtp_settings, config = fortios_notify.load_smtp_preview_snapshot(
                smtp_settings_path=SMTP_SETTINGS_PATH,
            )
            preview = self.compose_notification_email_preview(
                {"scenario": payload["scenario"], "appearance": payload["appearance"]},
                app_url=config.app_url,
                run_timestamp=payload["runTimestamp"],
            )
            result = fortios_notify.send_email_preview_result(
                config,
                preview,
                recipient=recipient,
            )
        except (TypeError, ValueError, OSError) as error:
            self.write_json_response(
                {"error": str(error)[:500]},
                HTTPStatus.BAD_REQUEST,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        self.write_json_response(
            {
                "sent": result.sent,
                "message": "Aperçu email envoyé." if result.sent else result.message,
                "checks": list(result.checks),
                "summary": {
                    "recipient": recipient.strip(),
                    "subject": preview["subject"],
                    "scenario": preview["scenario"],
                },
            },
            HTTPStatus.OK if result.sent else HTTPStatus.SERVICE_UNAVAILABLE,
            extra_headers={"Cache-Control": "no-store"},
        )

    def handle_notification_test_email(self) -> None:
        if self.require_admin_session(csrf=True) is None:
            return
        session_id = self.cert_session_id()
        if session_id is None or not self.cert_test_email_limiter.try_record(session_id):
            self.write_json_response(
                {"error": "Limite de trois emails de test par minute atteinte."},
                HTTPStatus.TOO_MANY_REQUESTS,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        try:
            payload = self.read_json_body(max_bytes=4096)
            if not isinstance(payload, dict) or set(payload) != {"recipient"}:
                raise ValueError("Destinataire de test requis.")
            recipient = payload["recipient"]
            if not isinstance(recipient, str):
                raise TypeError("Destinataire de test invalide.")
            settings = fortios_notify.load_notification_settings(
                NOTIFICATION_SETTINGS_PATH
            )
            smtp_settings, config = fortios_notify.load_smtp_snapshot(
                settings=settings,
                settings_path=NOTIFICATION_SETTINGS_PATH,
                smtp_settings_path=SMTP_SETTINGS_PATH,
            )
            result = fortios_notify.send_test_email_result(
                config,
                recipient=recipient,
                appearance=smtp_settings.email_appearance,
            )
        except (TypeError, ValueError, OSError) as error:
            self.write_json_response(
                {"error": str(error)[:500]},
                HTTPStatus.BAD_REQUEST,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        security_labels = {
            "starttls": "STARTTLS",
            "tls": "TLS implicite",
            "none": "Sans chiffrement explicitement autorisé",
        }
        summary = {
            "smtp": f"{config.smtp_host}:{config.smtp_port}",
            "security": security_labels.get(
                config.smtp_security, "Configuration inconnue"
            ),
            "from": config.smtp_from,
            "recipient": recipient.strip(),
        }
        if not result.sent and result.message == "Destinataire de test invalide.":
            result = fortios_notify.SmtpResult(
                False, "Destinataire de test invalide."
            )
        self.write_json_response(
            {
                "sent": result.sent,
                "message": result.message,
                "checks": list(result.checks),
                "summary": summary,
            },
            HTTPStatus.OK if result.sent else HTTPStatus.SERVICE_UNAVAILABLE,
            extra_headers={"Cache-Control": "no-store"},
        )

    def translate_path(self, path: str) -> str:
        # Checking the raw request string against an allowed prefix before decoding/normalizing
        # is not enough: "/data/%2e%2e/scripts/fortios_server.py" starts with "/data/" as a
        # literal string, but percent-decodes and normalizes (posixpath.normpath collapses
        # "data/.." against the preceding segment) to a path outside data/ entirely. Both
        # branches below resolve first, then check where the request actually landed on disk —
        # the only check that can't be fooled by encoding — before ever serving it.
        url_path = urllib.parse.urlsplit(path).path
        if url_path == "/cert" or url_path.startswith("/cert/"):
            relative = urllib.parse.unquote(
                url_path[len("/cert/") :] if url_path != "/cert" else "",
            )
            candidate = (
                (ALLOWED_STATIC_DIR_CERT / relative).resolve()
                if relative
                else ALLOWED_STATIC_DIR_CERT
            )
            if candidate == ALLOWED_STATIC_DIR_CERT or candidate.is_relative_to(
                ALLOWED_STATIC_DIR_CERT,
            ):
                return str(candidate)
            return str(ROOT / "__not_served__")
        if url_path == "/data" or url_path.startswith("/data/"):
            # Resolved against DATA_DIR (overridable for isolated E2E tests), not against
            # self.directory/ROOT like the parent class would — otherwise FORTIOS_TEST_DATA_DIR
            # would have no effect on what gets served here.
            relative = urllib.parse.unquote(
                url_path[len("/data/") :] if url_path != "/data" else ""
            )
            name = Path(relative).name
            private_prefixes = (
                "notification-settings.json",
                ".notification-settings.json",
                "fortios-notify-history.json",
                ".fortios-notify-history.json",
                "smtp-settings.json",
                ".smtp-settings.json",
                "smtp-password",
                ".smtp-password",
            )
            if name.startswith(private_prefixes):
                return str(ROOT / "__not_served__")
            candidate = (
                (DATA_DIR / relative).resolve() if relative else DATA_DIR.resolve()
            )
            if candidate != ALLOWED_STATIC_DIR_DATA and candidate.is_relative_to(
                ALLOWED_STATIC_DIR_DATA
            ):
                return str(candidate)
            return str(ROOT / "__not_served__")

        resolved = Path(super().translate_path(path)).resolve()
        if resolved == ALLOWED_STATIC_DIR_APP or resolved.is_relative_to(
            ALLOWED_STATIC_DIR_APP
        ):
            return str(resolved)
        return str(ROOT / "__not_served__")

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
        if self.path.startswith("/api/cert/"):
            if not self.certificate_ui_available():
                self.send_error(HTTPStatus.NOT_FOUND, "Endpoint inconnu")
                return
            if not self.is_safe_cert_origin():
                self.send_error(HTTPStatus.FORBIDDEN, "Origin invalide")
                return
            if self.path == "/api/cert/login":
                self.handle_cert_login()
            elif self.path == "/api/cert/logout":
                self.handle_cert_logout()
            elif self.path == "/api/cert/notifications":
                self.handle_notification_settings_write()
            elif self.path == "/api/cert/smtp":
                self.handle_smtp_settings_write()
            elif self.path == "/api/cert/notifications/test":
                self.handle_notification_test_email()
            elif self.path == "/api/cert/notifications/preview":
                self.handle_notification_email_preview()
            elif self.path == "/api/cert/notifications/send-preview":
                self.handle_notification_email_preview_send()
            elif self.path in ("/api/cert/validate", "/api/cert/install"):
                self.handle_cert_upload(install=self.path.endswith("/install"))
            else:
                self.send_error(HTTPStatus.NOT_FOUND, "Endpoint inconnu")
            return
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

    def handle_cert_login(self) -> None:
        client = self.cert_client_identity()
        authenticated = False
        reserved = False
        try:
            payload = self.read_json_body(max_bytes=16 * 1024)
            username_value = payload.get("username")
            password_value = payload.get("password")
            if not isinstance(username_value, str) or not isinstance(
                password_value, str
            ):
                raise TypeError("Identifiants invalides.")
            username = username_value
            password = password_value
            if (
                len(username) > 64
                or len(password.encode("utf-8")) > MAX_PASSWORD_LENGTH
            ):
                raise ValueError("Identifiants invalides.")
            if not self.cert_login_limiter.try_begin(client):
                self.write_json_response(
                    {"error": "Trop de tentatives. Réessaie dans quelques minutes."},
                    HTTPStatus.TOO_MANY_REQUESTS,
                    extra_headers={"Cache-Control": "no-store", "Retry-After": "10"},
                )
                return
            reserved = True
            with credential_lock(self.cert_admin_file, exclusive=False):
                revision = authenticate_credentials(
                    self.cert_admin_file, username, password
                )
                if revision is None:
                    self.write_json_response(
                        {"error": "Identifiant ou mot de passe invalide."},
                        HTTPStatus.UNAUTHORIZED,
                        extra_headers={"Cache-Control": "no-store"},
                    )
                    return
                authenticated = True
                session_id, session = self.cert_sessions.create(username, revision)
            attributes = [
                f"fortios_cert_session={session_id}",
                "Path=/api/cert",
                "HttpOnly",
                "SameSite=Strict",
                f"Max-Age={self.cert_sessions.ttl_seconds}",
            ]
            if self.request_is_secure():
                attributes.append("Secure")
            self.write_json_response(
                {"authenticated": True, "csrfToken": session.csrf_token},
                extra_headers={
                    "Cache-Control": "no-store",
                    "Set-Cookie": "; ".join(attributes),
                },
            )
        except (CredentialError, ValueError, OSError) as error:
            self.write_json_response(
                {"error": str(error)},
                HTTPStatus.BAD_REQUEST,
                extra_headers={"Cache-Control": "no-store"},
            )
        finally:
            if reserved:
                self.cert_login_limiter.finish(client, success=authenticated)

    def handle_cert_upload(self, *, install: bool) -> None:
        session_id = self.cert_session_id()
        session = self.authenticated_cert_session()
        if session_id is None or session is None:
            self.write_json_response(
                {"error": "Session administrateur requise."},
                HTTPStatus.UNAUTHORIZED,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        csrf_token = self.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(session.csrf_token, csrf_token):
            self.write_json_response(
                {"error": "Jeton CSRF invalide."},
                HTTPStatus.FORBIDDEN,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        if not self.cert_hostname:
            self.write_json_response(
                {"error": "FORTIOS_TLS_HOSTNAME doit être configuré."},
                HTTPStatus.SERVICE_UNAVAILABLE,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        if install and not self.cert_direct_install:
            self.write_json_response(
                {"error": "L'activation directe n'est pas autorisée dans ce mode."},
                HTTPStatus.FORBIDDEN,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        try:
            payload = self.read_json_body(max_bytes=MAX_CERT_UPLOAD_BODY_BYTES)
            if install:
                with credential_lock(self.cert_admin_file, exclusive=False):
                    current_session = self.authenticated_cert_session()
                    if current_session is None or not hmac.compare_digest(
                        current_session.csrf_token,
                        csrf_token,
                    ):
                        self.write_json_response(
                            {"error": "Session administrateur expirée ou révoquée."},
                            HTTPStatus.UNAUTHORIZED,
                            extra_headers={"Cache-Control": "no-store"},
                        )
                        return
                    validation_token = payload.get("validationToken")
                    if not isinstance(
                        validation_token, str
                    ) or not self.cert_validation_tickets.consume(
                        validation_token,
                        session_id,
                        payload,
                    ):
                        self.write_json_response(
                            {
                                "error": "Prévalidation expirée ou non concordante. Valide à nouveau le certificat."
                            },
                            HTTPStatus.CONFLICT,
                            extra_headers={"Cache-Control": "no-store"},
                        )
                        return
                    summary = activate_uploaded_certificate(
                        payload,
                        self.cert_hostname,
                        self.cert_output_dir,
                        helper_socket=self.cert_helper_socket,
                        credentials_revision=current_session.credentials_revision,
                    )
                response = {
                    "installed": True,
                    "restartRequired": self.tls_active and self.cert_helper_socket is None,
                    **summary,
                }
            else:
                summary = validate_uploaded_certificate(payload, self.cert_hostname)
                validation_token = self.cert_validation_tickets.issue(
                    session_id, payload
                )
                response = {
                    "valid": True,
                    "validationToken": validation_token,
                    **summary,
                }
            self.write_json_response(
                response,
                extra_headers={"Cache-Control": "no-store"},
            )
        except (
            CredentialError,
            HelperError,
            certctl.CertificateError,
            ValueError,
            OSError,
        ) as error:
            # This pattern redacts a temporary path from an error; it does not create or access one.
            message = re.sub(r"/tmp/fortios-[^\s:]+", "<upload>", str(error))  # nosec B108
            self.write_json_response(
                {"error": message[:1000]},
                HTTPStatus.BAD_REQUEST,
                extra_headers={"Cache-Control": "no-store"},
            )

    def handle_cert_logout(self) -> None:
        session_id = self.cert_session_id()
        session = self.cert_sessions.get(session_id) if session_id else None
        csrf_token = self.headers.get("X-CSRF-Token", "")
        if (
            session_id is None
            or session is None
            or not hmac.compare_digest(session.csrf_token, csrf_token)
        ):
            self.write_json_response(
                {"error": "Session ou jeton CSRF invalide."},
                HTTPStatus.FORBIDDEN,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        self.cert_sessions.revoke(session_id)
        attributes = [
            "fortios_cert_session=",
            "Path=/api/cert",
            "HttpOnly",
            "SameSite=Strict",
            "Max-Age=0",
        ]
        if self.request_is_secure():
            attributes.append("Secure")
        self.write_json_response(
            {"authenticated": False},
            extra_headers={
                "Cache-Control": "no-store",
                "Set-Cookie": "; ".join(attributes),
            },
        )

    def do_PUT(self) -> None:
        if not self.is_safe_origin():
            self.send_error(HTTPStatus.FORBIDDEN, "Origin invalide")
            return
        if self.path.startswith(ADVISORIES_PREFIX) and len(self.path) > len(
            ADVISORIES_PREFIX
        ):
            self.handle_update_advisory(self.path[len(ADVISORIES_PREFIX) :])
        elif self.path.startswith(COMPATIBILITIES_PREFIX) and len(self.path) > len(
            COMPATIBILITIES_PREFIX
        ):
            self.handle_update_compatibility(self.path[len(COMPATIBILITIES_PREFIX) :])
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint inconnu")

    def do_DELETE(self) -> None:
        if not self.is_safe_origin():
            self.send_error(HTTPStatus.FORBIDDEN, "Origin invalide")
            return
        if self.path == "/api/cert/smtp/password":
            self.handle_smtp_password_delete()
        elif self.path.startswith(ADVISORIES_PREFIX) and len(self.path) > len(
            ADVISORIES_PREFIX
        ):
            self.handle_delete_advisory(self.path[len(ADVISORIES_PREFIX) :])
        elif self.path.startswith(COMPATIBILITIES_PREFIX) and len(self.path) > len(
            COMPATIBILITIES_PREFIX
        ):
            self.handle_delete_compatibility(self.path[len(COMPATIBILITIES_PREFIX) :])
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint inconnu")

    def handle_official_path(self) -> None:
        try:
            payload = self.read_json_body()
            request = parse_official_path_request(payload)
            if not OFFICIAL_PATH_SEMAPHORE.acquire(blocking=False):
                self.write_json_response(
                    {"error": OFFICIAL_PATH_BUSY_MESSAGE},
                    HTTPStatus.TOO_MANY_REQUESTS,
                    extra_headers={"Retry-After": "1"},
                )
                return
            try:
                result = fetch_official_upgrade_path(request, self.timeout)
            finally:
                OFFICIAL_PATH_SEMAPHORE.release()
            if not result:
                self.write_json_response(
                    {
                        "error": "Fortinet n'a pas retourné de chemin pour cette requête."
                    },
                    HTTPStatus.NOT_FOUND,
                )
                return

            official_path, firmwares = result
            with cross_process_lock(DATA_PATH):
                state = normalize_state(
                    read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {})
                )
                for firmware in firmwares:
                    upsert_firmware(state, firmware)
                upsert_path(state, official_path)
                record_search_history(
                    state,
                    request.product,
                    request.model,
                    request.from_version,
                    request.to_version,
                    official_path.hops,
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
        except (TypeError, ValueError) as error:
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        except KeyError as error:
            self.write_json_response(
                {"error": f"Champ manquant : {error.args[0]}"}, HTTPStatus.BAD_REQUEST
            )
        except Exception:  # noqa: BLE001 - log details, return only a safe client message.
            self.write_internal_error("handle_official_path", HTTPStatus.BAD_GATEWAY)

    def handle_create_advisory(self) -> None:
        try:
            payload = self.read_json_body()
            fields = parse_advisory_fields(payload)
            advisory: dict[str, Any] = {
                "id": f"adv-{slugify(fields['title'])}-{secrets.token_hex(4)}",
                "createdAt": utc_now(),
                **fields,
            }

            with cross_process_lock(DATA_PATH):
                state = normalize_state(
                    read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {})
                )
                upsert_advisory(state, advisory)
                state["generatedAt"] = utc_now()
                write_json(DATA_PATH, state)

            self.write_json_response({"state": state, "advisory": advisory})
        except (TypeError, ValueError) as error:
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        except Exception:  # noqa: BLE001 - log details, return only a safe client message.
            self.write_internal_error("handle_create_advisory", HTTPStatus.BAD_GATEWAY)

    def handle_update_advisory(self, raw_id: str) -> None:
        try:
            advisory_id = urllib.parse.unquote(raw_id)
            with cross_process_lock(DATA_PATH):
                state = normalize_state(
                    read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {})
                )
                existing = next(
                    (
                        item
                        for item in state["advisories"]
                        if item.get("id") == advisory_id
                    ),
                    None,
                )
                if existing is None:
                    self.write_json_response(
                        {"error": "Alerte introuvable."}, HTTPStatus.NOT_FOUND
                    )
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
        except (TypeError, ValueError) as error:
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        except Exception:  # noqa: BLE001 - log details, return only a safe client message.
            self.write_internal_error("handle_update_advisory", HTTPStatus.BAD_GATEWAY)

    def handle_delete_advisory(self, raw_id: str) -> None:
        try:
            advisory_id = urllib.parse.unquote(raw_id)
            with cross_process_lock(DATA_PATH):
                state = normalize_state(
                    read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {})
                )
                target = next(
                    (
                        item
                        for item in state["advisories"]
                        if item.get("id") == advisory_id
                    ),
                    None,
                )
                if target is None:
                    self.write_json_response(
                        {"error": "Alerte introuvable."}, HTTPStatus.NOT_FOUND
                    )
                    return

                state["advisories"] = [
                    item
                    for item in state["advisories"]
                    if item.get("id") != advisory_id
                ]
                state["generatedAt"] = utc_now()
                write_json(DATA_PATH, state)
                prune_unreferenced_images(
                    referenced_image_filenames(target.get("description", "")), state
                )

            self.write_json_response({"state": state})
        except Exception:  # noqa: BLE001 - log details, return only a safe client message.
            self.write_internal_error("handle_delete_advisory", HTTPStatus.BAD_GATEWAY)

    def handle_create_compatibility(self) -> None:
        try:
            payload = self.read_json_body()
            fields = parse_compatibility_fields(payload)
            item: dict[str, Any] = {
                "id": f"compat-{slugify(fields['emsVersion'])}-{secrets.token_hex(4)}",
                "createdAt": utc_now(),
                **fields,
            }

            with cross_process_lock(DATA_PATH):
                state = normalize_state(
                    read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {})
                )
                upsert_compatibility(state, item)
                state["generatedAt"] = utc_now()
                write_json(DATA_PATH, state)

            self.write_json_response({"state": state, "compatibility": item})
        except (TypeError, ValueError) as error:
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        except Exception:  # noqa: BLE001 - log details, return only a safe client message.
            self.write_internal_error("handle_create_compatibility", HTTPStatus.BAD_GATEWAY)

    def handle_update_compatibility(self, raw_id: str) -> None:
        try:
            item_id = urllib.parse.unquote(raw_id)
            with cross_process_lock(DATA_PATH):
                state = normalize_state(
                    read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {})
                )
                existing = next(
                    (
                        item
                        for item in state["compatibilities"]
                        if item.get("id") == item_id
                    ),
                    None,
                )
                if existing is None:
                    self.write_json_response(
                        {"error": "Combinaison introuvable."}, HTTPStatus.NOT_FOUND
                    )
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
        except (TypeError, ValueError) as error:
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        except Exception:  # noqa: BLE001 - log details, return only a safe client message.
            self.write_internal_error("handle_update_compatibility", HTTPStatus.BAD_GATEWAY)

    def handle_delete_compatibility(self, raw_id: str) -> None:
        try:
            item_id = urllib.parse.unquote(raw_id)
            with cross_process_lock(DATA_PATH):
                state = normalize_state(
                    read_json(DATA_PATH, None) or read_json(SAMPLE_PATH, {})
                )
                remaining = [
                    item
                    for item in state["compatibilities"]
                    if item.get("id") != item_id
                ]
                if len(remaining) == len(state["compatibilities"]):
                    self.write_json_response(
                        {"error": "Combinaison introuvable."}, HTTPStatus.NOT_FOUND
                    )
                    return

                state["compatibilities"] = remaining
                state["generatedAt"] = utc_now()
                write_json(DATA_PATH, state)

            self.write_json_response({"state": state})
        except Exception:  # noqa: BLE001 - log details, return only a safe client message.
            self.write_internal_error("handle_delete_compatibility", HTTPStatus.BAD_GATEWAY)

    def handle_upload_image(self) -> None:
        try:
            payload = self.read_json_body(max_bytes=MAX_IMAGE_UPLOAD_BODY_BYTES)
            content_type = str(payload.get("contentType") or "").strip().lower()
            data_base64 = str(payload.get("dataBase64") or "").strip()
            if content_type not in IMAGE_EXTENSIONS:
                raise ValueError(
                    f"Format d'image non supporté : {content_type or 'inconnu'}"
                )
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
        except (TypeError, ValueError) as error:
            self.write_json_response({"error": str(error)}, HTTPStatus.BAD_REQUEST)
        except Exception:  # noqa: BLE001 - log details, return only a safe client message.
            self.write_internal_error("handle_upload_image", HTTPStatus.BAD_GATEWAY)

    def read_json_body(self, max_bytes: int = MAX_JSON_BODY_BYTES) -> dict[str, Any]:
        # Requiring the exact Content-Type also closes the "CORS-simple request" loophole a
        # cross-origin fetch() could otherwise use (e.g. text/plain) to reach this endpoint
        # without a preflight — paired with is_safe_origin() above.
        content_type = (
            (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        )
        if content_type != "application/json":
            self.close_connection = True
            raise ValueError("Content-Type doit être application/json.")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            self.close_connection = True
            raise ValueError("Content-Length invalide.") from error
        if length <= 0:
            raise ValueError("Corps JSON manquant.")
        if length > max_bytes:
            self.close_connection = True
            raise ValueError(
                f"Corps de requête trop volumineux ({length} octets, max {max_bytes})."
            )
        raw = self.rfile.read(length)
        if len(raw) != length:
            self.close_connection = True
            raise ValueError("Corps JSON incomplet.")
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise TypeError("Le corps JSON doit être un objet.")
        return payload

    def write_internal_error(
        self,
        context: str,
        status: HTTPStatus = HTTPStatus.INTERNAL_SERVER_ERROR,
    ) -> None:
        self.log_exception(context)
        self.write_json_response({"error": INTERNAL_ERROR_MESSAGE}, status)

    def log_exception(self, context: str) -> None:
        sys.stderr.write(
            f"{self.log_date_time_string()} - unhandled error in {context}\n"
        )
        traceback.print_exc(file=sys.stderr)

    def write_json_response(
        self,
        payload: dict[str, Any],
        status: HTTPStatus = HTTPStatus.OK,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write(f"{self.log_date_time_string()} - {format % args}\n")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Serve FortiOS Upgrade Intelligence.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--tls-cert", default=os.environ.get("FORTIOS_TLS_CERT"))
    parser.add_argument("--tls-key", default=os.environ.get("FORTIOS_TLS_KEY"))
    args = parser.parse_args(argv)
    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("--tls-cert et --tls-key doivent être fournis ensemble")

    return args


def resolve_tls_pair(certificate: Path, private_key: Path) -> tuple[Path, Path]:
    """Resolve a shared version symlink once so a renewal cannot mix generations."""
    if certificate.parent == private_key.parent:
        parent = certificate.parent.resolve(strict=True)
        return parent / certificate.name, parent / private_key.name
    return certificate, private_key


def parse_trusted_proxy_networks(
    value: str,
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in value.split(","):
        candidate = item.strip()
        if candidate:
            networks.append(ipaddress.ip_network(candidate, strict=True))
    return tuple(networks)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    tls_active = bool(args.tls_cert)
    allow_insecure_localhost = (
        os.environ.get("FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST") == "1"
    )
    try:
        cert_trusted_proxy_networks = parse_trusted_proxy_networks(
            os.environ.get("FORTIOS_CERT_TRUSTED_PROXY_CIDRS", "")
        )
    except ValueError as error:
        print(f"FORTIOS_CERT_TRUSTED_PROXY_CIDRS invalide: {error}", file=sys.stderr)
        return 78
    cert_admin_file = Path(
        os.environ.get("FORTIOS_CERT_ADMIN_FILE", str(DEFAULT_CREDENTIALS))
    )
    cert_sessions = SessionStore()
    cert_login_limiter = LoginRateLimiter()
    cert_test_email_limiter = ActionRateLimiter()
    cert_preview_limiter = ActionRateLimiter(max_actions=30)
    cert_validation_tickets = ValidationTicketStore()
    email_previews = EmailPreviewStore()
    cert_hostname = os.environ.get("FORTIOS_TLS_HOSTNAME", "").strip()
    cert_output_dir = Path(
        os.environ.get("FORTIOS_CERT_OUTPUT_DIR", "/opt/fortios/certificates/active"),
    )
    cert_helper_socket_value = os.environ.get("FORTIOS_CERT_HELPER_SOCKET", "").strip()
    cert_helper_socket = Path(cert_helper_socket_value) if cert_helper_socket_value else None
    cert_direct_install = (
        os.environ.get("FORTIOS_CERT_DIRECT_INSTALL") == "1"
        or cert_helper_socket is not None
    )

    def handler(*handler_args: Any, **handler_kwargs: Any) -> FortiosHandler:
        return FortiosHandler(
            *handler_args,
            timeout=args.timeout,
            tls_active=tls_active,
            allow_insecure_localhost=allow_insecure_localhost,
            cert_trusted_proxy_networks=cert_trusted_proxy_networks,
            cert_admin_file=cert_admin_file,
            cert_sessions=cert_sessions,
            cert_hostname=cert_hostname,
            cert_output_dir=cert_output_dir,
            cert_direct_install=cert_direct_install,
            cert_helper_socket=cert_helper_socket,
            cert_login_limiter=cert_login_limiter,
            cert_test_email_limiter=cert_test_email_limiter,
            cert_preview_limiter=cert_preview_limiter,
            cert_validation_tickets=cert_validation_tickets,
            email_previews=email_previews,
            **handler_kwargs,
        )

    server = ThreadingHTTPServer((args.host, args.port), handler)
    scheme = "http"
    if args.tls_cert:
        certificate_arg = Path(args.tls_cert)
        key_arg = Path(args.tls_key)
        with managed_pair_lock(certificate_arg, key_arg):
            tls_certificate, tls_key = resolve_tls_pair(certificate_arg, key_arg)
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
            tls_context.load_cert_chain(tls_certificate, tls_key)
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    print(f"FortiOS Upgrade Intelligence: {scheme}://{args.host}:{args.port}/app/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt du serveur.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
