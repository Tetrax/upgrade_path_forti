"""Session primitives for the private certificate administration interface."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
import shutil
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import certctl

MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024
MAX_PRIVATE_KEY_BYTES = 8 * 1024 * 1024
MAX_CHAIN_BYTES = 16 * 1024 * 1024
MAX_PASSWORD_BYTES = 1024


@dataclass(frozen=True)
class AdminSession:
    username: str
    csrf_token: str
    expires_at: float
    credentials_revision: str = ""


class SessionStore:
    def __init__(self, ttl_seconds: int = 30 * 60, maximum_sessions: int = 128) -> None:
        if min(ttl_seconds, maximum_sessions) <= 0:
            raise ValueError(
                "Les limites de session doivent être strictement positives."
            )
        self.ttl_seconds = ttl_seconds
        self.maximum_sessions = maximum_sessions
        self._sessions: dict[str, AdminSession] = {}
        self._lock = threading.Lock()

    def create(
        self, username: str, credentials_revision: str = ""
    ) -> tuple[str, AdminSession]:
        now = time.monotonic()
        session_id = secrets.token_urlsafe(32)
        session = AdminSession(
            username=username,
            csrf_token=secrets.token_urlsafe(32),
            expires_at=now + self.ttl_seconds,
            credentials_revision=credentials_revision,
        )
        with self._lock:
            self._prune(now)
            while len(self._sessions) >= self.maximum_sessions:
                oldest = min(
                    self._sessions,
                    key=lambda key: self._sessions[key].expires_at,
                )
                self._sessions.pop(oldest, None)
            self._sessions[session_id] = session
        return session_id, session

    def get(self, session_id: str) -> AdminSession | None:
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            return self._sessions.get(session_id)

    def revoke(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def _prune(self, now: float) -> None:
        expired = [
            key for key, session in self._sessions.items() if session.expires_at <= now
        ]
        for key in expired:
            self._sessions.pop(key, None)


class LoginRateLimiter:
    def __init__(
        self,
        max_failures: int = 5,
        window_seconds: int = 10 * 60,
        maximum_clients: int = 1024,
        maximum_concurrent: int = 2,
    ) -> None:
        if min(max_failures, window_seconds, maximum_clients, maximum_concurrent) <= 0:
            raise ValueError(
                "Les limites de connexion doivent être strictement positives."
            )
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.maximum_clients = maximum_clients
        self.maximum_concurrent = maximum_concurrent
        self._failures: dict[str, list[float]] = {}
        self._inflight: dict[str, int] = {}
        self._total_inflight = 0
        self._lock = threading.Lock()

    def _recent(self, client: str, now: float) -> list[float]:
        cutoff = now - self.window_seconds
        recent = [
            attempt for attempt in self._failures.get(client, []) if attempt > cutoff
        ]
        if recent:
            self._failures[client] = recent
        else:
            self._failures.pop(client, None)
        return recent

    def _prune_all(self, now: float) -> None:
        for client in list(self._failures):
            self._recent(client, now)

    def _make_room(self, client: str) -> bool:
        if client in self._failures or len(self._failures) < self.maximum_clients:
            return True
        candidates = [key for key in self._failures if not self._inflight.get(key)]
        if not candidates:
            return False
        oldest = min(candidates, key=lambda key: self._failures[key][-1])
        self._failures.pop(oldest, None)
        return True

    def try_begin(self, client: str) -> bool:
        """Atomically reserve one expensive credential-verification slot."""
        now = time.monotonic()
        with self._lock:
            self._prune_all(now)
            client_inflight = self._inflight.get(client, 0)
            if (
                self._total_inflight >= self.maximum_concurrent
                or len(self._failures.get(client, [])) + client_inflight
                >= self.max_failures
                or not self._make_room(client)
            ):
                return False
            self._inflight[client] = client_inflight + 1
            self._total_inflight += 1
            return True

    def finish(self, client: str, *, success: bool) -> None:
        now = time.monotonic()
        with self._lock:
            inflight = self._inflight.get(client, 0)
            if inflight:
                self._total_inflight -= 1
                if inflight == 1:
                    self._inflight.pop(client, None)
                else:
                    self._inflight[client] = inflight - 1
            if success:
                self._failures.pop(client, None)
                return
            recent = self._recent(client, now)
            if self._make_room(client):
                recent.append(now)
                self._failures[client] = recent

    def blocked(self, client: str) -> bool:
        now = time.monotonic()
        with self._lock:
            self._prune_all(now)
            return (
                len(self._failures.get(client, [])) + self._inflight.get(client, 0)
                >= self.max_failures
            )

    def record_failure(self, client: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._prune_all(now)
            recent = self._recent(client, now)
            if self._make_room(client):
                recent.append(now)
                self._failures[client] = recent

    def record_success(self, client: str) -> None:
        with self._lock:
            self._failures.pop(client, None)


class ActionRateLimiter:
    """Bound a sensitive authenticated action per session and time window."""

    def __init__(
        self,
        max_actions: int = 3,
        window_seconds: int = 60,
        maximum_sessions: int = 1024,
    ) -> None:
        if min(max_actions, window_seconds, maximum_sessions) <= 0:
            raise ValueError("Les limites d'action doivent être strictement positives.")
        self.max_actions = max_actions
        self.window_seconds = window_seconds
        self.maximum_sessions = maximum_sessions
        self._actions: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def try_record(self, session_id: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            for key in list(self._actions):
                recent = [value for value in self._actions[key] if value > cutoff]
                if recent:
                    self._actions[key] = recent
                else:
                    self._actions.pop(key, None)
            if session_id not in self._actions and len(self._actions) >= self.maximum_sessions:
                oldest = min(
                    self._actions,
                    key=lambda key: self._actions[key][-1],
                )
                self._actions.pop(oldest, None)
            recent = self._actions.setdefault(session_id, [])
            if len(recent) >= self.max_actions:
                return False
            recent.append(now)
            return True


@dataclass(frozen=True)
class ValidationTicket:
    session_id: str
    payload_digest: bytes
    expires_at: float


class ValidationTicketStore:
    def __init__(self, ttl_seconds: int = 10 * 60, maximum: int = 64) -> None:
        self.ttl_seconds = ttl_seconds
        self.maximum = maximum
        self._tickets: dict[str, ValidationTicket] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _digest(payload: dict[str, Any]) -> bytes:
        normalized = {
            key: value for key, value in payload.items() if key != "validationToken"
        }
        encoded = json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).digest()

    def issue(self, session_id: str, payload: dict[str, Any]) -> str:
        now = time.monotonic()
        ticket_id = secrets.token_urlsafe(32)
        ticket = ValidationTicket(
            session_id=session_id,
            payload_digest=self._digest(payload),
            expires_at=now + self.ttl_seconds,
        )
        with self._lock:
            self._prune(now)
            while len(self._tickets) >= self.maximum:
                oldest = min(
                    self._tickets, key=lambda key: self._tickets[key].expires_at
                )
                self._tickets.pop(oldest, None)
            self._tickets[ticket_id] = ticket
        return ticket_id

    def consume(self, ticket_id: str, session_id: str, payload: dict[str, Any]) -> bool:
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            ticket = self._tickets.get(ticket_id)
            if ticket is None:
                return False
            if ticket.session_id != session_id or not hmac.compare_digest(
                ticket.payload_digest,
                self._digest(payload),
            ):
                return False
            self._tickets.pop(ticket_id, None)
            return True

    def _prune(self, now: float) -> None:
        expired = [
            key for key, ticket in self._tickets.items() if ticket.expires_at <= now
        ]
        for key in expired:
            self._tickets.pop(key, None)


@dataclass(frozen=True)
class EmailPreviewDocument:
    session_id: str
    html: str
    expires_at: float


class EmailPreviewStore:
    """Short-lived, session-bound email HTML kept only in process memory."""

    def __init__(self, ttl_seconds: int = 5 * 60, maximum: int = 128) -> None:
        if min(ttl_seconds, maximum) <= 0:
            raise ValueError("Les limites d'aperçu doivent être strictement positives.")
        self.ttl_seconds = ttl_seconds
        self.maximum = maximum
        self._documents: dict[str, EmailPreviewDocument] = {}
        self._lock = threading.Lock()

    def issue(self, session_id: str, html: str) -> str:
        now = time.monotonic()
        token = secrets.token_urlsafe(32)
        document = EmailPreviewDocument(
            session_id=session_id,
            html=html,
            expires_at=now + self.ttl_seconds,
        )
        with self._lock:
            self._prune(now)
            while len(self._documents) >= self.maximum:
                oldest = min(
                    self._documents,
                    key=lambda key: self._documents[key].expires_at,
                )
                self._documents.pop(oldest, None)
            self._documents[token] = document
        return token

    def get(self, token: str, session_id: str) -> str | None:
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            document = self._documents.get(token)
            if document is None or not hmac.compare_digest(
                document.session_id, session_id
            ):
                return None
            return document.html

    def _prune(self, now: float) -> None:
        expired = [
            key
            for key, document in self._documents.items()
            if document.expires_at <= now
        ]
        for key in expired:
            self._documents.pop(key, None)


def _decode_upload(payload: dict[str, Any], field: str, maximum: int) -> bytes:
    value = payload.get(field, "")
    if not isinstance(value, str):
        raise certctl.CertificateError(f"Champ {field} invalide.")
    if not value:
        return b""
    maximum_encoded = 4 * ((maximum + 2) // 3)
    if len(value) > maximum_encoded:
        raise certctl.CertificateError(f"Champ {field} trop volumineux.")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise certctl.CertificateError(f"Champ {field} mal encodé.") from error
    if len(raw) > maximum:
        raise certctl.CertificateError(f"Champ {field} trop volumineux.")
    return raw


def _write_private(path: Path, data: bytes) -> None:
    descriptor = path.open("xb")
    try:
        descriptor.write(data)
        descriptor.flush()
    finally:
        descriptor.close()
    path.chmod(0o600)


def _remove_temporary_directory(path: Path) -> None:
    shutil.rmtree(path)


def certificate_summary(output_dir: Path, hostname: str) -> dict[str, Any]:
    fullchain = output_dir / "fullchain.pem"
    blocks = certctl.normalize_certificate_blocks(fullchain.read_bytes())
    leaf = blocks[0]
    dates = certctl.run_openssl(
        "x509", "-noout", "-startdate", "-enddate", input_data=leaf
    ).stdout
    serial = certctl.run_openssl("x509", "-noout", "-serial", input_data=leaf).stdout
    fingerprint = certctl.run_openssl(
        "x509",
        "-noout",
        "-fingerprint",
        "-sha256",
        input_data=leaf,
    ).stdout
    san_output = certctl.run_openssl(
        "x509",
        "-noout",
        "-ext",
        "subjectAltName",
        input_data=leaf,
    ).stdout.decode("utf-8", errors="replace")
    dns_names = re.findall(r"DNS:([^,\s]+)", san_output)
    date_values = {}
    for line in dates.decode("ascii", errors="replace").splitlines():
        name, separator, value = line.partition("=")
        if separator:
            date_values[name] = value
    return {
        "hostname": hostname,
        "subject": certctl.certificate_name(leaf, "subject").decode(
            "utf-8", errors="replace"
        ),
        "issuer": certctl.certificate_name(leaf, "issuer").decode(
            "utf-8", errors="replace"
        ),
        "dnsNames": dns_names,
        "notBefore": date_values.get("notBefore", ""),
        "notAfter": date_values.get("notAfter", ""),
        "serial": serial.decode("ascii", errors="replace").strip().partition("=")[2],
        "sha256Fingerprint": fingerprint.decode("ascii", errors="replace")
        .strip()
        .partition("=")[2],
        "chainLength": len(blocks),
    }


def _stage_uploaded_certificate(
    payload: dict[str, Any],
    directory: Path,
) -> tuple[Path, Path | None, Path | None, bytes | None]:
    certificate = _decode_upload(payload, "certificateBase64", MAX_CERTIFICATE_BYTES)
    private_key = _decode_upload(payload, "privateKeyBase64", MAX_PRIVATE_KEY_BYTES)
    chain = _decode_upload(payload, "chainBase64", MAX_CHAIN_BYTES)
    password_value = payload.get("password", "")
    if not isinstance(password_value, str):
        raise certctl.CertificateError("Mot de passe de certificat invalide.")
    password = password_value.encode("utf-8")
    if len(password) > MAX_PASSWORD_BYTES:
        raise certctl.CertificateError("Mot de passe de certificat trop long.")
    if not certificate:
        raise certctl.CertificateError("Certificat ou bundle manquant.")
    if not private_key and chain:
        raise certctl.CertificateError(
            "Une chaîne séparée nécessite une clé privée séparée."
        )

    source = directory / "certificate-upload"
    key_path = directory / "private-key" if private_key else None
    chain_path = directory / "certificate-chain" if chain else None
    _write_private(source, certificate)
    if key_path is not None:
        _write_private(key_path, private_key)
    if chain_path is not None:
        _write_private(chain_path, chain)
    return source, key_path, chain_path, password or None


def _install_staged_certificate(
    staged: tuple[Path, Path | None, Path | None, bytes | None],
    hostname: str,
    output_dir: Path,
) -> None:
    source, key_path, chain_path, password = staged
    certctl.install_certificate(
        source,
        key_path,
        hostname,
        output_dir,
        chain=chain_path,
        password=password,
    )


def install_uploaded_certificate(
    payload: dict[str, Any],
    hostname: str,
    output_dir: Path,
) -> dict[str, Any]:
    directory = Path(tempfile.mkdtemp(prefix="fortios-cert-web-"))
    activated = False
    try:
        staged = _stage_uploaded_certificate(payload, directory)
        validated_output = directory / "validated"
        _install_staged_certificate(staged, hostname, validated_output)
        summary = certificate_summary(validated_output, hostname)
        _install_staged_certificate(staged, hostname, output_dir)
        activated = True
        return summary
    finally:
        pending_error = sys.exc_info()[0] is not None
        try:
            _remove_temporary_directory(directory)
        except OSError:
            if activated:
                print(
                    "Avertissement : certificat activé, mais le répertoire temporaire privé "
                    "n'a pas pu être nettoyé.",
                    file=sys.stderr,
                )
            elif not pending_error:
                raise


def validate_uploaded_certificate(
    payload: dict[str, Any], hostname: str
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="fortios-cert-validation-") as temporary:
        directory = Path(temporary)
        staged = _stage_uploaded_certificate(payload, directory)
        output_dir = directory / "active"
        _install_staged_certificate(staged, hostname, output_dir)
        return certificate_summary(output_dir, hostname)
