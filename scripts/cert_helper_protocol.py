"""Bounded length-prefixed JSON protocol for the certificate helper."""

from __future__ import annotations

import json
import socket
import struct
from pathlib import Path
from typing import Any

HEADER = struct.Struct("!I")
MAX_REQUEST_BYTES = 64 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
PROTOCOL_VERSION = 1


class ProtocolError(ValueError):
    """Raised when a helper message violates the wire protocol."""


class HelperError(RuntimeError):
    """Raised when the privileged helper refuses an installation."""


class HelperConflictError(HelperError):
    """Raised when the administrator account already exists."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    for key, value in pairs:
        if key in decoded:
            raise ProtocolError("Le message helper contient une clé JSON dupliquée.")
        decoded[key] = value
    return decoded


def _reject_non_json_constant(value: str) -> None:
    raise ProtocolError(f"Constante JSON interdite: {value}.")


def _receive_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise ProtocolError("Message helper tronqué.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_message(connection: socket.socket, message: dict[str, Any], *, maximum_bytes: int) -> None:
    try:
        encoded = json.dumps(
            message,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ProtocolError("Message helper JSON invalide.") from error
    if not encoded or len(encoded) > maximum_bytes:
        raise ProtocolError("Message helper trop volumineux.")
    connection.sendall(HEADER.pack(len(encoded)) + encoded)


def receive_message(connection: socket.socket, *, maximum_bytes: int) -> dict[str, Any]:
    size = HEADER.unpack(_receive_exact(connection, HEADER.size))[0]
    if size == 0 or size > maximum_bytes:
        raise ProtocolError("Taille de message helper invalide.")
    try:
        decoded = json.loads(
            _receive_exact(connection, size).decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError("Message helper JSON invalide.") from error
    if not isinstance(decoded, dict):
        raise ProtocolError("Le message helper doit être un objet JSON.")
    return decoded


def request_helper(
    socket_path: Path,
    message: dict[str, Any],
    *,
    timeout_seconds: float = 30.0,
    response_timeout_seconds: float | None = 30.0,
) -> dict[str, Any]:
    if not socket_path.is_absolute():
        raise ProtocolError("Le chemin du socket helper doit être absolu.")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout_seconds)
        connection.connect(str(socket_path))
        send_message(connection, message, maximum_bytes=MAX_REQUEST_BYTES)
        connection.settimeout(response_timeout_seconds)
        return receive_message(connection, maximum_bytes=MAX_RESPONSE_BYTES)


def install_via_helper(
    socket_path: Path,
    payload: dict[str, Any],
    *,
    credentials_revision: str,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    field_names = (
        "certificateBase64",
        "privateKeyBase64",
        "chainBase64",
        "password",
    )
    try:
        certificate_payload = {name: payload[name] for name in field_names}
    except KeyError as error:
        raise ProtocolError("Payload certificat incomplet.") from error
    if any(not isinstance(value, str) for value in certificate_payload.values()):
        raise ProtocolError("Les champs du certificat doivent être textuels.")
    if not isinstance(credentials_revision, str) or len(credentials_revision) != 64:
        raise ProtocolError("Révision des identifiants invalide.")
    response = request_helper(
        socket_path,
        {
            "version": PROTOCOL_VERSION,
            "action": "install",
            "credentialsRevision": credentials_revision,
            "payload": certificate_payload,
        },
        timeout_seconds=timeout_seconds,
        response_timeout_seconds=None,
    )
    if response.get("ok") is not True:
        error = response.get("error")
        raise HelperError(error if isinstance(error, str) else "Installation refusée par le helper.")
    summary = response.get("summary")
    if not isinstance(summary, dict):
        raise ProtocolError("Réponse d'installation helper invalide.")
    return summary


def setup_via_helper(
    socket_path: Path,
    username: str,
    password: str,
    *,
    timeout_seconds: float = 30.0,
) -> str:
    if not isinstance(username, str) or not isinstance(password, str):
        raise ProtocolError("Champs de configuration invalides.")
    response = request_helper(
        socket_path,
        {
            "version": PROTOCOL_VERSION,
            "action": "setup",
            "username": username,
            "password": password,
        },
        timeout_seconds=timeout_seconds,
    )
    if response.get("ok") is not True:
        error = response.get("error")
        message = error if isinstance(error, str) else "Configuration refusée par le helper."
        if response.get("errorCode") == "credentials_exists":
            raise HelperConflictError(message)
        raise HelperError(message)
    revision = response.get("credentialsRevision")
    if not isinstance(revision, str) or len(revision) != 64:
        raise ProtocolError("Réponse de configuration helper invalide.")
    return revision