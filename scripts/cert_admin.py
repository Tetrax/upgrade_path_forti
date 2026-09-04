#!/usr/bin/env python3
"""Manage the administrator account used by the certificate web interface."""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import fcntl
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DEFAULT_CREDENTIALS = Path(
    os.environ.get(
        "FORTIOS_CERT_ADMIN_FILE",
        "/opt/fortios/certificates/admin/credentials.json",
    ),
)
DEFAULT_ADMIN_STATE = DEFAULT_CREDENTIALS.with_name("admin-state.json")
USERNAME_RE = re.compile(r"[A-Za-z0-9._@-]{1,64}\Z")
EMAIL_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LENGTH = 32
SCRYPT_MAXMEM = 64 * 1024 * 1024
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024
MAX_RECOVERY_EMAIL_LENGTH = 254
MAX_RECOVERY_TOKENS = 64
RECOVERY_VERIFICATION_TTL_SECONDS = 30 * 60
PASSWORD_RESET_TTL_SECONDS = 15 * 60
RECOVERY_PURPOSE_VERIFY = "verify_recovery_email"
RECOVERY_PURPOSE_RESET = "password_reset"


class CredentialError(RuntimeError):
    """The certificate administrator credentials are invalid or unavailable."""


class CredentialExistsError(CredentialError):
    """The certificate administrator account already exists."""


class CredentialAuthenticationError(CredentialError):
    """The current administrator password is incorrect."""


class CredentialValidationError(CredentialError):
    """The requested administrator password does not meet the account contract."""


class CredentialRevisionError(CredentialError):
    """The administrator credentials changed before a requested mutation."""


class RecoveryTokenError(CredentialError):
    """The requested recovery token is invalid, expired, or no longer current."""


class AdminStateError(CredentialError):
    """The optional recovery state is unavailable or corrupt."""


def _encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def derive_password(password: str, salt: bytes) -> bytes:
    encoded_password = password.encode("utf-8")
    if not MIN_PASSWORD_LENGTH <= len(encoded_password) <= MAX_PASSWORD_LENGTH:
        raise CredentialError(
            "Le mot de passe administrateur doit contenir entre "
            f"{MIN_PASSWORD_LENGTH} et {MAX_PASSWORD_LENGTH} octets UTF-8.",
        )
    return hashlib.scrypt(
        encoded_password,
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_LENGTH,
        maxmem=SCRYPT_MAXMEM,
    )


def credential_payload(username: str, password: str) -> dict[str, Any]:
    if not USERNAME_RE.fullmatch(username):
        raise CredentialError(
            "L'identifiant doit contenir 1 à 64 caractères parmi lettres, chiffres, . _ @ et -.",
        )
    salt = secrets.token_bytes(16)
    return {
        "version": 1,
        "username": username,
        "algorithm": "scrypt",
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "salt": _encode(salt),
        "digest": _encode(derive_password(password, salt)),
    }


def configured_runtime_gid() -> int | None:
    if os.geteuid() != 0 or not os.environ.get("PGID"):
        return None
    try:
        runtime_gid = int(os.environ["PGID"])
    except ValueError as error:
        raise CredentialError("PGID doit être numérique.") from error
    if runtime_gid <= 0:
        raise CredentialError("PGID doit être strictement supérieur à zéro.")
    return runtime_gid


def credential_lock_path(path: Path) -> Path:
    return path.with_name(f".{path.name}.lock")


def _open_credential_lock(lock_path: Path, flags: int, mode: int) -> int:
    safe_flags = flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(lock_path, safe_flags, mode)
        metadata = os.fstat(descriptor)
        current = os.stat(lock_path, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise CredentialError("Verrou du compte administrateur invalide.")
        return descriptor
    except (OSError, CredentialError) as error:
        if descriptor is not None:
            os.close(descriptor)
        if isinstance(error, CredentialError):
            raise
        raise CredentialError("Verrou du compte administrateur indisponible.") from error


@contextmanager
def credential_lock(
    path: Path,
    *,
    exclusive: bool,
    runtime_gid: int | None = None,
):
    lock_path = credential_lock_path(path)
    if exclusive:
        lock_mode = 0o660 if runtime_gid is not None else 0o600
        descriptor = _open_credential_lock(
            lock_path,
            os.O_RDWR | os.O_CREAT,
            lock_mode,
        )
        if runtime_gid is not None:
            os.fchmod(descriptor, lock_mode)
            os.fchown(descriptor, 0, runtime_gid)
        elif os.fstat(descriptor).st_uid == os.geteuid():
            os.fchmod(descriptor, lock_mode)
    else:
        descriptor = _open_credential_lock(lock_path, os.O_RDONLY, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        current = os.stat(lock_path, follow_symlinks=False)
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
            raise CredentialError("Verrou du compte administrateur remplacé.")
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def ensure_credential_lock(path: Path) -> bool:
    """Recreate an upgrade-missing lock without reading or replacing credentials."""
    if not os.path.lexists(path):
        return False
    lock_existed = os.path.lexists(credential_lock_path(path))
    runtime_gid = configured_runtime_gid()
    with credential_lock(path, exclusive=True, runtime_gid=runtime_gid):
        pass
    return not lock_existed


def _prepare_credentials_directory(path: Path, runtime_gid: int | None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if runtime_gid is not None:
        path.parent.chmod(0o750)
        os.chown(path.parent, 0, runtime_gid)


def _write_credentials_unlocked(
    path: Path,
    payload: dict[str, Any],
    runtime_gid: int | None,
) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o640 if runtime_gid is not None else 0o600)
        if runtime_gid is not None:
            os.fchown(descriptor, 0, runtime_gid)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def admin_state_path(credentials_path: Path, state_file: Path | None = None) -> Path:
    """Return the private state file associated with one credentials file."""
    return state_file if state_file is not None else credentials_path.with_name("admin-state.json")


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _timestamp(value: dt.datetime | None = None) -> str:
    return (value or _utc_now()).astimezone(dt.timezone.utc).isoformat()


def _validate_timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CredentialError(f"{label} invalide.")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as error:
        raise CredentialError(f"{label} invalide.") from error
    if parsed.tzinfo is None:
        raise CredentialError(f"{label} invalide.")
    return value


def validate_recovery_email(value: Any, *, allow_empty: bool = True) -> str:
    if not isinstance(value, str):
        raise CredentialValidationError("Adresse email de récupération invalide.")
    normalized = value.strip()
    if not normalized and allow_empty:
        return ""
    if (
        not normalized
        or len(normalized) > MAX_RECOVERY_EMAIL_LENGTH
        or "\r" in normalized
        or "\n" in normalized
        or not EMAIL_RE.fullmatch(normalized)
    ):
        raise CredentialValidationError("Adresse email de récupération invalide.")
    return normalized


def _default_admin_state(password_changed_at: str | None = None) -> dict[str, Any]:
    return {
        "version": 1,
        "passwordChangedAt": password_changed_at or _timestamp(),
        "currentRecoveryEmail": "",
        "pendingRecoveryEmail": "",
        "tokens": [],
    }


_TOKEN_KEYS = {
    "purpose",
    "digest",
    "createdAt",
    "expiresAt",
    "credentialsRevision",
    "email",
}


def _validate_admin_state(payload: Any) -> dict[str, Any]:
    required = {
        "version",
        "passwordChangedAt",
        "currentRecoveryEmail",
        "pendingRecoveryEmail",
        "tokens",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise CredentialError("État du compte administrateur invalide.")
    if payload["version"] != 1 or type(payload["version"]) is not int:
        raise CredentialError("Version de l'état du compte administrateur inconnue.")
    password_changed_at = _validate_timestamp(
        payload["passwordChangedAt"], "Date de changement du mot de passe"
    )
    current = validate_recovery_email(payload["currentRecoveryEmail"])
    pending = validate_recovery_email(payload["pendingRecoveryEmail"])
    tokens = payload["tokens"]
    if not isinstance(tokens, list) or len(tokens) > MAX_RECOVERY_TOKENS:
        raise CredentialError("Liste de tokens de récupération invalide.")
    validated_tokens: list[dict[str, Any]] = []
    for token in tokens:
        if not isinstance(token, dict) or set(token) != _TOKEN_KEYS:
            raise CredentialError("Token de récupération invalide.")
        if token["purpose"] not in {RECOVERY_PURPOSE_VERIFY, RECOVERY_PURPOSE_RESET}:
            raise CredentialError("Objet du token de récupération invalide.")
        digest = token["digest"]
        revision = token["credentialsRevision"]
        if (
            not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not isinstance(revision, str)
            or not re.fullmatch(r"[0-9a-f]{64}", revision)
        ):
            raise CredentialError("Token de récupération invalide.")
        created_at = _validate_timestamp(token["createdAt"], "Création du token")
        expires_at = _validate_timestamp(token["expiresAt"], "Expiration du token")
        try:
            if dt.datetime.fromisoformat(expires_at) <= dt.datetime.fromisoformat(created_at):
                raise CredentialError("Expiration du token de récupération invalide.")
        except ValueError as error:
            raise CredentialError("Token de récupération invalide.") from error
        email = validate_recovery_email(token["email"])
        if token["purpose"] == RECOVERY_PURPOSE_VERIFY and not email:
            raise CredentialError("Token de vérification invalide.")
        if token["purpose"] == RECOVERY_PURPOSE_RESET and email:
            raise CredentialError("Token de réinitialisation invalide.")
        validated_tokens.append(
            {
                "purpose": token["purpose"],
                "digest": digest,
                "createdAt": created_at,
                "expiresAt": expires_at,
                "credentialsRevision": revision,
                "email": email,
            }
        )
    return {
        "version": 1,
        "passwordChangedAt": password_changed_at,
        "currentRecoveryEmail": current,
        "pendingRecoveryEmail": pending,
        "tokens": validated_tokens,
    }


def _credentials_mtime_timestamp(path: Path) -> str:
    try:
        return _timestamp(dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc))
    except OSError as error:
        raise CredentialError("Compte administrateur indisponible.") from error


def _load_admin_state_unlocked(credentials_path: Path, state_path: Path) -> dict[str, Any]:
    if not state_path.exists():
        return _default_admin_state(_credentials_mtime_timestamp(credentials_path))
    try:
        metadata = state_path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise AdminStateError("État du compte administrateur invalide.")
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except AdminStateError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdminStateError("État du compte administrateur indisponible.") from error
    try:
        return _validate_admin_state(payload)
    except CredentialError as error:
        raise AdminStateError("État du compte administrateur invalide.") from error


def load_admin_state(
    credentials_path: Path,
    state_file: Path | None = None,
) -> dict[str, Any]:
    """Read account state while sharing the credentials lock with all mutations."""
    state_path = admin_state_path(credentials_path, state_file)
    with credential_lock(credentials_path, exclusive=False):
        load_credentials_with_revision(credentials_path)
        return _load_admin_state_unlocked(credentials_path, state_path)


def _write_admin_state_unlocked(
    credentials_path: Path,
    state_path: Path,
    state: dict[str, Any],
    runtime_gid: int | None,
) -> None:
    validated = _validate_admin_state(state)
    _write_credentials_unlocked(state_path, validated, runtime_gid)


def save_admin_state(
    credentials_path: Path,
    state: dict[str, Any],
    state_file: Path | None = None,
) -> None:
    state_path = admin_state_path(credentials_path, state_file)
    runtime_gid = configured_runtime_gid()
    _prepare_credentials_directory(state_path, runtime_gid)
    with credential_lock(credentials_path, exclusive=True, runtime_gid=runtime_gid):
        load_credentials_with_revision(credentials_path)
        _write_admin_state_unlocked(credentials_path, state_path, state, runtime_gid)


def set_recovery_email(
    credentials_path: Path,
    email: str,
    state_file: Path | None = None,
    *,
    expected_revision: str | None = None,
) -> dict[str, Any]:
    """Set a pending address without replacing the currently verified address."""
    normalized = validate_recovery_email(email, allow_empty=False)
    state_path = admin_state_path(credentials_path, state_file)
    runtime_gid = configured_runtime_gid()
    _prepare_credentials_directory(state_path, runtime_gid)
    with credential_lock(credentials_path, exclusive=True, runtime_gid=runtime_gid):
        _, current_revision = load_credentials_with_revision(credentials_path)
        if expected_revision is not None and not hmac.compare_digest(
            expected_revision, current_revision
        ):
            raise CredentialRevisionError("Les identifiants administrateur ont été modifiés.")
        state = _load_admin_state_unlocked(credentials_path, state_path)
        recovery_email_changed = normalized != state["currentRecoveryEmail"]
        if not recovery_email_changed:
            state["pendingRecoveryEmail"] = ""
        else:
            state["pendingRecoveryEmail"] = normalized
        state["tokens"] = [
            token
            for token in state["tokens"]
            if token["purpose"] != RECOVERY_PURPOSE_VERIFY
            and not (
                recovery_email_changed
                and token["purpose"] == RECOVERY_PURPOSE_RESET
            )
        ]
        _write_admin_state_unlocked(credentials_path, state_path, state, runtime_gid)
        return state


def _token_digest(token: str) -> str:
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", token):
        raise RecoveryTokenError("Token de récupération invalide.")
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _coerce_now(value: dt.datetime | None) -> dt.datetime:
    current = value or _utc_now()
    if current.tzinfo is None:
        raise CredentialError("Horodatage de récupération invalide.")
    return current.astimezone(dt.timezone.utc)


def _issue_recovery_token(
    credentials_path: Path,
    *,
    purpose: str,
    email: str = "",
    now: dt.datetime | None = None,
    state_file: Path | None = None,
    expected_revision: str | None = None,
    expected_recovery_email: str | None = None,
) -> str:
    if purpose not in {RECOVERY_PURPOSE_VERIFY, RECOVERY_PURPOSE_RESET}:
        raise RecoveryTokenError("Objet du token de récupération invalide.")
    if purpose == RECOVERY_PURPOSE_VERIFY:
        email = validate_recovery_email(email, allow_empty=False)
    elif email:
        raise RecoveryTokenError("Token de réinitialisation invalide.")
    state_path = admin_state_path(credentials_path, state_file)
    runtime_gid = configured_runtime_gid()
    _prepare_credentials_directory(state_path, runtime_gid)
    current = _coerce_now(now)
    with credential_lock(credentials_path, exclusive=True, runtime_gid=runtime_gid):
        _, revision = load_credentials_with_revision(credentials_path)
        if expected_revision is not None and not hmac.compare_digest(
            expected_revision, revision
        ):
            raise CredentialRevisionError("Les identifiants administrateur ont été modifiés.")
        state = _load_admin_state_unlocked(credentials_path, state_path)
        if purpose == RECOVERY_PURPOSE_VERIFY and state["pendingRecoveryEmail"] != email:
            raise RecoveryTokenError("Aucune adresse de récupération en attente.")
        if purpose == RECOVERY_PURPOSE_RESET and not state["currentRecoveryEmail"]:
            raise RecoveryTokenError("Aucune adresse de récupération vérifiée.")
        if (
            purpose == RECOVERY_PURPOSE_RESET
            and expected_recovery_email is not None
            and state["currentRecoveryEmail"] != expected_recovery_email
        ):
            raise RecoveryTokenError("L'adresse de récupération a été modifiée.")
        digest = secrets.token_urlsafe(32)
        expires = current + dt.timedelta(
            seconds=(
                RECOVERY_VERIFICATION_TTL_SECONDS
                if purpose == RECOVERY_PURPOSE_VERIFY
                else PASSWORD_RESET_TTL_SECONDS
            )
        )
        record = {
            "purpose": purpose,
            "digest": _token_digest(digest),
            "createdAt": _timestamp(current),
            "expiresAt": _timestamp(expires),
            "credentialsRevision": revision,
            "email": email,
        }
        state["tokens"] = [
            token_record
            for token_record in state["tokens"]
            if token_record["purpose"] != purpose
        ]
        state["tokens"].append(record)
        _write_admin_state_unlocked(credentials_path, state_path, state, runtime_gid)
    return digest


def consume_verification_token(
    credentials_path: Path,
    token: str,
    *,
    now: dt.datetime | None = None,
    state_file: Path | None = None,
    expected_revision: str | None = None,
) -> dict[str, Any]:
    """Consume one verification token and atomically promote its address."""
    digest = _token_digest(token)
    current = _coerce_now(now)
    state_path = admin_state_path(credentials_path, state_file)
    runtime_gid = configured_runtime_gid()
    _prepare_credentials_directory(state_path, runtime_gid)
    with credential_lock(credentials_path, exclusive=True, runtime_gid=runtime_gid):
        _, revision = load_credentials_with_revision(credentials_path)
        if expected_revision is not None and not hmac.compare_digest(
            expected_revision, revision
        ):
            raise CredentialRevisionError("Les identifiants administrateur ont été modifiés.")
        state = _load_admin_state_unlocked(credentials_path, state_path)
        selected: dict[str, Any] | None = None
        for token_record in state["tokens"]:
            if not hmac.compare_digest(token_record["digest"], digest):
                continue
            if token_record["purpose"] != RECOVERY_PURPOSE_VERIFY:
                continue
            if token_record["credentialsRevision"] != revision:
                continue
            if token_record["email"] != state["pendingRecoveryEmail"]:
                continue
            if dt.datetime.fromisoformat(token_record["expiresAt"]) <= current:
                continue
            selected = token_record
            break
        if selected is None:
            raise RecoveryTokenError("Token de récupération invalide.")
        state["currentRecoveryEmail"] = selected["email"]
        state["pendingRecoveryEmail"] = ""
        state["tokens"] = [
            token_record
            for token_record in state["tokens"]
            if token_record is not selected
        ]
        _write_admin_state_unlocked(credentials_path, state_path, state, runtime_gid)
        return state


def issue_verification_token(
    credentials_path: Path,
    *,
    now: dt.datetime | None = None,
    state_file: Path | None = None,
    expected_revision: str | None = None,
    expected_recovery_email: str | None = None,
) -> str:
    recipient = expected_recovery_email
    if recipient is None:
        state = load_admin_state(credentials_path, state_file)
        recipient = state["pendingRecoveryEmail"]
    return _issue_recovery_token(
        credentials_path,
        purpose=RECOVERY_PURPOSE_VERIFY,
        email=recipient,
        now=now,
        state_file=state_file,
        expected_revision=expected_revision,
    )


def issue_password_reset_token(
    credentials_path: Path,
    *,
    now: dt.datetime | None = None,
    state_file: Path | None = None,
    expected_revision: str | None = None,
    expected_recovery_email: str | None = None,
) -> str:
    if expected_recovery_email is not None:
        expected_recovery_email = validate_recovery_email(
            expected_recovery_email,
            allow_empty=False,
        )
    return _issue_recovery_token(
        credentials_path,
        purpose=RECOVERY_PURPOSE_RESET,
        now=now,
        state_file=state_file,
        expected_revision=expected_revision,
        expected_recovery_email=expected_recovery_email,
    )


def reset_credentials_with_token(
    credentials_path: Path,
    token: str,
    new_password: str,
    confirmation: str,
    *,
    now: dt.datetime | None = None,
    state_file: Path | None = None,
    expected_revision: str | None = None,
) -> str:
    """Consume a reset token and atomically replace the administrator password."""
    digest = _token_digest(token)
    if not isinstance(new_password, str) or not isinstance(confirmation, str):
        raise CredentialValidationError("Champs de réinitialisation invalides.")
    if new_password != confirmation:
        raise CredentialValidationError("Les mots de passe ne correspondent pas.")
    current = _coerce_now(now)
    state_path = admin_state_path(credentials_path, state_file)
    runtime_gid = configured_runtime_gid()
    _prepare_credentials_directory(state_path, runtime_gid)
    with credential_lock(credentials_path, exclusive=True, runtime_gid=runtime_gid):
        payload, revision = load_credentials_with_revision(credentials_path)
        if expected_revision is not None and not hmac.compare_digest(
            expected_revision, revision
        ):
            raise CredentialRevisionError("Les identifiants administrateur ont été modifiés.")
        state = _load_admin_state_unlocked(credentials_path, state_path)
        selected: dict[str, Any] | None = None
        for token_record in state["tokens"]:
            if not hmac.compare_digest(token_record["digest"], digest):
                continue
            if token_record["purpose"] != RECOVERY_PURPOSE_RESET:
                continue
            if token_record["credentialsRevision"] != revision:
                continue
            if dt.datetime.fromisoformat(token_record["expiresAt"]) <= current:
                continue
            selected = token_record
            break
        if selected is None:
            raise RecoveryTokenError("Token de récupération invalide.")
        try:
            replacement = credential_payload(str(payload["username"]), new_password)
        except CredentialError as error:
            raise CredentialValidationError(str(error)) from error
        _write_credentials_unlocked(credentials_path, replacement, runtime_gid)
        state["passwordChangedAt"] = _timestamp(current)
        state["tokens"] = []
        try:
            _write_admin_state_unlocked(credentials_path, state_path, state, runtime_gid)
        except OSError:
            # The credential revision already invalidates every persisted token.
            # Reporting failure here would invite a retry after the password
            # has in fact changed, so keep the successful reset authoritative.
            pass
        return credentials_revision(credentials_path)


def mask_recovery_email(email: str) -> str:
    if not email:
        return ""
    local, domain = email.split("@", 1)
    if len(local) <= 1:
        masked_local = "*"
    elif len(local) == 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + "***" + local[-1]
    return f"{masked_local}@{domain}"


def admin_account_projection(
    credentials: dict[str, Any],
    state: dict[str, Any] | None,
    *,
    session_count: int,
) -> dict[str, Any]:
    if state is None:
        return {
            "username": credentials["username"],
            "recoveryStateAvailable": False,
            "recoveryEmail": "",
            "recoveryEmailVerified": False,
            "pendingRecoveryEmail": "",
            "pendingRecoveryEmailPresent": False,
            "passwordChangedAt": "",
            "sessionCount": max(0, int(session_count)),
        }
    return {
        "username": credentials["username"],
        "recoveryStateAvailable": True,
        "recoveryEmail": mask_recovery_email(state["currentRecoveryEmail"]),
        "recoveryEmailVerified": bool(state["currentRecoveryEmail"]),
        "pendingRecoveryEmail": mask_recovery_email(state["pendingRecoveryEmail"]),
        "pendingRecoveryEmailPresent": bool(state["pendingRecoveryEmail"]),
        "passwordChangedAt": state["passwordChangedAt"],
        "sessionCount": max(0, int(session_count)),
    }


def write_credentials(path: Path, payload: dict[str, Any]) -> None:
    runtime_gid = configured_runtime_gid()
    _prepare_credentials_directory(path, runtime_gid)
    with credential_lock(path, exclusive=True, runtime_gid=runtime_gid):
        _write_credentials_unlocked(path, payload, runtime_gid)


def create_initial_credentials(
    path: Path,
    username: str,
    password: str,
    *,
    recovery_email: str | None = None,
    state_file: Path | None = None,
) -> str:
    """Create the first account and its recovery state exactly once."""
    recovery = "" if recovery_email is None else validate_recovery_email(recovery_email)
    if os.path.lexists(path):
        raise CredentialExistsError("Le compte administrateur existe déjà.")
    runtime_gid = configured_runtime_gid()
    _prepare_credentials_directory(path, runtime_gid)
    state_path = admin_state_path(path, state_file)
    with credential_lock(path, exclusive=True, runtime_gid=runtime_gid):
        if os.path.lexists(path):
            raise CredentialExistsError("Le compte administrateur existe déjà.")
        _write_credentials_unlocked(
            path,
            credential_payload(username, password),
            runtime_gid,
        )
        state = _default_admin_state(_timestamp())
        state["pendingRecoveryEmail"] = recovery
        try:
            _prepare_credentials_directory(state_path, runtime_gid)
            _write_admin_state_unlocked(path, state_path, state, runtime_gid)
        except OSError:
            # Recovery is optional during First Run. The credential write is the
            # authoritative account creation; an unavailable sidecar leaves
            # email recovery disabled rather than leaving setup ambiguous.
            pass
        return credentials_revision(path)


def load_credentials_with_revision(path: Path) -> tuple[dict[str, Any], str]:
    try:
        encoded = path.read_bytes()
        payload = json.loads(encoded.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CredentialError("Compte administrateur indisponible.") from error
    required = {"version", "username", "algorithm", "n", "r", "p", "salt", "digest"}
    if not isinstance(payload, dict) or not required.issubset(payload):
        raise CredentialError("Fichier du compte administrateur invalide.")
    if payload.get("algorithm") != "scrypt" or payload.get("version") != 1:
        raise CredentialError("Format du compte administrateur non pris en charge.")
    username = payload.get("username")
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        raise CredentialError("Fichier du compte administrateur invalide.")
    if any(
        type(payload.get(name)) is not int or payload[name] != expected
        for name, expected in (("n", SCRYPT_N), ("r", SCRYPT_R), ("p", SCRYPT_P))
    ):
        raise CredentialError("Paramètres du compte administrateur invalides.")
    salt = payload.get("salt")
    digest = payload.get("digest")
    if not isinstance(salt, str) or not isinstance(digest, str):
        raise CredentialError("Fichier du compte administrateur invalide.")
    try:
        decoded_salt = _decode(salt)
        decoded_digest = _decode(digest)
    except (binascii.Error, ValueError) as error:
        raise CredentialError("Fichier du compte administrateur invalide.") from error
    if len(decoded_salt) != 16 or len(decoded_digest) != SCRYPT_LENGTH:
        raise CredentialError("Fichier du compte administrateur invalide.")
    return payload, hashlib.sha256(encoded).hexdigest()


def load_credentials(path: Path) -> dict[str, Any]:
    payload, _ = load_credentials_with_revision(path)
    return payload


def credentials_revision(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise CredentialError("Compte administrateur indisponible.") from error


def authenticate_credentials(path: Path, username: str, password: str) -> str | None:
    encoded_password = password.encode("utf-8")
    if (
        not USERNAME_RE.fullmatch(username)
        or not MIN_PASSWORD_LENGTH <= len(encoded_password) <= MAX_PASSWORD_LENGTH
    ):
        return None
    try:
        payload, revision = load_credentials_with_revision(path)
        if (
            int(payload["n"]) != SCRYPT_N
            or int(payload["r"]) != SCRYPT_R
            or int(payload["p"]) != SCRYPT_P
        ):
            return None
        salt = _decode(str(payload["salt"]))
        expected = _decode(str(payload["digest"]))
        stored_username = str(payload["username"])
        if (
            len(salt) != 16
            or len(expected) != SCRYPT_LENGTH
            or not USERNAME_RE.fullmatch(stored_username)
        ):
            return None
        candidate = hashlib.scrypt(
            encoded_password,
            salt=salt,
            n=int(payload["n"]),
            r=int(payload["r"]),
            p=int(payload["p"]),
            dklen=len(expected),
            maxmem=SCRYPT_MAXMEM,
        )
    except (CredentialError, TypeError, ValueError):
        return None
    if hmac.compare_digest(
        stored_username.encode("ascii"),
        username.encode("ascii"),
    ) and hmac.compare_digest(expected, candidate):
        return revision
    return None


def verify_credentials(path: Path, username: str, password: str) -> bool:
    return authenticate_credentials(path, username, password) is not None


def rotate_credentials(
    path: Path,
    username: str,
    current_password: str,
    new_password: str,
    confirmation: str,
    *,
    expected_revision: str,
    state_file: Path | None = None,
) -> str:
    """Replace only the password when account, password and revision still match."""
    if not all(
        isinstance(value, str)
        for value in (
            username,
            current_password,
            new_password,
            confirmation,
            expected_revision,
        )
    ):
        raise CredentialValidationError("Champs de rotation invalides.")
    if new_password != confirmation:
        raise CredentialValidationError("Les mots de passe ne correspondent pas.")
    if not os.path.lexists(path):
        raise CredentialError("Compte administrateur indisponible.")

    runtime_gid = configured_runtime_gid()
    state_path = admin_state_path(path, state_file)
    _prepare_credentials_directory(state_path, runtime_gid)
    with credential_lock(path, exclusive=True, runtime_gid=runtime_gid):
        payload, current_revision = load_credentials_with_revision(path)
        if not hmac.compare_digest(expected_revision, current_revision):
            raise CredentialRevisionError(
                "Les identifiants administrateur ont été modifiés. Reconnectez-vous."
            )
        if not hmac.compare_digest(str(payload["username"]), username):
            raise CredentialRevisionError("La session administrateur ne correspond plus au compte.")
        authenticated_revision = authenticate_credentials(path, username, current_password)
        if authenticated_revision is None or not hmac.compare_digest(
            authenticated_revision, current_revision
        ):
            raise CredentialAuthenticationError("Mot de passe actuel incorrect.")
        if hmac.compare_digest(
            current_password.encode("utf-8"),
            new_password.encode("utf-8"),
        ):
            raise CredentialValidationError(
                "Le nouveau mot de passe doit être différent du mot de passe actuel."
            )
        try:
            replacement = credential_payload(username, new_password)
        except CredentialError as error:
            raise CredentialValidationError(str(error)) from error
        _write_credentials_unlocked(path, replacement, runtime_gid)
        try:
            state = _load_admin_state_unlocked(path, state_path)
            state["passwordChangedAt"] = _timestamp()
            state["tokens"] = []
            _write_admin_state_unlocked(path, state_path, state, runtime_gid)
        except (CredentialError, OSError):
            # The fresh credential revision already invalidates every token.
            # A broken recovery sidecar must not block password rotation.
            pass
        return credentials_revision(path)


def reset_credentials(
    path: Path,
    username: str,
    password: str,
    *,
    state_file: Path | None = None,
) -> str:
    """Break-glass reset that preserves recovery metadata but invalidates all tokens."""
    if not os.path.lexists(path):
        raise CredentialError("Compte administrateur indisponible.")
    runtime_gid = configured_runtime_gid()
    state_path = admin_state_path(path, state_file)
    _prepare_credentials_directory(state_path, runtime_gid)
    replacement = credential_payload(username, password)
    with credential_lock(path, exclusive=True, runtime_gid=runtime_gid):
        _write_credentials_unlocked(path, replacement, runtime_gid)
        try:
            state = _load_admin_state_unlocked(path, state_path)
            state["passwordChangedAt"] = _timestamp()
            state["tokens"] = []
            _write_admin_state_unlocked(path, state_path, state, runtime_gid)
        except (CredentialError, OSError):
            # Break-glass password recovery remains available even when the
            # optional recovery sidecar is corrupt or temporarily unwritable.
            pass
        return credentials_revision(path)


def read_password(password_stdin: bool) -> tuple[str, str]:
    if password_stdin:
        first = sys.stdin.readline().rstrip("\r\n")
        second = sys.stdin.readline().rstrip("\r\n")
    else:
        first = getpass.getpass("Mot de passe : ")
        second = getpass.getpass("Confirmation du mot de passe : ")
    return first, second


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Configurer le compte administrateur de /cert."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("setup", "reset"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--credentials", type=Path, default=DEFAULT_CREDENTIALS)
        subparser.add_argument("--username", required=True)
        subparser.add_argument("--password-stdin", action="store_true")
        if command == "setup":
            subparser.add_argument("--recovery-email")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.command == "setup" and args.credentials.exists():
        print("Erreur : le compte administrateur existe déjà.", file=sys.stderr)
        return 1
    if args.command == "reset" and not args.credentials.exists():
        print("Erreur : aucun compte administrateur à réinitialiser.", file=sys.stderr)
        return 1
    first, second = read_password(args.password_stdin)
    if first != second:
        print("Erreur : les mots de passe ne correspondent pas.", file=sys.stderr)
        return 1
    try:
        if args.command == "setup":
            create_initial_credentials(
                args.credentials,
                args.username,
                first,
                recovery_email=args.recovery_email,
            )
        else:
            reset_credentials(args.credentials, args.username, first)
    except (CredentialError, OSError, ValueError) as error:
        print(f"Erreur : {error}", file=sys.stderr)
        return 1
    print(f"Compte administrateur configuré : {args.username}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
