#!/usr/bin/env python3
"""Manage the administrator account used by the certificate web interface."""

from __future__ import annotations

import argparse
import base64
import fcntl
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
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
USERNAME_RE = re.compile(r"[A-Za-z0-9._@-]{1,64}\Z")
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LENGTH = 32
SCRYPT_MAXMEM = 64 * 1024 * 1024
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024


class CredentialError(RuntimeError):
    """The certificate administrator credentials are invalid or unavailable."""


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


@contextmanager
def credential_lock(
    path: Path,
    *,
    exclusive: bool,
    runtime_gid: int | None = None,
):
    lock_path = credential_lock_path(path)
    if exclusive:
        descriptor = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT,
            0o640 if runtime_gid is not None else 0o600,
        )
        os.fchmod(descriptor, 0o640 if runtime_gid is not None else 0o600)
        if runtime_gid is not None:
            os.fchown(descriptor, 0, runtime_gid)
    else:
        try:
            descriptor = os.open(lock_path, os.O_RDONLY)
        except OSError as error:
            raise CredentialError(
                "Verrou du compte administrateur indisponible."
            ) from error
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def write_credentials(path: Path, payload: dict[str, Any]) -> None:
    runtime_gid = configured_runtime_gid()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if runtime_gid is not None:
        path.parent.chmod(0o750)
        os.chown(path.parent, 0, runtime_gid)
    with credential_lock(path, exclusive=True, runtime_gid=runtime_gid):
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


def load_credentials_with_revision(path: Path) -> tuple[dict[str, Any], str]:
    try:
        encoded = path.read_bytes()
        payload = json.loads(encoded.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CredentialError("Compte administrateur indisponible.") from error
    required = {"username", "algorithm", "n", "r", "p", "salt", "digest"}
    if not isinstance(payload, dict) or not required.issubset(payload):
        raise CredentialError("Fichier du compte administrateur invalide.")
    if payload.get("algorithm") != "scrypt" or payload.get("version") != 1:
        raise CredentialError("Format du compte administrateur non pris en charge.")
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
        write_credentials(args.credentials, credential_payload(args.username, first))
    except (CredentialError, OSError, ValueError) as error:
        print(f"Erreur : {error}", file=sys.stderr)
        return 1
    print(f"Compte administrateur configuré : {args.username}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
