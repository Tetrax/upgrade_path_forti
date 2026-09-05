"""Minimal privileged certificate installer exposed through a private Unix socket."""

from __future__ import annotations

import argparse
import base64
import hmac
import os
import re
import socket
import socketserver
import stat
import struct
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import cert_admin
import certctl
from cert_helper_protocol import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    PROTOCOL_VERSION,
    ProtocolError,
    receive_message,
    request_helper,
    send_message,
)
from cert_web import install_uploaded_certificate

DEFAULT_SOCKET = Path("/run/fortios-cert-helper/helper.sock")
DEFAULT_OUTPUT = Path("/opt/fortios/certificates/active")
DEFAULT_CREDENTIALS = Path("/opt/fortios/certificates/admin/credentials.json")
REQUEST_TIMEOUT_SECONDS = 30.0
_ALLOWED_PAYLOAD_KEYS = {
    "certificateBase64",
    "privateKeyBase64",
    "chainBase64",
    "password",
}


class HelperAuthorizationError(PermissionError):
    """Raised when a Unix peer is not the configured web process."""


class CertificateReloadError(RuntimeError):
    """Raised when Nginx rejects or cannot load an activated certificate."""


class NginxReloader:
    def __call__(self) -> None:
        try:
            for command in (
                ["/usr/sbin/nginx", "-t"],
                ["/usr/bin/systemctl", "reload", "nginx"],
            ):
                subprocess.run(
                    command,
                    capture_output=True,
                    check=True,
                    timeout=15,
                )
        except (OSError, subprocess.SubprocessError) as error:
            raise CertificateReloadError("Échec du rechargement Nginx.") from error


def peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise HelperAuthorizationError("SO_PEERCRED est indisponible.")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


class CertificateInstallProcessor:
    def __init__(
        self,
        *,
        hostname: str,
        output_dir: Path,
        credentials_file: Path,
        admin_state_file: Path | None = None,
        allowed_uid: int,
        allowed_gid: int,
        reload_callback: Callable[[], None] | None = None,
    ) -> None:
        if not hostname:
            raise ValueError("FORTIOS_TLS_HOSTNAME doit être configuré.")
        if allowed_uid <= 0 or allowed_gid <= 0:
            raise ValueError("PUID et PGID doivent être strictement supérieurs à zéro.")
        self.hostname = hostname
        self.output_dir = output_dir
        self.credentials_file = credentials_file
        self.admin_state_file = admin_state_file
        cert_admin.ensure_credential_lock(credentials_file)
        self.allowed_uid = allowed_uid
        self.allowed_gid = allowed_gid
        self.reload_callback = reload_callback

    def install(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.reload_callback is None:
            return install_uploaded_certificate(payload, self.hostname, self.output_dir)

        fullchain = self.output_dir / "fullchain.pem"
        private_key = self.output_dir / "privkey.pem"
        try:
            previous_fullchain = fullchain.read_bytes()
            previous_private_key = private_key.read_bytes()
        except OSError as error:
            raise RuntimeError(
                "Une paire TLS active est requise avant d'autoriser le rechargement Nginx."
            ) from error

        summary = install_uploaded_certificate(payload, self.hostname, self.output_dir)
        try:
            self.reload_callback()
        except Exception:
            owner = certctl.configured_runtime_owner()
            runtime_gid = owner[1] if owner is not None else None
            with certctl.certificate_directory_lock(
                self.output_dir.parent,
                exclusive=True,
                create=True,
                runtime_gid=runtime_gid,
            ):
                certctl.activate_version(
                    self.output_dir,
                    previous_fullchain,
                    previous_private_key,
                    owner,
                )
            try:
                self.reload_callback()
            except Exception as rollback_error:
                raise RuntimeError(
                    "Échec du rechargement Nginx et du rechargement après rollback."
                ) from rollback_error
            raise
        return summary

    def process(self, message: dict[str, Any], *, peer_uid: int, peer_gid: int) -> dict[str, Any]:
        if message.get("version") != PROTOCOL_VERSION:
            raise ProtocolError("Version du protocole helper invalide.")
        action = message.get("action")
        if action == "ping":
            if set(message) != {"version", "action"}:
                raise ProtocolError("Requête ping invalide.")
            if peer_uid not in {0, self.allowed_uid}:
                raise HelperAuthorizationError("Processus pair non autorisé.")
            return {"ok": True, "version": PROTOCOL_VERSION}
        if peer_uid != self.allowed_uid or peer_gid != self.allowed_gid:
            raise HelperAuthorizationError("Processus pair non autorisé.")
        if action == "setup":
            allowed = {"version", "action", "username", "password"}
            if set(message) not in (allowed, allowed | {"recoveryEmail"}):
                raise ProtocolError("Requête de configuration invalide.")
            username = message.get("username")
            password = message.get("password")
            recovery_email = message.get("recoveryEmail")
            if not isinstance(username, str) or not isinstance(password, str):
                raise ProtocolError("Champs de configuration invalides.")
            if recovery_email is not None and not isinstance(recovery_email, str):
                raise ProtocolError("Adresse email de récupération invalide.")
            revision = cert_admin.create_initial_credentials(
                self.credentials_file,
                username,
                password,
                recovery_email=recovery_email,
                state_file=self.admin_state_file,
            )
            return {"ok": True, "credentialsRevision": revision}
        if action == "rotate":
            required = {
                "version",
                "action",
                "username",
                "currentPassword",
                "newPassword",
                "confirmation",
                "credentialsRevision",
            }
            if set(message) != required:
                raise ProtocolError("Requête de rotation invalide.")
            fields = (
                message.get("username"),
                message.get("currentPassword"),
                message.get("newPassword"),
                message.get("confirmation"),
                message.get("credentialsRevision"),
            )
            if any(not isinstance(value, str) for value in fields):
                raise ProtocolError("Champs de rotation invalides.")
            revision = cert_admin.rotate_credentials(
                self.credentials_file,
                str(fields[0]),
                str(fields[1]),
                str(fields[2]),
                str(fields[3]),
                expected_revision=str(fields[4]),
                state_file=self.admin_state_file,
            )
            return {"ok": True, "credentialsRevision": revision}
        if action == "set_recovery_email":
            required = {"version", "action", "email", "credentialsRevision"}
            if set(message) != required or not isinstance(message.get("email"), str):
                raise ProtocolError("Requête de récupération invalide.")
            revision = message.get("credentialsRevision")
            if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}", revision):
                raise ProtocolError("Révision des identifiants invalide.")
            cert_admin.set_recovery_email(
                self.credentials_file,
                message["email"],
                self.admin_state_file,
                expected_revision=revision,
            )
            return {"ok": True}
        if action in {"issue_verification", "issue_reset"}:
            required = {
                "version",
                "action",
                "credentialsRevision",
                "recoveryEmail",
            }
            if set(message) != required:
                raise ProtocolError("Requête d'émission de token invalide.")
            revision = message.get("credentialsRevision")
            if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}", revision):
                raise ProtocolError("Révision des identifiants invalide.")
            recovery_email = message.get("recoveryEmail")
            if not isinstance(recovery_email, str):
                raise ProtocolError("Adresse email de récupération invalide.")
            if action == "issue_verification":
                token = cert_admin.issue_verification_token(
                    self.credentials_file,
                    state_file=self.admin_state_file,
                    expected_revision=revision,
                    expected_recovery_email=recovery_email,
                )
                purpose = cert_admin.RECOVERY_PURPOSE_VERIFY
            else:
                token = cert_admin.issue_password_reset_token(
                    self.credentials_file,
                    state_file=self.admin_state_file,
                    expected_revision=revision,
                    expected_recovery_email=recovery_email,
                )
                purpose = cert_admin.RECOVERY_PURPOSE_RESET
            state = cert_admin.load_admin_state(
                self.credentials_file,
                self.admin_state_file,
            )
            record = next(record for record in state["tokens"] if record["purpose"] == purpose)
            return {"ok": True, "token": token, "expiresAt": record["expiresAt"]}
        if action == "verify_recovery":
            required = {"version", "action", "token", "credentialsRevision"}
            if set(message) != required:
                raise ProtocolError("Requête de vérification invalide.")
            token = message.get("token")
            revision = message.get("credentialsRevision")
            if (
                not isinstance(token, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", token)
                or not isinstance(revision, str)
                or not re.fullmatch(r"[0-9a-f]{64}", revision)
            ):
                raise ProtocolError("Requête de vérification invalide.")
            cert_admin.consume_verification_token(
                self.credentials_file,
                token,
                state_file=self.admin_state_file,
                expected_revision=revision,
            )
            return {"ok": True, "verified": True}
        if action == "reset_password":
            required = {
                "version",
                "action",
                "token",
                "newPassword",
                "confirmation",
                "credentialsRevision",
            }
            if set(message) != required or not all(
                isinstance(message.get(name), str)
                for name in ("token", "newPassword", "confirmation", "credentialsRevision")
            ):
                raise ProtocolError("Requête de réinitialisation invalide.")
            token = message["token"]
            revision = message["credentialsRevision"]
            if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", token) or not re.fullmatch(
                r"[0-9a-f]{64}", revision
            ):
                raise ProtocolError("Requête de réinitialisation invalide.")
            new_revision = cert_admin.reset_credentials_with_token(
                self.credentials_file,
                token,
                message["newPassword"],
                message["confirmation"],
                state_file=self.admin_state_file,
                expected_revision=revision,
            )
            return {"ok": True, "credentialsRevision": new_revision}
        if action != "install" or set(message) != {
            "version",
            "action",
            "credentialsRevision",
            "payload",
        }:
            raise ProtocolError("Opération helper interdite.")
        payload = message.get("payload")
        if not isinstance(payload, dict) or set(payload) != _ALLOWED_PAYLOAD_KEYS:
            raise ProtocolError("Payload d'installation invalide.")
        if any(not isinstance(payload[key], str) for key in _ALLOWED_PAYLOAD_KEYS):
            raise ProtocolError("Les champs du certificat doivent être textuels.")
        requested_revision = message.get("credentialsRevision")
        if not isinstance(requested_revision, str) or len(requested_revision) != 64:
            raise ProtocolError("Révision des identifiants invalide.")
        with cert_admin.credential_lock(self.credentials_file, exclusive=False):
            current_revision = cert_admin.credentials_revision(self.credentials_file)
            if not hmac.compare_digest(requested_revision, current_revision):
                raise HelperAuthorizationError("Les identifiants administrateur ont été modifiés.")
            summary = self.install(payload)
        return {"ok": True, "summary": summary}


class _CertificateRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        connection = self.request
        connection.settimeout(REQUEST_TIMEOUT_SECONDS)
        try:
            _, peer_uid, peer_gid = peer_credentials(connection)
            message = receive_message(connection, maximum_bytes=MAX_REQUEST_BYTES)
            response = self.server.processor.process(  # type: ignore[attr-defined]
                message,
                peer_uid=peer_uid,
                peer_gid=peer_gid,
            )
        except cert_admin.CredentialExistsError as error:
            response = {
                "ok": False,
                "error": str(error)[:1000],
                "errorCode": "credentials_exists",
            }
        except cert_admin.CredentialAuthenticationError as error:
            response = {
                "ok": False,
                "error": str(error)[:1000],
                "errorCode": "authentication_failed",
            }
        except cert_admin.CredentialValidationError as error:
            response = {
                "ok": False,
                "error": str(error)[:1000],
                "errorCode": "validation_failed",
            }
        except cert_admin.CredentialRevisionError as error:
            response = {
                "ok": False,
                "error": str(error)[:1000],
                "errorCode": "credentials_changed",
            }
        except cert_admin.CredentialError as error:
            response = {
                "ok": False,
                "error": str(error)[:1000],
                "errorCode": "credentials_invalid",
            }
        except (
            ProtocolError,
            HelperAuthorizationError,
            CertificateReloadError,
            certctl.CertificateError,
            ValueError,
            OSError,
        ) as error:
            # This redacts a temporary path from an error; it never opens that path.
            message = re.sub(r"/tmp/fortios-[^\s:]+", "<upload>", str(error))  # nosec B108
            response = {"ok": False, "error": message[:1000]}
        except Exception as error:  # noqa: BLE001 - never disclose internal failures to the web process
            print(f"Erreur interne du helper certificat: {type(error).__name__}", file=sys.stderr)
            response = {"ok": False, "error": "Erreur interne du helper certificat."}
        try:
            send_message(connection, response, maximum_bytes=MAX_RESPONSE_BYTES)
        except (ProtocolError, OSError):
            return


class CertificateHelperServer(socketserver.UnixStreamServer):
    request_queue_size = 4

    def __init__(
        self,
        socket_path: Path,
        processor: CertificateInstallProcessor,
        *,
        socket_gid: int | None = None,
    ) -> None:
        if not socket_path.is_absolute():
            raise ValueError("Le chemin du socket helper doit être absolu.")
        self.socket_path = socket_path
        self.processor = processor
        self._socket_identity: tuple[int, int] | None = None
        self._prepare_socket_directory(socket_gid)
        self._remove_stale_socket()
        super().__init__(str(socket_path), _CertificateRequestHandler)
        if socket_gid is not None:
            os.chown(socket_path, 0, socket_gid)
        socket_path.chmod(0o660)
        current = socket_path.stat()
        self._socket_identity = (current.st_dev, current.st_ino)

    def _prepare_socket_directory(self, socket_gid: int | None) -> None:
        directory = self.socket_path.parent
        try:
            current = directory.lstat()
        except FileNotFoundError as error:
            raise ValueError("Le répertoire du socket helper doit exister.") from error
        if (
            not stat.S_ISDIR(current.st_mode)
            or directory.is_symlink()
            or current.st_uid not in {0, os.geteuid()}
        ):
            raise ValueError("Le répertoire du socket helper n'est pas un répertoire géré sûr.")
        if socket_gid is not None:
            os.chown(directory, 0, socket_gid)
        directory.chmod(0o750)

    def _remove_stale_socket(self) -> None:
        try:
            current = self.socket_path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(current.st_mode) or current.st_uid not in {0, os.geteuid()}:
            raise ValueError("Le chemin du helper existe et n'est pas un socket géré sûr.")
        self.socket_path.unlink()

    def server_close(self) -> None:
        super().server_close()
        try:
            current = self.socket_path.lstat()
        except FileNotFoundError:
            return
        if self._socket_identity == (current.st_dev, current.st_ino) and stat.S_ISSOCK(current.st_mode):
            self.socket_path.unlink()

    def handle_error(self, request: Any, client_address: Any) -> None:
        print("Erreur de traitement isolée dans le helper certificat.", file=sys.stderr)


def renew_from_lineage(processor: CertificateInstallProcessor, lineage: Path) -> dict[str, Any]:
    """Activate a Certbot renewal through the same validator and rollback as the UI.

    Called only by the host-root CLI, never exposed as a socket operation. The
    exclusive account lock serializes renewal with web activation and rotation.
    """
    payload = {
        "certificateBase64": base64.b64encode((lineage / "fullchain.pem").read_bytes()).decode("ascii"),
        "privateKeyBase64": base64.b64encode((lineage / "privkey.pem").read_bytes()).decode("ascii"),
        "chainBase64": "",
        "password": "",
    }
    with cert_admin.credential_lock(processor.credentials_file, exclusive=True):
        return processor.install(payload)


def positive_identifier(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise ValueError("L'identifiant doit être strictement supérieur à zéro.")
    return parsed


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("serve")
    subparsers.add_parser("ping")
    subparsers.add_parser("renew")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    socket_path = Path(os.environ.get("FORTIOS_CERT_HELPER_SOCKET", str(DEFAULT_SOCKET)))
    if args.command == "ping":
        response = request_helper(
            socket_path,
            {"version": PROTOCOL_VERSION, "action": "ping"},
            timeout_seconds=5,
            response_timeout_seconds=5,
        )
        return 0 if response.get("ok") is True else 1
    if os.geteuid() != 0:
        print("Le service helper certificat doit être exécuté en root.", file=sys.stderr)
        return 77
    try:
        uid = positive_identifier(os.environ.get("PUID", "1000"))
        gid = positive_identifier(os.environ.get("PGID", "1000"))
        processor = CertificateInstallProcessor(
            hostname=os.environ.get("FORTIOS_TLS_HOSTNAME", "").strip(),
            output_dir=Path(os.environ.get("FORTIOS_CERT_OUTPUT_DIR", str(DEFAULT_OUTPUT))),
            credentials_file=Path(
                os.environ.get("FORTIOS_CERT_ADMIN_FILE", str(DEFAULT_CREDENTIALS)),
            ),
            admin_state_file=(
                Path(os.environ["FORTIOS_CERT_ADMIN_STATE_FILE"])
                if os.environ.get("FORTIOS_CERT_ADMIN_STATE_FILE")
                else None
            ),
            allowed_uid=uid,
            allowed_gid=gid,
            reload_callback=(
                NginxReloader()
                if os.environ.get("FORTIOS_CERT_RELOAD_NGINX") == "1"
                else None
            ),
        )
        if args.command == "renew":
            lineage = os.environ.get("RENEWED_LINEAGE", "")
            if not lineage or processor.reload_callback is None:
                raise ValueError("RENEWED_LINEAGE et le rechargement Nginx sont requis.")
            renew_from_lineage(processor, Path(lineage))
            return 0
        server = CertificateHelperServer(socket_path, processor, socket_gid=gid)
    except (OSError, ValueError) as error:
        print(f"Configuration du helper certificat invalide: {error}", file=sys.stderr)
        return 78
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))