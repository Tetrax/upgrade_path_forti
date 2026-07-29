#!/usr/bin/env python3
"""Install and validate TLS certificates for the FortiOS web service."""

from __future__ import annotations

import argparse
import os
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from tls_lock import certificate_directory_lock


class CertificateError(RuntimeError):
    """A certificate cannot be validated or installed safely."""


CERTIFICATE_BLOCK_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----\s*",
    re.DOTALL,
)


def _openssl_result(
    *args: str,
    input_data: bytes | None = None,
    password: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    command = ["openssl", *args]
    if password is None:
        return subprocess.run(command, input=input_data, capture_output=True, check=False)

    read_descriptor, write_descriptor = os.pipe()
    try:
        os.write(write_descriptor, password + b"\n")
        os.close(write_descriptor)
        write_descriptor = -1
        command.extend(["-passin", f"fd:{read_descriptor}"])
        return subprocess.run(
            command,
            input=input_data,
            capture_output=True,
            check=False,
            pass_fds=(read_descriptor,),
        )
    finally:
        if write_descriptor >= 0:
            os.close(write_descriptor)
        os.close(read_descriptor)


def run_openssl(
    *args: str,
    input_data: bytes | None = None,
    password: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    result = _openssl_result(*args, input_data=input_data, password=password)
    if result.returncode:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise CertificateError(message or f"OpenSSL failed: {' '.join(args)}")
    return result


def public_key_from_certificate(path: Path) -> bytes:
    pem = run_openssl("x509", "-in", str(path), "-pubkey", "-noout").stdout
    return run_openssl("pkey", "-pubin", "-outform", "DER", input_data=pem).stdout


def private_key_arguments(path: Path, password_file: Path | None = None) -> list[str]:
    arguments = ["pkey", "-in", str(path)]
    if password_file:
        arguments.extend(["-passin", f"file:{password_file}"])
    return arguments


def public_key_from_private_key(
    path: Path,
    password_file: Path | None = None,
    password: bytes | None = None,
) -> bytes:
    return run_openssl(
        *private_key_arguments(path, password_file),
        "-pubout",
        "-outform",
        "DER",
        password=password,
    ).stdout


def normalize_certificate_blocks(data: bytes) -> list[bytes]:
    blocks = CERTIFICATE_BLOCK_RE.findall(data)
    normalized: list[bytes] = []
    for block in blocks:
        normalized.append(
            run_openssl(
                "x509", "-inform", "PEM", "-outform", "PEM", input_data=block,
            ).stdout
        )
    return normalized


def normalized_chain(path: Path) -> list[bytes]:
    blocks = CERTIFICATE_BLOCK_RE.findall(path.read_bytes())
    if blocks:
        return normalize_certificate_blocks(path.read_bytes())
    for encoding in ("DER", "PEM"):
        result = subprocess.run(
            ["openssl", "pkcs7", "-in", str(path), "-inform", encoding, "-print_certs"],
            capture_output=True,
            check=False,
        )
        blocks = CERTIFICATE_BLOCK_RE.findall(result.stdout)
        if result.returncode == 0 and blocks:
            return normalize_certificate_blocks(result.stdout)
    try:
        return [run_openssl("x509", "-in", str(path), "-outform", "PEM").stdout]
    except CertificateError as error:
        raise CertificateError(f"Chaîne de certificats non reconnue : {path}") from error


def validate_certificate_dates(certificate: bytes, label: str) -> None:
    run_openssl("x509", "-noout", "-checkend", "0", input_data=certificate)
    start = run_openssl("x509", "-noout", "-startdate", input_data=certificate).stdout
    try:
        not_before = start.decode("ascii").strip().split("=", 1)[1]
        starts_at = ssl.cert_time_to_seconds(not_before)
    except (IndexError, UnicodeDecodeError, ValueError) as error:
        raise CertificateError(f"Date de début invalide pour {label}.") from error
    if starts_at > time.time():
        raise CertificateError(f"Le certificat {label} n'est pas encore valide.")


def certificate_name(certificate: bytes, field: str) -> bytes:
    result = run_openssl(
        "x509", "-noout", f"-{field}", "-nameopt", "RFC2253", input_data=certificate,
    ).stdout.strip()
    return result.split(b"=", 1)[1] if b"=" in result else result


def order_chain(leaf: bytes, chain: list[bytes]) -> list[bytes]:
    if leaf in chain or len(set(chain)) != len(chain):
        raise CertificateError("La chaîne contient le certificat feuille ou un doublon.")
    remaining = list(chain)
    ordered: list[bytes] = []
    current = leaf
    while remaining:
        issuer = certificate_name(current, "issuer")
        matches = [
            certificate
            for certificate in remaining
            if certificate_name(certificate, "subject") == issuer
        ]
        if len(matches) != 1:
            raise CertificateError("La chaîne est ambiguë ou ne correspond pas au certificat.")
        current = matches[0]
        remaining.remove(current)
        ordered.append(current)
    return ordered


def validate_chain(leaf: bytes, chain: list[bytes]) -> list[bytes]:
    chain = order_chain(leaf, chain) if chain else []
    certificates = [leaf, *chain]
    for index, certificate in enumerate(certificates):
        validate_certificate_dates(certificate, "feuille" if index == 0 else f"de chaîne {index}")
    for child, issuer in zip(certificates, certificates[1:]):
        if certificate_name(child, "issuer") != certificate_name(issuer, "subject"):
            raise CertificateError("La chaîne n'est pas ordonnée ou ne correspond pas au certificat.")

    with tempfile.TemporaryDirectory(prefix="fortios-chain-") as temporary:
        directory = Path(temporary)
        leaf_path = directory / "leaf.pem"
        trusted_path = directory / "trusted.pem"
        leaf_path.write_bytes(leaf)
        trusted_path.write_bytes(chain[-1] if chain else leaf)
        arguments = [
            "verify", "-partial_chain", "-purpose", "sslserver",
            "-trusted", str(trusted_path),
        ]
        if len(chain) > 1:
            intermediates = directory / "intermediates.pem"
            intermediates.write_bytes(b"".join(chain[:-1]))
            arguments.extend(["-untrusted", str(intermediates)])
        run_openssl(*arguments, str(leaf_path))
    return chain


def write_durable(path: Path, data: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def cleanup_pkcs12_directory(path: Path) -> None:
    shutil.rmtree(path)


def configured_runtime_owner() -> tuple[int, int] | None:
    if os.geteuid() != 0 or not (os.environ.get("PUID") or os.environ.get("PGID")):
        return None
    try:
        uid = int(os.environ.get("PUID", "1000"))
        gid = int(os.environ.get("PGID", "1000"))
    except ValueError as error:
        raise CertificateError("PUID et PGID doivent être numériques.") from error
    if uid <= 0 or gid <= 0:
        raise CertificateError("PUID et PGID doivent être strictement supérieurs à zéro.")
    return uid, gid


def activate_version(
    output_dir: Path,
    fullchain_data: bytes,
    private_key_data: bytes,
    owner: tuple[int, int] | None,
) -> None:
    active_pattern = re.compile(rf"\.{re.escape(output_dir.name)}-[0-9a-f]{{16}}")
    link_pattern = re.compile(rf"\.{re.escape(output_dir.name)}-link-[0-9a-f]{{16}}")
    previous_version: str | None = None
    if output_dir.is_symlink():
        current_target = os.readlink(output_dir)
        if Path(current_target).is_absolute() or not active_pattern.fullmatch(current_target):
            raise CertificateError("Le lien actif existant n'est pas géré par certctl.")
        previous_path = output_dir.parent / current_target
        if previous_path.is_symlink() or not previous_path.is_dir():
            raise CertificateError("La version TLS active n'est pas un répertoire géré valide.")
        previous_version = current_target
    elif output_dir.exists():
        raise CertificateError(f"Le chemin de sortie existe et n'est pas un lien géré : {output_dir}")

    for candidate in output_dir.parent.iterdir():
        if (
            active_pattern.fullmatch(candidate.name)
            and candidate.name != previous_version
            and candidate.is_dir()
            and not candidate.is_symlink()
        ):
            shutil.rmtree(candidate)
        elif link_pattern.fullmatch(candidate.name) and candidate.is_symlink():
            candidate.unlink()
    fsync_directory(output_dir.parent)

    version_dir = output_dir.parent / f".{output_dir.name}-{secrets.token_hex(8)}"
    temporary_link = output_dir.parent / f".{output_dir.name}-link-{secrets.token_hex(8)}"
    version_dir.mkdir(mode=0o700)
    activated = False
    try:
        fullchain = version_dir / "fullchain.pem"
        privkey = version_dir / "privkey.pem"
        write_durable(fullchain, fullchain_data, 0o644)
        write_durable(privkey, private_key_data, 0o600)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(fullchain, privkey)

        if owner is not None:
            _, runtime_gid = owner
            os.chown(fullchain, 0, runtime_gid)
            os.chown(privkey, 0, runtime_gid)
            os.chown(version_dir, 0, runtime_gid)
            fullchain.chmod(0o640)
            privkey.chmod(0o640)
            version_dir.chmod(0o750)
        fsync_directory(version_dir)

        temporary_link.symlink_to(version_dir.name, target_is_directory=True)
        os.replace(temporary_link, output_dir)
        activated = True
    except Exception:
        temporary_link.unlink(missing_ok=True)
        if not activated:
            shutil.rmtree(version_dir, ignore_errors=True)
        raise

    post_commit_warning = False
    try:
        fsync_directory(output_dir.parent)
    except Exception:
        post_commit_warning = True
    if previous_version is not None:
        try:
            shutil.rmtree(output_dir.parent / previous_version)
        except Exception:
            post_commit_warning = True
    try:
        fsync_directory(output_dir.parent)
    except Exception:
        post_commit_warning = True
    if post_commit_warning:
        print(
            "Avertissement : certificat activé, mais le nettoyage ou la synchronisation durable "
            "de l'ancienne génération a échoué.",
            file=sys.stderr,
        )


def install_pem(
    source: Path,
    key: Path,
    hostname: str,
    output_dir: Path,
    chain: Path | None = None,
    password_file: Path | None = None,
    password: bytes | None = None,
) -> None:
    run_openssl("x509", "-in", str(source), "-noout")
    normalized_certificate = run_openssl(
        "x509", "-in", str(source), "-outform", "PEM",
    ).stdout
    validate_certificate_dates(normalized_certificate, "feuille")
    san = subprocess.run(
        ["openssl", "x509", "-in", str(source), "-noout", "-ext", "subjectAltName"],
        capture_output=True,
        check=False,
    )
    if san.returncode != 0 or b"DNS:" not in san.stdout:
        raise CertificateError("Le certificat doit contenir un SAN DNS.")
    run_openssl("x509", "-in", str(source), "-noout", "-checkhost", hostname)
    if public_key_from_certificate(source) != public_key_from_private_key(
        key,
        password_file,
        password,
    ):
        raise CertificateError("La clé privée ne correspond pas au certificat.")

    source_blocks = normalize_certificate_blocks(source.read_bytes())
    chain_certificates = source_blocks[1:]
    if chain:
        chain_certificates.extend(normalized_chain(chain))
    chain_certificates = validate_chain(normalized_certificate, chain_certificates)
    normalized_key = run_openssl(
        *private_key_arguments(key, password_file),
        password=password,
    ).stdout

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    owner = configured_runtime_owner()
    runtime_gid = owner[1] if owner is not None else None
    with certificate_directory_lock(
        output_dir.parent, exclusive=True, create=True, runtime_gid=runtime_gid,
    ):
        activate_version(
            output_dir,
            normalized_certificate + b"".join(chain_certificates),
            normalized_key,
            owner,
        )


def install_certificate(
    source: Path,
    key: Path | None,
    hostname: str,
    output_dir: Path,
    password_file: Path | None = None,
    chain: Path | None = None,
    password: bytes | None = None,
) -> None:
    if password_file is not None and password is not None:
        raise CertificateError("Le mot de passe doit être fourni par fichier ou en mémoire, pas les deux.")
    if key is not None:
        install_pem(source, key, hostname, output_dir, chain, password_file, password)
        return

    if chain is not None:
        raise CertificateError("--chain ne peut pas être combiné avec un bundle PKCS#12.")

    passin = f"file:{password_file}" if password_file else "pass:"
    temporary_dir = Path(tempfile.mkdtemp(prefix="fortios-certctl-"))
    activated = False
    try:
        leaf = temporary_dir / "leaf.pem"
        chain_file = temporary_dir / "chain.pem"
        private_key = temporary_dir / "private-key.pem"
        password_arguments = [] if password is not None else ["-passin", passin]
        run_openssl(
            "pkcs12",
            "-in",
            str(source),
            "-clcerts",
            "-nokeys",
            "-out",
            str(leaf),
            *password_arguments,
            password=password,
        )
        chain_result = _openssl_result(
            "pkcs12",
            "-in",
            str(source),
            "-cacerts",
            "-nokeys",
            "-out",
            str(chain_file),
            *password_arguments,
            password=password,
        )
        chain = (
            chain_file
            if chain_result.returncode == 0
            and CERTIFICATE_BLOCK_RE.search(chain_file.read_bytes())
            else None
        )
        raw_key = run_openssl(
            "pkcs12",
            "-in",
            str(source),
            "-nocerts",
            "-nodes",
            *password_arguments,
            password=password,
        ).stdout
        private_key.write_bytes(raw_key)
        private_key.chmod(0o600)
        install_pem(leaf, private_key, hostname, output_dir, chain)
        activated = True
    finally:
        pending_error = sys.exc_info()[0] is not None
        try:
            cleanup_pkcs12_directory(temporary_dir)
        except OSError:
            if activated:
                print(
                    "Avertissement : certificat activé, mais les données PKCS#12 temporaires "
                    "n'ont pas pu être nettoyées.",
                    file=sys.stderr,
                )
            elif not pending_error:
                raise


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Installer un certificat TLS pour Upgrade Path.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    install = subparsers.add_parser("install", help="Valider et installer un certificat.")
    install.add_argument("source", type=Path)
    install.add_argument("--key", type=Path)
    install.add_argument("--password-file", type=Path)
    install.add_argument("--chain", type=Path)
    install.add_argument("--hostname", required=True)
    install.add_argument("--output-dir", type=Path, default=Path("certificates/active"))
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        install_certificate(
            args.source, args.key, args.hostname, args.output_dir,
            args.password_file, args.chain,
        )
    except (CertificateError, OSError) as error:
        print(f"Erreur certificat : {error}", file=sys.stderr)
        return 1
    print(f"Certificat installé pour {args.hostname} dans {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
