#!/usr/bin/env python3
"""Container healthcheck for the HTTP or direct-TLS web listener."""

from __future__ import annotations

import os
import ssl
import sys
import urllib.request
from pathlib import Path

import certctl
from fortios_server import resolve_tls_pair
from tls_lock import managed_pair_lock


def drop_container_root() -> None:
    if os.geteuid() != 0 or os.environ.get("FORTIOS_CONTAINER_HEALTHCHECK") != "1":
        return
    try:
        uid = int(os.environ.get("PUID", "1000"))
        gid = int(os.environ.get("PGID", "1000"))
    except ValueError as error:
        raise RuntimeError("PUID et PGID doivent être numériques.") from error
    if uid <= 0 or gid <= 0:
        raise RuntimeError("PUID et PGID doivent être strictement supérieurs à zéro.")
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)


def validate_tls_material(certificate: Path, key: Path, hostname: str) -> None:
    certificates = certctl.normalize_certificate_blocks(certificate.read_bytes())
    if not certificates:
        raise certctl.CertificateError(
            "Le fullchain TLS ne contient aucun certificat PEM."
        )
    leaf, *chain = certificates
    certctl.validate_certificate_dates(leaf, "feuille")
    certctl.validate_chain(leaf, chain)
    san = certctl.run_openssl(
        "x509",
        "-in",
        str(certificate),
        "-noout",
        "-ext",
        "subjectAltName",
    ).stdout
    if b"DNS:" not in san:
        raise certctl.CertificateError("Le certificat TLS ne contient aucun SAN DNS.")
    certctl.run_openssl(
        "x509",
        "-in",
        str(certificate),
        "-noout",
        "-checkhost",
        hostname,
    )
    if certctl.public_key_from_certificate(
        certificate
    ) != certctl.public_key_from_private_key(key):
        raise certctl.CertificateError(
            "La clé TLS active ne correspond pas au certificat."
        )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, key)


def main() -> int:
    drop_container_root()
    certificate_value = os.environ.get("FORTIOS_TLS_CERT", "")
    key_value = os.environ.get("FORTIOS_TLS_KEY", "")
    if bool(certificate_value) != bool(key_value):
        raise RuntimeError(
            "FORTIOS_TLS_CERT et FORTIOS_TLS_KEY doivent être fournis ensemble."
        )

    scheme = "http"
    context: ssl.SSLContext | None = None
    if certificate_value:
        hostname = os.environ.get("FORTIOS_TLS_HOSTNAME", "").strip()
        if not hostname:
            raise RuntimeError("FORTIOS_TLS_HOSTNAME est obligatoire avec TLS.")
        certificate_arg = Path(certificate_value)
        key_arg = Path(key_value)
        with managed_pair_lock(certificate_arg, key_arg):
            certificate, key = resolve_tls_pair(certificate_arg, key_arg)
            validate_tls_material(certificate, key, hostname)
            scheme = "https"
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

    port = int(os.environ.get("FORTIOS_HEALTHCHECK_PORT", "8000"))
    with urllib.request.urlopen(
        f"{scheme}://127.0.0.1:{port}/app/",
        timeout=5,
        context=context,
    ) as response:
        response.read(1)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # noqa: BLE001
        print(f"Healthcheck failed: {error}", file=sys.stderr)
        raise SystemExit(1)
