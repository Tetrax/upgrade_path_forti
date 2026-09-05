#!/bin/sh
# Certbot deploy hook for the FortiUpgrade managed certificate pair only.
# The invoking renewal job must own the shared infrastructure lock across
# authentication and this hook; see docs/certificates.md.
set -eu
[ "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/fortiupgrade.valdev.me ] || exit 0
set -a
. /etc/fortios-cert-helper.env
set +a
exec /usr/bin/python3 /opt/fortios-cert-helper/scripts/cert_helper.py renew
