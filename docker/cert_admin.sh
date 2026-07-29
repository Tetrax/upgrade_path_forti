#!/bin/sh
set -eu

# docker exec runs as root. cert_admin stores only a salted scrypt derivative and
# grants the configured runtime group read-only access to the resulting file.
exec python /opt/fortios/scripts/cert_admin.py "$@"
