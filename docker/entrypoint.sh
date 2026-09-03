#!/bin/sh
set -eu

PUID="${PUID:-1000}"
PGID="${PGID:-1000}"

case "$PUID" in
  '' | *[!0-9]*) echo "PUID must be a non-zero numeric value." >&2; exit 64 ;;
esac
case "$PGID" in
  '' | *[!0-9]*) echo "PGID must be a non-zero numeric value." >&2; exit 64 ;;
esac
if [ "$PUID" -eq 0 ] || [ "$PGID" -eq 0 ]; then
  echo "PUID and PGID must be greater than zero." >&2
  exit 64
fi

# Bind mounts are commonly created as root by Docker/Portainer. Prepare only
# the persistent paths, then run every application process without root.
mkdir -p /opt/fortios/data/advisory-images /opt/fortios/docs
chown -R "$PUID:$PGID" /opt/fortios/data /opt/fortios/docs
if [ -z "${FORTIOS_CERT_HELPER_SOCKET:-}" ]; then
  ADMIN_CREDENTIALS="${FORTIOS_CERT_ADMIN_FILE:-/opt/fortios/certificates/admin/credentials.json}"
  ADMIN_DIR="$(dirname "$ADMIN_CREDENTIALS")"
  mkdir -p "$ADMIN_DIR"
  chown -R "0:$PGID" /opt/fortios/certificates
  chown "0:$PGID" "$ADMIN_DIR"
  chmod -R u=rwX,g=rX,o= /opt/fortios/certificates
  chmod 0770 "$ADMIN_DIR"
  # Older installations may have credentials without the lock introduced later.
  # Recreate only that coordination file; credentials and active/ remain untouched.
  if [ -e "$ADMIN_CREDENTIALS" ]; then
    PGID="$PGID" python -c 'import sys; from pathlib import Path; from scripts.cert_admin import ensure_credential_lock; ensure_credential_lock(Path(sys.argv[1]))' "$ADMIN_CREDENTIALS"
  fi
elif [ ! -d /opt/fortios/certificates ]; then
  echo "The read-only certificate volume is unavailable." >&2
  exit 78
fi

exec gosu "$PUID:$PGID" "$@"
