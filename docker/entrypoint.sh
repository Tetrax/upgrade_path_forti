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
mkdir -p /opt/fortios/data/advisory-images /opt/fortios/docs /opt/fortios/certificates
chown -R "$PUID:$PGID" /opt/fortios/data /opt/fortios/docs
chown -R "0:$PGID" /opt/fortios/certificates
chmod -R u=rwX,g=rX,o= /opt/fortios/certificates

exec gosu "$PUID:$PGID" "$@"
