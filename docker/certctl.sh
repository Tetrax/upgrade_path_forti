#!/bin/sh
set -eu

# docker exec starts as root because the image must prepare arbitrary PUID/PGID
# mounts. certctl safely normalizes the material, keeps it root-owned and grants
# read-only access to the configured runtime group before atomic activation.
exec python /opt/fortios/scripts/certctl.py "$@"
