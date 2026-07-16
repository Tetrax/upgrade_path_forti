#!/usr/bin/env bash
# À exécuter avec sudo depuis la racine du repo, une fois les fichiers de ce
# dossier relus. Installe/actualise le service systemd et le bloc nginx.
# Idempotent : peut être relancé après chaque modif de config (ex: client_max_body_size)
# sans jamais dupliquer de bloc nginx ni laisser le service tourner avec du code obsolète.
set -euo pipefail

REPO_ROOT="/home/tetrax/workspace/upgrade_path"
NGINX_SITE_NAME="fortios-upgrade-intelligence.conf"
NGINX_AVAILABLE="/etc/nginx/sites-available/$NGINX_SITE_NAME"
NGINX_ENABLED="/etc/nginx/sites-enabled/$NGINX_SITE_NAME"
LEGACY_MARKER="# FortiOS Upgrade Intelligence"

# Fail fast, before touching anything (venv, systemd units, service restart, nginx file) — this
# script's actual effect must be all-or-nothing: either it fully applies, or nothing does.
if grep -q "$LEGACY_MARKER" /etc/nginx/sites-available/default 2>/dev/null; then
  echo "ERREUR : un bloc FortiOS Upgrade Intelligence existe encore dans" >&2
  echo "  /etc/nginx/sites-available/default (installé par une ancienne version de ce script)." >&2
  echo "  Il ferait doublon avec $NGINX_AVAILABLE (même port, même server_name) — nginx pourrait" >&2
  echo "  ignorer silencieusement la config dédiée (client_max_body_size et le reste)." >&2
  echo >&2
  echo "  Ce script ne le retire pas automatiquement (ce fichier est partagé avec d'autres apps" >&2
  echo "  sur ce VPS — FortiFlow, Ideabox... — et une suppression scriptée mal ciblée y casserait" >&2
  echo "  leur config)." >&2
  echo >&2
  echo "  À faire à la main : ouvrir /etc/nginx/sites-available/default, retirer le bloc" >&2
  echo "  \"$LEGACY_MARKER\" ... jusqu'à son accolade fermante, en laissant tout le reste" >&2
  echo "  intact, puis relancer ce script." >&2
  exit 1
fi

VENV_DIR="$REPO_ROOT/.venv-compat"
if [ ! -x "$VENV_DIR/bin/python3" ]; then
  echo "Provisioning $VENV_DIR (pdfplumber, requis par l'import automatique de la matrice de compatibilité FortiClient/EMS)..."
  sudo -u tetrax /home/tetrax/.local/bin/uv venv "$VENV_DIR" --python 3.12
  sudo -u tetrax /home/tetrax/.local/bin/uv pip install --python "$VENV_DIR/bin/python" pdfplumber
fi

install -m 644 "$REPO_ROOT/deploy/fortios-upgrade.service" /etc/systemd/system/fortios-upgrade.service
install -m 644 "$REPO_ROOT/deploy/fortios-catalog-refresh.service" /etc/systemd/system/fortios-catalog-refresh.service
install -m 644 "$REPO_ROOT/deploy/fortios-catalog-refresh.timer" /etc/systemd/system/fortios-catalog-refresh.timer
systemctl daemon-reload

# enable --now is a no-op if already enabled/running; restart unconditionally afterwards so a
# config or code change (this run's whole point, e.g. client_max_body_size) always actually
# reaches the running process instead of silently waiting for someone to notice and do it by
# hand (see docs/last_report.md history — that happened at least once).
systemctl enable --now fortios-upgrade.service
systemctl restart fortios-upgrade.service
systemctl enable --now fortios-catalog-refresh.timer
systemctl restart fortios-catalog-refresh.timer
systemctl status --no-pager fortios-upgrade.service
systemctl list-timers --no-pager fortios-catalog-refresh.timer

# Own dedicated file, always overwritten in place — this is what makes re-running this script
# actually pick up a config change (client_max_body_size and similar), unlike the old approach
# of appending into sites-available/default only once and skipping every run after.
install -m 644 "$REPO_ROOT/deploy/nginx-fortios-upgrade.conf" "$NGINX_AVAILABLE"
ln -sf "$NGINX_AVAILABLE" "$NGINX_ENABLED"

nginx -t
systemctl reload nginx

echo "OK — https://valdev.me:3001/app/"
