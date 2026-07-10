#!/usr/bin/env bash
# À exécuter avec sudo depuis la racine du repo, une fois les fichiers de ce
# dossier relus. Installe le service systemd et ajoute le bloc nginx.
set -euo pipefail

REPO_ROOT="/home/tetrax/workspace/upgrade_path"

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
systemctl enable --now fortios-upgrade.service
systemctl enable --now fortios-catalog-refresh.timer
systemctl status --no-pager fortios-upgrade.service
systemctl list-timers --no-pager fortios-catalog-refresh.timer

if ! grep -q "FortiOS Upgrade Intelligence" /etc/nginx/sites-available/default; then
  cat "$REPO_ROOT/deploy/nginx-fortios-upgrade.conf" >> /etc/nginx/sites-available/default
  nginx -t
  systemctl reload nginx
else
  echo "Bloc nginx déjà présent, rien ajouté."
fi

echo "OK — https://valdev.me:3001/app/"
