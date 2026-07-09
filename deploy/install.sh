#!/usr/bin/env bash
# À exécuter avec sudo depuis la racine du repo, une fois les fichiers de ce
# dossier relus. Installe le service systemd et ajoute le bloc nginx.
set -euo pipefail

REPO_ROOT="/home/tetrax/workspace/upgrade_path"

install -m 644 "$REPO_ROOT/deploy/fortios-upgrade.service" /etc/systemd/system/fortios-upgrade.service
systemctl daemon-reload
systemctl enable --now fortios-upgrade.service
systemctl status --no-pager fortios-upgrade.service

if ! grep -q "FortiOS Upgrade Intelligence" /etc/nginx/sites-available/default; then
  cat "$REPO_ROOT/deploy/nginx-fortios-upgrade.conf" >> /etc/nginx/sites-available/default
  nginx -t
  systemctl reload nginx
else
  echo "Bloc nginx déjà présent, rien ajouté."
fi

echo "OK — https://valdev.me:3001/app/"
