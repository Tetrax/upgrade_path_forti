# Upgrade Path — Guide opérationnel

> Déploiement initial et mise à jour avec Portainer Repository, image GHCR et HTTPS interne.

Image : `ghcr.io/tetrax/upgrade_path_forti:latest`
Stack : `upgrade-path`
Dépôt public : `https://github.com/Tetrax/upgrade_path_forti`

## 1. Prérequis

### Accès et composants

- VM Linux avec Docker 24 ou plus récent.
- Portainer Community Edition accessible avec un compte administrateur.
- Accès SSH administrateur à la VM.
- Accès sortant vers GitHub et `ghcr.io`.
- Adresse IP fixe et, pour HTTPS, un nom DNS interne.

### Paramètres de référence

| Élément | Valeur |
|---|---|
| Dépôt | `https://github.com/Tetrax/upgrade_path_forti` |
| Branche | `refs/heads/main` |
| Compose | `docker-compose.portainer.yml` |
| Image | `ghcr.io/tetrax/upgrade_path_forti:latest` |
| Services | `web`, `scheduler` |
| Port interne web | `8000` |
| Port hôte initial | `8000` |

> Le dépôt et l’image sont publics. Ne pas construire l’image sur la VM et ne pas importer de fichier TAR.

## 2. Préparer le serveur cible

### Vérifier Docker et Portainer

```bash
docker version
docker ps --filter name=portainer
```

Docker doit répondre et Portainer doit être en cours d’exécution.

### Préparer les répertoires persistants

```bash
mkdir -p /srv/upgrade-path/data \
  /srv/upgrade-path/docs \
  /srv/upgrade-path/certificates
chown -R 1000:1000 /srv/upgrade-path
```

Ces répertoires doivent être conservés lors d’une mise à jour ou d’une recréation de conteneur.

### Vérifier les ports

```bash
ss -tlnp | grep -E ':(8000|443)\b' || true
```

Le port `8000` doit être libre pour l’amorçage HTTP. Le port `443` doit être libre avant l’activation HTTPS.

## 3. Déployer avec Portainer

### Créer la stack Repository

1. Ouvrir Portainer puis **Stacks** → **Add stack**.
2. Nommer la stack `upgrade-path`.
3. Choisir **Repository**.
4. Renseigner :

```text
Repository URL       : https://github.com/Tetrax/upgrade_path_forti
Repository reference : refs/heads/main
Compose path         : docker-compose.portainer.yml
```

> Utiliser exclusivement le mode Repository. Le compose télécharge l’image GHCR ; aucun TAR manuel n’est nécessaire.

### Renseigner les variables

Dans **Environment variables**, ajouter :

```text
PUID=1000
PGID=1000
FORTIOS_HTTP_BIND_ADDRESS=0.0.0.0
FORTIOS_HTTP_PORT=8000
FORTIOS_TLS_CERT=
FORTIOS_TLS_KEY=
FORTIOS_TLS_HOSTNAME=
FORTIOS_RUN_ON_START=0
FORTIOS_EMAIL_ENABLED=false
FORTIOS_APP_URL=http://IP_LAN_VM:8000/app/
FORTIOS_DATA_DIR=/srv/upgrade-path/data
FORTIOS_DOCS_DIR=/srv/upgrade-path/docs
FORTIOS_CERTS_DIR=/srv/upgrade-path/certificates
```

Remplacer `IP_LAN_VM` par l’adresse réelle. Adapter `PUID` et `PGID` si le compte de service n’utilise pas `1000:1000`.

### Déployer

Cliquer **Deploy the stack**. Portainer crée `web` et `scheduler` à partir de la même image.

## 4. Vérifier le déploiement

### Contrôler les conteneurs

Dans Portainer, `web` doit être **running (healthy)** et `scheduler` **running**.

```bash
WEB_CONTAINER="$(docker ps \
  --filter label=com.docker.compose.project=upgrade-path \
  --filter label=com.docker.compose.service=web \
  --format '{{.Names}}')"
test -n "$WEB_CONTAINER"
docker logs --tail 50 "$WEB_CONTAINER"
docker inspect --format '{{.State.Health.Status}}' \
  "$WEB_CONTAINER"
```

Le dernier résultat attendu est `healthy`. Contrôler aussi les logs du service `scheduler` dans Portainer.

### Tester l’application

```bash
curl --fail --silent --show-error \
  http://127.0.0.1:8000/app/ >/dev/null
```

Depuis un poste autorisé, ouvrir `http://IP_LAN_VM:8000/app/`. Limiter ce port au réseau interne pendant l’amorçage.

## 5. Configurer HTTPS

### Installer le certificat dans le conteneur web

Le certificat doit contenir le FQDN dans le SAN, par exemple `upgrade-path.sns-security.lan`. Retrouver d’abord le conteneur comme au chapitre 4.

Pour un PFX/P12 :

```bash
docker cp certificat-interne.pfx \
  "$WEB_CONTAINER":/tmp/certificat.pfx
read -rsp 'Mot de passe PFX : ' PFX_PASSWORD; echo
printf '%s' "$PFX_PASSWORD" | docker exec -i \
  "$WEB_CONTAINER" sh -c \
  'umask 077; cat > /tmp/cert-password'
unset PFX_PASSWORD

docker exec "$WEB_CONTAINER" fortios-certctl install \
  /tmp/certificat.pfx \
  --password-file /tmp/cert-password \
  --hostname upgrade-path.sns-security.lan \
  --output-dir /opt/fortios/certificates/active

docker exec "$WEB_CONTAINER" rm -f \
  /tmp/certificat.pfx /tmp/cert-password
```

Pour un certificat, une clé et une chaîne séparés :

```bash
docker cp serveur.crt "$WEB_CONTAINER":/tmp/serveur.crt
docker cp serveur.key "$WEB_CONTAINER":/tmp/serveur.key
docker cp chaine.p7b "$WEB_CONTAINER":/tmp/chaine.p7b

docker exec "$WEB_CONTAINER" fortios-certctl install \
  /tmp/serveur.crt --key /tmp/serveur.key \
  --chain /tmp/chaine.p7b \
  --hostname upgrade-path.sns-security.lan \
  --output-dir /opt/fortios/certificates/active

docker exec "$WEB_CONTAINER" rm -f \
  /tmp/serveur.crt /tmp/serveur.key /tmp/chaine.p7b
```

Omettre `--chain` si elle n’est pas nécessaire et `--password-file` si le PFX n’a pas de mot de passe.

### Activer HTTPS dans Portainer

Dans les variables de la stack, remplacer les valeurs suivantes :

```text
FORTIOS_HTTP_PORT=443
FORTIOS_TLS_CERT=/opt/fortios/certificates/active/fullchain.pem
FORTIOS_TLS_KEY=/opt/fortios/certificates/active/privkey.pem
FORTIOS_TLS_HOSTNAME=upgrade-path.sns-security.lan
FORTIOS_APP_URL=https://upgrade-path.sns-security.lan/app/
```

Cliquer **Update the stack** sans supprimer les répertoires persistants.

```bash
curl --fail --silent --show-error \
  https://upgrade-path.sns-security.lan/app/ >/dev/null
```

Le poste client doit résoudre le FQDN et faire confiance à la CA interne. L’application utilise un unique listener interne `8000`, en HTTP ou en HTTPS selon les variables TLS.

> Ne jamais stocker une clé privée ou un mot de passe PFX dans Git, l’image ou une variable Portainer.

## 6. Mettre à jour

### Redéployer l’image courante

1. Ouvrir Portainer → **Stacks** → `upgrade-path`.
2. Cliquer **Pull and redeploy**.
3. Confirmer avec **Update**.
4. Attendre que `web` redevienne **healthy** et que `scheduler` soit **running**.

Portainer récupère `ghcr.io/tetrax/upgrade_path_forti:latest` et recrée les deux conteneurs. Les répertoires persistants restent montés.

### Vérifier après mise à jour

```bash
docker inspect --format '{{.State.Health.Status}}' \
  "$WEB_CONTAINER"
docker logs --tail 50 "$WEB_CONTAINER"
```

Tester ensuite l’URL HTTPS et vérifier les logs du scheduler. Pour renouveler le certificat, répéter l’installation du chapitre 5 puis redémarrer uniquement `web`.

## 7. Dépannage

| Symptôme | Vérification ou action |
|---|---|
| Stack non déployée | Vérifier l’URL, `refs/heads/main`, le compose, les chemins hôte et l’accès à `ghcr.io`. |
| `web` non healthy | Lire ses logs et vérifier que les variables TLS sont fournies ensemble. |
| `scheduler` arrêté | Lire ses logs et contrôler les chemins data/docs et les variables email. |
| Certificat refusé | Vérifier SAN, dates, usage serveur, clé correspondante et chaîne. |
| Alerte navigateur | Vérifier DNS, SAN, dates, chaîne et confiance dans la CA interne. |
| HTTP encore exposé | Confirmer `FORTIOS_HTTP_PORT=443` puis mettre à jour la stack. |
| Données absentes | Vérifier les trois chemins `/srv/upgrade-path` et leurs permissions. |
| Image introuvable | Confirmer le nom GHCR et relancer **Pull and redeploy**. |

## 8. Checklist finale

- [ ] Docker et Portainer sont opérationnels.
- [ ] Les trois répertoires persistants existent avec les bons droits.
- [ ] La stack `upgrade-path` utilise le mode Repository.
- [ ] Le dépôt, la branche et le chemin du compose sont exacts.
- [ ] L’image GHCR a été téléchargée sans build ni TAR manuel.
- [ ] `web` est `healthy` et `scheduler` est `running`.
- [ ] L’application répond en HTTP pendant l’amorçage.
- [ ] Le certificat a été validé et installé par `fortios-certctl`.
- [ ] Le FQDN interne résout l’adresse de la VM.
- [ ] HTTPS répond avec un certificat approuvé.
- [ ] Les ports sont limités aux réseaux autorisés.
- [ ] La procédure **Pull and redeploy** → **Update** a été testée.
