# TLS direct et gestion CLI des certificats

`upgrade_path` peut servir HTTPS directement depuis son conteneur Python, sans
Nginx ni Caddy. Le FQDN cible recommandé est
`upgrade-path.sns-security.lan`; le DNS interne doit le résoudre vers l'IP LAN de
la VM Docker.

Une autorité publique telle que Let's Encrypt ne délivre pas de certificat pour
un domaine `.lan`. Utiliser un certificat de la PKI interne avec un SAN exact
`upgrade-path.sns-security.lan`, ou le wildcard `*.sns-security.lan`. Les postes
clients doivent faire confiance à la CA interne.

## Formats acceptés

Le CLI `scripts/certctl.py` s'appuie sur OpenSSL et normalise l'installation vers
`fullchain.pem` et `privkey.pem` :

- PKCS#12 `.pfx` / `.p12`, protégé ou non par mot de passe ;
- certificat PEM `.pem`, `.crt`, `.cert`, `.cer` avec clé séparée ;
- certificat DER `.der` / `.cer` avec clé séparée ;
- clé privée PEM ou PKCS#8, chiffrée ou non ;
- chaîne PEM, DER ou PKCS#7 `.p7b` / `.p7c` avec `--chain`.

L'extension n'est pas utilisée comme preuve du contenu. Avant installation, le
CLI vérifie le format de chaque certificat, les dates de début et de fin, le
SAN/FQDN, la correspondance certificat/clé et les relations d'émission de la
chaîne. Il charge aussi la paire normalisée dans un contexte TLS Python avant
l'activation atomique. Hors conteneur, la clé normalisée est écrite en mode
`0600`. Dans le conteneur, elle reste propriété de `root`, en mode `0640`, et
n'est lisible que par le PGID du processus applicatif ; ce processus ne peut ni
modifier la clé ni remplacer le lien actif.

## Tester la page `/cert` sans Docker

Le mode local permet de valider le parcours complet dans un navigateur, tout en
bornant l'exception HTTP à un client loopback. Depuis la racine du dépôt :

```bash
python3 scripts/cert_admin.py setup \
  --credentials certificates/local/admin/credentials.json \
  --username admin
```

Le mot de passe est demandé deux fois sans être affiché. Seuls le sel et le
dérivé `scrypt` sont écrits ; sa longueur doit être comprise entre 12 et 1 024
octets UTF-8. Démarrer ensuite le serveur local :

```bash
FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST=1 \
FORTIOS_CERT_DIRECT_INSTALL=1 \
FORTIOS_CERT_ADMIN_FILE=certificates/local/admin/credentials.json \
FORTIOS_CERT_OUTPUT_DIR=certificates/local/active \
FORTIOS_TLS_HOSTNAME=upgrade-path.sns-security.lan \
python3 scripts/fortios_server.py --host 127.0.0.1 --port 8000
```

Ouvrir `http://127.0.0.1:8000/cert/`. La page propose deux actions distinctes :

1. **Valider** : utilise un répertoire temporaire, affiche uniquement les
   métadonnées, ne modifie pas la paire active et délivre un ticket à usage
   unique, lié à la session et au contenu validé pendant 10 minutes ;
2. **Activer** : réexécute toutes les validations de `certctl.py`, puis remplace
   atomiquement `certificates/local/active`. L'API refuse l'activation sans ce
   ticket de prévalidation ou si les fichiers ont changé.

Le mode HTTP est refusé sans `FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST=1` et reste
inaccessible à un client non-loopback. Ces deux drapeaux sont réservés à ce test
local ; ils ne doivent pas être activés dans la Stack Docker. Pour réinitialiser
le compte local :

```bash
python3 scripts/cert_admin.py reset \
  --credentials certificates/local/admin/credentials.json \
  --username admin
```

Une réinitialisation invalide immédiatement toutes les sessions existantes :
les utilisateurs déjà connectés doivent s'authentifier avec le nouveau mot de
passe. Une activation déjà autorisée termine avant le retour de la commande de
réinitialisation ; une activation encore en lecture est rejetée après celle-ci.

En HTTPS, `/cert` est disponible sans l'exception HTTP locale. Les sessions sont
en mémoire, expirent après 30 minutes et utilisent un cookie `HttpOnly`,
`SameSite=Strict` et `Secure` lorsque TLS est actif. Les mutations exigent aussi
un jeton CSRF et une origine exacte. Le listener TLS ajoute également HSTS.

## 1. Déploiement HTTP initial

Déployer d'abord la Stack Portainer avec :

```text
FORTIOS_HTTP_BIND_ADDRESS=0.0.0.0
FORTIOS_HTTP_PORT=8000
FORTIOS_TLS_CERT=
FORTIOS_TLS_KEY=
FORTIOS_TLS_HOSTNAME=
FORTIOS_RUN_ON_START=0
```

Le volume nommé `upgrade-path_fortios-certificates` est alors créé et préparé
par l'entrypoint avec `root` comme propriétaire et le PGID applicatif en lecture.

Sur la VM, retrouver le nom réel du conteneur web :

```bash
WEB_CONTAINER="$(docker ps \
  --filter label=com.docker.compose.project=upgrade-path \
  --filter label=com.docker.compose.service=web \
  --format '{{.Names}}')"
printf 'Conteneur web : %s\n' "$WEB_CONTAINER"
```

La variable ne doit contenir qu'un seul nom. Si elle est vide, vérifier dans
Portainer le nom de la Stack et du service.

Créer ensuite le compte dédié à `/cert` dans le volume persistant. Cette commande
demande et confirme le mot de passe sans l'afficher :

```bash
docker exec -it "$WEB_CONTAINER" fortios-cert-admin setup \
  --credentials /opt/fortios/certificates/admin/credentials.json \
  --username admin
```

Pour une rotation ultérieure, utiliser la même commande avec `reset` à la place
de `setup`. Ne jamais placer le mot de passe dans la ligne de commande.

## 2A. Installer un PFX/P12

Copier l'archive dans le tmpfs du conteneur :

```bash
docker cp ./certificat-interne.pfx "$WEB_CONTAINER":/tmp/certificat.pfx
```

Pour un PFX protégé, transférer le mot de passe par l'entrée standard, jamais en
argument de commande :

```bash
read -rsp 'Mot de passe PFX : ' PFX_PASSWORD; echo
printf '%s' "$PFX_PASSWORD" | docker exec -i "$WEB_CONTAINER" \
  sh -c 'umask 077; cat > /tmp/cert-password'
unset PFX_PASSWORD

docker exec "$WEB_CONTAINER" fortios-certctl install \
  /tmp/certificat.pfx \
  --password-file /tmp/cert-password \
  --hostname upgrade-path.sns-security.lan \
  --output-dir /opt/fortios/certificates/active

docker exec "$WEB_CONTAINER" rm -f /tmp/certificat.pfx /tmp/cert-password
```

Pour un PFX sans mot de passe, omettre `--password-file`.

## 2B. Installer certificat, clé et chaîne séparés

```bash
docker cp ./serveur.crt "$WEB_CONTAINER":/tmp/serveur.crt
docker cp ./serveur.key "$WEB_CONTAINER":/tmp/serveur.key
docker cp ./chaine.p7b "$WEB_CONTAINER":/tmp/chaine.p7b

docker exec "$WEB_CONTAINER" fortios-certctl install \
  /tmp/serveur.crt \
  --key /tmp/serveur.key \
  --chain /tmp/chaine.p7b \
  --hostname upgrade-path.sns-security.lan \
  --output-dir /opt/fortios/certificates/active

docker exec "$WEB_CONTAINER" rm -f \
  /tmp/serveur.crt /tmp/serveur.key /tmp/chaine.p7b
```

Si la clé privée est chiffrée, créer `/tmp/cert-password` comme dans la procédure
PFX et ajouter `--password-file /tmp/cert-password`.

## 3. Activer HTTPS dans Portainer

Dans **Stacks → upgrade-path → Editor**, définir :

```text
FORTIOS_HTTP_BIND_ADDRESS=0.0.0.0
FORTIOS_HTTP_PORT=443
FORTIOS_TLS_CERT=/opt/fortios/certificates/active/fullchain.pem
FORTIOS_TLS_KEY=/opt/fortios/certificates/active/privkey.pem
FORTIOS_TLS_HOSTNAME=upgrade-path.sns-security.lan
FORTIOS_APP_URL=https://upgrade-path.sns-security.lan/app/
```

Cliquer **Update the stack** sans supprimer les volumes. Le port hôte 443 est
mappé vers l'unique listener interne 8000, désormais chiffré ; le processus
Python reste non-root. L'API n'est donc plus contournable en HTTP sur 8000.
Vérifier ensuite :

```text
https://upgrade-path.sns-security.lan/app/
```

Les logs du conteneur web doivent annoncer HTTPS sur le listener interne 8000.
Le healthcheck choisit HTTP ou HTTPS selon la configuration TLS et doit devenir
`healthy`.

Pour revenir temporairement au mode HTTP, vider `FORTIOS_TLS_CERT` et
`FORTIOS_TLS_KEY`, remettre `FORTIOS_HTTP_PORT=8000`, puis mettre à jour la
Stack. Il n'existe volontairement pas de listener HTTP applicatif parallèle au
mode HTTPS.

## Renouvellement

Répéter l'installation CLI avec le nouveau certificat. Une fois le message de
succès obtenu, redémarrer uniquement le conteneur `web` depuis Portainer pour
charger le nouveau certificat. Ne pas recréer ou supprimer les volumes. Les
installations sont sérialisées par verrou interprocessus et, après activation,
toutes les générations remplacées ainsi que leurs clés sont supprimées. Un
échec avant activation conserve la version courante.

## Sécurité

- ne jamais intégrer de certificat privé ou de clé dans l'image ou Git ;
- ne jamais placer un mot de passe PFX directement sur la ligne de commande ;
- limiter 443 aux VLAN attendus avec le firewall de la VM ;
- n'utiliser HTTP/8000 que pour l'amorçage ou un diagnostic interne contrôlé ;
- conserver le certificat et sa clé uniquement dans le volume dédié ;
- le CLI normalise la chaîne fournie, mais la confiance finale dépend de la CA
  installée sur les postes d'entreprise.
