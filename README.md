# FortiOS Upgrade Intelligence

Outil interne pour afficher le chemin de mise à niveau FortiOS recommandé par Fortinet, puis ajouter les informations utiles à l'ingénieur : problèmes connus, changements de comportement et actions obligatoires.

La ligne autoritative du produit est **`main`** du dépôt
`git@github.com:Tetrax/upgrade_path_forti.git`, travaillée dans une seule copie
canonical : `/home/tetrax/workspace/Fortiupgrade`, qui héberge aussi le runtime
vivant dans `runtime/` (ignoré par Git). Les branches servent au travail en cours.
Certificats, reverse proxy,
notifications CVE (seuil de sévérité configurable) et transports email sont intégrés dans cette même ligne.
Voir la [cartographie de convergence et les validations](docs/delivery.md#convergence-des-branches).

## Structure

```text
Upgrade_path/
  app/
    index.html
    shared.css
    cert/
      index.html
      cert.css
      cert.js
    alerte/
      index.html
      app.js
    forticlient/
      index.html
      app.js
  data/
    fortios-data.sample.json
  scripts/
    cert_admin.py
    cert_web.py
    certctl.py
    fortios_server.py
    fortios_watch.py
    import_forticlient_compat.py
  docs/
```

### URLs

```text
https://<host>/               application principale (chemins d'upgrade, CVE, état des données)
https://<host>/alerte/        alertes internes
https://<host>/forticlient/   versions et compatibilité FortiClient / EMS
https://<host>/admin/         administration : Certificats, Notifications, Compte, SMTP, Microsoft 365
```

Les API et les données gardent leurs URL internes, indépendantes de la navigation :
`/api/cert/*`, `/api/official-path`, `/api/advisories`, `/api/advisory-images`,
`/api/compatibilities` et `/data/*`. Elles ne sont jamais redirigées ni renommées, et le cookie de
session de l'administration reste `Path=/api/cert`.

Les anciennes URL restent utilisables, en **redirection 302** avec la query string conservée :

```text
/app[/<reste>]        → /         (302)
/app/cert[/<reste>]   → /admin/   (302)
/cert[/<reste>]       → /admin/   (302)
```

302 et jamais 301/308 : une redirection permanente est mise en cache par le navigateur presque
définitivement, ce qui casserait un retour arrière vers une image ne connaissant que `/app/` et
`/cert/`. La query string est recopiée à l'identique — `/cert/verify-email?token=…` redirige vers
`/admin/verify-email?token=…` — pour que les liens de récupération déjà envoyés par email restent
opérants. Aucune redirection n'est appliquée à `/api/*` ni à `/data/*`.

## Lancer l'interface

Pour que **Afficher le chemin** puisse interroger Fortinet en direct, lancer le serveur local depuis la racine :

```bash
python3 scripts/fortios_server.py --port 8000
```

L'endpoint borne les appels Fortinet à deux requêtes simultanées par défaut. Pour ajuster cette limite sans ajouter de compte utilisateur, définir `FORTIOS_OFFICIAL_PATH_MAX_CONCURRENCY` dans l'environnement du service web (valeur acceptée : 1 à 32) ; une saturation répond HTTP 429. La déduplication/cache des recherches reste volontairement différée afin de ne pas modifier la sémantique de rafraîchissement direct.

Puis ouvrir :

```text
http://localhost:8000/
```

La page privée de gestion des certificats peut également être testée entièrement
hors Docker sur `http://127.0.0.1:8000/admin/`. Elle utilise un compte
administrateur unique, une session `HttpOnly`, un jeton CSRF et le moteur de
validation de `scripts/certctl.py`. Si aucun compte n'existe, un parcours First
Run côté web permet de le créer avec une adresse de récupération optionnelle.
La section **Compte & sécurité** gère ensuite le mot de passe, la vérification de
cette adresse, la révocation globale des sessions et le parcours public de
réinitialisation sans révéler l'état du compte. Les notifications de récupération
réutilisent le transport email sélectionné ; le CLI reste le mécanisme break-glass. Le démarrage
local borné, la migration compatible et le rollback sont documentés dans
[`docs/certificates.md`](docs/certificates.md).

Ce serveur sert l'interface et ajoute l'endpoint local `POST /api/official-path`. **Chaque clic** sur **Afficher le chemin** envoie le modèle, la version actuelle et la version cible à cet endpoint, qui interroge en direct le service public Fortinet Upgrade Path Tool, met à jour `data/fortios-data.generated.json`, puis rafraîchit l'affichage — jamais de confiance aveugle dans un chemin déjà en cache. Le chemin en cache ne sert que de repli si Fortinet est injoignable au moment du clic ; dans ce cas, l'interface l'affiche quand même (pour ne pas laisser un écran vide) mais l'indique clairement via un bandeau d'avertissement ("chemin affiché depuis le cache local, à revérifier dès que le service est de nouveau accessible").

Il reste possible d'ouvrir directement :

```text
app/index.html
```

Ou de lancer un serveur statique :

```bash
python3 -m http.server 8000
```

Dans ces deux modes, l'interface reste consultable, mais la récupération automatique depuis Fortinet ne peut pas fonctionner car aucun endpoint local ne relaie la requête. Si la page est ouverte directement depuis le fichier HTML, le navigateur peut aussi bloquer le chargement automatique du JSON. Dans ce cas, utiliser **Importer** et sélectionner `data/fortios-data.generated.json`.

## Rapport d'intervention

Depuis le chemin affiché, les boutons **Rapport** et **Markdown** permettent de copier ou télécharger une synthèse prête à joindre au dossier de changement :

- chemin Fortinet recommandé ;
- builds par étape ;
- alertes internes par version ou par saut ;
- commandes à contrôler après upgrade.

## Générer les données

Depuis la racine du projet :

```bash
python3 scripts/fortios_watch.py --skip-network
```

Le script produit :

```text
data/fortios-data.generated.json
docs/last_report.md
```

Dans l'interface, cliquer sur **Importer** puis sélectionner `data/fortios-data.generated.json`.

## Récupérer le catalogue FortiGate/FortiOS public

Pour enrichir la base avec les modèles FortiGate/FortiWiFi et les versions FortiOS publiées dans les release notes Fortinet :

```bash
python3 scripts/fortios_watch.py --docs-catalog
```

Le script parcourt `docs.fortinet.com`, récupère les versions de release notes par train FortiOS, puis extrait les modèles supportés et les builds depuis les sections **Supported models**.

La base générée contient alors :

- tous les modèles trouvés dans les release notes publiques exploitables ;
- les versions FortiOS supportées par chaque modèle ;
- les builds publiés dans les release notes.

Les très anciennes branches peuvent ne pas exposer la section modèles dans le HTML public. Elles sont listées dans `docs/last_report.md` comme non intégrées.

Important : ce catalogue ne remplace pas l'Upgrade Path Tool. Il sert à connaître les versions disponibles par modèle.

## FortiAnalyzer et FortiManager

L'outil gère aussi FortiAnalyzer et FortiManager, avec exactement les mêmes fonctionnalités que FortiGate : chemin recommandé Fortinet, catalogue modèles/versions, alertes internes.

Pour récupérer le catalogue modèles/versions de FortiAnalyzer et FortiManager :

```bash
python3 scripts/fortios_watch.py --base data/fortios-data.generated.json --tool-products fortianalyzer,fortimanager
```

Contrairement à FortiGate (scraping des release notes), cette commande utilise directement les endpoints JSON de l'Upgrade Path Tool (`/upgrade-tool/products/<slug>.json` pour la liste des modèles, puis `/upgrade-tool/upgrade-path` pour les versions/builds par modèle) — plus rapide et plus fiable, mais uniquement disponible pour les produits que l'outil connaît.

Dans l'interface (outil principal comme page `/alerte/`), un sélecteur **Produit** permet de basculer entre FortiGate/FortiOS, FortiAnalyzer et FortiManager. Chaque alerte interne est rattachée à un seul produit ; la liste des alertes se filtre par produit par défaut (option "Tous les produits" disponible).

## FortiClient et FortiClient EMS

FortiClient (Windows/macOS/Linux) et FortiClient EMS n'existent pas dans l'Upgrade Path Tool public de Fortinet (vérifié dans son propre code) — **pas de chemin recommandé automatique** pour ces deux produits. En revanche, l'outil récupère leur catalogue de versions et permet de leur créer des alertes internes, exactement comme les autres produits (sélecteur **Produit** sur `/alerte/`).

Pour récupérer le catalogue FortiClient/EMS :

```bash
python3 scripts/fortios_watch.py --base data/fortios-data.generated.json --forticlient-catalog
```

Chaque plateforme FortiClient (Windows, macOS, Linux) est traitée comme un "modèle" du produit `forticlient`, chacune avec ses propres versions/builds (scrapés depuis leurs release notes publiques respectives). FortiClient EMS est un produit séparé (`forticlient-ems`) avec un seul modèle.

### Page `/forticlient/` — versions et compatibilité EMS ↔ FortiClient

```text
http://localhost:8000/forticlient/
```

En plus d'afficher un résumé du catalogue de versions connues, cette page permet d'enregistrer des **combinaisons EMS ↔ FortiClient qui fonctionnent bien** (testées en prod), pour éviter de retester à chaque fois : choisir une version d'EMS, cocher une ou plusieurs versions FortiClient compatibles, ajouter une note et une source. Modifier/supprimer une combinaison fonctionne comme pour les alertes.

Les **alertes internes** créées pour FortiClient ou FortiClient EMS s'affichent aussi sur cette page (lecture seule), pour tout avoir au même endroit. Elles se créent et se modifient toujours depuis `/alerte/` — le bouton "Modifier dans Alertes internes" de chaque carte y renvoie directement, pré-filtré sur le bon produit via `?product=forticlient` ou `?product=forticlient-ems` dans l'URL (ce paramètre fonctionne sur `/alerte/` en général, pas seulement depuis cette page).

La grille de compatibilité **officielle** de Fortinet (publiée en PDF, `FortiClient_ems-compatibility-matrix.pdf`) est importée automatiquement chaque jour par le timer systemd (voir Planification ci-dessous). Elle peut aussi être relancée à la main :

```bash
.venv-compat/bin/python3 scripts/import_forticlient_compat.py            # aperçu seulement
.venv-compat/bin/python3 scripts/import_forticlient_compat.py --commit   # écrit dans data/fortios-data.generated.json
```

`.venv-compat/` est un venv dédié (gitignored, provisionné par `deploy/install.sh`) contenant `pdfplumber`, seule dépendance non-stdlib du projet — nécessaire car le PDF de Fortinet a des en-têtes de colonnes tournés à 90°, qui ressortent à l'extraction sous forme de texte inversé (ex: "7.2.10" devient "01.2.7"). Le script est volontairement prudent : il refuse de commiter si moins de `MIN_EXPECTED_ENTRIES` (10) combinaisons sont extraites, ce qui indiquerait que Fortinet a changé le format du PDF plutôt qu'une vraie absence de données. Un re-import ne touche que la liste de versions FortiClient de chaque entrée existante (`compat-official-<version EMS>`) — `note`, `source` et `createdAt` d'une entrée déjà modifiée à la main sont préservés, et `updatedAt` ne bouge que si les versions compatibles ont réellement changé. Les combinaisons importées ont pour source `"FortiClient EMS Compatibility Matrix (Fortinet, officielle)"`, pour les distinguer des combinaisons testées par l'équipe.

## Récupérer des chemins officiels Fortinet

Le script peut appeler le service public utilisé par l'Upgrade Path Tool Fortinet :

```text
https://docs.fortinet.com/upgrade-tool/fortigate
```

Créer ou modifier :

```text
data/official-path-requests.csv
```

Avec les colonnes :

```csv
model,from,to
FGT40F,7.0.15,7.4.11
```

Puis lancer :

```bash
python3 scripts/fortios_watch.py --docs-catalog
```

Le script interroge `https://docs.fortinet.com/upgrade-tool/upgrade-path` et stocke le chemin retourné dans `data/fortios-data.generated.json`.

Pour une requête ponctuelle sans CSV :

```bash
python3 scripts/fortios_watch.py --official-path FGT40F:7.0.15:7.4.11
```

Ces chemins sont affichés comme **Recommended path** dans l'interface avec la source `Fortinet Upgrade Path Tool public service`.

Depuis l'interface, le même appel se fait automatiquement en cliquant sur **Afficher le chemin** si l'application a été lancée avec :

```bash
python3 scripts/fortios_server.py --port 8000
```

Le chemin récupéré est sauvegardé dans `data/fortios-data.generated.json`. La requête suivante sur le même modèle et le même couple de versions utilisera donc la valeur stockée, avec possibilité de cliquer à nouveau sur **Fortinet** pour actualiser.

## Ajouter un export Fortinet Upgrade Path Tool

Créer le dossier :

```text
data/upgrade_exports/
```

Y déposer un export Fortinet avec ce nommage :

```text
FGT90G__7.2.10__7.4.11.json
FGT90G__7.2.10__7.4.11.csv
FGT90G__7.2.10__7.4.11.txt
```

Le script extrait automatiquement les versions dans l'ordre d'apparition. Exemple :

```text
7.2.10 > 7.4.8 > 7.4.11
```

devient un chemin recommandé stocké pour le modèle `FGT90G`.

## Ajouter des alertes internes

### Depuis l'interface (recommandé)

```text
http://localhost:8000/alerte/
```

Cette page permet à un ingénieur de déclarer une alerte interne (titre, description, sévérité, moment) en cochant une ou plusieurs versions FortiOS concernées, et en choisissant si elle s'applique à tous les boîtiers ou à une sélection précise. L'alerte est envoyée à l'endpoint local `POST /api/advisories`, qui l'ajoute dans `data/fortios-data.generated.json`. Elle s'affiche ensuite automatiquement dans l'outil principal dès qu'un chemin d'upgrade passe par une des versions concernées, pour un modèle concerné.

Le champ description accepte une mise en forme légère, avec aperçu en direct et boutons dédiés dans la page :

- `**texte**` pour du **gras**
- `__texte__` pour du souligné
- une ligne commençant par `- ` pour une puce de liste
- une ligne vide pour démarrer un nouveau paragraphe
- coller (Ctrl+V) ou glisser une image dans le champ, ou utiliser le bouton Image, pour insérer une capture d'écran (PNG/JPEG/GIF/WEBP, 8 Mo max)

Le rendu (dans `/alerte/` comme dans l'outil principal) est toujours construit en DOM à partir de ce texte brut, jamais en interprétant du HTML.

Les images sont envoyées à `POST /api/advisory-images`, stockées dans `data/advisory-images/` (non versionné dans Git — voir `.gitignore`, pour ne pas alourdir le dépôt avec des captures potentiellement sensibles) et référencées dans la description via `![alt](/data/advisory-images/...)`. Supprimer une alerte supprime aussi les images qu'elle référence, et modifier une alerte supprime celles qui ne sont plus référencées dans la nouvelle description (une image encore utilisée par une autre alerte n'est jamais supprimée).

Deux champs optionnels, **Bug ID / Change Fortinet** et **Version où identifié**, permettent de noter le numéro de bug/change interne Fortinet et la ou les versions où il a été vu (ex: `1004258` / `7.2.11, 7.4.5, 7.6.1`), pour le retrouver facilement plus tard dans les sections Resolved/Known issues des release notes. Purement informatif : ces champs n'influencent pas le déclenchement de l'alerte, contrairement aux versions concernées.

La case **Changement de comportement par défaut (pas un bug)** ajoute un badge distinct (⚙) sur l'alerte, pour la distinguer d'un coup d'œil d'un vrai bug — utile pour les cas type "Changes in default behavior" des release notes Fortinet, où le comportement change intentionnellement plutôt que d'être corrigé.

### Comportement du mode "à partir de versions"

Pour une alerte en mode "à partir de versions" (`minVersions` ou l'ancien `minVersion`), le déclenchement suit la logique suivante : une fois le changement en place, il est considéré comme définitif (il ne revient pas en arrière dans une version ultérieure). En conséquence, l'alerte ne s'affiche que si **cette upgrade précise** fait franchir le seuil — si la version de départ a déjà dépassé un des seuils renseignés, l'alerte ne s'affiche pas (le changement a déjà eu lieu lors d'une upgrade précédente, ce n'est pas le cas ici). Exemple : seuils `7.4.10`, `7.6.5`, `8.0.0` — un upgrade de `7.4.11` vers `7.6.7` ne déclenche pas l'alerte (déjà en 7.4.11, donc déjà après le seuil 7.4.10), mais un upgrade de `7.2.13` vers `7.4.12` la déclenche bien.

Comme pour la récupération Fortinet, cette page a besoin de `scripts/fortios_server.py` pour fonctionner (pas d'un simple serveur statique).

### Depuis un CSV (import en masse)

Créer `data/advisories.csv` avec les colonnes suivantes :

```csv
id,product,models,version,from,to,severity,title,description,command,source
```

Exemple :

```csv
adv-7.4.11-traffic-redirect,fortigate-fortios,FGT90G,7.4.11,,,important,Option a verifier apres passage en 7.4.11,Verifier allow-traffic-redirect apres upgrade,"config system settings
  set allow-traffic-redirect enable
end",Base interne SNS
```

Puis lancer `python3 scripts/fortios_watch.py --base data/fortios-data.generated.json`. La colonne `version` ne prend qu'une seule version par ligne ; pour cibler plusieurs versions avec la même alerte, passer par la page `/alerte/` (colonne `versions`, tableau) ou dupliquer la ligne CSV.

## CVE PSIRT Fortinet

En plus des alertes internes (bugs remontés par l'équipe), l'outil croise automatiquement les versions avec les **CVE publiées par le Fortinet PSIRT** pour FortiOS, FortiAnalyzer, FortiManager, FortiClient et FortiClient EMS. Fortinet publie pour chaque advisory (`FG-IR-xx-xxx`) un export **CVRF** (Common Vulnerability Reporting Framework, un format XML standard et structuré) dont les `ProductID` décrivent les versions exactes ou le train concerné — bien plus fiable qu'un scraping de la page HTML humaine.

Affichage :

- Sur l'outil principal (`/`), chaque version du chemin affiche un badge `🛡 CVE-xxxx-xxxxx` si elle est concernée, et une section dédiée liste les CVE du chemin avec sévérité CVSS, score, lien vers la fiche PSIRT, et indique si le chemin choisi corrige la CVE ou si la version cible reste vulnérable.
- Sur `/forticlient/`, les cartes de combinaisons EMS ↔ FortiClient affichent la même pastille et le même détail si l'une des versions du couple est concernée.

Collecte (`scripts/fortios_watch.py`) :

- `--cve-catalog` : rafraîchissement quotidien, incrémental. Ne regarde que le flux RSS PSIRT (`https://www.fortiguard.com/rss/ir.xml`, les ~50 dernières advisories tous produits confondus), puis lit directement l'export CVRF public `https://fortiguard.fortinet.com/psirt/cvrf/{advisory_id}` pour chaque ID; la page HTML humaine n'est pas utilisée par le collecteur. Branché sur le timer quotidien (`deploy/fortios-catalog-refresh.service`).
- `--cve-backfill [--cve-backfill-max-pages N]` : backfill historique complet, à lancer manuellement de temps en temps. Parcourt la liste paginée PSIRT filtrée par produit (`fortiguard.fortinet.com/psirt?product=...`) pour chacun des 5 produits suivis, donc bien plus de requêtes (plusieurs centaines) — pas dans le timer quotidien.
- `--cve-retry-delays-seconds "300,900"` (défaut) : avec ~50 requêtes HTTP séquentielles par jour vers le PSIRT, une advisory isolée qui timeout est courant et presque toujours transitoire (rate limiting, coupure brève côté Fortinet). Plutôt que de marquer tout de suite la source `cve-psirt` en avertissement, `fortios_watch.py` retente les advisories restées en échec après chacun de ces délais (dans l'ordre, en s'arrêtant dès qu'il n'en reste plus) avant de calculer le statut de santé final. Volontairement **borné** plutôt qu'en boucle jusqu'à 100% vert : une advisory peut être légitimement sans export CVRF (indiscernable ici d'un vrai échec réseau), donc une boucle infinie tournerait dessus indéfiniment tous les jours ; et insister plus fort/plus vite quand le PSIRT est déjà instable aggrave le rate limiting au lieu de l'absorber (observé en pratique : forcer deux relances manuelles coup sur coup a fait passer 1 advisory en échec à 3). Chaîne vide (`""`) pour désactiver toute relance.

Une CVE n'est retenue que si elle touche au moins un des 5 produits suivis par l'outil (le reste du catalogue PSIRT — FortiWeb, FortiMail, FortiSandbox, etc. — est ignoré). Une même CVE peut apparaître dans plusieurs `Vulnerability` du CVRF (par exemple avec plusieurs plateformes ou produits) : elles sont fusionnées en une seule entrée avant d'être stockées, sinon la dernière écraserait les précédentes.

## État de santé des collectes

`data/fortios-health.json` (gitignored, généré automatiquement, séparé du catalogue principal) suit l'état de chaque source de collecte : `fortios-docs`, `fortianalyzer`, `fortimanager`, `forticlient`, `forticlient-ems`, `cve-psirt`, `fortios-lifecycle`, `compat-matrix`, et `daily-run` (résumé global). Pour chaque source : statut (`ok`/`warning`/`error`/`running`/`skipped`), date de dernière tentative/dernier succès/dernière erreur (résolution à la microseconde — nécessaire pour que deux tentatives démarrées la même seconde ne s'écrasent jamais l'une l'autre), message d'erreur court (jamais de traceback ni de secret), durée, nombre d'éléments collectés, et compteur d'échecs consécutifs.

Écrit par `scripts/fortios_watch.py` (une source par étape de collecte) et par `scripts/import_forticlient_compat.py` (source `compat-matrix`, exécuté dans une étape séparée APRÈS `fortios_watch.py` — voir "Planification" plus bas), sous le même verrou interprocessus que le catalogue principal (`cross_process_lock`). Une source « ignorée » (flag désactivé, ou `--skip-network`) n'est jamais comptée comme un échec ; un échec n'efface jamais la date du dernier succès connu ; l'écriture de l'état de santé ne peut jamais faire échouer la collecte elle-même — un fichier corrompu, tronqué ou de structure invalide est traité comme un état vide (jamais une exception qui interromprait la collecte), et archivé aside (`fortios-health.json.corrupt-<timestamp>`) pour diagnostic plutôt que silencieusement écrasé.

Affiché dans `/` sous le bandeau de briefing : section repliable « État des données » avec un point vert/orange/rouge par source (rouge = échecs répétés ou données de plus de 48h, orange = source vieillissante/ignorée/échec isolé, vert = collecte récente réussie), un bandeau d'avertissement si une source est en rouge, et le détail complet par source dans un tableau replié par défaut. Le point global du bandeau (`#healthSummaryDot`) reflète TOUTES les sources, pas seulement `daily-run` : comme `compat-matrix` tourne dans une étape séparée après que `fortios_watch.py` a déjà figé son propre statut `daily-run`, un échec de `compat-matrix` seul doit quand même faire passer le point global au rouge — `daily-run` structurellement ne peut pas savoir ce qu'une étape ultérieure va faire.

## Notifications email

Le moteur existant de `scripts/fortios_notify.py` est conservé : déduplication, checkpoint, outbox persistante, retry et isolation des erreurs de transport. Deux modes sont disponibles dans **Administration → Notifications** : **SMTP** et **Microsoft 365 / Azure**, via Microsoft Graph et OAuth 2.0 non interactif. Aucun daemon ni scheduler supplémentaire n'est nécessaire ; les notifications sont déclenchées par le diff de chaque collecte PSIRT existante.

La configuration sépare préférences, choix du transport et credentials :

- `notification-settings.json` : activation, produits surveillés et destinataires ;
- `smtp-settings.json` : paramètres SMTP non secrets et apparence, lorsque la GUI a enregistré le schéma `schemaVersion: 1` ;
- `email-transport-settings.json` : choix SMTP/Microsoft 365 et paramètres Microsoft non secrets ;
- environnement : bootstrap SMTP (serveur, port, sécurité, utilisateur, expéditeur, URL et timeout) lorsqu'aucun document SMTP marqué n'existe ;
- `FORTIOS_SMTP_PASSWORD_FILE` : unique chemin du mot de passe, choisi par l'environnement et jamais remplacé par le JSON ; le volume dédié est inscriptible par le web et monté en lecture seule par le scheduler.
- `FORTIOS_MICROSOFT365_CLIENT_SECRET_FILE` : unique fichier du secret Entra dans un volume privé dédié, inscriptible par le web et monté en lecture seule par le scheduler.

Les paramètres SMTP non secrets peuvent être modifiés dans **Administration → Notifications**.
Un fichier `smtp-settings.json` marqué et valide prévaut sur l'environnement ; un
ancien fichier non marqué est ignoré pour le transport et ne conserve que
l'apparence valide. Un fichier existant tronqué, illisible ou marqué mais
malformé met le SMTP en échec fermé jusqu'à une sauvegarde complète valide.
Les préférences et le choix du transport sont validés et remplacés atomiquement
sous verrou dans leurs fichiers respectifs. Les réponses GET et les réponses
publiques ne renvoient jamais les secrets ni leurs chemins, seulement leur
état de disponibilité.

Le mot de passe utilise une opération séparée, protégée par session/CSRF : un
champ vide conserve le secret existant ; une nouvelle valeur est écrite
atomiquement en `0600` seulement si `FORTIOS_SMTP_PASSWORD_FILE` pointe vers un
stockage dédié préparé et inscriptible. Un fichier externe monté en lecture
seule reste utilisable pour l'envoi mais ne peut pas être modifié par la GUI.
Le répertoire global des secrets et celui des certificats ne deviennent jamais
inscriptibles pour SMTP.

Le **Client Secret Microsoft 365 peut être saisi ou remplacé dans la GUI HTTPS** :
champ masqué, contrôle administrateur/CSRF, écriture atomique, jamais de relecture
de la valeur enregistrée. Son enregistrement n'envoie pas de mail et ne change
pas le transport. Les Compose local/Portainer/import partagent le même volume
`fortios-microsoft365-secrets`, sans helper supplémentaire propre au VPS : ce
fonctionnement est portable en VM entreprise et en TLS direct. Mettre à jour
l'image **et le Stack** pour une ancienne installation ; conserver les autres
volumes et les montages secrets SMTP/certificats protégés. Voir la migration et
les sauvegardes dans le [guide Microsoft 365](docs/microsoft365.md#5-saisir-ou-remplacer-le-secret-dans-linterface).

Pour Microsoft 365, **Tester la connexion** obtient un token puis envoie un mail
de test depuis la boîte configurée. `202 Accepted` confirme la soumission Graph,
pas la remise finale. L'autorisation recommandée est **Exchange Online RBAC for
Applications**, rôle `Application Mail.Send` limité à cette boîte, sans ajouter
une permission Entra `Mail.Send` globale qui annulerait cette restriction.
Le [guide Microsoft 365 pas à pas](docs/microsoft365.md), accessible depuis
l'interface, décrit l'App Registration, le secret, les permissions, la recette
réelle et le dépannage. Voir aussi [architecture et reprises](docs/notifications.md).

Les variables `FORTIOS_SMTP_HOST`, `FORTIOS_SMTP_PORT`, `FORTIOS_SMTP_USERNAME`, `FORTIOS_SMTP_PASSWORD_FILE`, `FORTIOS_SMTP_SECURITY`, `FORTIOS_SMTP_TIMEOUT`, `FORTIOS_SMTP_FROM` et `FORTIOS_APP_URL` servent de bootstrap lorsqu'aucun `smtp-settings.json` marqué n'existe. Après une sauvegarde GUI valide, les paramètres SMTP non secrets enregistrés prévalent sur ces variables ; un ancien fichier non marqué reste ignoré pour le transport. Voir [livraison, migration SMTP et rollback](docs/delivery.md) avant de mettre à jour une ancienne console Web SMTP. Ne pas effacer le checkpoint ou l'outbox.

Format persistant :

```json
{
  "enabled": true,
  "minimumSeverity": "high",
  "products": {
    "fortigate-fortios": true,
    "fortimanager": true,
    "fortianalyzer": true,
    "forticlient-ems": true,
    "forticlient": {
      "windows": true,
      "macos": true,
      "linux": true
    }
  },
  "recipients": ["security@example.com"]
}
```

Les identifiants reprennent directement le catalogue applicatif : FortiClient reste le produit canonique `forticlient`, avec les modèles existants `windows`, `macos` et `linux`. Il n'existe pas de seconde taxonomie produit.

### Seuil de sévérité des notifications CVE

Le champ **Sévérité minimale** (`minimumSeverity`) est un vrai seuil de notification : une CVE ne produit un événement que si sa sévérité est **égale ou supérieure** au niveau configuré. Les niveaux proposés sont ceux que Fortinet publie réellement — `critical`, `high`, `medium`, `low`, du plus sévère au moins sévère. `high` reste la valeur par défaut et la valeur des configurations existantes : un déploiement n'augmente donc jamais son volume d'alertes sans décision explicite.

| Seuil | CVE notifiées |
| --- | --- |
| `critical` | Critical |
| `high` (défaut) | Critical, High |
| `medium` | Critical, High, Medium |
| `low` | Critical, High, Medium, Low |

La comparaison utilise une hiérarchie explicite (`critical` = 4 … `low` = 1), jamais un ordre alphabétique. Une CVE sans score CVSS (sévérité `unknown`) n'atteint aucun seuil : elle n'est jamais présentée comme « au moins Low ». Une valeur inconnue est refusée par l'API (`400`), sans repli silencieux vers `high`.

Un événement de sécurité est donc produit uniquement pour :

- une nouvelle CVE dont la sévérité atteint le seuil configuré, touchant au moins un produit sélectionné ;
- une CVE existante dont la sévérité **augmente réellement** et atteint le seuil configuré (par exemple `Medium → High`, `High → Critical`, ou `Low → Medium` avec un seuil `medium`).

Ne produisent aucun email : une CVE sous le seuil, une sévérité inchangée, une **baisse** de sévérité, une simple republication PSIRT, une modification de texte/CVSS/périmètre sans escalade, ou un produit non sélectionné. Une CVE qui touche plusieurs produits sélectionnés reste une seule entrée avec tous les produits concernés.

Le filtre est appliqué **avant** la composition : une CVE écartée n'apparaît ni dans le corps, ni dans les compteurs, ni dans les produits concernés, et le renderer nomme et colore chaque sévérité qu'il reçoit effectivement.

**Le seuil ne provoque aucun rattrapage.** Le checkpoint enregistre toute CVE collectée, y compris celles que le seuil écarte ; une CVE déjà observée n'est donc jamais « nouvelle » parce que l'administrateur baisse le seuil. Seules les CVE découvertes après le changement suivent le nouveau seuil, et une escalade de sévérité observée ensuite reste notifiée selon la logique existante.

Un run produit au maximum un email synthétique. L'objet annonce le volume puis la répartition réellement retenue (`[FortiUpgrade] 3 nouvelles vulnérabilités — 1 Critical / 1 High / 1 Medium`) ; le corps contient les compteurs par sévérité présente, le nombre de CVE par produit, puis une section par CVE badgée de son propre niveau. Le message est multipart `text/plain` + HTML compact compatible avec les clients email limités.

Les catégories historiques restent actives lorsque les notifications sont activées :

- **DAILY** : nouvelles versions FortiOS/FortiAnalyzer/FortiManager et branche passant en fin de support ;
- **OPERATIONS** : source en échec depuis ≥ 2 exécutions consécutives ou retour à la normale ;
- **CRITICAL** : CVE Critical, avec le seuil de sévérité configurable détaillé ci-dessus.

Une branche FortiOS franchissant sa date de fin de support déclenche un événement même si aucune donnée du catalogue n'a changé ce jour-là (`fortios_watch.py`/`endoflife.date` renvoient la même date de fin de support avant et après — seule l'avancée du calendrier fait la différence) : l'état « cette branche est-elle en fin de support » est donc suivi séparément d'une collecte à l'autre (`eolState` dans `data/fortios-notify-history.json`), pas dérivé d'une comparaison avant/après catalogue. Une branche vue pour la première fois initialise silencieusement cet état sans envoyer d'email, pour ne pas spammer toutes les fins de support déjà passées lors de la toute première activation ; ensuite, l'événement part exactement une fois au moment du franchissement, y compris après plusieurs jours sans collecte.

Chaque événement a une clé de déduplication stable (`type|source|resource_id|new_value`, par exemple `new-cve|psirt|CVE-2026-12345|critical` ou `cve-severity|psirt|CVE-2026-12345|high-to-critical`). Les événements sont toujours calculés par différence entre le checkpoint de notification et la collecte courante, jamais par re-scan du catalogue entier : ni la première activation, ni un `--cve-backfill` historique, ne déclenchent d'email pour des données déjà existantes.

**Outbox persistante (`data/fortios-notify-history.json`, gitignored)** — un échec SMTP (réseau, STARTTLS, authentification) est journalisé sans jamais faire échouer la collecte ni afficher le mot de passe, et ne fait plus perdre l'événement : celui-ci est écrit dans une file d'attente persistante *avant* toute tentative d'envoi, et n'en est retiré qu'après un envoi réussi. Une collecte suivante — même sans aucun changement neuf dans le catalogue — reprend automatiquement tout ce qui est resté en attente et retente l'envoi avec les événements de ce nouveau run. Le fichier tient quatre choses sous le même verrou interprocessus (`cross_process_lock`) :

Désactiver les notifications suspend les envois sans supprimer l'outbox ; les événements déjà en attente après un échec SMTP seront donc retentés à la prochaine réactivation. Les nouvelles collectes effectuées pendant la désactivation ne créent pas d'événement en attente.

```json
{
  "sentKeys": {"new-cve|psirt|CVE-2026-12345|critical": "2026-07-17T07:23:36Z"},
  "outbox": [{"category": "CRITICAL", "dedupKey": "...", "summary": "...", "severity": "critical", "details": {"kind": "cve"}, "queuedAt": "...", "claimedBy": null, "claimedAt": null}],
  "eolState": {"7.6": true},
  "checkpoint": {"versionsByProduct": {}, "cvesById": {}, "health": {}}
}
```

- `sentKeys` : historique de déduplication (purge après 180 jours), comme avant.
- `outbox` : file d'attente des événements pas encore envoyés avec succès.
- `eolState` : dernier état connu « branche en fin de support ou non » par branche (voir ci-dessus).
- `checkpoint` : dernier catalogue/état de santé pris comme base du diff de notification.

Chaque collecte réserve («&nbsp;réclame&nbsp;») les entrées de l'outbox qui ne sont pas déjà tenues par une autre exécution encore en cours (`claimedBy`/`claimedAt`, expire après 10&nbsp;minutes — largement au-delà du pire timeout SMTP réaliste — pour qu'une exécution plantée ne bloque pas indéfiniment les tentatives suivantes) : deux collectes qui se chevauchent ne peuvent donc jamais envoyer le même événement en double, la seconde ne réclamant rien de ce que la première tient déjà. Sur un succès d'envoi, les événements réclamés sont retirés de l'outbox et leur clé passe dans `sentKeys` ; sur un échec, la réclamation est simplement relâchée pour la prochaine collecte.

Un fichier `fortios-notify-history.json` existant mais corrompu, tronqué, illisible ou de structure invalide est conservé en place, sans réinitialisation. Les notifications restent suspendues avec une erreur nettoyée ; la collecte continue indépendamment. **Récupération :** conserver ce fichier ainsi que la dernière sauvegarde valide, puis réconcilier checkpoint, outbox et clés d'envoi avant reprise. Ne pas supprimer l'historique comme remède : un nouvel amorçage est silencieux et ne reconstruit pas les événements en attente perdus ; restaurer un ancien checkpoint sans réconciliation peut aussi rejouer des événements déjà envoyés. Les anciennes archives `.corrupt-*` doivent aussi être conservées pour cette réconciliation. Voir [rollback et données persistantes](docs/delivery.md#update--rollback).

L'interface privée `/admin/` expose les onglets **Certificats** et **Notifications** avec la même session administrateur, le même contrôle d'origine et le même jeton CSRF. La section **Configuration SMTP** permet de modifier et d'enregistrer le transport non secret : STARTTLS, TLS implicite, ou mode clair explicitement autorisé. Le mot de passe est saisi séparément dans un champ masqué et n'est jamais relu ; un champ vide le conserve. Les paramètres d'apparence (introduction, nom et signature) entourent le contenu de sécurité généré et ne peuvent pas retirer les CVE, produits, versions, avertissements ou liens obligatoires.

Dans **Apparence des emails**, les scénarios fictifs **1 CVE**, **Plusieurs CVE** et **Multi-produits** sont construits uniquement en mémoire par le backend. La route administrateur `/api/cert/notifications/preview` transmet ces événements au renderer autoritatif `fortios_notify.compose_email()` et retourne son vrai sujet, son HTML et son alternative texte ; l'interface n'embarque aucun second template. `/api/cert/notifications/send-preview` recompose les mêmes données et les envoie avec le moteur SMTP existant, même lorsque les notifications sont désactivées. Cet envoi de prévisualisation reste soumis à la session, au contrôle d'origine, au CSRF et au rate limiting des tests SMTP. Il n'écrit ni catalogue, ni paramètres de notification, ni checkpoint, ni outbox, ni `sentKeys`, ni `eolState`. Rollback : retirer ces deux routes et les contrôles d'aperçu ne nécessite aucune migration de données persistantes.

Le bouton **Envoyer un email de test** exige un destinataire contrôlé, réutilise le moteur SMTP de `fortios_notify.py` et retourne des étapes nettoyées (connexion, TLS, authentification, acceptation). Cette opération n'écrit ni checkpoint, ni outbox, ni `sentKeys`, ni événement. Les routes SMTP sont protégées par la session administrateur et CSRF ; l'envoi de test est limité à trois tentatives par minute et par session.

Tester aussi en CLI sans lancer de collecte ni toucher au catalogue, à la santé ou à l'outbox :

```bash
python3 scripts/fortios_watch.py --test-email
```

## Automatisation FortiCare / FNDN

Le script accepte déjà un export JSON authentifié :

```bash
FORTICARE_FIRMWARE_JSON=data/forticare-export.json python3 scripts/fortios_watch.py
```

Format compact accepté :

```json
{
  "firmwares": [
    {
      "product": "fortigate-fortios",
      "model": "FGT90G",
      "version": "7.4.11",
      "build": "2878",
      "notes": ["resolved", "known", "upgrade", "behavior"]
    }
  ]
}
```

La prochaine étape consiste à vérifier avec le compte entreprise si FNDN expose une API documentée pour :

- lister les firmwares par modèle ;
- calculer le chemin recommandé, équivalent à l'Upgrade Path Tool.

Si l'API existe, elle doit alimenter directement le format JSON ci-dessus. Si elle n'existe pas, il faudra évaluer une automatisation navigateur contrôlée de l'outil Fortinet, en vérifiant les conditions d'utilisation.

## Tests

Suite `unittest` stdlib (`tests/`, aucune dépendance) :

```bash
python3 -m unittest discover -s tests
```

Suite E2E navigateur (`tests/e2e/`, Playwright — **dev/CI uniquement, jamais nécessaire en production**) :

```bash
uv venv .venv-test && uv pip install --python .venv-test/bin/python -r requirements-dev.txt
.venv-test/bin/python -m playwright install --with-deps chromium
.venv-test/bin/python -m pytest tests/e2e/
```

Chaque test lance sa propre instance isolée de `scripts/fortios_server.py` (port libre, répertoire `data/` temporaire — jamais `data/fortios-data.generated.json` ni `data/advisory-images/` réels), avec les appels Fortinet remplacés par une réponse simulée déterministe (`FORTIOS_TEST_DATA_DIR` / `FORTIOS_E2E_MOCK_NETWORK` / `FORTIOS_E2E_MOCK_RESPONSE_FILE`, inertes tant que ces variables ne sont pas positionnées — aucun effet en production). Capture d'écran, vidéo et trace Playwright conservées uniquement en cas d'échec. Le workflow GitHub Actions (`.github/workflows/tests.yml`) lance les deux suites à chaque push/PR, sans secret SMTP réel ni appel PSIRT/Fortinet.

### Contrôles CI : bloquants et informatif

Contrôles **bloquants** (un échec rend le run rouge) : Ruff, tests unitaires, Playwright, construction/push de l'image.

Le scan **Trivy** de l'image (`security-scan`) est un contrôle **informatif** : il analyse systématiquement les paquets OS et les dépendances Python (`severity: HIGH,CRITICAL`, `ignore-unfixed: true`) mais **ne fait jamais échouer le run**. Les vulnérabilités sont publiées dans le résumé de l'étape (`scripts/trivy_report.py` → `$GITHUB_STEP_SUMMARY` : compteurs Critical/High, paquet, CVE, version installée, version corrigée), dans une annotation `::warning::`, et dans l'artefact **`trivy-report`** (`trivy.json`, conservé 30 jours). Un rapport absent ou illisible est signalé comme tel — jamais confondu avec « aucune vulnérabilité ».

Deux conséquences assumées et documentées dans l'en-tête du workflow :

- `ignore-unfixed: true` : seules les vulnérabilités **disposant d'un correctif** sont remontées, pour que chaque alerte soit actionnable (rafraîchir l'image de base épinglée par digest, ou monter le paquet). Une vulnérabilité sans correctif ne produirait qu'une alerte sans action possible.
- le run reste **vert** même avec des findings : un pipeline rouge à chaque build masquerait les régressions réelles. Pour rendre Trivy bloquant, mettre `exit-code: 1` sur l'étape de scan et retirer `if-no-files-found: warn` de l'upload.

## Planification

Un timer systemd (`deploy/fortios-catalog-refresh.timer` + `.service`, installés par `deploy/install.sh`) lance chaque jour à 7h00 heure de Paris (CET/CEST, résolu par systemd — le VPS lui-même tourne en UTC), en deux étapes :

```bash
python3 scripts/fortios_watch.py --base data/fortios-data.generated.json --docs-catalog --tool-products fortianalyzer,fortimanager --forticlient-catalog --cve-catalog
.venv-compat/bin/python3 scripts/import_forticlient_compat.py --commit
```

La première commande détecte automatiquement les nouvelles versions FortiOS publiées dans un train déjà connu et les nouveaux modèles FortiGate/FortiWiFi apparus dans les release notes publiques `docs.fortinet.com`, les nouveaux modèles/versions FortiAnalyzer et FortiManager via les endpoints de l'Upgrade Path Tool, les nouvelles versions FortiClient/FortiClient EMS via leurs release notes publiques, et les nouvelles CVE PSIRT (voir ci-dessus). La seconde réimporte la grille de compatibilité officielle EMS ↔ FortiClient (voir plus haut). Le résultat est fusionné dans `data/fortios-data.generated.json` (les chemins déjà récupérés via l'app ne sont pas perdus) et un rapport est écrit dans `docs/last_report.md`. Si la première étape échoue, systemd n'enchaîne pas sur la seconde (`ExecStart=` multiples) — sans gravité, le timer réessaie le lendemain.

Un second timer, plus léger (`deploy/fortios-cve-afternoon-refresh.timer` + `.service`), relance uniquement `--cve-catalog` à 15h30 heure de Paris — une passe de rattrapage l'après-midi pour les advisories encore en échec après les deux relances internes du matin (voir `--cve-retry-delays-seconds` dans la section "CVE PSIRT Fortinet" plus haut), sans re-scraper inutilement les autres catalogues. ~8h30 d'écart avec le run du matin : largement de quoi laisser un vrai rate limiting côté PSIRT se dissiper, sans pour autant sursolliciter leur infra deux fois par jour à intervalle rapproché (même logique de relances bornées, pas de boucle jusqu'au 100% vert).

Important : `--base data/fortios-data.generated.json` est indispensable en tâche planifiée. Sans lui, le script repart de `data/fortios-data.sample.json` (le petit exemple) et écraserait les chemins déjà récupérés via l'interface.

Un train FortiOS totalement nouveau (ex: un futur 8.4) n'est détecté que s'il figure dans `DEFAULT_DOCS_MAJOR_VERSIONS` (dans `scripts/fortios_watch.py`) ou via `--docs-major-versions`.

Suivre l'exécution :

```bash
systemctl list-timers fortios-catalog-refresh.timer
journalctl -u fortios-catalog-refresh.service -n 50
```

## Déploiement Docker / Portainer

**Procédure de livraison actuelle : [docs/delivery.md](docs/delivery.md)** — Git Stack,
image SHA/digest, secrets read-only, compatibilité des données et récupération admin.

La stack Docker remplace le serveur systemd et ses deux timers par deux
conteneurs :

- `web` sert l'interface et l'API sur un listener unique, HTTP ou HTTPS ;
- `scheduler` lance le rafraîchissement complet à 07:00, le rattrapage à 07:45 et la
  passe CVE à 15:30 Europe/Paris.

Les répertoires `data/`, `docs/` et `certificates/` sont des montages persistants. Ils
doivent être conservés ensemble lors d'une migration : ils contiennent le
catalogue, l'état de santé, l'outbox SMTP, les images d'alertes et le dernier
rapport. Les certificats et les secrets ne sont jamais inclus dans l'image.

### Préparer et démarrer

```bash
install -m 600 .env.example .env
# Adapter PUID/PGID et les variables SMTP dans .env si nécessaire.
docker compose up --build -d
docker compose ps
docker compose logs -f web scheduler
```

Par défaut, le port applicatif est lié à l'interface loopback. Pour un test LAN
temporaire, modifier
`FORTIOS_HTTP_BIND_ADDRESS=0.0.0.0` dans `.env`; ne pas exposer ce port vers
Internet. Le TLS direct est facultatif et ses certificats restent dans le
montage persistant dédié, jamais dans l'image applicative.

La première exécution du scheduler attend le prochain créneau. Pour demander
explicitement une collecte complète unique après une migration, définir
`FORTIOS_RUN_ON_START=1`, redémarrer `scheduler`, attendre la fin des logs puis
le remettre à `0`.

### Migration via l'interface web Portainer

Cette procédure est adaptée à une VM interne avec Portainer Community Edition.
Elle transporte une image applicative et utilise des volumes nommés. L'image ne
transporte pas les données acquises, préférences, secrets ou l'outbox. Restaurer
séparément la sauvegarde des volumes sur la cible avant de démarrer une migration.
Un volume vierge n'est pas une restauration et ne doit pas remplacer un volume existant.

#### 1. Télécharger le fichier de Stack puis préparer l'image sur la machine source

Télécharger d'abord `docker-compose.portainer-import.yml` depuis la conversation
Hermes sur le poste qui ouvre Portainer. Ce fichier et l'image `.tar` devront
être sélectionnés depuis ce même navigateur lors des étapes suivantes.

Ne pas arrêter le VPS existant à ce stade.

```bash
cd ~/workspace/upgrade_path
docker build -t fortios-upgrade-intelligence:local .
docker save fortios-upgrade-intelligence:local \
  -o ~/fortios-upgrade-intelligence.tar
```

Télécharger ou transférer ensuite `~/fortios-upgrade-intelligence.tar` sur le
poste depuis lequel Portainer est ouvert. Ne pas le compresser en `.tar.gz` : le
bouton d'import Portainer attend l'archive Docker `.tar` produite par
`docker save`.

#### 2. Importer l'image dans Portainer

1. Ouvrir l'environnement Docker cible (par exemple `local`).
2. Dans le menu latéral, ouvrir **Images** (et non **Registries**).
3. Dans la barre d'actions au-dessus de la liste, cliquer **Import**, entre
   **Remove** et **Export**.
4. Sélectionner `fortios-upgrade-intelligence.tar` et confirmer l'import.
5. Attendre la fin de l'opération, puis vérifier la présence de l'image
   `fortios-upgrade-intelligence:local` dans la liste.

#### 3. Déployer la Stack dans Portainer

1. Dans le menu latéral, ouvrir **Stacks** puis cliquer **Add stack**.
2. Donner le nom `upgrade-path`.
3. Choisir **Upload** et sélectionner
   `docker-compose.portainer-import.yml`.
4. Dans la section des variables d'environnement, ajouter :

   ```text
   PUID=1000
   PGID=1000
   FORTIOS_HTTP_BIND_ADDRESS=0.0.0.0
   FORTIOS_HTTP_PORT=8000
   FORTIOS_RUN_ON_START=0
   FORTIOS_SMTP_HOST=smtp.example.com
   FORTIOS_SMTP_PORT=587
   FORTIOS_SMTP_USERNAME=fortiupgrade@example.com
   FORTIOS_SECRETS_DIR=/etc/fortiupgrade/secrets
   FORTIOS_SMTP_PASSWORD_FILE=/opt/fortios/smtp-secrets/password
   FORTIOS_SMTP_STARTTLS=true
   FORTIOS_SMTP_TIMEOUT=10
   FORTIOS_SMTP_FROM=fortiupgrade@example.com
   FORTIOS_APP_URL=https://upgrade-path.example.internal/
   ```

   Ce sont des valeurs d'exemple sans secret réel. Ne jamais créer de variable
   `FORTIOS_SMTP_PASSWORD` dans Portainer : utiliser uniquement
   `FORTIOS_SMTP_PASSWORD_FILE`, pointant par défaut vers le volume SMTP privé
   partagé (web RW, scheduler RO). La GUI permet ensuite de saisir le mot de passe.

   Un montage externe en lecture seule reste une alternative compatible, sans
   remplacement du mot de passe en GUI. Exemple pour un fichier hôte déjà créé en
   mode `0640` root:PGID (lisible par le processus non-root), si un montage personnalisé est nécessaire :

   ```yaml
   volumes:
     - /chemin/hors-depot/smtp-password:/run/secrets/fortios-smtp-password:ro
   environment:
     FORTIOS_SMTP_PASSWORD_FILE: /run/secrets/fortios-smtp-password
   ```
   Les destinataires, l'activation et les produits ne sont pas des variables de
   Stack : les enregistrer ensuite dans **Administration > Notifications**.
5. Cliquer **Deploy the stack**.

La Stack crée deux conteneurs, `web` et `scheduler`, et des volumes nommés
préfixés par le nom de la Stack, généralement `upgrade-path_fortios-data` et
`upgrade-path_fortios-docs`, plus `upgrade-path_fortios-certificates`,
`upgrade-path_fortios-smtp-secrets` et `upgrade-path_fortios-microsoft365-secrets`.

#### 4. Vérifier puis basculer

1. Aller dans **Containers** et ouvrir les logs de `upgrade-path-web-1` : la
   ligne `FortiOS Upgrade Intelligence: http://0.0.0.0:8000/` doit apparaître.
2. Ouvrir les logs de `upgrade-path-scheduler-1` : il doit annoncer le prochain
   créneau de collecte.
3. Conserver `FORTIOS_RUN_ON_START=0` : les données migrées restent intactes et
   le scheduler attend 07:00/15:30 Europe/Paris.
4. Accéder depuis le LAN à `http://<IP_LOCALE_DE_LA_VM>:8000/`. Autoriser
   TCP/8000 uniquement depuis les VLAN/sous-réseaux internes nécessaires au
   firewall de la VM. Le TLS direct avec certificat de PKI interne peut ensuite
   être activé sans ajouter de reverse proxy.

Ne pas supprimer ces volumes nommés lors d'une mise à jour ou d'une
suppression/recréation de Stack : ils contiennent les données accumulées après
la migration. Garder l'instance VPS actuelle en fonctionnement jusqu'à la
validation complète de la nouvelle instance.

#### Accès LAN sans reverse proxy

Nginx n'est pas obligatoire. Pour publier temporairement ou durablement le port
applicatif sur le réseau interne, modifier dans Portainer la variable de Stack :

```text
FORTIOS_HTTP_BIND_ADDRESS=0.0.0.0
FORTIOS_HTTP_PORT=8000
```

Puis cliquer **Update the stack**. L'application sera accessible depuis le LAN
sur `http://<IP_LOCALE_DE_LA_VM>:8000/` (l'IP de la VM, jamais celle du
conteneur). Autoriser le port 8000 uniquement depuis les VLAN/sous-réseaux
internes nécessaires au niveau du firewall de la VM. Ce mode est du HTTP sans
TLS ni authentification supplémentaire : les échanges ne sont pas chiffrés et
il ne doit pas être exposé sur Internet. Il n'y a pas d'alerte de certificat en
HTTP ; pour HTTPS et un nom DNS fiable, activer le TLS direct décrit ci-dessous
ou placer ultérieurement un reverse proxy devant l'application.

### HTTPS direct sans Nginx

Le serveur Python peut aussi terminer TLS directement, sans conteneur proxy.
Dans ce mode, le listener interne 8000 passe entièrement en HTTPS et le port
hôte devient 443. HTTP/8000 n'est plus servi en parallèle, afin d'éviter le
contournement du chiffrement pour les API applicatives.
Pour le domaine interne `sns-security.lan`, utiliser un certificat PKI contenant
`upgrade-path.sns-security.lan` ou le wildcard `*.sns-security.lan`. Le CLI
accepte PKCS#12/PFX/P12, PEM, DER, clés PKCS#8 et chaînes PEM/DER/PKCS#7, puis
normalise le résultat dans le volume persistant de certificats.

La procédure d'installation, d'activation et de renouvellement se trouve dans
[`docs/certificates.md`](docs/certificates.md).
