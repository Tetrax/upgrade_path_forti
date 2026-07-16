# FortiOS Upgrade Intelligence

Outil interne pour afficher le chemin de mise à niveau FortiOS recommandé par Fortinet, puis ajouter les informations utiles à l'ingénieur : problèmes connus, changements de comportement et actions obligatoires.

## Structure

```text
Upgrade_path/
  app/
    index.html
    shared.css
    alerte/
      index.html
      app.js
    forticlient/
      index.html
      app.js
  data/
    fortios-data.sample.json
  scripts/
    fortios_server.py
    fortios_watch.py
    import_forticlient_compat.py
  docs/
```

## Lancer l'interface

Pour que **Afficher le chemin** puisse interroger Fortinet en direct, lancer le serveur local depuis la racine :

```bash
python3 scripts/fortios_server.py --port 8000
```

Puis ouvrir :

```text
http://localhost:8000/app/
```

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

Dans l'interface (outil principal comme page `/app/alerte/`), un sélecteur **Produit** permet de basculer entre FortiGate/FortiOS, FortiAnalyzer et FortiManager. Chaque alerte interne est rattachée à un seul produit ; la liste des alertes se filtre par produit par défaut (option "Tous les produits" disponible).

## FortiClient et FortiClient EMS

FortiClient (Windows/macOS/Linux) et FortiClient EMS n'existent pas dans l'Upgrade Path Tool public de Fortinet (vérifié dans son propre code) — **pas de chemin recommandé automatique** pour ces deux produits. En revanche, l'outil récupère leur catalogue de versions et permet de leur créer des alertes internes, exactement comme les autres produits (sélecteur **Produit** sur `/app/alerte/`).

Pour récupérer le catalogue FortiClient/EMS :

```bash
python3 scripts/fortios_watch.py --base data/fortios-data.generated.json --forticlient-catalog
```

Chaque plateforme FortiClient (Windows, macOS, Linux) est traitée comme un "modèle" du produit `forticlient`, chacune avec ses propres versions/builds (scrapés depuis leurs release notes publiques respectives). FortiClient EMS est un produit séparé (`forticlient-ems`) avec un seul modèle.

### Page `/app/forticlient/` — versions et compatibilité EMS ↔ FortiClient

```text
http://localhost:8000/app/forticlient/
```

En plus d'afficher un résumé du catalogue de versions connues, cette page permet d'enregistrer des **combinaisons EMS ↔ FortiClient qui fonctionnent bien** (testées en prod), pour éviter de retester à chaque fois : choisir une version d'EMS, cocher une ou plusieurs versions FortiClient compatibles, ajouter une note et une source. Modifier/supprimer une combinaison fonctionne comme pour les alertes.

Les **alertes internes** créées pour FortiClient ou FortiClient EMS s'affichent aussi sur cette page (lecture seule), pour tout avoir au même endroit. Elles se créent et se modifient toujours depuis `/app/alerte/` — le bouton "Modifier dans Alertes internes" de chaque carte y renvoie directement, pré-filtré sur le bon produit via `?product=forticlient` ou `?product=forticlient-ems` dans l'URL (ce paramètre fonctionne sur `/app/alerte/` en général, pas seulement depuis cette page).

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
http://localhost:8000/app/alerte/
```

Cette page permet à un ingénieur de déclarer une alerte interne (titre, description, sévérité, moment) en cochant une ou plusieurs versions FortiOS concernées, et en choisissant si elle s'applique à tous les boîtiers ou à une sélection précise. L'alerte est envoyée à l'endpoint local `POST /api/advisories`, qui l'ajoute dans `data/fortios-data.generated.json`. Elle s'affiche ensuite automatiquement dans l'outil principal dès qu'un chemin d'upgrade passe par une des versions concernées, pour un modèle concerné.

Le champ description accepte une mise en forme légère, avec aperçu en direct et boutons dédiés dans la page :

- `**texte**` pour du **gras**
- `__texte__` pour du souligné
- une ligne commençant par `- ` pour une puce de liste
- une ligne vide pour démarrer un nouveau paragraphe
- coller (Ctrl+V) ou glisser une image dans le champ, ou utiliser le bouton Image, pour insérer une capture d'écran (PNG/JPEG/GIF/WEBP, 8 Mo max)

Le rendu (dans `/app/alerte/` comme dans l'outil principal) est toujours construit en DOM à partir de ce texte brut, jamais en interprétant du HTML.

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

Puis lancer `python3 scripts/fortios_watch.py --base data/fortios-data.generated.json`. La colonne `version` ne prend qu'une seule version par ligne ; pour cibler plusieurs versions avec la même alerte, passer par la page `/app/alerte/` (colonne `versions`, tableau) ou dupliquer la ligne CSV.

## CVE PSIRT Fortinet

En plus des alertes internes (bugs remontés par l'équipe), l'outil croise automatiquement les versions avec les **CVE publiées par le Fortinet PSIRT** pour FortiOS, FortiAnalyzer, FortiManager, FortiClient et FortiClient EMS. Fortinet publie pour chaque advisory (`FG-IR-xx-xxx`) un export **CSAF** (Common Security Advisory Framework, un format JSON standard et structuré) qui donne, pour chaque CVE, la ou les plages de versions exactement affectées par branche (ex: `FortiOS >=7.6.0|<=7.6.4`, ou `FortiClientEMS 7.0 all versions` quand toute la branche est concernée) — bien plus fiable qu'un scraping de la page HTML humaine.

Affichage :

- Sur l'outil principal (`/app/`), chaque version du chemin affiche un badge `🛡 CVE-xxxx-xxxxx` si elle est concernée, et une section dédiée liste les CVE du chemin avec sévérité CVSS, score, lien vers la fiche PSIRT, et indique si le chemin choisi corrige la CVE ou si la version cible reste vulnérable.
- Sur `/app/forticlient/`, les cartes de combinaisons EMS ↔ FortiClient affichent la même pastille et le même détail si l'une des versions du couple est concernée.

Collecte (`scripts/fortios_watch.py`) :

- `--cve-catalog` : rafraîchissement quotidien, incrémental. Ne regarde que le flux RSS PSIRT (`https://www.fortiguard.com/rss/ir.xml`, les ~50 dernières advisories tous produits confondus) et ne va chercher le CSAF que pour les advisories pas encore connues — quelques requêtes par jour dans l'usage normal. Branché sur le timer quotidien (`deploy/fortios-catalog-refresh.service`).
- `--cve-backfill [--cve-backfill-max-pages N]` : backfill historique complet, à lancer manuellement de temps en temps. Parcourt la liste paginée PSIRT filtrée par produit (`fortiguard.fortinet.com/psirt?product=...`) pour chacun des 5 produits suivis, donc bien plus de requêtes (plusieurs centaines) — pas dans le timer quotidien.

Une CVE n'est retenue que si elle touche au moins un des 5 produits suivis par l'outil (le reste du catalogue PSIRT — FortiWeb, FortiMail, FortiSandbox, etc. — est ignoré). Une même CVE peut apparaître dans plusieurs `vulnerabilities[]` du CSAF (une par plateforme FortiClient par exemple) : elles sont fusionnées en une seule entrée avant d'être stockées, sinon la dernière écraserait les précédentes.

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

## Planification

Un timer systemd (`deploy/fortios-catalog-refresh.timer` + `.service`, installés par `deploy/install.sh`) lance chaque jour à 7h15, en deux étapes :

```bash
python3 scripts/fortios_watch.py --base data/fortios-data.generated.json --docs-catalog --tool-products fortianalyzer,fortimanager --forticlient-catalog --cve-catalog
.venv-compat/bin/python3 scripts/import_forticlient_compat.py --commit
```

La première commande détecte automatiquement les nouvelles versions FortiOS publiées dans un train déjà connu et les nouveaux modèles FortiGate/FortiWiFi apparus dans les release notes publiques `docs.fortinet.com`, les nouveaux modèles/versions FortiAnalyzer et FortiManager via les endpoints de l'Upgrade Path Tool, les nouvelles versions FortiClient/FortiClient EMS via leurs release notes publiques, et les nouvelles CVE PSIRT (voir ci-dessus). La seconde réimporte la grille de compatibilité officielle EMS ↔ FortiClient (voir plus haut). Le résultat est fusionné dans `data/fortios-data.generated.json` (les chemins déjà récupérés via l'app ne sont pas perdus) et un rapport est écrit dans `docs/last_report.md`. Si la première étape échoue, systemd n'enchaîne pas sur la seconde (`ExecStart=` multiples) — sans gravité, le timer réessaie le lendemain.

Important : `--base data/fortios-data.generated.json` est indispensable en tâche planifiée. Sans lui, le script repart de `data/fortios-data.sample.json` (le petit exemple) et écraserait les chemins déjà récupérés via l'interface.

Un train FortiOS totalement nouveau (ex: un futur 8.4) n'est détecté que s'il figure dans `DEFAULT_DOCS_MAJOR_VERSIONS` (dans `scripts/fortios_watch.py`) ou via `--docs-major-versions`.

Suivre l'exécution :

```bash
systemctl list-timers fortios-catalog-refresh.timer
journalctl -u fortios-catalog-refresh.service -n 50
```
