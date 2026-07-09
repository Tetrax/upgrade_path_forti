# FortiOS Upgrade Intelligence

Outil interne pour afficher le chemin de mise à niveau FortiOS recommandé par Fortinet, puis ajouter les informations utiles à l'ingénieur : problèmes connus, changements de comportement et actions obligatoires.

## Structure

```text
Upgrade_path/
  app/
    index.html
  data/
    fortios-data.sample.json
  scripts/
    fortios_server.py
    fortios_watch.py
  docs/
```

## Lancer l'interface

Pour utiliser le bouton **Récupérer Fortinet**, lancer le serveur local depuis la racine :

```bash
python3 scripts/fortios_server.py --port 8000
```

Puis ouvrir :

```text
http://localhost:8000/app/
```

Ce serveur sert l'interface et ajoute l'endpoint local `POST /api/official-path`. Quand on clique sur **Récupérer Fortinet**, l'interface lui envoie le modèle, la version actuelle et la version cible. Le serveur interroge alors le service public Fortinet Upgrade Path Tool, ajoute le chemin officiel dans `data/fortios-data.generated.json`, puis rafraîchit l'affichage.

Il reste possible d'ouvrir directement :

```text
app/index.html
```

Ou de lancer un serveur statique :

```bash
python3 -m http.server 8000
```

Dans ces deux modes, l'interface reste consultable, mais le bouton **Récupérer Fortinet** ne peut pas fonctionner car aucun endpoint local ne relaie la requête vers Fortinet. Si la page est ouverte directement depuis le fichier HTML, le navigateur peut aussi bloquer le chargement automatique du JSON. Dans ce cas, utiliser **Importer** et sélectionner `data/fortios-data.generated.json`.

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

Depuis l'interface, le même appel est disponible directement avec le bouton **Récupérer Fortinet** si l'application a été lancée avec :

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

Créer `data/advisories.csv` avec les colonnes suivantes :

```csv
id,product,models,version,from,to,severity,timing,title,description,command,source
```

Exemple :

```csv
adv-7.4.11-traffic-redirect,fortigate-fortios,FGT90G,7.4.11,,,important,post-upgrade,Option a verifier apres passage en 7.4.11,Verifier allow-traffic-redirect apres upgrade,"config system settings
  set allow-traffic-redirect enable
end",Base interne SNS
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

## Planification

Exemple cron quotidien :

```cron
15 7 * * * cd /chemin/vers/Upgrade_path && /usr/bin/python3 scripts/fortios_watch.py >> docs/cron.log 2>&1
```
