# Sécurité de l'image Docker (Trivy) — ingestion et alertes

Cette brique surveille les vulnérabilités **corrigibles** de l'image Docker de l'application
elle-même, détectées par Trivy dans la CI, et prévient une liste de destinataires **distincte** de
celle des alertes Fortinet.

Elle est volontairement séparée des alertes CVE Fortinet : document de préférences distinct, seuil
distinct (deux niveaux seulement), liste de destinataires distincte, email distinct, et aucune
retombée de l'une sur l'autre dans un sens comme dans l'autre.

## Boucle quotidienne

| Heure (Paris) | Étape | Où |
| --- | --- | --- |
| 06:17 | Le workflow `Tests` scane `main` (cron `17 4 * * *`) et publie l'artefact `trivy-report` | GitHub Actions |
| 06:50 | `scripts/sync_trivy_report.py` récupère le dernier artefact réussi et l'écrit dans `runtime/data/` | VPS, timer systemd |
| 07:00 | La collecte planifiée ingère le rapport, met à jour l'état et envoie un email s'il y a du nouveau | conteneur `scheduler` |
| 12:30 | Deuxième passe de synchronisation (filet de sécurité si la CI du matin a été retardée ou a échoué) | VPS, même timer |

Les deux passes du timer sont idempotentes : un artefact identique à celui déjà ingéré n'est **pas**
réécrit, les fichiers d'état restent donc octet pour octet identiques.

La passe de l'après-midi n'envoie rien de plus le jour même : elle publie le rapport, et c'est la
passe CVE de 15:30 qui l'ingère. Le filet de sécurité sert donc surtout à rattraper une CI en échec
le lendemain matin, sans jamais dupliquer une alerte (l'ingestion est idempotente par construction,
voir plus bas).

## Fichiers

Tous dans le répertoire de données de l'application (`runtime/data/` sur le VPS, monté en
`/opt/fortios/data` dans les conteneurs) :

| Fichier | Rôle | Écrit par |
| --- | --- | --- |
| `trivy-report.json` | L'artefact de la CI, publié **tel quel** (aucune transformation) | `sync_trivy_report.py` |
| `trivy-report.meta.json` | Provenance : `commit`, `runId`, `runUrl`, `sha256`, `downloadedAt` | `sync_trivy_report.py` |
| `container-security-settings.json` | Préférences de la catégorie (actif, seuil, destinataires) | interface d'administration |
| `fortios-notify-history.json` → `containerSecurityState` | Ligne de base : findings connus + dernier scan ingéré | l'ingestion |

Le rapport Trivy **ne contient aucun SHA Git** (vérifié sur l'artefact réel) : c'est le fichier de
métadonnées qui porte le commit du run, et c'est lui que l'email affiche comme provenance.

## Garanties

- **Aucun rapport n'est jamais lu comme « aucune vulnérabilité ».** L'état distingue quatre
  situations : *aucun rapport ingéré*, *à jour*, *obsolète* (> 48 h), *refusé* (avec la raison).
  Sans rapport ingéré, les compteurs valent `null` et l'interface affiche « — », jamais `0`.
- **Première activation silencieuse.** Le premier rapport ingéré établit la ligne de base : même
  une vulnérabilité critique déjà présente ne déclenche rien. On n'envoie jamais le stock initial.
- **Aucun rattrapage lors d'une baisse de seuil.** Toute vulnérabilité du rapport est enregistrée
  dans la ligne de base, y compris sous le seuil. Baisser le seuil ensuite ne renvoie pas
  l'historique ; seule une transition réellement nouvelle notifie.
- **Deux transitions notifient**, et seulement deux : une vulnérabilité **nouvelle**, et une
  **élévation de sévérité** (High → Critical). Une vulnérabilité corrigée est comptée dans l'email
  suivant, jamais à l'origine d'un email.
- **Idempotence par construction.** Un rapport dont l'horodatage de scan n'est pas strictement
  postérieur au dernier ingéré est ignoré : l'état est rendu inchangé et **aucune écriture** n'a
  lieu. Rejouer le même artefact ne peut pas produire d'alerte, indépendamment de la
  déduplication par clé.
- **Refus global, jamais partiel.** Un rapport structurellement invalide est refusé en entier : une
  ligne de base bâtie sur un sous-ensemble silencieusement écarté ferait apparaître des
  vulnérabilités fausses (« nouvelle » après un rejet, « corrigée » à tort). Le refus conserve la
  ligne de base précédente, ne marque rien comme corrigé, et enregistre la raison pour l'afficher.
- **Les octets vérifiés sont les octets analysés.** Le `sha256` du fichier est contrôlé puis le
  même tampon d'octets est analysé (jamais une seconde lecture), donc un remplacement atomique du
  fichier entre les deux étapes ne peut pas faire ingérer un contenu non vérifié.
- **Aucune écriture partielle.** `os.replace()` après `fsync` : un plantage ne laisse jamais un
  fichier d'état tronqué, ni un fichier temporaire derrière lui.
- **Un échec ne détruit rien.** Téléchargement impossible, artefact invalide, empreinte qui ne
  correspond pas : le rapport précédent et ses métadonnées restent en place, et l'application
  continue d'afficher le dernier scan connu (marqué obsolète par son âge) plutôt que de le perdre.

## Où se règlent ces préférences

Dans l'administration, onglet **Système** : la carte **Sécurité de l'image Docker** porte l'interrupteur, le seuil et
les destinataires, et la carte **Rapport Trivy** affiche l'état du dernier rapport ingéré. Les deux cartes sont côte à
côte sur un écran large et empilées en dessous ; les alertes Fortinet et la chaîne email restent dans l'onglet
**Notifications**, dont le périmètre est inchangé.

## Préférences

- `enabled` : active la catégorie. Désactivée, la collecte continue d'ingérer le rapport et
  l'interface continue d'afficher l'état — désactiver est une **pause**, pas une mémoire tampon :
  rien n'est rejoué à la réactivation, et aucune alerte n'est envoyée pendant la pause.
- `minimumSeverity` : `critical` ou `high` uniquement (ce sont les deux niveaux que la surveillance
  couvre ; tout autre niveau est refusé en 400, jamais rabattu silencieusement sur un défaut).
- `recipients` : liste indépendante. Activer avec une liste vide est refusé : un interrupteur vert
  qui n'enverrait nulle part est exactement la mauvaise configuration à empêcher.

Le document de préférences est strict (clés inconnues refusées) mais **non destructif** : un fichier
invalide est signalé et laissé intact, jamais réécrit ni archivé. C'est une différence assumée avec
`notification-settings.json`, dont la récupération historique écrase le fichier illisible.

## Email

Même identité visuelle (logo, panthéon, palette, pied « Équipe Support ») que les autres alertes
internes, contenu propre : compteurs Critical / High / au total, une carte par vulnérabilité (CVE,
paquet, sévérité, version installée, version corrigée, titre court, lien avis), puis le contexte du
scan (image analysée, commit, date), et un bouton **VOIR LE RAPPORT TRIVY** pointant sur le run
GitHub. Le nombre de vulnérabilités corrigées depuis le scan précédent est rappelé quand il y en a.

Aucune introduction éditoriale n'est reprise des alertes CVE : le champ `introduction` de
l'apparence email est un texte rédigé pour les CVE Fortinet, et le réutiliser ici reproduirait
exactement le défaut corrigé par le passé (un paragraphe hors sujet dans un email automatique).
Le rendu produit sa propre phrase, comme le fait déjà l'email des nouvelles versions. Le pied de
signature reste partagé.

Un scan volumineux est tronqué à `MAX_FINDINGS_PER_EMAIL` (20) avec un reste explicite (« … et N
autres ») : l'email reste lisible, le détail complet reste dans l'artefact.

Le bouton ne peut pointer que sur une URL GitHub validée (https, hôte `github.com`). Une URL absente,
d'un autre hôte, ou non https fait retomber le bouton sur l'URL de l'application — jamais sur un lien
non vérifié.

## Exploitation

```bash
# État du timer et de la dernière passe
systemctl list-timers --no-pager fortios-trivy-report-sync.timer
journalctl -u fortios-trivy-report-sync.service -n 30

# Passe manuelle (utile après un run CI à récupérer tout de suite)
cd /home/tetrax/workspace/Fortiupgrade
sudo -u tetrax env HOME=/home/tetrax python3 scripts/sync_trivy_report.py \
  --data-dir /home/tetrax/workspace/Fortiupgrade/runtime/data

# Ce que l'application a réellement ingéré
python3 -c "import json;print(json.load(open('runtime/data/trivy-report.meta.json')))"
python3 -c "import json;s=json.load(open('runtime/data/fortios-notify-history.json'))['containerSecurityState'];print(s['lastScanAt'], len(s['findings']), s['reportError'])"
```

Un rapport qui ne se rafraîchit plus se voit sans journal : après 48 h, l'administration affiche
« Rapport obsolète ». C'est le symptôme à surveiller si l'authentification `gh` venait à casser.

## Prérequis d'exploitation

Le timer tourne **en tant que `tetrax`** (c'est l'utilisateur qui possède `runtime/data/`, et donc
celui qui peut y écrire avec le bon propriétaire pour les conteneurs). Il lui faut donc une
authentification `gh` valide :

```bash
sudo -u tetrax env HOME=/home/tetrax gh auth status
```

Le dépôt étant public, la liste des runs et les métadonnées d'artefact sont lisibles sans
authentification, mais **le téléchargement d'un artefact exige un jeton** (401 en anonyme, vérifié).
L'authentification `gh` est donc la seule dépendance de credential de cette brique ; elle est
stockée dans `/home/tetrax/.config/gh/hosts.yml` (0600, propriétaire `tetrax`) et n'est ni montée
dans les conteneurs ni copiée dans l'image.

L'authentification ne doit pas être perdue : sans elle, la synchronisation échoue proprement
(exit 1, une ligne dans le journal, aucune écriture), et l'application le montre par l'obsolescence
du rapport.

## Ce que cette brique ne fait pas

- Elle ne remplace pas la CI : le scan reste exécuté par le workflow, informatif et non bloquant
  (voir la section « Contrôles CI » du README). Cette brique consomme son résultat.
- Elle ne détecte pas les vulnérabilités **sans correctif** : le workflow filtre
  `ignore-unfixed: true`, pour que chaque alerte soit actionnable.
- Elle n'envoie aucun email au premier scan ni lors d'une baisse de seuil, volontairement.
- Elle ne modifie pas l'image : corriger une vulnérabilité reste un geste explicite (rafraîchir
  l'image de base épinglée, ou monter le paquet), suivi d'un nouveau scan.
