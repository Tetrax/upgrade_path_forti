# FortiUpgrade — Project Instructions

## Produit

FortiUpgrade, également nommé **FortiOS Upgrade Intelligence** dans le dépôt, est un outil interne d’aide aux opérations de mise à niveau Fortinet.

Il fournit les chemins de mise à niveau recommandés par Fortinet et les enrichit avec les informations utiles à l’ingénieur : versions et builds, problèmes connus, changements de comportement, alertes internes, vulnérabilités et actions obligatoires.

Lorsqu’un chemin officiel peut être obtenu auprès de Fortinet, cette source prévaut. Le cache local est un mécanisme de continuité, jamais une validation définitive d’un chemin.

## Dépôt et worktrees

FortiUpgrade est :

- un seul produit ;
- un seul dépôt Git autoritatif ;
- une seule copie de travail canonical.

Le dépôt autoritatif est :

```text
git@github.com:Tetrax/upgrade_path_forti.git
```

La copie de travail canonical est :

```text
/home/tetrax/workspace/Fortiupgrade
```

Elle héberge à la fois les sources suivies par Git et le runtime vivant placé dans `runtime/` (fichier Compose, `data/`, `docs/` runtime, archives de rollback), lui-même ignoré par Git. Les branches servent au travail en cours ; un worktree temporaire doit être supprimé dès que sa branche est mergée. Aucune seconde copie FortiUpgrade, aucun worktree permanent et aucun dossier de déploiement parallèle ne doivent subsister.

L’absence d’une fonctionnalité dans la copie de travail courante ne signifie pas qu’elle est absente de FortiUpgrade. Avant de créer une fonctionnalité ou une architecture, vérifier les branches actives (`git branch -r`) afin d’identifier une implémentation existante ou un travail concurrent.

Une fonctionnalité déjà présente ailleurs doit être intégrée, adaptée ou corrigée dans sa source autoritative plutôt que réimplémentée parallèlement.

## Convergence et sources de vérité

FortiUpgrade doit converger vers une implémentation intégrée et autoritative unique.

Une branche spécialisée peut temporairement porter une évolution, mais elle ne doit pas devenir une implémentation durable indépendante. La convergence s’effectue par le workflow Git normal vers la branche d’intégration désignée.

Lors d’une convergence :

- déterminer quelle implémentation devient autoritative ;
- préserver les comportements utiles déjà présents dans chaque branche ;
- résoudre les divergences sans juxtaposer plusieurs moteurs équivalents ;
- migrer les appelants, les données et les tests vers le mécanisme retenu ;
- supprimer un ancien chemin uniquement lorsque son remplacement est intégré et vérifié.

Un conflit Git ne doit jamais être résolu en supprimant silencieusement une fonctionnalité existante. Une convergence doit notamment préserver les chemins de mise à niveau, les garde-fous contre les downgrades, les collectes, les données acquises, la gestion des certificats et le moteur de notifications.

## Mécanismes autoritatifs

Les mécanismes existants suivants sont les points d’extension à privilégier :

- `scripts/fortios_server.py` pour le serveur applicatif et les endpoints locaux ;
- `scripts/fortios_watch.py` pour les collectes et la mise à jour du catalogue ;
- `scripts/fortios_notify.py` pour la détection, la composition et l’envoi des notifications ;
- `scripts/certctl.py` pour la validation, la normalisation et l’installation des certificats ;
- les helpers de certificats existants pour l’activation directe ou via reverse proxy ;
- `data/fortios-data.generated.json` pour le catalogue généré et enrichi.

Ces noms peuvent évoluer avec l’architecture, mais il doit toujours exister un seul mécanisme autoritatif par responsabilité. Un remplacement doit migrer les usages et être documenté ; il ne doit pas laisser durablement deux implémentations concurrentes.

Les identifiants produits du catalogue constituent une taxonomie commune à toutes les fonctions. FortiClient reste le produit canonique `forticlient`, avec les plateformes `windows`, `macos` et `linux`. Ne pas créer de taxonomie parallèle pour les collectes, les alertes ou les notifications.

## Notifications CVE

`scripts/fortios_notify.py` est le moteur autoritatif des notifications. Les notifications restent rattachées au cycle de collecte existant ; elles ne doivent pas introduire un second pipeline de collecte ou un état concurrent.

### Catégories et commutateurs

Deux commutateurs fonctionnels indépendants, persistés dans `data/notification-settings.json` :

- `enabled` — portée **historique** : les CVE **et** les catégories système (fin de support, échecs répétés de collecte, retours à la normale, reprise de compatibilité). Ce n’est pas un alias des CVE ; le réduire à cette seule catégorie casserait les notifications système existantes.
- `releaseNotificationsEnabled` — les alertes de **nouvelles versions** uniquement.
- `releaseRecipientsShared` — `true` par défaut : les nouvelles versions utilisent la liste `recipients`.
- `releaseRecipients` — liste dédiée aux nouvelles versions, utilisée uniquement si `releaseRecipientsShared` est `false` ; elle est alors obligatoirement non vide.

Les trois clés de release sont **optionnelles** au chargement : un fichier antérieur hérite de `enabled` / `true` / `[]`. Un partage désactivé avec une liste dédiée vide est **refusé** explicitement (jamais de repli silencieux vers les destinataires CVE, jamais d’email sans destinataire).

### Routage de livraison

Les événements sont regroupés en **un email par liste de destinataires effective** : CVE et catégories système vers `recipients`, nouvelles versions vers la liste effective des releases. Quand les deux listes sont identiques, un seul email groupé est conservé (comportement historique) ; quand elles diffèrent, deux emails distincts sont produits. Chaque lot est composé, livré, finalisé ou relâché **indépendamment** : un échec sur une catégorie ne bloque ni ne duplique l’autre, et la catégorie déjà délivrée n’est jamais renvoyée. Clés de déduplication, point de contrôle, réclamations et concurrence restent inchangés.

L’apparence est commune aux deux catégories, **sauf l’introduction** : `introduction` alimente les emails CVE, `releaseIntroduction` les emails de nouvelle version. Les deux acceptent d’être vides, auquel cas le renderer écrit son propre texte. Quand `releaseIntroduction` est vide, l’email de release garde la phrase automatique du renderer, accordée au nombre de versions rapportées : « FortiUpgrade a détecté une nouvelle version Fortinet disponible au téléchargement. » pour une seule, « FortiUpgrade a détecté N nouvelles versions Fortinet disponibles au téléchargement. » pour plusieurs.

`releaseIntroduction` est **optionnelle au chargement** : un document d’apparence écrit avant elle (`displayName`, `introduction`, `signature`) continue de se charger sans perte — `introduction` garde sa portée historique (le paragraphe des alertes CVE) et les emails de nouvelle version prennent le texte automatique du renderer. Une clé inconnue reste rejetée, et un enregistrement depuis l’interface écrit toujours les deux champs.

Les destinataires sont communs par défaut et peuvent être rendus dédiés aux nouvelles versions (`releaseRecipientsShared: false`). Une collecte produit alors un email par liste de destinataires effective, et au maximum un par catégorie.

Un fichier `notification-settings.json` écrit avant l’existence de `releaseNotificationsEnabled` n’en contient pas la clé : il l’hérite alors de `enabled`. Le chargement d’un fichier légitime ne doit ni déclencher la reprise « configuration corrompue », ni perdre les destinataires existants, ni réécrire le fichier. Le champ est **optionnel** au chargement ; les véritables clés inconnues restent rejetées.

Le commutateur des versions ne conditionne que la dérivation de `derive_version_events()`. Lorsqu’il est désactivé, le point de contrôle `versionsByProduct` continue d’avancer : une réactivation ne doit provoquer aucun rattrapage historique.

La clé de déduplication des versions (`new-version|<produit>|<produit>|<version>`) est un format historique stable : elle ne doit jamais changer, sinon une release déjà envoyée serait renotifiée.

Les emails de nouvelles versions utilisent un composer dédié (`fortios_email_render.compose_release_email`) qui réutilise l’identité SNS (hero, logo, panthère, palette, CTA, pied Support) sans reprendre les composants métier des CVE (badge de sévérité, compteurs, détail par CVE). Un email ne contenant que des nouvelles versions n’utilise plus le rendu texte historique.

### Règles High/Critical

Une notification CVE est créée uniquement pour :

- une nouvelle CVE **High** ou **Critical** affectant au moins un produit sélectionné ;
- une CVE existante passant de `Unknown`, `Low` ou `Medium` à `High` ;
- une CVE existante passant de `Unknown`, `Low` ou `Medium` à `Critical` ;
- une CVE existante passant de `High` à `Critical`.

Ne doivent pas produire de notification CVE :

- les CVE `Unknown`, `Low` ou `Medium` ;
- une CVE High ou Critical dont la sévérité n’augmente pas ;
- une simple republication PSIRT ;
- une modification de texte, de CVSS ou de périmètre sans escalade de sévérité ;
- une CVE ne concernant aucun produit sélectionné.

Une CVE affectant plusieurs produits sélectionnés reste un seul événement contenant tous les produits concernés. Un run doit produire au maximum un email synthétique, dont la priorité reflète la sévérité la plus forte du lot.

Les notifications CVE doivent converger avec les catégories historiques existantes, notamment les nouvelles versions, les passages en fin de support, les échecs répétés de collecte et les retours à la normale. Elles ne doivent pas les remplacer silencieusement.

### Checkpoint et backfill

Les événements sont calculés par différence avec un checkpoint de notification persistant, jamais en interprétant l’ensemble du catalogue courant comme un ensemble de nouveaux événements.

Le checkpoint doit représenter une référence durable antérieure à la collecte. Son initialisation et son avancement doivent rester coordonnés avec la persistance des événements produits afin qu’une interruption ne puisse ni perdre une notification ni provoquer le rejeu de tout l’historique.

La première activation initialise silencieusement la référence courante.

Un backfill historique, notamment un `--cve-backfill`, enrichit le catalogue sans notifier les données déjà existantes. Une reconstruction ou une migration d’état ne doit pas transformer l’historique en nouveaux événements.

Les transitions dépendantes du temps, telles que le passage d’une branche en fin de support, conservent leur propre état persistant. La première observation d’un état déjà ancien est silencieuse ; une transition ultérieure est notifiée une seule fois.

### Déduplication et outbox

Chaque événement possède une clé de déduplication stable représentant son type, sa source, sa ressource et la transition observée.

La déduplication doit empêcher :

- l’ajout multiple du même événement dans l’outbox ;
- un nouvel envoi après succès ;
- l’envoi concurrent du même événement par plusieurs collectes.

Elle ne doit pas dépendre uniquement d’un timestamp, du contenu rendu de l’email ou d’un état en mémoire.

Un événement est persisté dans l’outbox avant toute tentative SMTP. Il n’en est retiré qu’après confirmation d’un envoi réussi.

En cas d’échec SMTP :

- l’événement reste disponible pour une tentative ultérieure ;
- une exécution suivante peut le reprendre, même sans nouvel événement ;
- une exécution interrompue ne doit pas bloquer définitivement la réclamation ;
- aucune donnée sensible ne doit être journalisée ;
- la collecte principale ne doit pas échouer à cause de la notification.

Deux exécutions concurrentes ne doivent pas pouvoir envoyer le même événement. Les mécanismes existants de verrouillage, de réclamation et d’expiration font partie de cet invariant et ne doivent pas être contournés.

Désactiver les notifications suspend les envois sans effacer l’outbox existante. La désactivation ne doit pas accumuler rétroactivement tout le catalogue en vue d’un futur envoi.

L’état persistant des notifications conserve de manière cohérente le checkpoint, l’outbox, l’historique de déduplication et les autres états nécessaires aux transitions. Toute évolution de ce schéma doit préserver la reprise après redémarrage et la compatibilité des données existantes, ou fournir une migration explicite.

Un fichier d'état existant mais invalide ou illisible n'est pas une première activation : conserver ses octets et suspendre les notifications avec un diagnostic nettoyé, sans bloquer la collecte. Ne pas réinitialiser silencieusement l'ensemble de l'état à cause d'une corruption partielle du checkpoint ou d'un autre champ ; la récupération réconcilie explicitement checkpoint, outbox et clés d'envoi.

### Indépendance entre collecte et notification

La collecte et la mise à jour du catalogue restent fonctionnelles même si la configuration SMTP est absente, invalide ou temporairement indisponible.

Une erreur de résolution DNS, connexion, STARTTLS, authentification, timeout, construction de message ou lecture de configuration SMTP doit être isolée du résultat de la collecte.

Le moteur de notification doit retourner un état exploitable et nettoyé plutôt que propager une erreur susceptible d’interrompre le pipeline de données.

### Configuration fonctionnelle et secrets SMTP

Maintenir deux responsabilités distinctes :

**Configuration fonctionnelle :**

- activation des notifications ;
- produits surveillés ;
- destinataires ;
- seuil fonctionnel supporté.

Elle est validée et persistée dans l’état applicatif prévu à cet effet.

**Infrastructure SMTP :**

- serveur et port ;
- compte technique ;
- STARTTLS et timeout ;
- expéditeur ;
- URL applicative ;
- référence vers le secret SMTP.

Les paramètres SMTP non secrets sont modifiables dans l’administration et persistés par le moteur existant. L’environnement sert de bootstrap ; une sauvegarde GUI valide et explicitement versionnée devient autoritative. Les anciens fichiers non marqués ne doivent jamais réactiver silencieusement des paramètres obsolètes. Une configuration enregistrée invalide suspend les envois plutôt que revenir à une autre source.

La référence du mot de passe SMTP reste définie par l’environnement de déploiement. Sa saisie administrateur est write-only, avec les protections de session, d’origine et de CSRF existantes ; un champ vide conserve le secret actuel. L’écriture atomique utilise un stockage privé dédié, inscriptible par le web et en lecture seule pour le scheduler, sans rendre inscriptibles les répertoires globaux de secrets ou de certificats. Les anciens montages en lecture seule restent utilisables pour l’envoi. Le mot de passe ne doit jamais être enregistré dans Git, dans la configuration fonctionnelle, dans l’image, dans une réponse au navigateur ou dans les logs. Les procédures de migration et de rollback restent dans `docs/delivery.md`.

Une compatibilité historique par variables d’environnement peut servir au bootstrap initial, mais elle ne doit pas devenir une seconde source de vérité après l’enregistrement de la configuration fonctionnelle.

Le test d’envoi depuis l’administration et l’envoi après collecte doivent utiliser le même moteur SMTP autoritatif.

## Certificats

`scripts/certctl.py` et les helpers existants constituent le mécanisme autoritatif de gestion des certificats. Ne pas créer un second chemin d’installation ou d’activation qui contournerait leurs validations et leurs frontières de privilèges.

Avant activation, le mécanisme autoritatif doit vérifier au minimum :

- le format réel des éléments fournis ;
- la validité temporelle du certificat ;
- le SAN/FQDN attendu ;
- la correspondance entre certificat et clé privée ;
- la cohérence de la chaîne ;
- la capacité de la paire normalisée à être chargée comme configuration TLS.

L’activation doit rester atomique : une paire partielle, incohérente ou invalide ne doit jamais devenir la paire active.

Les clés privées, mots de passe d’archives et credentials administrateur restent hors du dépôt et des images. Ils ne doivent pas apparaître dans les logs, les réponses HTTP ou les arguments visibles d’un processus.

Les modes TLS direct et terminaison TLS par reverse proxy doivent conserver les frontières de privilèges documentées. Lorsqu’un helper privilégié est utilisé, le conteneur applicatif ne doit pas pouvoir le contourner ni obtenir un accès d’écriture équivalent.

Toute évolution de ce domaine doit conserver un retour à la paire précédente en cas d’échec d’activation ou de rechargement. Les procédures opérationnelles détaillées restent dans `docs/certificates.md` et dans les fichiers de déploiement autoritatifs.

## Données persistantes et déploiement

Le catalogue, les données acquises, l’état de santé, les préférences, l’état des notifications, les alertes, les certificats et les autres états applicatifs persistants ne sont pas des artefacts jetables du conteneur.

Une reconstruction d’image ou un redéploiement ne doit pas réinitialiser ces données ni repartir silencieusement du catalogue d’exemple.

Tout changement de schéma, de conteneur, de montage ou de stockage doit :

- préserver la compatibilité des données existantes ou fournir une migration vérifiée ;
- être testé avec les états persistants concernés avant déploiement ;
- conserver les secrets et certificats hors de l’image ;
- disposer d’un rollback simple vers la version précédente.

Un retour vers une image antérieure à un durcissement du schéma de
`data/notification-settings.json` exige de restaurer le fichier de préférences de
cette version : l'ancien validateur rejette une clé inconnue et perd alors les
destinataires et les commutateurs. Le fichier de préférences fait donc partie du
jeu de rollback au même titre que l'image et la configuration, et ne doit jamais
être supprimé pour faire disparaître un diagnostic.

L’image, la configuration et les données nécessaires au retour arrière doivent rester disponibles jusqu’à validation réelle du nouveau déploiement. Les détails de migration et d’exploitation appartiennent à la documentation de déploiement, pas à ce fichier.

## Documentation d’architecture

Tout changement d’architecture significatif doit être documenté dans le même changement Git.

La documentation doit rendre explicites :

- le problème résolu ;
- le mécanisme devenu autoritatif ;
- les anciens chemins remplacés ;
- les impacts sur les données persistantes et les frontières de sécurité ;
- les besoins de migration ;
- le principe de rollback.

Mettre à jour la documentation autoritative existante, notamment `README.md`, `docs/` et les fichiers de déploiement concernés, plutôt que créer une description concurrente.

## Condition de complétion

Un changement FortiUpgrade n’est terminé que lorsque son comportement réel est vérifié.

La validation doit démontrer, selon le périmètre concerné :

- que les autres worktrees ou branches actives pertinents ont été examinés avant toute nouvelle implémentation susceptible de chevaucher un travail existant ;
- que la branche destinée à l’intégration converge vers une seule implémentation ;
- que les fonctionnalités existantes concernées sont conservées ;
- que les tests pertinents et les contrôles du dépôt réussissent ;
- que les invariants de notification, certificat et persistance concernés restent respectés ;
- qu’une migration ou un changement de conteneur fonctionne avec les données persistantes existantes ;
- que le service démarre et que le parcours modifié fonctionne effectivement ;
- que le rollback prévu reste praticable ;
- que la documentation reflète l’architecture livrée.

La réussite d’un test isolé dans un seul worktree ne prouve ni la convergence du produit ni l’absence de régression sur la future branche intégrée.

## Clôture — cohérence Git et Obsidian

Toute tâche significative modifiant le fonctionnel, l’architecture, l’UX/UI, le déploiement/exploitation, la roadmap ou une décision importante impose une réconciliation documentaire avant clôture :

1. Identifier la note canonique dans `/home/tetrax/workspace/Obsidian` à partir des références de ce fichier, puis des liens projet/système pertinents ; lire les instructions du vault. Ne jamais créer une documentation parallèle à une note canonique existante.
2. Comparer l’état réel aux documents du dépôt et à Obsidian : état, progression, fonctionnalités terminées, décisions, blocages, `next_action`, architecture et exploitation. Corriger uniquement ce qui est réellement obsolète, en préservant structure et conventions ; utiliser les mécanismes existants du vault pour les champs dérivés, le cockpit et les validations.
3. Vérifier Git : branche, fichiers modifiés, non suivis pertinents, commits locaux et avance/retard par rapport au remote actualisé. Commit/push le projet lorsque la mission ou son workflow normal le prévoit ; vérifier le résultat distant, sans intégrer de travaux étrangers ni autoriser implicitement merge ou déploiement.
4. Inclure les seules modifications Obsidian pertinentes dans Git et créer un commit selon le workflow du vault. Ne jamais y mêler de modifications étrangères ; aucun push Obsidian tant qu’aucun remote n’est configuré.
5. Le rapport final doit signaler explicitement tout reste non commité, non poussé, non documenté ou toute divergence volontaire, avec sa raison. Ne pas déclarer une terminaison totale tant que code réel, état Git attendu, documentation projet et Obsidian ne sont pas cohérents ; distinguer sources livrées et runtime déployé.

Une lecture, un audit sans modification, une question, une investigation sans changement d’état ou une expérience temporaire ensuite annulée ne justifie aucun commit ni mise à jour documentaire artificielle. Si la vérification ne révèle rien d’obsolète, ne pas modifier les notes pour produire du bruit.

Référence canonique : `01 - Projects/FortiUpgrade/fortiupgrade.md` dans le vault ; suivre ses liens vers les sous-projets pour le chantier concerné. Les règles versionnées doivent être intégrées dans les autres branches par le workflow Git normal, pas copiées manuellement entre worktrees.
