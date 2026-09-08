# FortiUpgrade — Project Instructions

## Produit

FortiUpgrade, également nommé **FortiOS Upgrade Intelligence** dans le dépôt, est un outil interne d’aide aux opérations de mise à niveau Fortinet.

Il fournit les chemins de mise à niveau recommandés par Fortinet et les enrichit avec les informations utiles à l’ingénieur : versions et builds, problèmes connus, changements de comportement, alertes internes, vulnérabilités et actions obligatoires.

Lorsqu’un chemin officiel peut être obtenu auprès de Fortinet, cette source prévaut. Le cache local est un mécanisme de continuité, jamais une validation définitive d’un chemin.

## Dépôt et worktrees

FortiUpgrade est :

- un seul produit ;
- un seul dépôt Git autoritatif ;
- potentiellement plusieurs branches et worktrees.

Le dépôt autoritatif est :

```text
git@github.com:Tetrax/upgrade_path_forti.git
```

Les worktrees sont des surfaces de travail. Ils ne constituent jamais des frontières fonctionnelles ou produit.

Les worktrees actuellement connus sont :

- `/home/tetrax/workspace/upgrade_path`
- `/home/tetrax/workspace/upgrade_path_cert_proxy`
- `/home/tetrax/workspace/upgrade_path_cve_notifications`

Cette liste décrit l’état actuel et peut évoluer. L’appartenance au produit doit être déterminée par Git, pas uniquement par le nom ou l’emplacement du répertoire.

L’absence d’une fonctionnalité dans le worktree courant ne signifie pas qu’elle est absente de FortiUpgrade. Avant de créer une fonctionnalité ou une architecture, vérifier les autres branches et worktrees actifs afin d’identifier une implémentation existante ou un travail concurrent.

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

Elle relève de l’environnement de déploiement.

Le mot de passe SMTP est fourni par un fichier secret monté en lecture seule. Il ne doit jamais être enregistré dans Git, dans la configuration fonctionnelle, dans l’image, dans une réponse au navigateur ou dans les logs.

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
