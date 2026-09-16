# Configurer Microsoft 365 pour les emails FortiUpgrade

Ce guide concerne Microsoft 365 professionnel avec une boîte **Exchange Online**,
dans le cloud Microsoft public. Il ne concerne pas Outlook.com personnel, un
serveur Exchange uniquement local, ni les clouds nationaux Microsoft.

**Principe :** FortiUpgrade s'authentifie comme une application Microsoft Entra,
puis soumet ses emails à Microsoft Graph. Aucun serveur SMTP, mot de passe
utilisateur Microsoft, redirection de connexion ou reconnexion après redémarrage
n'est nécessaire. SMTP reste disponible comme autre transport.

Documentation officielle vérifiée le **9 septembre 2026**. Les noms anglais des
écrans sont conservés pour faciliter leur recherche dans un portail traduit.

## 1. Préparer la boîte et les droits d'administration

Prévoir :

- le tenant Microsoft 365 de l'organisation ;
- une boîte Exchange Online existante, par exemple `fortiupgrade@entreprise.fr`,
  provisionnée et autorisée à envoyer selon les règles/licences de l'organisation ;
- un destinataire de recette que l'administrateur est autorisé à contacter ;
- un administrateur pouvant créer une application Entra et un administrateur
  Exchange pouvant attribuer des rôles d'application ;
- un accès HTTPS sortant depuis **web et scheduler** à
  `login.microsoftonline.com` et `graph.microsoft.com`, avec résolution DNS et
  validation TLS fonctionnelles.

L'adresse expéditrice identifie une **boîte**, pas l'application Entra. L'ID client
n'est ni une adresse email ni un compte utilisateur. Une boîte partagée est
possible si elle est correctement provisionnée dans Exchange Online ; ne pas
créer un utilisateur avec un mot de passe pour faire tourner le connecteur.

## 2. Créer l'application Entra

1. Ouvrir [Microsoft Entra admin center](https://entra.microsoft.com/).
2. Vérifier le tenant sélectionné, surtout si le compte admin gère plusieurs
   organisations.
3. Aller dans **Entra ID → App registrations → New registration**.
4. Nommer l'application, par exemple **FortiUpgrade Notifications**.
5. Choisir **Single tenant only** / **Accounts in this organizational directory
   only**. Ne pas ouvrir aux comptes personnels ou aux autres tenants.
6. Ne pas ajouter de Redirect URI : le flux serveur `client_credentials` n'en a
   pas besoin. Enregistrer l'application.
7. Dans **Overview**, relever :
   - **Directory (tenant) ID** : Tenant ID ;
   - **Application (client) ID** : Client ID.
8. Dans **Entra ID → Enterprise apps / Enterprise applications**, ouvrir
   l'application correspondante et relever son **Object ID**.

**Attention aux identifiants :** l'Object ID de l'**Enterprise application** est
l'identifiant du *service principal*. L'Object ID affiché dans **App
registrations** est un autre objet : ne pas l'utiliser pour `New-ServicePrincipal`
dans Exchange. Tenant ID et Client ID ne sont pas des secrets ; le credential
créé à l'étape suivante en est un.

## 3. Créer le credential

Dans l'App Registration : **Certificates & secrets → Client secrets → New client
secret**. Donner une description et une échéance conforme à la politique de
l'organisation. Copier immédiatement la **Value**, pas le **Secret ID**, vers le
gestionnaire de secrets de déploiement. La valeur n'est visible qu'à la création.

Ne jamais la coller dans un ticket, une PR, Git, un fichier Compose, une variable
d'environnement en clair, `notification-settings.json` ou une capture d'écran.
Ne pas exécuter une commande `curl` contenant le secret dans ses arguments.

Cette V1 utilise un **client secret stocké dans un fichier privé persistant**,
saisissable dans l'administration HTTPS. Le scheduler le monte en lecture seule.
Microsoft recommande certificat ou identité fédérée pour un niveau d'assurance
supérieur ; ces méthodes ne sont pas activées dans cette V1. Elles pourront
remplacer l'acquisition du token sans remplacer le moteur de notifications.
L'expiration du secret doit être suivie dans les procédures de l'organisation.

## 4. Donner uniquement le droit d'envoyer depuis cette boîte

### Méthode recommandée : Exchange Online RBAC for Applications

Le rôle minimal est **`Application Mail.Send`**, limité à la boîte expéditrice par
un *management scope*. Il autorise l'opération Microsoft Graph `sendMail` sans
accès en lecture aux emails, au carnet d'adresses ou aux autres boîtes.

Microsoft indique que **RBAC for Applications remplace Application Access
Policies**. Pour une nouvelle installation, ne pas recopier un ancien tutoriel
basé sur `New-ApplicationAccessPolicy`.

> **Ne pas ajouter en parallèle la permission d'application Graph `Mail.Send`
> tenant-wide dans Entra.** Les autorisations Entra et les attributions RBAC
> s'additionnent : RBAC ne réduit pas un droit global déjà accordé. Retirer le
> consentement global existant pour cette application dédiée avant de compter
> sur la restriction RBAC. Si la permission déléguée `User.Read` a été créée par
> défaut, elle n'est pas nécessaire à FortiUpgrade.

Ces commandes sont à exécuter par l'**administrateur humain** dans PowerShell,
pas par FortiUpgrade. Il lui faut les droits Exchange appropriés : la documentation
Microsoft cite le groupe **Organization Management** (ou les délégations RBAC
équivalentes) et le rôle Entra **Exchange Administrator**. Ne pas donner ces rôles
administratifs à l'application FortiUpgrade.

Installer le module officiel [ExchangeOnlineManagement](https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell)
s'il n'est pas déjà disponible, puis se connecter :

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline
```

Les valeurs demandées ci-dessous sont des identifiants non secrets. Pour une
**nouvelle application dédiée**, exécuter :

```powershell
$ErrorActionPreference = 'Stop'
$clientId = [guid](Read-Host 'Application (client) ID')
$servicePrincipalId = [guid](Read-Host 'Object ID de Enterprise application')
$sender = Read-Host 'Adresse de la boite Exchange Online expeditrice'
$mailbox = Get-Mailbox -Identity $sender
$mailboxId = [guid]$mailbox.ExternalDirectoryObjectId

# Le scope utilise l'identifiant exact de la boite, sans toucher aux attributs metier.
$filter = "ExternalDirectoryObjectId -eq '$mailboxId'"
$targets = @(Get-Recipient -Filter $filter)
if ($targets.Count -ne 1) { throw 'Le scope doit correspondre a une seule boite.' }
$targets | Format-Table DisplayName, PrimarySmtpAddress, ExternalDirectoryObjectId

New-ServicePrincipal -AppId $clientId -ObjectId $servicePrincipalId `
    -DisplayName 'FortiUpgrade Notifications'
New-ManagementScope -Name 'FortiUpgrade-Sender' -RecipientRestrictionFilter $filter
New-ManagementRoleAssignment -Name 'FortiUpgrade-Mail.Send' `
    -App $servicePrincipalId -Role 'Application Mail.Send' `
    -CustomResourceScope 'FortiUpgrade-Sender'

Test-ServicePrincipalAuthorization -Identity $servicePrincipalId -Resource $sender |
    Format-Table RoleName, GrantedPermissions, AllowedResourceScope, InScope
```

Vérifier `Application Mail.Send` et **`InScope = True`** pour cette boîte. Tester
également une autre boîte de recette, qui doit être **hors scope** pour ce rôle.
Ne pas relancer aveuglément les commandes `New-*` si les objets existent : lire
les attributions avec `Get-ServicePrincipal`, `Get-ManagementScope` et
`Get-ManagementRoleAssignment`, puis réconcilier uniquement celles de FortiUpgrade.

`Test-ServicePrincipalAuthorization` teste les droits RBAC, **pas** les permissions
accordées séparément dans Entra. Il ne suffit donc pas, à lui seul, à prouver
l'absence d'un droit global. Examiner aussi les permissions consenties de
l'Enterprise application et les autres attributions de rôles Exchange.

La propagation des permissions peut prendre **30 minutes à 2 heures**. La commande
de test RBAC contourne ce cache, contrairement aux appels Graph réels. Un test RBAC
positif peut donc précéder la réussite de `sendMail`.

### Alternative explicite : droit global Entra

Seulement si l'organisation accepte que l'application puisse envoyer depuis
**toutes les boîtes du tenant** : App Registration → **API permissions → Add a
permission → Microsoft Graph → Application permissions → Mail.Send**, puis
**Grant admin consent for &lt;tenant&gt;** avec un administrateur habilité.

C'est une **alternative au modèle RBAC restreint**, pas une étape supplémentaire
de ce guide. L'application n'a besoin ni de `Mail.Read`, ni de `Mail.ReadWrite`, ni
de `User.Read.All`, ni de `Mail.Send.Shared`, ni de `SMTP.SendAsApp`. Aucun rôle
Azure sur une souscription ou un resource group n'est nécessaire à l'envoi Graph.

## 5. Saisir ou remplacer le secret dans l'interface

Dans **Administration → Notifications → Microsoft 365 / Azure**, saisir la
**Value** du client secret dans le champ masqué et utiliser son bouton
d'enregistrement. Cette action ne change pas le transport sélectionné, ne modifie
pas les paramètres métier et n'envoie aucun email. Le champ est vidé après la
soumission ; le secret enregistré n'est jamais prérempli ni retourné par l'API.
Une saisie vide ne supprime pas l'ancien secret.

Le serveur existant authentifie l'administrateur, vérifie HTTPS/Origin/CSRF et
écrit atomiquement le fichier configuré. Le fichier est l'unique source du
credential pour le moteur Microsoft Graph : ni JSON de configuration, ni cache
secret concurrent, ni dépendance à un helper propre au VPS.

### Stockage portable fourni avec Docker et Portainer

Tous les modèles Compose définissent le même stockage dédié :

```text
Volume Compose : fortios-microsoft365-secrets (préfixé par le nom du Stack)
Conteneur :      /opt/fortios/microsoft365-secrets/client-secret
Variable :       FORTIOS_MICROSOFT365_CLIENT_SECRET_FILE
Web :            volume rw, répertoire privé 0700, fichier 0600
Scheduler :      le même volume ro, mêmes PUID/PGID que web
```

Le volume est initialisé par l'entrypoint et reste vide tant qu'aucun vrai secret
n'est fourni. Le démarrage et SMTP restent fonctionnels. **Ne pas rendre
`/run/fortios-secrets` inscriptible** : les secrets externes y conservent leur
montage lecture seule. SMTP dispose de son propre volume `fortios-smtp-secrets`
pour sa saisie GUI, distinct de celui de Microsoft 365. Les certificats et leur helper
ne changent pas de frontière de privilèges.

| Environnement | Mécanisme |
| --- | --- |
| Compose local ou VPS derrière reverse proxy | Même volume dédié ; aucun helper supplémentaire. |
| Portainer Git Stack | `docker-compose.portainer.yml`, volume partagé web/scheduler. |
| Portainer import d'image / VM entreprise / TLS direct | `docker-compose.portainer-import.yml`, même volume ; aucun chemin hôte VPS requis pour le secret Microsoft. |
| Installation Python native | Configurer la même variable vers un fichier dans un répertoire privé persistant 0700 appartenant au compte web ; scheduler sous le même compte. Ne jamais choisir un chemin servi par HTTP ou versionné. |

### Mise à niveau d'une installation existante

Mettre à jour **l'image et la définition du Stack**, pas seulement l'image.
Conserver le nom du Stack et tous les volumes data/docs/certificates existants ;
ajouter les volumes privés dédiés manquants et leurs références identiques dans web
et scheduler. Pour migrer le mot de passe SMTP sans perdre sa valeur, suivre
[la procédure SMTP](delivery.md#migration-to-editable-smtp-administration).
Dans Portainer, retirer un éventuel ancien override de la variable
qui pointe vers `/run/fortios-secrets/microsoft365-client-secret`, ou le remplacer
par le nouveau chemin. Le même nom de Stack garantit la réutilisation du volume.

Si un vrai secret était déjà configuré dans un fichier externe, sauvegarder ce
fichier et copier sa valeur de façon protégée dans le nouveau stockage **avant**
de changer la référence ; préserver l'ancien fichier pour rollback. Si aucun
secret n'existe encore, ne copier aucune valeur fictive : le saisir ensuite dans
la GUI. Une référence externe en lecture seule reste utilisable pour l'envoi,
mais l'interface indique que son stockage n'est pas modifiable. Il n'y a pas de
fallback silencieux vers un second fichier.

Sauvegarder également le nouveau volume de secrets, de façon chiffrée ou
root-only, sans l'exporter avec le catalogue ni l'image. Pour rollback, conserver
le volume courant et la valeur la plus récente ; l'ancien connecteur sait lire
le même fichier via la même variable. Ne pas restaurer aveuglément un ancien
checkpoint/outbox ni supprimer les volumes (`down -v`).

**Rotation :** créer un nouveau secret dans Entra, le remplacer dans la GUI,
vérifier ensuite le véritable envoi/réception, puis révoquer l'ancien dans Entra.
Le prochain chargement du moteur web ou scheduler lit le nouveau fichier, sans
rebuild d'image. Un remplacement de secret ne valide pas à lui seul les droits
Microsoft ni la réception finale.

## Recette isolée sur ce VPS, sans toucher au runtime permanent

Le fichier `docker-compose.microsoft365-test.yml` lance une image candidate sur
**127.0.0.1:18443**, avec des volumes propres au projet
`fortiupgrade-m365-test`. Il ne monte aucune donnée, aucun credential admin et
aucun certificat du service permanent. Le catalogue initial est celui de
démonstration de l'image, pas un export opérationnel. Seul `web` démarre ; le
scheduler reste derrière le profil explicite `collection` pour éviter une
collecte/envoi automatique pendant la recette.

Sur le VPS, depuis la copie de travail canonical :

```bash
cd /home/tetrax/workspace/Fortiupgrade

# Première préparation uniquement : certificat LOCAL de test, pas credential Azure.
sudo install -d -m 0750 -o root -g 1000 /var/lib/fortiupgrade-m365-test/secrets
if ! sudo test -e /var/lib/fortiupgrade-m365-test/secrets/localhost.key; then
  sudo openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 30 \
    -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -keyout /var/lib/fortiupgrade-m365-test/secrets/localhost.key \
    -out /var/lib/fortiupgrade-m365-test/secrets/localhost.crt
  sudo chown root:1000 /var/lib/fortiupgrade-m365-test/secrets/localhost.{key,crt}
  sudo chmod 0640 /var/lib/fortiupgrade-m365-test/secrets/localhost.{key,crt}
fi

docker compose --env-file /dev/null -p fortiupgrade-m365-test \
  -f docker-compose.microsoft365-test.yml build web
docker compose --env-file /dev/null -p fortiupgrade-m365-test \
  -f docker-compose.microsoft365-test.yml up -d --wait web
```

Depuis ton poste, ouvrir un tunnel avec ta destination SSH habituelle :

```bash
ssh -N -L 18443:127.0.0.1:18443 tetrax@<adresse-SSH-du-VPS>
```

Ouvrir **https://localhost:18443/admin/**. Le certificat auto-signé est uniquement
destiné à cette boucle locale via SSH : accepter l'exception dans ce contexte,
pas sur le site permanent. Sa validité est de 30 jours ; le renouveler
explicitement après expiration. À la première ouverture, créer le compte admin
de recette dans **Première configuration** (mot de passe personnel, au moins
12 octets), puis ouvrir **Notifications**. Aucun compte admin par défaut n'est
fourni et aucun credential Microsoft n'est inventé.

Après création du véritable secret Entra, saisir sa **Value** dans la GUI comme
sur l'instance habituelle. Le Compose de recette configure le volume dédié
`candidate-microsoft365-secrets`, web en écriture et scheduler en lecture seule.
Ne pas créer de valeur fictive pour rendre le voyant vert. Le répertoire hôte
de recette ne contient désormais que les éléments TLS nécessaires à ce test.

Arrêter uniquement la recette, en conservant ses paramètres pour la prochaine fois :

```bash
docker compose --env-file /dev/null -p fortiupgrade-m365-test \
  -f docker-compose.microsoft365-test.yml down
```

Ne pas ajouter `-v` : cela supprimerait les volumes de recette. Ne jamais lancer
ces commandes avec le nom du Stack permanent. Pour une recette de collecte
explicite, après validation des destinataires et activation volontaire, le même
Compose peut démarrer `scheduler` avec `--profile collection` ; ce n'est pas
nécessaire pour le bouton **Tester la connexion**.

## 6. Configurer FortiUpgrade

Dans **Administration → Notifications**, choisir **Microsoft 365** comme mode
d'envoi et renseigner :

- Tenant ID de l'organisation ;
- Client ID de l'application dédiée ;
- adresse email de la boîte expéditrice ;
- nom affiché souhaité.

Le paramètre d'adresse sert à composer le champ From. L'URL Graph doit cibler
l'**UPN ou l'ID objet de la boîte** : ce n'est pas l'ID de l'application. Lorsque
l'UPN est identique à l'adresse email, cette dernière suffit. Si l'UPN et l'adresse
SMTP diffèrent, renseigner l'identité de boîte distincte dans le champ avancé
prévu à cet effet ; un alias arbitraire n'est pas un identifiant Graph garanti.

Enregistrer avant de tester. Les destinataires, les produits surveillés, les
règles High/Critical, l'apparence et les préférences existantes restent partagés
avec SMTP. Le nom affiché est une présentation, pas un droit d'usurpation :
Exchange et les clients de messagerie peuvent afficher le nom résolu dans
l'annuaire plutôt que le libellé transmis.

Les détails du stockage, les variables de bootstrap et les règles de reprise
sont documentés dans [notifications.md](notifications.md). Pour revenir à SMTP,
choisir SMTP et enregistrer : ne pas effacer les préférences, l'outbox ou les
credentials Microsoft. La configuration SMTP reste gérée par l'environnement.

## 7. Tester la connexion et activer

Le bouton **Tester la connexion** envoie un **vrai mail de test** au destinataire
explicitement choisi. Il ne génère pas une fausse CVE et n'injecte pas d'événement
dans l'outbox des notifications.

Il vérifie successivement :

1. l'acquisition d'un token sur
   `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` avec
   `grant_type=client_credentials` et `scope=https://graph.microsoft.com/.default` ;
2. la soumission du message à
   `https://graph.microsoft.com/v1.0/users/{UPN-ou-ID-de-boite}/sendMail` ;
3. l'acceptation de la requête par Graph pour cette boîte.

**`202 Accepted` signifie « soumis et accepté », pas « reçu ».** Le traitement
Exchange, les règles de flux, le routage et une éventuelle non-remise continuent
après la réponse Graph. Vérifier le mail reçu, les éléments envoyés/NDR de la
boîte et, si nécessaire, le suivi des messages dans Exchange admin center.
FortiUpgrade ne demande pas de permission de lecture supplémentaire pour cela.

Recette réelle avant activation :

- vérifier le test RBAC positif pour la boîte et négatif hors scope ;
- vérifier qu'aucun consentement Entra global n'élargit ce périmètre ;
- envoyer un test à un destinataire contrôlé et constater sa réception ;
- vérifier le From, le nom affiché, le sujet, le texte/HTML et les liens ;
- recréer web/scheduler sans modifier les volumes, puis refaire un test : aucun
  login Microsoft utilisateur ne doit être demandé ;
- activer les notifications et observer une collecte naturelle ; ne pas lancer
  un backfill pour fabriquer une notification ;
- si le tenant le permet, tester temporairement une boîte hors scope **de recette**
  et vérifier le refus Graph, puis restaurer l'expéditeur autorisé.

Sans credentials de tenant fournis, les tests automatisés utilisent des réponses
mockées : ils prouvent le contrat OAuth/Graph, l'intégration et les erreurs, pas
la délivrabilité dans l'organisation. Ne pas déclarer l'activation Azure validée
avant la recette réelle ci-dessus.

## 8. Dépannage

| Résultat | Vérifications et action |
| --- | --- |
| Secret absent ou illisible | Référence `_FILE`, montage `:ro`, fichier non vide, UID/GID des deux services. Ne pas afficher son contenu dans les logs. |
| `AADSTS7000215` | Client secret invalide : utiliser la **Value**, pas le Secret ID, et vérifier l'application associée. |
| `AADSTS7000222` | Secret expiré : appliquer la rotation décrite ci-dessus. |
| `AADSTS700016` | Application introuvable dans ce tenant : vérifier Client ID et Tenant ID. |
| `AADSTS90002` | Tenant introuvable ou mauvais cloud : vérifier le Directory tenant ID. |
| Refus OAuth / consentement | Vérifier le modèle d'autorisation choisi et les restrictions Entra sur les identités applicatives. Ne pas ajouter des droits globaux pour contourner un diagnostic. |
| Graph `401` | Token refusé : vérifier tenant, audience Graph et politiques Entra ; aucun token à copier dans un ticket. |
| Graph `403` | Rôle `Application Mail.Send`, scope, service principal, propagation ou consentement global de l'alternative Entra. Le token seul ne prouve pas ces droits. |
| Boîte absente / `404` | Boîte Exchange Online provisionnée, UPN/ID objet correct et adresse expéditrice cohérente ; ne pas utiliser l'Object ID de l'application. |
| Graph `429` | Limitation de débit : respecter `Retry-After`, ne pas cliquer en boucle sur le test. |
| Graph `5xx`, timeout, DNS/TLS | Incident Microsoft ou connectivité sortante ; consulter les journaux nettoyés et laisser la reprise différée agir. Ne pas désactiver la vérification TLS. |
| `202`, mais aucun mail reçu | Vérifier la quarantaine, les NDR, les règles Exchange et le suivi des messages. Ce n'est pas une preuve de remise. |

Une panne de transport ne doit pas faire échouer la collecte. Le moteur conserve
les événements non acceptés dans l'outbox et espace les tentatives. Les erreurs
permanentes de credential/droit nécessitent une correction administrative ; elles
ne déclenchent pas une boucle réseau agressive. Voir les délais exacts dans
[notifications.md](notifications.md).

Graph `sendMail` n'offre pas de garantie *exactly-once*. Une coupure après
acceptation mais avant réception du `202`, ou après `202` avant enregistrement du
succès local, peut produire un doublon lors d'une reprise. Le checkpoint, les clés
de déduplication et les claims évitent le rejeu normal et les envois concurrents
d'un même événement ; ils ne peuvent pas résoudre cette ambiguïté distante. Ne
pas purger l'historique pour résoudre un problème de transport.

## Sources Microsoft officielles

- [Enregistrer une application Entra](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app).
- [OAuth 2.0 client credentials](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow).
- [Graph v1.0 user: sendMail — permissions, MIME et réponse 202](https://learn.microsoft.com/en-us/graph/api/user-sendmail?view=graph-rest-1.0).
- [RBAC for Applications in Exchange Online](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac).
- [New-ManagementScope](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-managementscope?view=exchange-ps).
- [Propriétés de filtre Exchange — ExternalDirectoryObjectId](https://learn.microsoft.com/en-us/powershell/exchange/recipientfilter-properties?view=exchange-ps#externaldirectoryobjectid).
- [Gestion du throttling Graph](https://learn.microsoft.com/en-us/graph/throttling).
- [Traitement d'un envoi après acceptation Graph](https://learn.microsoft.com/en-us/graph/outlook-things-to-know-about-send-mail).
- [Codes d'erreur Microsoft Entra](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes).
