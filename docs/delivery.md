# Portainer/VPS delivery — operational gates

## Convergence des branches

Audit du 2026-09-08 après `git fetch origin` : **`main` est la seule ligne
autoritative**. Le socle `d2b8f9725c77df18175a8d08e416c199fd5cec1d` contient déjà
les fonctionnalités des PR #3 à #11 (la PR #9 est remplacée par #10) et correspond au code du runtime personnel. La branche temporaire
`integration/fortiupgrade-convergence`, alors ouverte dans le worktree
`/home/tetrax/workspace/upgrade_path_convergence`, partait de ce socle, intégrait par
merge les instructions `docs/agent-closeout-coherence@35f743b`, puis clôt les
incohérences documentaires et protégeait l'état de notification corrompu contre une
réinitialisation silencieuse. Elle n'a pas créé une seconde ligne de release.

### Cartographie Git historique (worktrees supprimés le 2026-09-15)

Tous ces worktrees appartenaient à `git@github.com:Tetrax/upgrade_path_forti.git`.
Ancêtre commun des trois worktrees demandés : `13fd5bb3170aa9ed2c42a475de26eb89355866dc`.
Certificats/CVE partageaient ensuite `0ab5c6330ca3223a910d4b73801f17407f379d50`.
Le stash commun est vide. Avance/retard : état avant cette clôture.

| Worktree / branche (supprimé) | HEAD | Upstream ; avance/retard | Relation à main |
| --- | --- | --- | --- |
| `upgrade_path` / `fix/upgrade-path-no-downgrades` | `13fd5bb` | `origin/fix/upgrade-path-no-downgrades` ; 0/10 | ancêtre ; 0/28 |
| `upgrade_path_cert_proxy` / `fix/cert-admin-reverse-proxy` | `ced3acc` | `origin/fix/upgrade-path-no-downgrades` ; 1/0 | 1/18 ; patch déjà adapté |
| `upgrade_path_cve_notifications` / `feature/cve-email-alerts` | `91845db` | `origin/feature/cve-email-alerts` ; 0/0 | ancêtre ; 0/13 |

`git range-diff ced3acc^..ced3acc 6355cf0^..6355cf0` ne montre que les
adaptations de contexte SMTP/imports : le certificat a été repris par `6355cf0`
dans la PR #4. `git cherry` seul ne reconnaît pas cette équivalence contextualisée.
Rejouer `ced3acc` ferait inutilement conflit avec le serveur et les Compose intégrés.
La PR #9 (`8a20432`, rotation du mot de passe) est fermée et remplacée par la
PR #10 (`c17c995`, compte et sécurité), pas une fonctionnalité abandonnée.

Les autres worktrees (compte, First Run, SMTP, aperçu, CSP, livraison, releases
détachées) étaient propres et déjà intégrés : ils ont été supprimés avec le reste.
Les copies disparues de `/opt/data/worktrees/*` ont été élaguées par
`git worktree prune`. Les branches distantes mergées ont été supprimées, puis
`feature/admin-password-change` (repliée par la PR #10) a été supprimée à son tour
le 2026-09-16 après vérification de son obsolescence ; son commit `8a20432` reste
archivé dans `runtime/archive/upgrade-path-legacy-20260915.bundle`. `main` est
désormais la seule branche, locale et distante.

### Copie de travail unique (2026-09-15)

`/home/tetrax/workspace/Fortiupgrade` est désormais la **seule** copie de travail
FortiUpgrade du VPS : le dépôt Git sur `main` **et** l'hôte du runtime vivant placé
dans `runtime/` (`compose.yml`, `data/`, `docs/` runtime, `rollback/`, `archive/`),
ignoré par Git parce que les `data/` et `docs/` versionnés contiennent les
échantillons et les guides : l'état vivant ne doit jamais être monté par-dessus.

Un seul worktree subsiste : ce workspace principal. Aucun worktree permanent,
aucun dossier de déploiement parallèle.

Suppression de l'ancien état, après archivage vérifiable :

- bundle Git complet des branches et refs locales :
  `runtime/archive/upgrade-path-legacy-20260915.bundle` (75 refs, historique complet) ;
- patch des 18 fichiers modifiés non commités du worktree historique :
  `runtime/archive/upgrade-path-legacy-uncommitted.patch` (+ liste `--porcelain --ignored`) ;
- copie octet à octet de l'état persistant vers `runtime/data` et `runtime/docs`
  (comparaison SHA-256 contre `runtime/archive/migration-baseline-20260915.json`) ;
- l'ancien dossier de déploiement `/home/tetrax/deploy/Fortiupgrade`, les 16
  worktrees, le clone obsolète `workspace/Fortiupgrade` et le clone
  `workspace/Fortiupgrade-audit-fixes` ont été supprimés.

La pile de production est celle du projet Compose `fortiupgrade` lancée depuis
`/home/tetrax/workspace/Fortiupgrade/runtime/compose.yml`. Le nom de projet et tous
les volumes nommés sont inchangés : la bascule ne recrée que les deux binds
`data`/`docs`.

Rollback après cette consolidation : la **bascule d'image** reste la procédure
normale — épingler le tag précédent dans `runtime/compose.yml` (`image:` des deux
services) et relancer la pile ; aucune donnée n'est concernée par un changement
d'image. En revanche, revenir à l'**ancien chemin de montage**
`/home/tetrax/deploy/Fortiupgrade/{data,docs}` n'est plus possible, ce répertoire
ayant été supprimé : les `compose.yml` archivés sous `runtime/rollback/` décrivent
l'organisation pré-migration et ne sont conservés qu'à titre de preuve (leurs
`source:` doivent être pointés sur `runtime/data` et `runtime/docs` pour être
réutilisables). Revenir à un état de données antérieur reste possible via les
sauvegardes de `/home/tetrax/backups/fortiupgrade/`.

### Matrice fonctionnelle et mécanismes retenus

| Responsabilité | Socle historique `13fd5bb` | Certificats `ced3acc` | CVE `91845db` | main retenue |
| --- | --- | --- | --- | --- |
| Serveur/API/UI, collecte Fortinet, catalogue, chemins, guards | présents | conservés | conservés | `fortios_server.py`, `fortios_watch.py`, catalogue commun |
| Certificats | CLI/TLS direct | helper Nginx + proxy fiable | même helper adapté | `certctl.py` valide ; helper active/recharge/rollback ; renouvellement PR #11 |
| Notifications historiques | versions/EOL/collecte/outbox | conservées | checkpoint et High/Critical | un seul `fortios_notify.py`, catégories historiques conservées |
| CVE | règles historiques plus bruyantes | idem | High/Critical et escalades uniquement | règles AGENTS, multi-produits regroupés, backfill silencieux |
| SMTP | environnement historique | idem | préférences métier séparées | transport environnement + secret read-only ; ancienne console PR #5 remplacée proprement par PR #11 |
| Persistance | data/docs/certificates | certificats read-only via helper | checkpoint/outbox dans data | mêmes arbres, apparence conservée, aucune migration nouvelle |
| Interface | chemins/alertes/CVE/état | certificats derrière proxy | onglet notifications | First Run, compte, certificats, notifications, diagnostic SMTP et aperçu unique intégrés |

Le scheduler existant et l'import de compatibilité restent les orchestrateurs
de leurs étapes, pas des moteurs concurrents. Les modes TLS direct et proxy
réutilisent le même validateur ; leurs frontières de privilèges restent distinctes.

### Changements locaux historiques préservés

Le worktree `upgrade_path` (supprimé le 2026-09-15, cf. ci-dessus) conservait sans
modification 18 fichiers suivis modifiés et `AGENTS.md` non suivi. Ils ne doivent
ni être committés en masse ni servir de source de déploiement :

- First Run/admin : `app/cert/{cert.css,cert.js,index.html}`, `scripts/cert_admin.py`,
  `scripts/fortios_server.py`, `docker/entrypoint.sh`, `tests/test_cert_admin.py`,
  `tests/test_cert_web.py`, `tests/e2e/{conftest.py,test_browser_flows.py}` ; les
  comportements validés sont déjà livrés par les PR #8/#10, avec le proxy et SMTP.
- Documentation/configuration ancienne : `README.md`, les deux Compose Portainer,
  `docs/certificates.md`, `docs/upgrade-path-tutoriel.md` et son PDF ; ne pas
  réintroduire les anciennes instructions SMTP ni les paramètres de site.
- Données acquises : `data/fortios-data.generated.json`, `docs/last_report.md` ;
  conserver sur place, sans écraser le catalogue runtime par cet ancien export.
- `AGENTS.md` : intégré depuis son commit versionné `35f743b`, pas copié entre worktrees.

Ces restes sont un filet historique explicitement non autoritatif, pas une
divergence de fonctionnalités à merger. Ils sont archivés dans `runtime/archive/`
(bundle Git complet et patch des modifications non commitées) ; les branches
historiques ont été supprimées et `main` est la seule branche conservée.

### Recette de convergence

Baseline locale sur le socle intégré avec les règles fusionnées, avant le
correctif de conservation des états corrompus :

- `python3 -m unittest discover -s tests` : 512 tests, succès, 1 skip root attendu ;
  `sudo python3 -m unittest tests.test_certctl -q` : 28 tests réussis, dont le test
  de transfert de permissions absent de la suite non-root.
- Node via `tests.test_advisory_matching` : 2 tests réussis ; pas de package npm.
- Playwright Chromium : 31 tests réussis (API/admin/preview/chemins et UI).
- Ruff scripts/tests, compilation Python et syntaxe shell : succès.
- Build Docker `fortiupgrade:convergence-d2b8f97` : succès ; base épinglée par digest.
- Copie opaque des arbres runtime data/docs/certificates, sans copier SMTP :
  démarrage TLS candidate, recréation puis rollback vers l'image actuelle ;
  healthcheck et cinq routes réussis à chaque étape, empreintes de tous les
  fichiers persistants inchangées (hors locks). Checkpoint, sentKeys, préférences,
  apparence, credentials et certificats conservés. Une sentinelle d'outbox en
  attente a été ajoutée uniquement à la copie pour tester le cas non vide.
- Isolation Docker `--network none`, aucun email possible ; copie supprimée
  après recette et données vivantes byte-identiques avant/après.
- Runtime existant : healthcheck réussi, Nginx valide, helper actif, HTTPS `/`
  répond 200. Les parcours authentifiés complets restent validés en isolation,
  sans réinitialisation du compte personnel ni revendication d'accès entreprise.

Le correctif additionnel interdit de remplacer silencieusement un historique
notifications invalide par un état vide. Recette finale locale : 514 tests
unitaires (1 skip non-root), 28 tests certificats root, Ruff et 31 Playwright
réussis. Image candidate reconstruite ; copie persistante TLS, recréation et
rollback réussis de nouveau avec empreintes inchangées et outbox non vide.

Le correctif interdit de remplacer silencieusement un historique
notifications invalide par un état vide. Un fichier absent reste une première
activation silencieuse ; un fichier existant invalide suspend les notifications
sans modifier ses octets, tout en laissant la collecte continuer. Il ne modifie
pas le schéma des états valides. Une récupération manuelle doit réconcilier
checkpoint/outbox/sentKeys avant reprise ; ne pas supprimer le fichier pour
faire disparaître l'erreur.

Runtime relevé avant livraison : code `d2b8f97`,
image `sha256:d6c520363553ddeb2bfdb3c00157cecfdc507987f30f9fae43db1af9096b839f`.
La release de convergence et le runtime sont volontairement distingués. La
candidate ajoute la protection des états corrompus ; elle n'est pas déployée
automatiquement : le login administrateur personnel n'est pas vérifiable avec
le secret archivé, et aucun accès entreprise actuel n'est disponible. Ces limites
ne bloquent pas la livraison des sources et de l'image, testées en isolation.
La bascule attend une recette authentifiée avec le compte actuel, sans reset
automatique. Utiliser l'image GHCR du SHA de merge de la PR #12 après CI verte,
sur web et scheduler ; le code du helper n'est pas modifié par cette PR.
Pour cette bascule, suivre les gates ci-dessous ; conserver l'image et les
données courantes pour rollback, sans restaurer aveuglément un ancien checkpoint.
Un ancien binaire ne doit pas être relancé sur un état corrompu sans cette
réconciliation : son comportement historique pouvait réamorcer un état vide.

## Source of truth and prerequisites

Use `docker-compose.portainer.yml` as a **Git Stack**, repository
`https://github.com/Tetrax/upgrade_path_forti`, reference `refs/heads/main` (or the
reviewed release SHA). Set `FORTIOS_IMAGE=ghcr.io/tetrax/upgrade_path_forti:<merge-SHA>`
or an immutable `@sha256:...` digest. Both services must resolve the same image.
The Stack now uses its own Compose network; no `Subnet-Docker` or fixed IP is needed.
If upgrading an installation using that network, explicitly preserve it with a
site-local override when required by its proxy. Recheck the actual proxy peer
address before setting `FORTIOS_CERT_TRUSTED_PROXY_CIDRS`; never trust all networks.

The alternative `docker-compose.portainer-import.yml` keeps named volumes for
existing installations. **Keep the original Stack name** so Portainer reuses the
same volumes. For offline image import set `FORTIOS_IMAGE` to the imported tag.
A different Stack name or bind path is a new data store, not a migration.

## Required variables/mounts

- `PUID`, `PGID`: existing non-root IDs (defaults 1000); don't change on upgrade.
- `FORTIOS_DATA_DIR`, `FORTIOS_DOCS_DIR`, `FORTIOS_CERTS_DIR`: absolute **existing**
  bind paths for Git Stack. Mount the entire certificate directory, including
  `admin/`, not only `active/`.
- `FORTIOS_SECRETS_DIR`: absolute host directory outside Git/data, mounted read-only
  at `/run/fortios-secrets` in web and scheduler. Create it even without SMTP.
- `FORTIOS_SMTP_PASSWORD_FILE=/opt/fortios/smtp-secrets/password`: dedicated
  `fortios-smtp-secrets` volume, web `rw`, scheduler `ro`, directory `0700` and
  file `0600` owned by PUID:PGID. The entrypoint prepares the directory; the GUI
  writes the optional password. An external read-only file remains supported
  for sending only. Do not use a plain `FORTIOS_SMTP_PASSWORD` variable or put
  a secret in Stack YAML. Migrate an existing password before changing its path.
- `FORTIOS_SMTP_HOST`, `FORTIOS_SMTP_PORT`, `FORTIOS_SMTP_USERNAME`,
  `FORTIOS_SMTP_FROM`, `FORTIOS_SMTP_TIMEOUT`, `FORTIOS_APP_URL`: bootstrap environment;
  a valid versioned GUI save takes precedence for these non-secret fields.
- `FORTIOS_SMTP_SECURITY`: `starttls` (default), `tls`, or `none`; clear SMTP also
  requires explicit `FORTIOS_SMTP_ALLOW_INSECURE=true`. Preserve your previous
  transport, sender and application URL.
- `FORTIOS_HTTP_BIND_ADDRESS=127.0.0.1` behind a host proxy; choose a LAN binding
  only with an established firewall. Keep the same port on update.
- TLS direct: `FORTIOS_TLS_CERT`, `FORTIOS_TLS_KEY`, `FORTIOS_TLS_HOSTNAME` and
  certificate mount `rw`, following [certificates.md](certificates.md).
- Host helper/proxy: certificates `ro`, private socket mount `ro`,
  `FORTIOS_CERT_HELPER_SOCKET=/run/fortios-cert-helper/helper.sock`; helper and web
  must be from the same release. No privileged helper inside the application.
- `FORTIOS_RUN_ON_START=0`. One scheduler, no simultaneous legacy systemd timers.
  Normal slots: 07:00 full, 07:45 recovery, 15:30 PSIRT, Europe/Paris.

Functional notification preferences and recipients stay in
`data/notification-settings.json`; non-secret SMTP settings and appearance reside
in `data/smtp-settings.json`. The password path always remains environment-owned.

## Adding the Microsoft 365 transport

The new image adds an optional Graph transport without replacing SMTP, data
mounts, notification history or the scheduler. All three Compose definitions
pass the same `FORTIOS_EMAIL_TRANSPORT` and `FORTIOS_MICROSOFT365_*` variables
to web and scheduler. Existing installations default to SMTP. Non-secret Graph
identity fields and transport selection are saved through Administration →
Notifications in `data/email-transport-settings.json`; once saved, they take
precedence over bootstrap environment values. SMTP non-secret settings are also
editable, with their own explicit schema marker; see the migration below.

Before enabling Microsoft 365:

1. Follow [the Entra/Exchange setup guide](microsoft365.md). Prefer scoped
   Exchange `Application Mail.Send` over tenant-wide Entra `Mail.Send` consent.
2. Use the dedicated `fortios-microsoft365-secrets` persistent volume in the
   updated Compose: web mounts it `rw`, scheduler mounts the same volume `ro`.
   Both use `FORTIOS_MICROSOFT365_CLIENT_SECRET_FILE=/opt/fortios/microsoft365-secrets/client-secret`.
   The entrypoint initializes directory ownership for PUID/PGID and mode `0700`;
   the GUI writes a mode-`0600` file atomically. Never put its value in Stack YAML,
   environment values or Docker build arguments. Only the authenticated HTTPS
   secret-write endpoint accepts the value; settings responses never return it.
3. Keep the same data/docs/certificate volumes, PUID/PGID, proxy configuration and
   Stack name. Recreate web and scheduler with the reviewed, pinned candidate
   image. No global Docker cleanup or volume deletion is required.
4. Set or replace the secret through Administration → Notifications → Microsoft
   365. Verify both containers can read it without printing it; scheduler cannot
   write the Microsoft volume. Keep the global external secrets directory read-only;
   SMTP GUI writes use a separate private volume. Allow DNS and outbound HTTPS to
   `login.microsoftonline.com` and `graph.microsoft.com`; do not weaken TLS.
5. Save the Graph parameters in the admin form and explicitly send a test mail.
   Check its reception as well as `202 Accepted`. Repeat after recreation to
   confirm persistence and non-interactive authentication.

The canonical guide is copied into the immutable application directory during
the Docker build, so an older persistent `/opt/fortios/docs` volume cannot hide
the new setup instructions. No runtime document directory is overwritten.
`.dockerignore` excludes transport settings and the conventional credential file
name, in addition to existing credential/catalog exclusions. Arbitrarily named
secrets still belong outside the build context; ignore patterns are not a secret
manager.

For upgrades from an externally provisioned Graph file, migrate the existing
credential into the dedicated volume before changing its path, or keep the old
reference and accept that GUI writes remain unavailable on read-only storage.
There is exactly one configured file, not a hidden override. Update both image
and Compose/Portainer Stack, retain its project name and all existing volumes.
The same model works with direct TLS and a host reverse proxy; no additional
host helper is required. Include the new private volume in protected backups.
An image rollback to a Graph-capable version can retain the same volume/path
and newest secret; do not revert secret rotation or notification state blindly.

### Data compatibility and rollback

Back up data/docs/certificates and deployment settings consistently before the
change, retaining the preceding immutable image. The transport sidecar is
additive; optional retry metadata extends existing outbox entries without
changing the checkpoint, event keys or historical categories. A rollback must
retain the **current** notification history rather than restoring an old
checkpoint that could replay already-accepted messages.

Before reverting to an older SMTP-only image, disable notifications via the
existing functional settings if unintended SMTP sending would be a risk: that
image ignores the Graph selection and Graph retry metadata and uses its SMTP
environment. Restore the old image and compatible Compose while keeping the
same volumes. The new sidecar can remain for a later re-upgrade. Verify health,
catalogue, admin UI, pending outbox and the selected delivery policy again.

The deployment gate must include an isolated copy of existing persistent data,
candidate startup, Graph settings/retry persistence, container recreation and
old-image rollback. Keep this copy disconnected from outbound delivery and do
not reuse operational recipients or credentials for a live test. Unit/mock
OAuth/Graph success and Docker health do not prove tenant permission or mail
delivery; real-tenant acceptance is a separate activation gate.

### Container image security (Trivy) — rollback

Rolling back an image that carries the container-security ingestion must restore, together with the
image and the Compose file, the two documents that belong to that feature:

| Element | Why |
| --- | --- |
| Image (previous immutable tag) | The feature only exists from the ingestion merge onward. |
| `compose.yml` | The image tag is pinned there; a half-restored pair would silently run the wrong image. |
| `runtime/data/container-security-settings.json` | The old image does not know this document. Left in place it is inert, but a later re-upgrade must not inherit a switch that was enabled in the meantime without a decision. |
| `runtime/data/fortios-notify-history.json` | Carries `containerSecurityState`, the baseline the next scan is diffed against. |

**An older image loses `containerSecurityState` on its first write.** Its `load_notify_state()`
returns a fixed set of keys and its save path writes back exactly what it loaded, so the section is
dropped the moment that image commits a notification state (checkpoint, outbox finalization, EOL
transition). This is not corruption and needs no repair: the section is additive and its absence is
a valid state.

Consequence to accept before rolling back: **the baseline is lost, and the findings known at that
moment become unknown again.** On the next ingestion, the first report after the rollback forward
establishes a new baseline silently — no flood, because a first ingestion never notifies (see
`docs/container-security.md`) — and only transitions observed after that point are alerted again.
A vulnerability that appeared during the rollback window and is still present afterwards is
therefore **not** reported: it is part of the new baseline. If that gap is unacceptable, capture the
`containerSecurityState` section before the rollback and restore it into the history file after the
roll-forward.

The reverse order also holds and is safe: restoring the history file alone (without the image) gives
an image that ignores the section, and the section is dropped at its next write as described above.

The Trivy artifact files (`runtime/data/trivy-report.json` and `.meta.json`) are inputs, not state:
keeping or removing them changes nothing for an image that does not read them, and the next daily
sync republishes them.

## Migration to editable SMTP administration

Before upgrading, stop only this Stack's scheduler and web for a consistent
backup (data, docs, certificates, deployment config, helper source). Record image
IDs/digests and retain the old image. Never remove volumes.

1. Establish the **currently active** non-secret settings and password reference.
   On environment-owned releases, preserve those environment values, not dormant
   unmarked JSON. If migrating directly from a historical editable console, first
   verify that its JSON/password sidecar is actually authoritative and transfer
   its non-secret values explicitly to bootstrap environment settings.
2. Update both image and Compose/Portainer Stack, keeping the original project
   name, data/docs/certificate mounts, PUID/PGID, network and proxy settings.
   Add only the dedicated SMTP volume (`rw` web, `ro` scheduler). Never turn the
   global secrets or certificate mounts writable to enable this feature.
3. Before switching `FORTIOS_SMTP_PASSWORD_FILE`, securely copy the active password
   into the new volume at `/opt/fortios/smtp-secrets/password`, owner PUID:PGID,
   mode `0600`, directory `0700`. Compare bytes without printing them. Preserve
   the prior protected file and Compose for rollback. If no password exists,
   do not invent one: the directory may remain empty until GUI configuration.
   Keeping an external read-only reference is supported, but prevents GUI rotation.
4. Recreate both services and verify sending configuration is still recognized,
   the web can write only the dedicated SMTP volume, and the scheduler cannot.
   Saving the form persists non-secret fields with `schemaVersion: 1`; later
   reads prefer this valid document over bootstrap environment values. Unmarked
   legacy JSON remains appearance-only and cannot silently reactivate stale SMTP.
   A malformed saved document fails closed and can be repaired by a complete
   valid form save. Passwords never enter either settings JSON.
5. Verify GUI save/reload, blank-password preservation, previews and container
   recreation. Configuration and optional password use separate operations: if
   the latter fails, the GUI explicitly reports that settings were saved but
   the password was not changed. A save never sends a test email. Exercise a
   real send only when authorized; retain recipients, checkpoint, outbox and retries.

For native Python deployment, prepare the private persistent `0700` directory
for the service account and point `FORTIOS_SMTP_PASSWORD_FILE` at its password
file. Never use an HTTP-served or versioned directory; the API does not create
parent directories. The same writer and validation are used in all deployments.

### SMTP rollback compatibility

The preceding environment-owned image ignores the new marked SMTP fields.
Therefore an image-only rollback with **new password + old environment host/login**
can produce an incoherent configuration after GUI edits. Restore the previous
Compose and its preserved password reference as a pair, or explicitly transfer
the current validated non-secret settings into that older image's environment
while retaining the current password volume. Do not claim automatic preservation
of new GUI settings by an older image. Keep the new sidecar/volume for re-upgrade.
Never restore an old notification checkpoint merely to roll back SMTP settings.

## Authentication upgrade and recovery

The September 3 incident notes report `Verrou du compte administrateur indisponible`
and an absent administrative directory/lock. PR #8 distinguishes missing
credentials (one-shot First Run) from corruption (fail-closed), and repairs a
missing lock without rewriting existing credentials. PR #10 adds password
rotation, verified recovery address, one-use reset links and global revocation.
The credential format remains compatible; `admin-state.json` is an optional
private sidecar. Sessions are memory-only: container recreation logs users out,
but must not alter their password.

1. Verify actual mounts, full `admin/` persistence, UID/GID, configured credential
   path, helper version, HTTPS Origin and trusted proxy source.
2. Do not delete `credentials.json` or switch off authentication to regain access.
3. Use the verified email recovery route if already configured. Otherwise use
   the existing interactive `fortios-cert-admin reset` CLI in direct mode, or
   host `scripts/cert_admin.py reset --credentials <existing-path>` with the
   configured PGID in helper mode. This is an explicit password change, not a
   routine update step; get the operator's authorization and deliver the new
   secret privately. Never include passwords in process arguments.
4. Test login, logout, invalid credentials, Origin/CSRF rejection and admin routes.

No current enterprise access is implied by historical notes; validate its real
login on its authorized network before calling the enterprise deployment complete.

## Update / rollback

1. Keep the previous YAML/env, image and root-only state backup. Check archive
   readability and checksums. Build/pull only the reviewed, authorized immutable
   SHA after green CI; an explicitly approved unmerged candidate is not a merge.
2. Reuse exactly the previous volumes/paths and Stack name. Set the new immutable
   `FORTIOS_IMAGE`, recreate web and scheduler, and update the host helper if used.
3. Check web healthy, scheduler running/next slot, HTTPS, catalogue/products,
   official path request, CVE display, admin, email preview and logs. Compare
   credential/cert/settings/checkpoint hashes with the baseline, accounting for
   legitimate new collection events only.
4. If unhealthy, restore the previous image and deployment config plus matching
   helper. No notification/catalogue schema migration is required by this release.
   The older account code ignores the recovery sidecar. Follow the SMTP rollback
   compatibility rule above; do not mix a previous host/login with a rotated password.
   A much older editable-console image may require its historical SMTP sidecars;
   reconcile those explicitly rather than restoring a whole data volume.
5. Prefer retaining current catalogue and outbox. Restoring an older notification
   checkpoint after successful sends risks replay: freeze sends and reconcile
   sent keys before any state rollback. Never blindly restore a whole old volume
   over newly acquired data.

On the shared VPS, hold `/home/tetrax/workspace/.locks/valdev-infra.lock` only
around targeted infrastructure mutation and verification. Do not hold it for builds
or long tests. Never perform Docker-wide pruning or restart other projects.

## URL migration (root + /admin) and its rollback

The application is served from `/` and the administration from `/admin/`. Legacy prefixes
(`/app`, `/app/<rest>`, `/app/cert`, `/cert`) answer **302 Found** with the query string preserved,
so bookmarks and already-delivered recovery emails keep working. The APIs (`/api/cert/*`,
`/api/official-path`, `/api/advisories`, `/api/advisory-images`, `/api/compatibilities`, `/data/*`)
are unchanged and never redirected; the session cookie keeps `Path=/api/cert`, so sessions and CSRF
behaviour do not move. Nginx is untouched: its single `location /` already proxies everything.

Use 302, never 301/308: a permanent redirect is cached almost forever by the browser and would keep
it requesting `/` and `/admin/` after a rollback to an image that only knows `/app/` and `/cert/`.

Rollback is NOT "restore the previous image" alone — the previous image serves `/app/` and `/cert/`
and knows nothing about `/` or `/admin/`:

1. restore the previous image reference and `runtime/compose.yml`;
2. restore `FORTIOS_APP_URL` to its previous `/app/` value;
3. restore `runtime/data/smtp-settings.json` (`appUrl`) to its previous `/app/` value: that stored
   value — not the environment — is what the emails actually use, and leaving the new root URL
   behind would send CTAs to a path the rolled-back image does not serve;
4. recreate web and scheduler, then verify: web healthy, scheduler running, 0 restart, unchanged
   `StartedAt`, `/app/` 200, `/cert/` 200, `POST /api/cert/login` 200, persistent state byte-identical.

The pre-switch set is captured in `runtime/rollback/<timestamp>-url-migration/`: previous image
reference, Compose file, `smtp-settings.json`, previous `FORTIOS_APP_URL` value, container
`StartedAt`/restart capture and the hashes of every persistent state file. The runtime `appUrl`
value is only moved to the new root URL **after** the switch has been validated in the browser and
with a controlled email preview/test.
