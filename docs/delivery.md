# Portainer/VPS delivery — operational gates

## Convergence des branches

Audit du 2026-09-08 après `git fetch origin` : **`main` est la seule ligne
autoritative**. Le socle `d2b8f9725c77df18175a8d08e416c199fd5cec1d` contient déjà
les fonctionnalités des PR #3 à #11 (la PR #9 est remplacée par #10) et correspond au code du runtime personnel. La branche temporaire
`integration/fortiupgrade-convergence`, worktree
`/home/tetrax/workspace/upgrade_path_convergence`, part de ce socle, intègre par
merge les instructions `docs/agent-closeout-coherence@35f743b`, puis clôt les
incohérences documentaires et protège l'état de notification corrompu contre une
réinitialisation silencieuse. Elle ne crée pas une seconde ligne de release.

### Cartographie Git initiale

Tous les worktrees appartiennent à `git@github.com:Tetrax/upgrade_path_forti.git`.
Ancêtre commun des trois worktrees demandés : `13fd5bb3170aa9ed2c42a475de26eb89355866dc`.
Certificats/CVE partagent ensuite `0ab5c6330ca3223a910d4b73801f17407f379d50`.
Le stash commun est vide. Avance/retard ci-dessous : état avant cette clôture.

| Worktree / branche | HEAD | Upstream ; avance/retard | Relation à main |
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

Les autres worktrees actifs ont été vérifiés : compte (`c17c995`), First Run
(`bd65829`), SMTP (`636ab81`), aperçu (`aa272cd`), CSP (`bad99f7`), livraison
(`d2b8f97`) et releases détachées sont propres et déjà intégrés. La branche
historique locale `main@7b6cffd` est obsolète ; la référence distante actualisée
fait foi. Les anciens worktrees `/opt/data/worktrees/*` signalés prunables et les
branches shelved/WIP restent conservés, sans nettoyage destructif.

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

Le worktree `upgrade_path` conserve sans modification 18 fichiers suivis modifiés
et `AGENTS.md` non suivi. Ils ne doivent ni être committés en masse ni servir de
source de déploiement :

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
divergence de fonctionnalités à merger. Les branches historiques sont conservées.

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
- Runtime existant : healthcheck réussi, Nginx valide, helper actif, HTTPS `/app/`
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
- `FORTIOS_SMTP_PASSWORD_FILE=/run/fortios-secrets/smtp-password` when configured.
  File root:PGID mode 0640, parent root:PGID mode 0750. Do not use a plain
  `FORTIOS_SMTP_PASSWORD` variable or put a secret in Stack YAML.
- `FORTIOS_SMTP_HOST`, `FORTIOS_SMTP_PORT`, `FORTIOS_SMTP_USERNAME`,
  `FORTIOS_SMTP_FROM`, `FORTIOS_SMTP_TIMEOUT`, `FORTIOS_APP_URL`: deployment environment.
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
`data/notification-settings.json`; appearance remains in `data/smtp-settings.json`.

## Adding the Microsoft 365 transport

The new image adds an optional Graph transport without replacing SMTP, data
mounts, notification history or the scheduler. All three Compose definitions
pass the same `FORTIOS_EMAIL_TRANSPORT` and `FORTIOS_MICROSOFT365_*` variables
to web and scheduler. Existing installations default to SMTP. Non-secret Graph
identity fields and transport selection are saved through Administration →
Notifications in `data/email-transport-settings.json`; once saved, they take
precedence over bootstrap environment values. SMTP infrastructure stays
deployment-owned.

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
   write the Microsoft volume. Keep the existing SMTP secret directory read-only
   in both containers. Allow DNS and outbound HTTPS to
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

## Migration from the historical Web SMTP console

Before upgrading, stop only this Stack's scheduler and web for a consistent
backup (data, docs, certificates, deployment config, helper source). Record image
IDs/digests and retain the old image. Never remove volumes.

The old `smtp-settings.json` contains non-secret `host`, `port`, `security`,
`allowInsecure`, `username`, `from`, `appUrl`, `timeout`: transfer their existing
values to the corresponding environment variables above. Copy `data/smtp-password`
into the protected `FORTIOS_SECRETS_DIR/smtp-password` without displaying it.
Verify the two files are byte-identical locally, then move the legacy secret to
the restricted rollback directory so it is no longer in writable application data.
Keep `smtp-settings.json`: its `emailAppearance` is read unchanged. Saving appearance
later writes only this non-secret block. Transport fields from the historical
file are ignored, even when environment values are missing. This is intentional:
missing deployment settings must be visible, not silently fall back to a second
SMTP source. Preserve recipients, notification checkpoint, sent keys and outbox.

Recreate both containers and verify secret mount `RW=false`, runtime UID/GID,
transport configured, preview rendering and a controlled test if authorized.
Do not replay synthetic CVEs against production. An SMTP failure must not fail
collection, and queued real events must remain available for retry.

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
   readability and checksums. Build/pull only the reviewed merge SHA after green CI.
2. Reuse exactly the previous volumes/paths and Stack name. Set the new immutable
   `FORTIOS_IMAGE`, recreate web and scheduler, and update the host helper if used.
3. Check web healthy, scheduler running/next slot, HTTPS, catalogue/products,
   official path request, CVE display, admin, email preview and logs. Compare
   credential/cert/settings/checkpoint hashes with the baseline, accounting for
   legitimate new collection events only.
4. If unhealthy, restore the previous image and deployment config plus matching
   helper. No notification/catalogue schema migration is required by this release.
   The older account code ignores the recovery sidecar. Old SMTP code expects
   the archived full `smtp-settings.json` and `smtp-password`; restore these from
   backup when rolling back after appearance-only saves.
5. Prefer retaining current catalogue and outbox. Restoring an older notification
   checkpoint after successful sends risks replay: freeze sends and reconcile
   sent keys before any state rollback. Never blindly restore a whole old volume
   over newly acquired data.

On the shared VPS, hold `/home/tetrax/workspace/.locks/valdev-infra.lock` only
around targeted infrastructure mutation and verification. Do not hold it for builds
or long tests. Never perform Docker-wide pruning or restart other projects.
