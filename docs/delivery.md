# Portainer/VPS delivery — operational gates

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
