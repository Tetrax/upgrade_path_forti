# Notification delivery

FortiUpgrade uses the existing notification collector, checkpoint, and durable outbox. It does not add a scheduler. The collector records a detected event and its checkpoint together; the outbox then claims, sends, retries, and marks the event sent without re-enqueuing an already-sent `dedupKey`.

## SMTP ownership

SMTP transport is deployment-owned and is read from the process environment on every snapshot load. The web console can save only the non-secret `emailAppearance` block. It cannot change transport or a password.

Set these values in the deployment environment (the same values must be available to the web and scheduler containers):

| Variable | Meaning |
| --- | --- |
| `FORTIOS_SMTP_HOST` | SMTP host. |
| `FORTIOS_SMTP_PORT` | SMTP port; defaults to `587` when omitted. |
| `FORTIOS_SMTP_USERNAME` | Optional SMTP login name. |
| `FORTIOS_SMTP_PASSWORD_FILE` | Sole password source. Point it at the read-only-mounted secret file. |
| `FORTIOS_SMTP_SECURITY` | `starttls`, `tls`, or `none`; `starttls` is the default. |
| `FORTIOS_SMTP_ALLOW_INSECURE` | Must be `true` before `none` is considered deliverable. |
| `FORTIOS_SMTP_FROM` | Sender address. |
| `FORTIOS_SMTP_TIMEOUT` | SMTP timeout in seconds; defaults to `10`. |
| `FORTIOS_APP_URL` | Canonical application URL used in notification links. |

Do not set or pass a plain `FORTIOS_SMTP_PASSWORD`, and do not put a password in Stack YAML, `smtp-settings.json`, browser payloads, logs, or preview data. The historical `data/smtp-password` sidecar is never a runtime fallback. `delete_smtp_password` is intentionally rejected because the mounted secret is managed by deployment operations.

`FORTIOS_SMTP_STARTTLS` remains accepted only as a compatibility input for older local configurations. New deployments should set `FORTIOS_SMTP_SECURITY` and, for clear SMTP, explicitly set `FORTIOS_SMTP_ALLOW_INSECURE=true`.

Functional notification preferences and recipients remain in `data/notification-settings.json`. The appearance sidecar at `data/smtp-settings.json` contains only:

```json
{
  "emailAppearance": {
    "displayName": "FortiUpgrade",
    "introduction": "",
    "signature": ""
  }
}
```

A POST to the appearance endpoint must contain exactly that `emailAppearance` object. Any transport field or password mutation is rejected. Existing legacy transport fields are ignored while the four user-visible concerns remain intact: display name, generated message title/subject, introduction, and signature. The generated security facts and links remain engine-owned and are escaped before rendering.

## Incomplete environments

The absence of SMTP variables is not a read or rendering error. `load_smtp_settings` returns environment-backed defaults with `state: incomplete`, so the authenticated SMTP page, previews, and recovery-link composition can still render. Actual delivery and recovery sends require a complete, valid transport; an incomplete configuration must not fail collection or mutate notification state.

The public settings response exposes transport metadata and `passwordConfigured`, never the password, secret contents, or secret file path. Preview HTML is session-bound, short-lived, and served with the isolated preview policy; it is rendered from the same production composer used for delivery.

## Notification rules

- New CVEs notify only when severity is `high` or `critical` and at least one configured product/model is affected.
- A modified CVE notifies only when its severity crosses into `high` or `critical`. Re-publication, wording/CVSS edits, and unchanged monitored severity are quiet.
- A CVE affecting several selected products is one event with one deduplication key and an aggregated affected-product section, not one email per product.
- Initial checkpoint/bootstrap and catalog backfill are quiet. Incomplete or malformed snapshots do not invent a baseline event; a valid later snapshot can produce the real transition.
- EOL transitions bootstrap silently on first sight and notify once on a later `False -> True` transition.
- Outbox claims are durable and reclaimable after a stale worker claim. Failed sends remain pending for a later run; successful sends are protected by sent-key deduplication. Concurrent collectors cannot claim or send the same event twice.

## Local verification

Use the repository test interpreter and the focused notification suite:

```text
/home/tetrax/workspace/upgrade_path_admin_password_change/.venv-test/bin/python -m pytest -q \
  tests/test_security_notifications.py \
  tests/test_email_notifications.py \
  tests/test_notify_outbox.py \
  tests/test_email_preview.py \
  tests/test_smtp_admin.py
```

The delivery tests use an isolated local SMTP sink and parse the resulting MIME message to compare its subject, text part, and HTML part with the production-rendered preview. They do not connect to a real SMTP service or use production data.
