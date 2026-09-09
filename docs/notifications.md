# Notification delivery

FortiUpgrade uses the existing notification collector, checkpoint, and durable outbox. It does not add a scheduler. The collector records a detected event and its checkpoint together; the outbox then claims, sends, retries, and marks the event sent without re-enqueuing an already-sent `dedupKey`.

## One engine, two email transports

`scripts/fortios_notify.py` owns composition and delivery for both **SMTP** and
**Microsoft 365 / Azure**. The latter uses OAuth 2.0 client credentials and
Microsoft Graph v1.0 `users/{mailboxIdentity}/sendMail`. Both transports submit the
same multipart MIME email, preserving recipients, subjects, HTML/text templates,
preview rendering, CVE rules and historical notification categories. No second
collector, token scheduler or parallel outbox is introduced.

In Administration → Notifications, choose the transport, save, then test with an
explicit recipient. **Tester la connexion** for Microsoft 365 actually acquires
a token and submits a test message as the configured mailbox: a token-only check
would not prove sending permission. Graph `202 Accepted` and SMTP acceptance are
provider hand-offs, not confirmation of final recipient delivery. The test and
preview routes never create notification events.

See [the Microsoft 365 setup guide](microsoft365.md) for Entra registration,
least-privilege Exchange RBAC, mounted credentials and the real-tenant checklist.

## SMTP ownership

SMTP infrastructure is deployment-owned and is read from the process environment
on every snapshot load. The console keeps SMTP host/port/security/login/sender
read-only. It can save the selected email transport, non-secret Microsoft 365
parameters and `emailAppearance`; it cannot create, replace or read either secret.

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

The historical `POST /api/cert/smtp/settings` payload containing only
`emailAppearance` remains supported. The same authenticated/CSRF-protected
endpoint also accepts exactly `transport`, `microsoft365` and `emailAppearance`
for the new form; unknown fields and secret mutations are rejected. Legacy SMTP
infrastructure fields in `smtp-settings.json` remain ignored. Generated security
facts and links stay engine-owned and are escaped before rendering.

## Microsoft 365 configuration and credentials

`data/email-transport-settings.json` is an additive, non-secret sidecar in the
existing persistent data volume. It contains `transport` (`smtp` or
`microsoft365`) and a `microsoft365` object with string fields `tenantId`,
`clientId`, `from`, `displayName`, `mailboxIdentity`. The optional mailbox identity
is an object GUID or UPN; when empty it defaults to the sender address. An SMTP
alias is not necessarily a Graph user identifier. Keep both provider settings
when switching; no checkpoint, recipients, appearance or credentials are deleted.

The sidecar is validated and atomically replaced under the existing cross-process
lock. Once present, saved choices prevail over deployment bootstrap values. An
existing corrupt/unreadable sidecar disables delivery rather than silently
falling back to SMTP; its original bytes are preserved. Correct it through the
form or restore a verified copy, never by resetting notification history.

The following variables are passed to both web and scheduler by all provided
Compose files:

| Variable | Meaning |
| --- | --- |
| `FORTIOS_EMAIL_TRANSPORT` | Bootstrap choice; defaults to `smtp` when no sidecar exists. |
| `FORTIOS_MICROSOFT365_TENANT_ID` | Bootstrap Directory tenant GUID or tenant domain. |
| `FORTIOS_MICROSOFT365_CLIENT_ID` | Bootstrap Application client GUID. |
| `FORTIOS_MICROSOFT365_FROM` | Bootstrap sender SMTP address. |
| `FORTIOS_MICROSOFT365_DISPLAY_NAME` | Bootstrap display name. |
| `FORTIOS_MICROSOFT365_MAILBOX_IDENTITY` | Optional bootstrap mailbox object GUID or UPN. |
| `FORTIOS_MICROSOFT365_CLIENT_SECRET_FILE` | Sole credential source; Compose defaults to `/opt/fortios/microsoft365-secrets/client-secret`. |
| `FORTIOS_MICROSOFT365_TIMEOUT` | Network timeout per request, 1–120 seconds; Compose defaults to 10. |

The secret is stored outside Git/data/image in a dedicated persistent volume:
web may set/replace it through the authenticated, same-origin, CSRF-protected
GUI endpoint; scheduler reads the same file through a read-only mount. The
existing SMTP secret directory remains read-only. The settings API reports
readiness and safe write capability, never the secret or its path. A blank
submission cannot delete the old credential; the input is cleared after submit
and never prefilled. No transport, checkpoint or outbox change accompanies a
secret rotation. Plain environment secret values are not accepted. Existing
read-only external files remain valid for delivery, with GUI writes unavailable.
No access token is persisted.
The confidential request targets are fixed Microsoft public-cloud HTTPS
endpoints; TLS verification is enabled and HTTP redirects are rejected. The V1
uses a client secret, not delegated user login; certificate/federated credentials
can later replace token acquisition without changing the notification engine.

Email appearance and transport are separate sidecars for backwards compatibility.
Both payloads are validated before either write, but the two file replacements
are not a cross-file transaction: after a storage failure, reload the form and
reconcile the shown settings. Neither write advances the notification checkpoint.

The compatibility-only recovery path passes the same configured appearance to
`compose_email()` as the main collector, including when retrying an existing
outbox. Display name, introduction and signature are preserved; an absent
appearance keeps the existing default rendering. No separate recovery template
or SMTP engine is used.

## Incomplete environments

Missing SMTP variables are not a read or rendering error and do not prevent a
complete Microsoft 365 configuration from sending. Missing/invalid selected
transport credentials leave the form and previews usable. Delivery requires a
complete selected transport; failures do not interrupt collection. Pending
events remain in the outbox and receive the retry metadata described below.

The public settings response exposes transport metadata, `passwordConfigured`
and `clientSecretConfigured`, never credentials or secret file paths. Preview
HTML is session-bound, short-lived, and served with the isolated preview policy;
it is rendered from the same production composer used for delivery.

## Notification rules

- New CVEs notify only when severity is `high` or `critical` and at least one configured product/model is affected.
- A modified CVE notifies only when its severity crosses into `high` or `critical`. Re-publication, wording/CVSS edits, and unchanged monitored severity are quiet.
- A CVE affecting several selected products is one event with one deduplication key and an aggregated affected-product section, not one email per product.
- Initial checkpoint/bootstrap and catalog backfill are quiet. Incomplete or malformed snapshots do not invent a baseline event; a valid later snapshot can produce the real transition.
- Disabling delivery continues to advance an existing notification reference without creating retroactive events, including legacy environment-only configuration (`FORTIOS_EMAIL_ENABLED=false` without `notification-settings.json`) and compatibility-only recovery. Pending outbox entries are retained, never sent while disabled, and remain eligible for retry after reactivation. Persisted functional settings, when present, remain authoritative and are not rewritten by this fallback.
- EOL transitions bootstrap silently on first sight and notify once on a later `False -> True` transition.
- Outbox claims are durable and reclaimable after a stale worker claim. Failed sends remain pending for a later run; successful sends are protected by sent-key deduplication. Concurrent collectors cannot claim or send the same event twice.

An existing unreadable or invalid notification history is not an initial activation.
It is retained byte-for-byte and notification processing fails closed, without
resetting its checkpoint, discarding pending events, or interrupting collection.
Restore/reconcile a verified history before resuming; do not delete it to silence
the diagnostic. This replaces the historical archive-and-empty recovery, which
could abandon a valid outbox when only another field was malformed. Valid legacy
states without a checkpoint remain supported; no data-schema migration is required.

## Failures, durable retries and rollback

The outbox accepts optional `nextAttemptAt`, `lastTransport`, `lastErrorCode`
fields. Old entries without them remain readable. On failure the claimed events
are released, not removed; both the main collector and compatibility recovery
use this same retry mechanism. Claims held by a live worker remain exclusive;
a crashed worker's claim becomes reclaimable after the existing 600-second TTL.

- Microsoft 365 invalid credentials, permission/consent failures and invalid configuration:
  300-second cooldown; an operator must fix the cause.
- Graph timeouts/network errors and transient server errors: 60 seconds when
  no usable provider delay is supplied.
- Graph HTTP 429/5xx with `Retry-After`: the provider delay is parsed from seconds
  or an HTTP date and preserved, including delays longer than a day. A value
  beyond the representable timestamp range defers to the latest supported date,
  rather than overflowing the outbox or silently retrying after an hour.
- SMTP collector delivery retains the existing boolean send contract and
  next-run retry eligibility. Structured SMTP test results distinguish permanent
  authentication/sender/recipient refusals, but do not change the historical
  collector retry policy. There is no in-process infinite retry loop.
- Switching transports makes entries deferred by the previous provider eligible
  for the next run, without stealing live claims or changing deduplication keys.

Results are normalized to safe operator messages, stable error codes, retry
eligibility and provider HTTP status. Microsoft diagnostics use only recognized
AADSTS codes; raw response bodies, exception text containing credentials,
Authorization headers and tokens are never returned. Delivery logs identify
`transport=microsoft365 provider=microsoft_graph` and the outcome.

Neither Graph nor SMTP offers a transactional exactly-once hand-off with the
local outbox. A connection loss after remote acceptance but before local success
persistence can cause an ambiguous retry/duplicate. Do not remove the pending
event simply because a token was obtained or to hide a timeout.

Rollback retains all data volumes, including the new sidecar and extended outbox.
The older SMTP image ignores the transport sidecar and optional retry metadata;
it may resume pending delivery through SMTP using its deployment environment.
Disable sending before rollback if that is not intended. Do not restore an older
checkpoint/history over events accepted since the upgrade. Keep the previous
image and SMTP environment available; see [delivery.md](delivery.md).

## Local verification

Use the repository test interpreter and the focused notification suite:

```text
.venv-test/bin/python -m pytest -q \
  tests/test_security_notifications.py \
  tests/test_email_notifications.py \
  tests/test_notify_outbox.py \
  tests/test_email_preview.py \
  tests/test_smtp_admin.py \
  tests/test_microsoft365_notifications.py \
  tests/test_microsoft365_config_safety.py
```

The delivery tests use an isolated local SMTP sink and parse the resulting MIME message to compare its subject, text part, and HTML part with the production-rendered preview. They do not connect to a real SMTP service or use production data.

Graph tests mock OAuth/HTTP responses, including failures and throttling. Run the
full unit/API suite and `tests/e2e/` for persistence, switching and browser
regressions. Passing mocks is not proof of tenant permissions or deliverability;
the real-tenant checklist in [microsoft365.md](microsoft365.md) remains required
before activation.
