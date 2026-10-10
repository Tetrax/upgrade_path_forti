# Notification delivery

FortiUpgrade uses the existing notification collector, checkpoint, and durable outbox. It does not add a scheduler. The collector records a detected event and its checkpoint together; the outbox then claims, sends, retries, and marks the event sent without re-enqueuing an already-sent `dedupKey`.

## One engine, two email transports

`scripts/fortios_notify.py` owns composition and delivery for both **SMTP** and
**Microsoft 365 / Azure**. The latter uses OAuth 2.0 client credentials and
Microsoft Graph v1.0 `users/{mailboxIdentity}/sendMail`. Both transports share the
same business data and the single authoritative renderer
`scripts/fortios_email_render.py`, which produces clean UTF-8 `(subject, text/plain, HTML)`.
The renderer exposes specialized composers of the same SNS identity: CVE (`compose_email`),
release (`compose_release_email`), system (`compose_system_email`) and container image security.
System emails reuse the shell (hero, logo, panther, palette, CTA, Support footer), with their
own subject/text/HTML and automatic introduction, without CVE/release business components or
the historical raw `<pre>` summary. Display name and signature remain shared.
Each transport then adapts that output to its own wire format:

- **SMTP** builds a `multipart/alternative` → `text/plain` + `multipart/related` →
  `text/html` + inline CID images, with every part `Content-Transfer-Encoding: base64`
  (never quoted-printable) under `policy.SMTP`.
- **Microsoft Graph** sends JSON `body.contentType="HTML"` / `body.content` (raw UTF-8
  HTML, not a pre-encoded MIME body) and attaches inline images as
  `fileAttachment` with `contentId`/`isInline`.

No second collector, token scheduler or parallel outbox is introduced.

### Admin preview document

The preview routes render the *same* authoritative HTML as a real notification, then adapt it
for display only: `fortios_email_render.inline_image_data_uris()` replaces the renderer's
`cid:` references with `data:` URIs, because a `cid:` cannot resolve outside a mail client.
The preview is therefore served under an isolated policy
(`default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:;
frame-ancestors 'self'; base-uri 'none'; form-action 'none'`) — scripts, styles from other
origins and any *network* image stay forbidden, so the document remains self-contained and
cannot leak or fetch anything. The sendable message always keeps real CID parts
(`multipart/related` for SMTP, inline `fileAttachment` for Graph); only the on-screen
document carries data URIs.

In Administration → Notifications, choose the transport, save, then test with an
explicit recipient. **Tester la connexion** for Microsoft 365 actually acquires
a token and submits a test message as the configured mailbox: a token-only check
would not prove sending permission. Graph `202 Accepted` and SMTP acceptance are
provider hand-offs, not confirmation of final recipient delivery. The test and
preview routes never create notification events.

See [the Microsoft 365 setup guide](microsoft365.md) for Entra registration,
least-privilege Exchange RBAC, mounted credentials and the real-tenant checklist.

## Encoding and MIME corruption (fixed)

Emails historically arrived with visible quoted-printable artifacts (`For=iUpgrade`,
`Forti=ate`, `R=C3=sumé`, `=strong>`, URLs broken by `=`). Root cause: Python's
`email.message.EmailMessage` encoded the long UTF-8 HTML with
`Content-Transfer-Encoding: quoted-printable`, whose `=` soft line-breaks leaked into the
rendered body — and the Microsoft Graph transport then re-sent that pre-encoded MIME body
as if it were plain HTML (`body.content`), while Outlook re-decoded what was already
transport-encoded, producing double-encoding and corruption.

The fix separates rendering from transport and eliminates quoted-printable on both paths:

- the renderer emits clean UTF-8 text/HTML only;
- SMTP parts are `base64` (no `=` soft-breaks), flattened under `policy.SMTP` (CRLF);
- Graph receives raw UTF-8 HTML via `body.contentType="HTML"` / `body.content`, never a
  pre-encoded MIME string.

Regression tests in `tests/test_email_sns_redesign.py` assert the absence of `=C3`,
`=E2`, `=strong`, `Forti=ate`, `sns=security` and `quoted-printable` in the final wire
message, while still allowing legitimate `=` inside URLs and query strings.

## SMTP ownership

SMTP non-secret infrastructure is editable by an authenticated administrator, with an explicit
bootstrap/migration rule. A valid `smtp-settings.json` carrying
`"schemaVersion": 1` is the saved source of truth for host, port, security, login,
sender, application URL, timeout, and appearance. When that marked document is
absent, the process environment supplies the initial values. A valid unmarked
historical document is treated as appearance-only: its stale transport fields
are ignored. An existing truncated, unreadable, non-object, or malformed marked
document fails closed and never falls back to the environment; its bytes remain
untouched until a complete valid save repairs it.

The full non-secret SMTP form is saved through the authenticated/CSRF-protected
`POST /api/cert/smtp` endpoint. The same endpoint still accepts the legacy
`{"emailAppearance": ...}` shape. Graph selection and appearance saves preserve
a valid marked SMTP document; a complete nested `smtp` object may explicitly
repair one. Passwords are never part of either configuration payload. The
optional `POST /api/cert/smtp/password` operation is separate and write-only.
An empty password field is a no-op, so it preserves the existing secret.

Set these values in the deployment environment for bootstrap (the same values must be available to the web and scheduler containers):

| Variable | Meaning |
| --- | --- |
| `FORTIOS_SMTP_HOST` | Bootstrap SMTP host. |
| `FORTIOS_SMTP_PORT` | Bootstrap SMTP port; defaults to `587` when omitted. |
| `FORTIOS_SMTP_USERNAME` | Bootstrap SMTP login name. |
| `FORTIOS_SMTP_PASSWORD_FILE` | Sole password source and write target when its storage is writable. |
| `FORTIOS_SMTP_SECURITY` | `starttls`, `tls`, or `none`; `starttls` is the default. |
| `FORTIOS_SMTP_ALLOW_INSECURE` | Must be `true` before `none` is considered deliverable. |
| `FORTIOS_SMTP_FROM` | Bootstrap sender address. |
| `FORTIOS_SMTP_TIMEOUT` | SMTP timeout in seconds; defaults to `10`. |
| `FORTIOS_APP_URL` | Canonical application URL used in notification links. |

`POST /api/cert/smtp/password` is the only request body that may carry the
write-only password; the value is not echoed, logged, or persisted in JSON.
Do not set or pass a plain `FORTIOS_SMTP_PASSWORD`, and do not put a password
in Stack YAML, `smtp-settings.json`, logs, or preview data. The historical
`data/smtp-password` sidecar is never a runtime fallback, and
`delete_smtp_password` remains rejected. Public settings expose only whether
password storage is configured and whether the selected file can be written;
they never expose the password or its path. The `FORTIOS_SMTP_PASSWORD_FILE`
environment variable remains authoritative for the secret path; the JSON schema
marker never overrides it.

The portable Compose definitions use a dedicated secret volume:

```text
Volume Compose : fortios-smtp-secrets (prefixed by the Stack name)
Container      : /opt/fortios/smtp-secrets/password
Variable       : FORTIOS_SMTP_PASSWORD_FILE
Web            : volume rw, directory 0700, file 0600
Scheduler      : the same volume ro
```

The entrypoint prepares only this dedicated volume. An external path such as a
read-only `/run/fortios-secrets` mount remains valid for delivery but is not a
GUI write target. The global certificate/secrets trees are never made writable
for SMTP administration.

`FORTIOS_SMTP_STARTTLS` remains accepted only as a compatibility input for older local configurations. New deployments should set `FORTIOS_SMTP_SECURITY` and, for clear SMTP, explicitly set `FORTIOS_SMTP_ALLOW_INSECURE=true`.

Functional notification preferences and recipients remain in `data/notification-settings.json`
(`enabled`, `releaseNotificationsEnabled`, `releaseRecipientsShared`, `releaseRecipients`,
`systemNotificationsEnabled`, `systemRecipients`, `minimumSeverity`, `products`, `recipients`). A newly saved SMTP document has this non-secret shape:

```json
{
  "schemaVersion": 1,
  "host": "smtp.example.tld",
  "port": 587,
  "security": "starttls",
  "allowInsecure": false,
  "username": "mailer@example.tld",
  "from": "fortiupgrade@example.tld",
  "appUrl": "https://fortiupgrade.example.tld/",
  "timeout": 10,
  "emailAppearance": {
    "displayName": "FortiUpgrade",
    "introduction": "",
    "signature": ""
  }
}
```

An appearance-only save remains deliberately unmarked for compatibility when
there is no valid marked SMTP document to preserve. It cannot reactivate any
historical infrastructure fields. Generated security facts and links stay
engine-owned and are escaped before rendering.

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
existing global/external secrets directory remains read-only; SMTP GUI writes
use their own separate private volume. The settings API reports
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
outbox. Display name and signature are preserved; the system introduction is automatic, not
the CVE introduction. An absent
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

### Container image security is a separate category

Vulnerabilities of the application's own Docker image (Trivy) are **not** part of
`notification-settings.json`. They have their own preferences document
(`data/container-security-settings.json`), their own two-level threshold, their own recipient list
and their own email, and they never fall back on the Fortinet recipient lists — in either
direction. Full documentation: [container-security.md](container-security.md).

This document below therefore describes the Fortinet/CVE and system categories only.

### Categories and switches

`data/notification-settings.json` carries three independent functional switches:

| Key | Scope |
| --- | --- |
| `enabled` | CVEs at or above `minimumSeverity` only. |
| `systemNotificationsEnabled` | System events: end of support, repeated collection failures, recoveries, compatibility recovery and other existing technical events outside CVE/release/Trivy. |
| `systemRecipients` | Dedicated system list only, with no sharing/fallback to `recipients`. Required when system alerts are ON. |
| `minimumSeverity` | Minimum CVE severity that may produce an event: `critical`, `high`, `medium` or `low`, most severe first. `high` is the default and the value every pre-existing configuration carries. |
| `releaseNotificationsEnabled` | New Fortinet releases only. |
| `releaseRecipientsShared` | `true` (default, and what a file without the key resolves to): releases deliver to `recipients`. |
| `releaseRecipients` | Dedicated release list, used only when `releaseRecipientsShared` is `false`; then it must not be empty. |

`minimumSeverity` is a genuine threshold, applied before composition. The four accepted
values are the severity levels Fortinet genuinely publishes, derived from the CSAF CVSS base
score by `fortios_watch.cvss_severity()`; `unknown` (our own fallback for a CVE whose CSAF
export carries no base score) is deliberately **not** selectable and never reaches any threshold, so an
unscored CVE is never presented as "at least Low". Comparison goes through an explicit hierarchy
(`critical` 4 … `unknown` 0), never through string ordering. An unknown value is refused by the
API (`400`) instead of falling back to `high`.

Raising or lowering the threshold filters **future** events only: the checkpoint records every
collected CVE regardless of the threshold, so a CVE seen while it was below the threshold is
never re-reported as new once the threshold drops, and no historical catch-up email is sent. A
genuine severity escalation observed afterwards notifies when it reaches the configured level.

`releaseNotificationsEnabled`, `releaseRecipientsShared` and `releaseRecipients` are all
**optional when loading**: a file written before them inherits `enabled` / `true` / `[]`, so an
upgrade preserves release routing, never triggers the
corrupt-configuration fallback and never loses recipients. An unknown key stays rejected.
`releaseNotificationsEnabled` gates `derive_version_events()` and pending release claims; `versionsByProduct` still
advances while it is off, so re-enabling it never replays history.

Disabling the share with an empty dedicated list is **refused** (`400` from the API, explicit
message in the form): the engine never falls back silently to the CVE list and never builds an
email without recipients.

### Delivery routing

`systemNotificationsEnabled` and `systemRecipients` are **optional when loading**, defaulting
to `false` / `[]`. Valid historical files remain byte-identical on reads; unknown keys are
still rejected. Every save writes both keys. Enabling system alerts without a dedicated recipient
is refused explicitly (API 400 and UI message). OFF continues to advance EOL/health baselines
silently, including compatibility recovery and backfill, so activation never replays transitions
observed while OFF. Existing system outbox entries are retained with their retry/claim metadata,
not claimed or sent while OFF/invalid; after valid activation they resume to `systemRecipients`.
When system alerts are enabled, a CVE backfill does not consume an EOL crossing: the crossing is
preserved and delivered by the next normal collection instead of being lost silently.

Events use the existing outbox with separate system and Trivy partitions:

| Situation | Result |
| --- | --- |
| CVEs + releases, same effective recipients | one grouped email (historical behaviour) |
| CVEs + releases, different recipients | two emails: the CVE email to `recipients`, the release email to `releaseRecipients` |
| Releases only | one email to the effective release list |
| CVEs only | one email to `recipients` |
| System events | one dedicated email to `systemRecipients`, never merged, even with identical addresses |

Collection and compatibility recovery share `deliver_notification_batches()`. Each batch is
composed, delivered, finalized or released on its own; releasing a failed batch never releases
the next batch's live claims. A failed batch stays in the
outbox with its retry metadata while the successful one is removed and recorded in `sentKeys`, so
a partial failure neither blocks nor duplicates the other category, and no event can be sent
twice. Dedup keys, the checkpoint, claims and concurrency guarantees are untouched.

A batch the SMTP server accepts for only **part** of its recipients is not a success: the
refused-recipient mapping is kept as `remainingRecipients` on the outbox entry, the diagnostic
reports a partial acceptance instead of claiming every destination was accepted, `sentKeys` is not
written and the entry stays in the outbox, so a later collection retries the refused destinations
only -- a recipient already accepted is never sent the same event again. The SMTP refusal mapping
is keyed by the envelope identity `smtplib` derives from the message (it normalizes an accepted
configured form such as `"bob"@example.invalid` or `<bob@example.invalid>` to
`bob@example.invalid`), so each refusal is attributed back to the configured destination it belongs
to before any progress is written: `remainingRecipients` stores that configured string and a
refusal that cannot be attributed to any destination of the batch is never recorded as a complete
acceptance -- the event stays owed with an explicit diagnostic
(`lastErrorCode=smtp_partial_unattributed`) and a bounded cooldown. Retries use
`remainingRecipients` intersected with the current configuration: a destination the operator
removed stops being retried, a newly added one is never notified retroactively, and when every
remaining destination was removed the event is resolved without any send (explicit diagnostic)
instead of being retried forever or silently re-sent to the full list. A transport change keeps the
same remaining set: the retry goes to the destinations still owed, never back to a recipient the
previous transport already accepted.

Appearance is shared except for the introduction: `introduction` feeds CVE emails and
`releaseIntroduction` feeds new-version emails. Both may be empty, which is when the renderer
writes its own text. An empty `releaseIntroduction` keeps the renderer's automatic release
sentence, which agrees with the number of releases actually reported ("FortiUpgrade a détecté une
nouvelle version Fortinet disponible au téléchargement." for one, "FortiUpgrade a détecté N
nouvelles versions Fortinet disponibles au téléchargement." for several).

`releaseIntroduction` is **optional when loading**: an appearance document written before it
(`displayName`, `introduction`, `signature`) keeps loading unchanged, `introduction` keeps its
historical CVE scope, and release emails take the automatic sentence. An unknown key stays
rejected, and saving from the admin UI always writes both fields.

Release emails keep the stable `new-version|<product>|<product>|<version>` dedup key and carry
their structured details (`kind`, `product`, `productLabel`, `version`, `detectedAt`, optional
`releaseNotesUrl`), so a pending outbox entry survives a retry and a version already sent is
never re-notified.

- New CVEs notify only when their severity reaches `minimumSeverity` (default `high`) and at least one configured product/model is affected.
- A modified CVE notifies only when its severity genuinely escalates and lands at or above `minimumSeverity`; a decrease never notifies. Re-publication, wording/CVSS edits, and unchanged severity are quiet. With the default `high` threshold this is exactly the documented `Medium/Low/Unknown -> High`, `-> Critical` and `High -> Critical` set.
- An event below the threshold is discarded before composition: it contributes no body section, no counter and no product row. The renderer names and colours each severity it actually receives.
- A CVE affecting several selected products is one event with one deduplication key and an aggregated affected-product section, not one email per product.
- Initial checkpoint/bootstrap and catalog backfill are quiet. Incomplete or malformed snapshots do not invent a baseline event; a valid later snapshot can produce the real transition.
- Disabling delivery continues to advance an existing notification reference without creating retroactive events, including legacy environment-only configuration (`FORTIOS_EMAIL_ENABLED=false` without `notification-settings.json`) and compatibility-only recovery. Pending outbox entries are retained, never sent while disabled, and remain eligible for retry after reactivation. Persisted functional settings, when present, remain authoritative and are not rewritten by this fallback.
- A `--cve-reconcile-existing` maintenance pass is silent and crash-safe at every persistence boundary: its definitive results are first recorded as a **durable intent** (`pendingCveBaseline` in the notification history), *before* the catalogue commit; right after the commit the intent is consumed against the catalogue that was actually written, and confirmed entries join the checkpoint's CVE baseline silently. The coordination between collectors is explicit at every write: an intent is only ever retired by a run that actually observed and resolved it (a commit never erases or replaces a concurrent intent it never saw, nor an entry re-staged since its observation), a run derives against the **durable checkpoint as it stands when the run derives** — never against its own stale start-up capture, so a baseline a completed pass already consumed stays opposable to a collection already in flight; the notification pass reads the committed catalogue AND the notify state (checkpoint, staged intent, EOL state) inside ONE short section of the existing history lock — no writer of that state can interleave between the two reads, so a maintenance pass finishing before or after the capture is always observed entirely on one side of it: an older in-flight catalogue image can never be paired with a freshly certified baseline, nor regress an already-certified correction; and the final commit cannot regress a checkpoint entry another writer certified since that observation. The same freshness conditions the events themselves: a pre-derived CVE event whose durable premise is already consumed (its id absorbed, or its `from` severity no longer the durable one) is dropped before it can enter the outbox — no replay, no global filtering; the other event families keep their own baselines and commit mechanisms. The staged intent is part of that same fresh state: a durable, catalogue-confirmed intent — even one staged after the run's own observation — neutralizes the exact correction it describes (same id and target severity) before the outbox, while a genuine novelty, a distinct escalation, and an unconfirmed or concurrently re-staged intent keep their normal fate. If the durable catalogue is absent, unreadable or structurally invalid at capture time — a consumed collection that is missing or of the wrong type is not a valid empty one, and validity is checked before any baseline can be written — notifications are suspended cleanly (state preserved as-is, diagnostic emitted) instead of being derived from the run's own `final_state` image — a later collection re-observes the durable state from scratch. The disabled-notifications path follows the same coherent observation: its silent baseline advance is conditioned on the observed baseline, so an older disabled run cannot regress a concurrent advance that a later reactivation would otherwise replay. The pass only ever absorbs its own confirmed corrections: a concurrent novelty — a new CVE from an advisory it did not resolve, a version collected in parallel — stays out of the baselines and is derived and delivered by the next normal collection, exactly once. If the process dies in between — or at any point after the commit — any later run, a normal collection included, re-confirms the intent before deriving anything: corrected history can never replay as notifications, and an entry whose correction never actually reached the catalogue stays pending instead of being advanced to a state the catalogue does not back. An intent that cannot be written aborts the pass's corrections for that run (nothing is committed, `cve-psirt` health reports the error, stderr carries the diagnostic) rather than committing history nothing would keep silent. Outbox, sent keys and preferences are left untouched (a pending legitimate event is still delivered, and a genuinely new event after the pass still notifies normally). A run that did not re-fetch an advisory never overwrites its stored CVEs with its own older snapshot, so a concurrent collector cannot undo a correction or a retraction.
- EOL transitions bootstrap silently on first sight and notify once on a later `False -> True` transition.
- New releases notify once per version newly present in the catalog for FortiGate/FortiOS, FortiManager or FortiAnalyzer — FortiClient and FortiClient EMS deliberately stay out of release notifications — and only while `releaseNotificationsEnabled` is on.
- A release email shows the product, the version, the detection date and the Fortinet release-notes link when the catalog publishes one; several releases from one collection become one card each in the same email.
- A release-only batch never uses the historical plain-text summary. When a batch also contains CVEs, it keeps the CVE email and lists the releases under "Autres événements" — which is what happens while the recipient lists are shared; with a dedicated release list the releases get their own release email instead.
- Outbox claims are durable and reclaimable after a stale worker claim. Failed sends remain pending for a later run; successful sends are protected by sent-key deduplication. Concurrent collectors cannot claim or send the same event twice.

An existing unreadable or invalid notification history is not an initial activation.
It is retained byte-for-byte and notification processing fails closed, without
resetting its checkpoint, discarding pending events, or interrupting collection.
Restore/reconcile a verified history before resuming; do not delete it to silence
the diagnostic. This replaces the historical archive-and-empty recovery, which
could abandon a valid outbox when only another field was malformed. Valid legacy
states without a checkpoint remain supported; no data-schema migration is required.

## Failures, durable retries and rollback

The outbox accepts optional `nextAttemptAt`, `lastTransport`, `lastErrorCode` fields.
Old entries without them remain readable. On failure the claimed events
are released, not removed; both the main collector and compatibility recovery
use this same retry mechanism. Claims held by a live worker remain exclusive;
a crashed worker's claim becomes reclaimable after the existing 600-second TTL.
A partially accepted send adds the optional `remainingRecipients` field: the
destinations still owed after the server accepted the rest of the batch. Its
**absence** is the legacy shape (a full-list pending event); when the field is
present it must be a non-empty list of valid destinations -- the same address
rule as the settings lists (trimmed, no duplicate). A present value that is
`null`, malformed, padded or duplicated is an invalid state, kept byte-identical
with notifications failing closed exactly like any other malformed history: it
is never read back as a full-list retry (which could resend to recipients already
accepted) and never silently resolved without a send.

- Microsoft 365 invalid credentials, permission/consent failures and invalid configuration:
  300-second cooldown; an operator must fix the cause.
- Graph timeouts/network errors and transient server errors: 60 seconds when
  no usable provider delay is supplied.
- Graph HTTP 429/5xx with `Retry-After`: the provider delay is parsed from seconds
  or an HTTP date and preserved, including delays longer than a day. A value
  beyond the representable timestamp range defers to the latest supported date,
  rather than overflowing the outbox or silently retrying after an hour.
- SMTP collector delivery keeps a next-run retry for transient failures. A **partial** acceptance
  (the server accepted at least one recipient and refused others) records the refused destinations
  -- attributed back to their configured form -- in the outbox `remainingRecipients` field and
  retries only them; the accepted destinations are never resent. A refusal subset that is entirely
  permanent (5xx) keeps the existing bounded cooldown (`nextAttemptAt`, 300 seconds) with
  `lastErrorCode=smtp_partial_delivery`, so a permanently refused destination is diagnosed and
  never abandoned silently nor retried in a tight loop. An unattributable refusal keeps the entry
  owed with `lastErrorCode=smtp_partial_unattributed` and the same bounded cooldown instead of
  being folded into a success. A total refusal (every recipient refused) keeps the historical
  all-or-nothing failure handling. Structured SMTP test results distinguish permanent
  authentication/sender/recipient refusals, but do not change the historical collector retry
  policy. The stateless test paths (`--test-email`, admin test email) create no outbox entry: a
  partially accepted test email keeps its partial outcome, reports a neutral diagnostic (counts
  only, no address) without promising a retry that would not run, and the CLI reports it as a
  non-success. There is no in-process infinite retry loop.
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

The older image also ignores `remainingRecipients`: a still-pending partial
entry is retried as a **full-list** send, so it can resend to recipients the new
image had already delivered to. Before rolling back to an image that predates
this field, either let the current image finish its pending partial retries (a
partial entry normally resolves on the next collection once the SMTP server
accepts the destination), or keep delivery disabled in the restored deployment
until re-upgrading.

An interrupted `--cve-reconcile-existing` pass leaves its durable intent
(`pendingCveBaseline` in the notification history) until a run confirms it
against the catalogue. Complete the pass — or let one normal collection run
under the current image, which consumes it the same way — before rolling the
image back: an image older than that key ignores it at load time but drops it on
its next write, and cannot consume it either (the maintenance flag itself does
not exist there). Outside maintenance passes the key is simply not written, and
a state file without it loads unchanged in both directions.

### Notification preferences and image downgrade

The new→old direction is the only hazardous one. An image older than the
system keys (including the immediately previous image) validates `data/notification-settings.json`
strictly and rejects the newer keys, so it can report a configuration problem
instead of the intended preferences. Before reverting to such an image:

- restore the `notification-settings.json` captured with that version (every
  timestamped rollback directory keeps its own copy);
- retain the current file for a later re-upgrade instead of deleting it: it
  holds the recipients and the switches, and deleting it to silence a
  diagnostic loses the configuration;
- never roll back the image alone when the switch schema changed in between.

The reverse direction is safe by design: a document written before the new keys
keeps loading unchanged, because those keys are optional at load time; system defaults OFF/empty.

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
  tests/test_microsoft365_config_safety.py \
  tests/test_partial_delivery.py
```

The delivery tests use an isolated local SMTP sink and parse the resulting MIME message to compare its subject, text part, and HTML part with the production-rendered preview. They do not connect to a real SMTP service or use production data.

Graph tests mock OAuth/HTTP responses, including failures and throttling. Run the
full unit/API suite and `tests/e2e/` for persistence, switching and browser
regressions. Passing mocks is not proof of tenant permissions or deliverability;
the real-tenant checklist in [microsoft365.md](microsoft365.md) remains required
before activation.
