"""Email notifications for FortiOS Upgrade Intelligence — stdlib only (smtplib,
email.message.EmailMessage), disabled by default, with functional settings persisted in data/ and
SMTP infrastructure supplied by environment variables plus a mounted password file.

Design in one paragraph: main() derives a list of NotificationEvents by diffing the durable
pre-collection checkpoint against the collected state (never by re-scanning the whole catalog, which is what keeps a first-time
activation or a --cve-backfill from spamming years of history). Events are deduplicated against
a small persistent history file keyed by a stable string, then whatever's left gets folded into
a single synthetic email per run (never one email per event) and sent over SMTP. Any failure
anywhere in this module — bad config, network, auth, whatever — is caught and logged without a
traceback or a leaked password, and never propagates to the caller: a broken mailbox must never
break the actual data collection.
"""

from __future__ import annotations

import base64
import datetime as dt
import fcntl
import html
import json
import os
import re
import secrets
import smtplib
import ssl
import stat
import sys
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from email import policy as email_policy
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fortios_email_render
from fortios_watch import (
    cross_process_lock,
    parse_health_timestamp,
    sanitize_health_error,
    utc_now,
    write_json,
)

# SMTP serialization policy: CRLF line endings, matching what smtplib.send_message flattens with.
SMTP_POLICY = email_policy.SMTP

CATEGORY_CRITICAL = "CRITICAL"
CATEGORY_DAILY = "DAILY"
CATEGORY_OPERATIONS = "OPERATIONS"

NOTIFY_HISTORY_RETENTION_DAYS = 180
MAX_EVENTS_PER_SECTION = 20
CONSECUTIVE_FAILURE_NOTIFY_THRESHOLD = 2
# How long a claimed-but-unfinished outbox entry stays "reserved" before a later run is allowed
# to retry it -- long enough to cover the slowest realistic SMTP timeout many times over, short
# enough that a genuinely crashed run's claim doesn't block retries for hours.
CLAIM_STALE_SECONDS = 600
# A permanent configuration/permission failure must not be retried on every scheduled pass.
# The cooldown is deliberately short enough that an operator can switch transports and retry
# promptly, while avoiding a tight loop when the selected provider will keep rejecting the request.
PERMANENT_RETRY_COOLDOWN_SECONDS = 300
# A transient Graph failure without a usable Retry-After header gets a bounded retry delay. SMTP's
# historical connection-failure path remains immediately retryable for compatibility; normalized
# permanent SMTP failures still use the permanent cooldown above.
GRAPH_TRANSIENT_RETRY_COOLDOWN_SECONDS = 60

EMAIL_TRANSPORT_SMTP = "smtp"
EMAIL_TRANSPORT_MICROSOFT365 = "microsoft365"
EMAIL_TRANSPORT_INVALID = "invalid"
MICROSOFT365_GRAPH_SCOPE = "https://graph.microsoft.com/.default"
MICROSOFT365_TOKEN_ENDPOINT = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
MICROSOFT365_SENDMAIL_ENDPOINT = "https://graph.microsoft.com/v1.0/users/{sender}/sendMail"
_AADSTS_HINTS = {
    "AADSTS90002": "Tenant Microsoft 365 introuvable.",
    "AADSTS700016": "Application Microsoft 365 introuvable dans ce tenant.",
    "AADSTS7000215": "Secret client Microsoft 365 refusé.",
    "AADSTS7000222": "Secret client Microsoft 365 expiré.",
    "AADSTS70011": "Périmètre Microsoft Graph invalide.",
}

_EMAIL_ADDRESS_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_MICROSOFT365_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_GUID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
_MICROSOFT365_CLIENT_RE = _GUID_RE
_MICROSOFT365_IDENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._%+@-]{0,319}$")

DEFAULT_NOTIFICATION_SETTINGS_PATH = Path("data/notification-settings.json")
DEFAULT_SMTP_SETTINGS_PATH = Path("data/smtp-settings.json")
DEFAULT_EMAIL_TRANSPORT_SETTINGS_PATH = Path("data/email-transport-settings.json")
SMTP_SETTINGS_SCHEMA_VERSION = 1
SMTP_PASSWORD_FILENAME = "smtp-password"  # historical data-sidecar name; not a runtime source
SMTP_PASSWORD_ENV = "FORTIOS_SMTP_PASSWORD_FILE"
SMTP_PASSWORD_CANONICAL_PATH = Path("/opt/fortios/smtp-secrets/password")
SMTP_PASSWORD_STORAGE_AVAILABLE = "available"
SMTP_PASSWORD_STORAGE_UNAVAILABLE = "storage-unavailable"
MAX_SMTP_PASSWORD_BYTES = 4096
MICROSOFT365_CLIENT_SECRET_ENV = "FORTIOS_MICROSOFT365_CLIENT_SECRET_FILE"
MICROSOFT365_SECRET_STORAGE_AVAILABLE = "available"
MICROSOFT365_SECRET_STORAGE_UNAVAILABLE = "storage-unavailable"
MAX_MICROSOFT365_CLIENT_SECRET_BYTES = 4096
_SETTINGS_PRODUCT_KEYS = (
    "fortigate-fortios",
    "fortimanager",
    "fortianalyzer",
    "forticlient-ems",
)
_FORTICLIENT_PLATFORM_KEYS = ("windows", "macos", "linux")
_MONITORED_SEVERITIES = frozenset({"high", "critical"})
_SEVERITY_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
PRODUCT_DISPLAY_LABELS = {
    "fortigate-fortios": "FortiGate / FortiOS",
    "fortimanager": "FortiManager",
    "fortianalyzer": "FortiAnalyzer",
    "forticlient-ems": "FortiClient EMS",
    "forticlient:windows": "FortiClient Windows",
    "forticlient:macos": "FortiClient macOS",
    "forticlient:linux": "FortiClient Linux",
}


def _default_notification_settings_payload() -> dict[str, Any]:
    return {
        "enabled": False,
        "minimumSeverity": "high",
        "products": {
            **{key: True for key in _SETTINGS_PRODUCT_KEYS},
            "forticlient": {key: True for key in _FORTICLIENT_PLATFORM_KEYS},
        },
        "recipients": [],
    }


@dataclass(frozen=True)
class NotificationSettings:
    enabled: bool
    minimum_severity: str
    products: dict[str, Any]
    recipients: tuple[str, ...]

    def to_payload(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "minimumSeverity": self.minimum_severity,
            "products": {
                **{key: self.products[key] for key in _SETTINGS_PRODUCT_KEYS},
                "forticlient": dict(self.products["forticlient"]),
            },
            "recipients": list(self.recipients),
        }

    def selected_product_keys(self) -> dict[str, bool]:
        selected = {key: bool(self.products[key]) for key in _SETTINGS_PRODUCT_KEYS}
        selected.update(
            {
                f"forticlient-{platform}": bool(
                    self.products["forticlient"][platform]
                )
                for platform in _FORTICLIENT_PLATFORM_KEYS
            }
        )
        return selected


def validate_notification_settings(payload: Any) -> NotificationSettings:
    if not isinstance(payload, dict) or set(payload) != {
        "enabled",
        "minimumSeverity",
        "products",
        "recipients",
    }:
        raise ValueError("Configuration de notifications invalide.")
    if not isinstance(payload["enabled"], bool):
        raise TypeError("Le champ enabled doit être un booléen.")
    if payload["minimumSeverity"] != "high":
        raise ValueError("La sévérité minimale doit être high.")

    products = payload["products"]
    expected_product_keys = {*_SETTINGS_PRODUCT_KEYS, "forticlient"}
    if not isinstance(products, dict) or set(products) != expected_product_keys:
        raise ValueError("Liste de produits surveillés invalide.")
    if any(not isinstance(products[key], bool) for key in _SETTINGS_PRODUCT_KEYS):
        raise ValueError("Chaque produit surveillé doit être un booléen.")
    forticlient = products["forticlient"]
    if not isinstance(forticlient, dict) or set(forticlient) != set(
        _FORTICLIENT_PLATFORM_KEYS
    ):
        raise ValueError("Plateformes FortiClient invalides.")
    if any(not isinstance(forticlient[key], bool) for key in _FORTICLIENT_PLATFORM_KEYS):
        raise ValueError("Chaque plateforme FortiClient doit être un booléen.")

    recipients = payload["recipients"]
    if not isinstance(recipients, list) or len(recipients) > 50:
        raise ValueError("Liste de destinataires invalide (50 maximum).")
    normalized: list[str] = []
    seen: set[str] = set()
    for value in recipients:
        if not isinstance(value, str):
            raise TypeError("Chaque destinataire doit être une adresse email.")
        address = value.strip()
        if not _EMAIL_ADDRESS_RE.fullmatch(address):
            raise ValueError(f"Adresse email destinataire invalide : {address or '?'}.")
        folded = address.casefold()
        if folded in seen:
            raise ValueError(f"Adresse email destinataire dupliquée : {address}.")
        seen.add(folded)
        normalized.append(address)

    return NotificationSettings(
        enabled=payload["enabled"],
        minimum_severity="high",
        products={
            **{key: products[key] for key in _SETTINGS_PRODUCT_KEYS},
            "forticlient": dict(forticlient),
        },
        recipients=tuple(normalized),
    )


def _legacy_settings_from_env(env: dict[str, str]) -> NotificationSettings:
    payload = _default_notification_settings_payload()
    payload["enabled"] = _env_bool(env, "FORTIOS_EMAIL_ENABLED", False)
    payload["recipients"] = [
        address.strip()
        for address in (env.get("FORTIOS_SMTP_TO") or "").split(",")
        if address.strip()
    ]
    try:
        return validate_notification_settings(payload)
    except (TypeError, ValueError):
        return validate_notification_settings(_default_notification_settings_payload())


def _archive_corrupt_settings_marker(path: Path, raw_text: str) -> None:
    """Record corruption without copying potentially secret unknown fields from invalid JSON."""
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%d%H%M%S%f")
    archive = path.with_name(f"{path.name}.corrupt-{timestamp}")
    temporary = archive.with_name(f"{archive.name}.tmp-{os.getpid()}")
    try:
        write_json(
            temporary,
            {
                "invalidNotificationSettings": True,
                "originalSizeBytes": len(raw_text.encode("utf-8")),
            },
        )
        os.replace(temporary, archive)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def load_notification_settings(
    path: Path = DEFAULT_NOTIFICATION_SETTINGS_PATH,
    *,
    env: dict[str, str] | None = None,
) -> NotificationSettings:
    environment = dict(os.environ) if env is None else env
    if not path.exists():
        # Backward-compatible bootstrap for existing deployments. As soon as the web UI saves
        # notification-settings.json, that file becomes authoritative and these two legacy
        # functional environment variables are ignored.
        return _legacy_settings_from_env(environment)
    safe_default = validate_notification_settings(_default_notification_settings_payload())
    with cross_process_lock(path):
        # It existed before locking but disappeared while a competing operation held the lock:
        # fail closed for this run rather than treating the race as a first migration.
        if not path.exists():
            return safe_default
        try:
            raw_text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return safe_default
        try:
            return validate_notification_settings(json.loads(raw_text))
        except (json.JSONDecodeError, TypeError, ValueError):
            # Write a secret-free marker first (never move/copy the invalid payload): if the
            # safe-default write fails, the invalid live file remains present and every later
            # process continues to fail closed. The same lock is also used by
            # save_notification_settings(), so a concurrent valid save cannot be mistaken for
            # the invalid file we just read.
            _archive_corrupt_settings_marker(path, raw_text)
            try:
                write_json(path, safe_default.to_payload())
            except OSError:
                pass
            return safe_default


def save_notification_settings(path: Path, payload: Any) -> NotificationSettings:
    settings = validate_notification_settings(payload)
    with cross_process_lock(path):
        write_json(path, settings.to_payload())
    return settings

# Short, stable names for dedup keys (type|source|resource_id|new_value) — independent of our
# internal product ids so the key format stays human-readable and matches the spec's examples.
PRODUCT_SHORT_NAMES = {
    "fortigate-fortios": "fortios",
    "fortianalyzer": "fortianalyzer",
    "fortimanager": "fortimanager",
}
# Only these three ever generate "new version" notifications — FortiClient/EMS churn far more
# often and isn't what an engineer needs paged about.
NOTIFIABLE_VERSION_PRODUCTS = tuple(PRODUCT_SHORT_NAMES)


@dataclass
class EmailConfig:
    enabled: bool
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str = field(repr=False)
    smtp_from: str
    smtp_to: tuple[str, ...]
    smtp_starttls: bool
    smtp_timeout: int
    app_url: str
    smtp_password_file: str = ""
    smtp_password_error: str = ""
    smtp_security: str = ""
    email_appearance: EmailAppearance | None = None
    smtp_allow_insecure: bool = False
    # The historical SMTP fields above remain the compatibility surface used by the collector,
    # recovery mail, previews, and existing tests. Microsoft 365 is an additive transport selected
    # by deployment configuration; its secret is read into memory only from a mounted file.
    transport: str = EMAIL_TRANSPORT_SMTP
    graph_tenant_id: str = ""
    graph_client_id: str = ""
    graph_client_secret: str = field(default="", repr=False)
    graph_client_secret_file: str = ""
    graph_client_secret_error: str = ""
    graph_client_secret_storage_state: str = MICROSOFT365_SECRET_STORAGE_UNAVAILABLE
    graph_client_secret_write_available: bool = False
    graph_sender: str = ""
    graph_display_name: str = ""
    graph_mailbox_identity: str = ""
    smtp_password_storage_state: str = SMTP_PASSWORD_STORAGE_UNAVAILABLE
    smtp_password_write_available: bool = False

    def is_complete(self) -> bool:
        if self.transport == EMAIL_TRANSPORT_MICROSOFT365:
            display_name = self.graph_display_name or (
                self.email_appearance.display_name
                if self.email_appearance is not None
                else "FortiUpgrade"
            )
            return bool(
                _MICROSOFT365_TENANT_RE.fullmatch(self.graph_tenant_id)
                and _MICROSOFT365_CLIENT_RE.fullmatch(self.graph_client_id)
                and self.graph_client_secret
                and not self.graph_client_secret_error
                and _EMAIL_ADDRESS_RE.fullmatch(self.graph_sender)
                and (
                    _GUID_RE.fullmatch(self.mailbox_identity)
                    or (
                        "@" in self.mailbox_identity
                        and _MICROSOFT365_IDENTITY_RE.fullmatch(self.mailbox_identity)
                    )
                )
                and self.smtp_to
                and 0 < self.smtp_timeout <= 120
                and isinstance(display_name, str)
                and bool(display_name.strip())
                and len(display_name) <= 100
                and not any(character in display_name for character in ("\0", "\r", "\n"))
            )
        if self.transport != EMAIL_TRANSPORT_SMTP:
            return False
        if not (self.smtp_host and self.smtp_from and self.smtp_to):
            return False
        if not (0 < self.smtp_port <= 65535):
            return False
        if self.smtp_timeout <= 0:
            return False
        if not _EMAIL_ADDRESS_RE.match(self.smtp_from.strip()):
            return False
        if not all(_EMAIL_ADDRESS_RE.match(addr.strip()) for addr in self.smtp_to):
            return False
        security = self.smtp_security or (
            "starttls" if self.smtp_starttls else "none"
        )
        if security not in {"starttls", "tls", "none"}:
            return False
        if security == "none" and not self.smtp_allow_insecure:
            return False
        return not (
            self.smtp_username and (not self.smtp_password or self.smtp_password_error)
        )

    @property
    def sender(self) -> str:
        return self.graph_sender if self.transport == EMAIL_TRANSPORT_MICROSOFT365 else self.smtp_from

    @property
    def display_name(self) -> str:
        if self.graph_display_name:
            return self.graph_display_name
        if self.email_appearance is not None:
            return self.email_appearance.display_name
        return "FortiUpgrade"

    @property
    def mailbox_identity(self) -> str:
        return self.graph_mailbox_identity or self.sender


@dataclass(frozen=True)
class EmailAppearance:
    display_name: str
    introduction: str
    signature: str

    def to_payload(self) -> dict[str, str]:
        return {
            "displayName": self.display_name,
            "introduction": self.introduction,
            "signature": self.signature,
        }


@dataclass(frozen=True)
class SmtpSettings:
    host: str
    port: int
    security: str
    allow_insecure: bool
    username: str
    sender: str
    app_url: str
    timeout: int
    email_appearance: EmailAppearance
    source: str = "saved"

    def to_payload(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "security": self.security,
            "allowInsecure": self.allow_insecure,
            "username": self.username,
            "from": self.sender,
            "appUrl": self.app_url,
            "timeout": self.timeout,
            "emailAppearance": self.email_appearance.to_payload(),
        }

    def to_saved_payload(self) -> dict[str, Any]:
        return {
            "schemaVersion": SMTP_SETTINGS_SCHEMA_VERSION,
            **self.to_payload(),
        }


@dataclass(frozen=True)
class EmailTransportSettings:
    """Non-secret transport selection and Microsoft 365 identity settings.

    The client secret is deliberately absent. It is always read from the read-only deployment
    secret file named by ``FORTIOS_MICROSOFT365_CLIENT_SECRET_FILE``.
    """

    transport: str = EMAIL_TRANSPORT_SMTP
    tenant_id: str = ""
    client_id: str = ""
    sender: str = ""
    display_name: str = ""
    mailbox_identity: str = ""

    def to_payload(self) -> dict[str, Any]:
        return {
            "transport": self.transport,
            "microsoft365": {
                "tenantId": self.tenant_id,
                "clientId": self.client_id,
                "from": self.sender,
                "displayName": self.display_name,
                "mailboxIdentity": self.mailbox_identity,
            },
        }


@dataclass
class NotificationEvent:
    category: str
    dedup_key: str
    summary: str
    severity: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


def _env_bool(env: dict[str, str], key: str, default: bool) -> bool:
    value = env.get(key)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env_int(env: dict[str, str], key: str, default: int) -> int:
    value = (env.get(key) or "").strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_secret(
    env: dict[str, str], key: str, *, label: str = "SMTP"
) -> tuple[str, str, str]:
    secret_file = (env.get(f"{key}_FILE") or "").strip()
    if not secret_file:
        return "", "", ""
    try:
        value = Path(secret_file).read_text(encoding="utf-8").rstrip("\r\n")
    except (OSError, UnicodeError) as error:
        return "", secret_file, sanitize_health_error(error) or f"Secret {label} illisible."
    if not value:
        return "", secret_file, f"Le fichier secret {label} est vide."
    return value, secret_file, ""


def _first_environment_value(environment: dict[str, str], *keys: str) -> str:
    for key in keys:
        value = (environment.get(key) or "").strip()
        if value:
            return value
    return ""


def _env_secret_from_keys(
    environment: dict[str, str], keys: tuple[str, ...], *, label: str
) -> tuple[str, str, str]:
    """Read the first configured secret-file alias without ever accepting plaintext secrets."""
    for key in keys:
        secret_file = (environment.get(key) or "").strip()
        if not secret_file:
            continue
        try:
            value = Path(secret_file).read_text(encoding="utf-8").rstrip("\r\n")
        except (OSError, UnicodeError) as error:
            return "", secret_file, sanitize_health_error(error) or f"Secret {label} illisible."
        if not value:
            return "", secret_file, f"Le fichier secret {label} est vide."
        return value, secret_file, ""
    return "", "", ""


class Microsoft365SecretValidationError(ValueError):
    """A submitted client secret is empty, malformed, or outside the byte limit."""


class Microsoft365SecretStorageError(OSError):
    """The environment-selected client-secret storage cannot be safely written."""


class SmtpPasswordValidationError(ValueError):
    """A submitted SMTP password is empty, malformed, or too large."""


class SmtpPasswordStorageError(OSError):
    """The dedicated SMTP password storage cannot be safely written."""


@dataclass(frozen=True)
class Microsoft365SecretStorageStatus:
    state: str
    can_write: bool
    configured: bool


def _microsoft365_secret_path(environment: dict[str, str]) -> Path | None:
    configured = (environment.get(MICROSOFT365_CLIENT_SECRET_ENV) or "").strip()
    if not configured or "\0" in configured:
        return None
    try:
        return Path(configured).absolute()
    except (TypeError, ValueError, OSError):
        return None


def _smtp_password_path(environment: dict[str, str]) -> Path | None:
    configured = (environment.get(SMTP_PASSWORD_ENV) or "").strip()
    if not configured or "\0" in configured:
        return None
    try:
        return Path(configured).absolute()
    except (TypeError, ValueError, OSError):
        return None


def _smtp_password_write_allowed(path: Path | None) -> bool:
    """Keep external, certificate, data, and Graph secret trees out of SMTP writes."""
    if path is None:
        return False
    protected = (
        Path("/run/fortios-secrets"),
        Path("/opt/fortios/certificates"),
        Path("/opt/fortios/data"),
        Path("/opt/fortios/microsoft365-secrets"),
    )
    return not any(path == prefix or prefix in path.parents for prefix in protected)


def _secret_parent_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _open_microsoft365_secret_parent(path: Path) -> int:
    """Open the configured parent by descriptor, rejecting symlinked components."""
    if not path.is_absolute() or not path.name or path.name in {".", ".."}:
        raise OSError("invalid Microsoft 365 secret path")
    parent_fd = os.open(os.sep, _secret_parent_open_flags())
    try:
        for component in path.parent.parts[1:]:
            child_fd = os.open(
                component,
                _secret_parent_open_flags(),
                dir_fd=parent_fd,
            )
            os.close(parent_fd)
            parent_fd = child_fd
        return parent_fd
    except BaseException:
        os.close(parent_fd)
        raise


def _secret_parent_is_safe(path: Path) -> bool:
    """Require every parent entry to be a real directory, never a symlink."""
    try:
        parent_fd = _open_microsoft365_secret_parent(path)
    except (OSError, ValueError):
        return False
    os.close(parent_fd)
    return True


def _secret_entry_kind_at(parent_fd: int, name: str) -> str:
    try:
        entry_stat = os.lstat(name, dir_fd=parent_fd)
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unavailable"
    if stat.S_ISLNK(entry_stat.st_mode):
        return "symlink"
    if not stat.S_ISREG(entry_stat.st_mode):
        return "nonregular"
    return "regular"


def _secret_target_kind(path: Path) -> str:
    parent_fd = -1
    try:
        parent_fd = _open_microsoft365_secret_parent(path)
        return _secret_entry_kind_at(parent_fd, path.name)
    except (OSError, ValueError):
        return "unavailable"
    finally:
        if parent_fd != -1:
            os.close(parent_fd)


def _secret_lock_is_safe(path: Path) -> bool:
    parent_fd = -1
    try:
        parent_fd = _open_microsoft365_secret_parent(path)
        return _secret_entry_kind_at(parent_fd, f"{path.name}.lock") in {
            "missing",
            "regular",
        }
    except (OSError, ValueError):
        return False
    finally:
        if parent_fd != -1:
            os.close(parent_fd)


def _secret_parent_is_writable(parent_fd: int) -> bool:
    try:
        if os.fstatvfs(parent_fd).f_flag & getattr(os, "ST_RDONLY", 1):
            return False
    except OSError:
        return False
    return os.access(
        ".",
        os.W_OK | os.X_OK,
        dir_fd=parent_fd,
        follow_symlinks=False,
    )


def _secret_entry_is_writable(parent_fd: int, name: str, *, target_kind: str) -> bool:
    if not _secret_parent_is_writable(parent_fd):
        return False
    return target_kind == "missing" or os.access(
        name,
        os.W_OK,
        dir_fd=parent_fd,
        follow_symlinks=False,
    )


def _secret_path_is_writable(path: Path, *, target_kind: str) -> bool:
    parent_fd = -1
    try:
        parent_fd = _open_microsoft365_secret_parent(path)
        return _secret_entry_is_writable(
            parent_fd,
            path.name,
            target_kind=target_kind,
        )
    except (OSError, ValueError):
        return False
    finally:
        if parent_fd != -1:
            os.close(parent_fd)


@contextmanager
def _microsoft365_secret_lock(path: Path):
    """Serialize secret writers through a pinned, non-symlinked parent descriptor."""
    parent_fd = _open_microsoft365_secret_parent(path)
    lock_fd = -1
    locked = False
    try:
        if not _secret_entry_is_writable(parent_fd, ".", target_kind="regular"):
            raise OSError("secret parent is not writable")
        lock_flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        lock_fd = os.open(
            f"{path.name}.lock",
            lock_flags,
            0o600,
            dir_fd=parent_fd,
        )
        if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
            raise OSError("secret lock is not a regular file")
        if not os.access(
            f"{path.name}.lock",
            os.W_OK,
            dir_fd=parent_fd,
            follow_symlinks=False,
        ):
            raise OSError("secret lock is not writable")
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        locked = True
        yield parent_fd
    finally:
        if locked:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        if lock_fd != -1:
            os.close(lock_fd)
        os.close(parent_fd)


def _inspect_microsoft365_secret_storage(
    path: Path | None,
) -> Microsoft365SecretStorageStatus:
    if path is None:
        return Microsoft365SecretStorageStatus(
            MICROSOFT365_SECRET_STORAGE_UNAVAILABLE,
            False,
            False,
        )
    parent_fd = -1
    try:
        parent_fd = _open_microsoft365_secret_parent(path)
        target_kind = _secret_entry_kind_at(parent_fd, path.name)
        lock_kind = _secret_entry_kind_at(parent_fd, f"{path.name}.lock")
        if target_kind not in {"missing", "regular"} or lock_kind not in {
            "missing",
            "regular",
        }:
            return Microsoft365SecretStorageStatus(
                MICROSOFT365_SECRET_STORAGE_UNAVAILABLE,
                False,
                target_kind == "regular",
            )
        if lock_kind == "regular" and not os.access(
            f"{path.name}.lock",
            os.W_OK,
            dir_fd=parent_fd,
            follow_symlinks=False,
        ):
            return Microsoft365SecretStorageStatus(
                MICROSOFT365_SECRET_STORAGE_UNAVAILABLE,
                False,
                target_kind == "regular",
            )
        can_write = _secret_entry_is_writable(
            parent_fd,
            path.name,
            target_kind=target_kind,
        )
        return Microsoft365SecretStorageStatus(
            MICROSOFT365_SECRET_STORAGE_AVAILABLE
            if can_write
            else MICROSOFT365_SECRET_STORAGE_UNAVAILABLE,
            can_write,
            target_kind == "regular",
        )
    except (OSError, ValueError):
        return Microsoft365SecretStorageStatus(
            MICROSOFT365_SECRET_STORAGE_UNAVAILABLE,
            False,
            False,
        )
    finally:
        if parent_fd != -1:
            os.close(parent_fd)


def _microsoft365_storage_error() -> Microsoft365SecretStorageError:
    return Microsoft365SecretStorageError(
        "Stockage du secret Microsoft 365 indisponible."
    )


def _validate_microsoft365_client_secret(value: object) -> bytes:
    if not isinstance(value, str) or not value:
        raise Microsoft365SecretValidationError("Secret client Microsoft 365 invalide.")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise Microsoft365SecretValidationError(
            "Secret client Microsoft 365 invalide."
        ) from error
    if not encoded or len(encoded) > MAX_MICROSOFT365_CLIENT_SECRET_BYTES:
        raise Microsoft365SecretValidationError("Secret client Microsoft 365 invalide.")
    if all(
        character.isspace() or unicodedata.category(character).startswith("C")
        for character in value
    ):
        raise Microsoft365SecretValidationError("Secret client Microsoft 365 invalide.")
    return encoded


def _write_private_secret_bytes(
    path: Path | None,
    encoded: bytes,
    unavailable_error: Any,
) -> str:
    """Atomically replace one file-backed secret through the existing descriptor-bound writer."""
    status = _inspect_microsoft365_secret_storage(path)
    if path is None or not status.can_write:
        raise unavailable_error()

    try:
        with _microsoft365_secret_lock(path) as parent_fd:
            target_kind = _secret_entry_kind_at(parent_fd, path.name)
            if target_kind not in {"missing", "regular"}:
                raise unavailable_error()
            if not _secret_entry_is_writable(
                parent_fd,
                path.name,
                target_kind=target_kind,
            ):
                raise unavailable_error()

            temporary_name = f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
            try:
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
                try:
                    with os.fdopen(descriptor, "wb") as handle:
                        descriptor = -1
                        os.fchmod(handle.fileno(), 0o600)
                        handle.write(encoded)
                        handle.flush()
                        os.fsync(handle.fileno())
                finally:
                    if descriptor != -1:
                        os.close(descriptor)

                target_kind = _secret_entry_kind_at(parent_fd, path.name)
                if target_kind not in {"missing", "regular"} or not _secret_entry_is_writable(
                    parent_fd,
                    path.name,
                    target_kind=target_kind,
                ):
                    raise unavailable_error()
                os.replace(
                    temporary_name,
                    path.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                temporary_name = ""
                try:
                    os.fsync(parent_fd)
                except OSError:
                    # The rename already completed atomically.
                    pass
            finally:
                if temporary_name:
                    try:
                        os.unlink(temporary_name, dir_fd=parent_fd)
                    except FileNotFoundError:
                        pass
            return MICROSOFT365_SECRET_STORAGE_AVAILABLE
    except (OSError, UnicodeError, ValueError) as error:
        raise unavailable_error() from error


def save_microsoft365_client_secret(
    value: object,
    *,
    env: dict[str, str] | None = None,
) -> str:
    """Atomically replace the environment-selected Graph secret without accepting a path."""
    encoded = _validate_microsoft365_client_secret(value)
    environment = dict(os.environ) if env is None else env
    path = _microsoft365_secret_path(environment)
    return _write_private_secret_bytes(path, encoded, _microsoft365_storage_error)


def _smtp_password_storage_error() -> SmtpPasswordStorageError:
    return SmtpPasswordStorageError("Stockage du mot de passe SMTP indisponible.")


def _validate_smtp_password(value: object) -> bytes:
    if not isinstance(value, str) or not value:
        raise SmtpPasswordValidationError("Mot de passe SMTP invalide.")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise SmtpPasswordValidationError("Mot de passe SMTP invalide.") from error
    if len(encoded) > MAX_SMTP_PASSWORD_BYTES or all(
        character.isspace() or unicodedata.category(character).startswith("C")
        for character in value
    ):
        raise SmtpPasswordValidationError("Mot de passe SMTP invalide.")
    return encoded


def _smtp_password_storage_status(
    environment: dict[str, str],
) -> Microsoft365SecretStorageStatus:
    path = _smtp_password_path(environment)
    status = _inspect_microsoft365_secret_storage(path)
    if not _smtp_password_write_allowed(path):
        return Microsoft365SecretStorageStatus(
            SMTP_PASSWORD_STORAGE_UNAVAILABLE,
            False,
            status.configured,
        )
    return Microsoft365SecretStorageStatus(
        SMTP_PASSWORD_STORAGE_AVAILABLE
        if status.can_write
        else SMTP_PASSWORD_STORAGE_UNAVAILABLE,
        status.can_write,
        status.configured,
    )


def save_smtp_password(
    value: object,
    *,
    env: dict[str, str] | None = None,
) -> str:
    """Atomically write the optional GUI-managed SMTP password to its dedicated path."""
    environment = dict(os.environ) if env is None else env
    # A blank browser field means "keep the current secret". It must not create, truncate, or
    # otherwise touch the file, and is valid even when deployments deliberately expose no writer.
    if isinstance(value, str) and value == "":
        return _smtp_password_storage_status(environment).state
    encoded = _validate_smtp_password(value)
    path = _smtp_password_path(environment)
    if not _smtp_password_write_allowed(path):
        raise _smtp_password_storage_error()
    return _write_private_secret_bytes(path, encoded, _smtp_password_storage_error)


def _load_microsoft365_client_secret(
    environment: dict[str, str],
) -> tuple[str, str, str, Microsoft365SecretStorageStatus]:
    path = _microsoft365_secret_path(environment)
    status = _inspect_microsoft365_secret_storage(path)
    if path is None:
        return "", "", "Secret Microsoft 365 non configuré.", status

    parent_fd = -1
    descriptor = -1
    try:
        # Resolve every parent component with O_NOFOLLOW, then keep that directory descriptor
        # pinned while opening the target. O_NONBLOCK prevents a target swapped to a FIFO between
        # the lstat and open from hanging the collector.
        parent_fd = _open_microsoft365_secret_parent(path)
        target_kind = _secret_entry_kind_at(parent_fd, path.name)
        if target_kind == "missing":
            return "", str(path), "Secret Microsoft 365 non configuré.", status
        if target_kind != "regular":
            unavailable = Microsoft365SecretStorageStatus(
                MICROSOFT365_SECRET_STORAGE_UNAVAILABLE,
                False,
                False,
            )
            return "", str(path), "Secret Microsoft 365 non configuré.", unavailable
        descriptor = os.open(
            path.name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_fd,
        )
        target_stat = os.fstat(descriptor)
        if not stat.S_ISREG(target_stat.st_mode):
            unavailable = Microsoft365SecretStorageStatus(
                MICROSOFT365_SECRET_STORAGE_UNAVAILABLE,
                False,
                False,
            )
            return "", str(path), "Secret Microsoft 365 non configuré.", unavailable
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(MAX_MICROSOFT365_CLIENT_SECRET_BYTES + 1)
        if len(raw) > MAX_MICROSOFT365_CLIENT_SECRET_BYTES:
            return "", str(path), "Secret Microsoft 365 illisible.", status
        value = raw.decode("utf-8").rstrip("\r\n")
    except (OSError, UnicodeError, ValueError):
        unavailable = Microsoft365SecretStorageStatus(
            MICROSOFT365_SECRET_STORAGE_UNAVAILABLE,
            False,
            False,
        )
        return "", str(path), "Secret Microsoft 365 illisible.", unavailable
    finally:
        if descriptor != -1:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if parent_fd != -1:
            os.close(parent_fd)
    if not value:
        return "", str(path), "Secret Microsoft 365 illisible.", status
    return value, str(path), "", status


def _email_transport_from_env(environment: dict[str, str]) -> str:
    return _first_environment_value(environment, "FORTIOS_EMAIL_TRANSPORT").casefold() or EMAIL_TRANSPORT_SMTP


def smtp_password_path(settings_path: Path) -> Path:
    """Return the historical sidecar location without making it a runtime secret source."""
    return settings_path.with_name(SMTP_PASSWORD_FILENAME)


def _default_email_appearance() -> EmailAppearance:
    return EmailAppearance(
        display_name="FortiUpgrade",
        introduction="",
        signature="",
    )


def validate_email_appearance(payload: Any) -> EmailAppearance:
    if not isinstance(payload, dict) or set(payload) != {
        "displayName",
        "introduction",
        "signature",
    }:
        raise ValueError("Apparence des emails invalide.")
    if any(
        not isinstance(payload[key], str)
        for key in ("displayName", "introduction", "signature")
    ):
        raise TypeError("Les champs d'apparence doivent être des chaînes.")
    if not payload["displayName"].strip() or len(payload["displayName"]) > 100:
        raise ValueError("Nom affiché invalide.")
    if len(payload["introduction"]) > 2000 or len(payload["signature"]) > 2000:
        raise ValueError("Le contenu personnalisé des emails est trop long.")
    return EmailAppearance(
        display_name=payload["displayName"].strip(),
        introduction=payload["introduction"].strip(),
        signature=payload["signature"].strip(),
    )


def validate_smtp_settings(payload: Any, *, source: str = "saved") -> SmtpSettings:
    expected = {
        "host",
        "port",
        "security",
        "allowInsecure",
        "username",
        "from",
        "appUrl",
        "timeout",
        "emailAppearance",
    }
    if not isinstance(payload, dict) or set(payload) != expected:
        raise ValueError("Configuration SMTP invalide.")
    appearance = validate_email_appearance(payload["emailAppearance"])
    string_fields = ("host", "security", "username", "from", "appUrl")
    if any(not isinstance(payload[key], str) for key in string_fields):
        raise TypeError("Les champs SMTP textuels doivent être des chaînes.")
    if not isinstance(payload["port"], int) or isinstance(payload["port"], bool):
        raise TypeError("Le port SMTP doit être un entier.")
    if not isinstance(payload["timeout"], int) or isinstance(payload["timeout"], bool):
        raise TypeError("Le timeout SMTP doit être un entier.")
    if not isinstance(payload["allowInsecure"], bool):
        raise TypeError("Le champ allowInsecure doit être un booléen.")
    if payload["security"] not in {"starttls", "tls", "none"}:
        raise ValueError("Mode de sécurité SMTP invalide.")
    if payload["security"] == "none" and not payload["allowInsecure"]:
        raise ValueError("Le SMTP sans chiffrement doit être explicitement autorisé.")
    host = payload["host"].strip()
    if (
        not host
        or len(host) > 253
        or "://" in host
        or any(character.isspace() for character in host)
        or not re.fullmatch(r"[A-Za-z0-9.:-]+", host)
    ):
        raise ValueError("Serveur SMTP invalide.")
    if not (0 < payload["port"] <= 65535):
        raise ValueError("Port SMTP invalide.")
    sender = payload["from"].strip()
    if not _EMAIL_ADDRESS_RE.fullmatch(sender):
        raise ValueError("Adresse expéditeur invalide.")
    if not (0 < payload["timeout"] <= 120):
        raise ValueError("Le timeout SMTP doit être compris entre 1 et 120 secondes.")
    parsed_app_url = urllib.parse.urlsplit(payload["appUrl"].strip())
    if (
        parsed_app_url.scheme not in {"http", "https"}
        or not parsed_app_url.netloc
        or parsed_app_url.username is not None
        or parsed_app_url.password is not None
    ):
        raise ValueError("URL FortiUpgrade invalide.")
    username = payload["username"].strip()
    if len(username) > 320 or any(character in username for character in ("\0", "\r", "\n")):
        raise ValueError("Utilisateur SMTP invalide.")
    return SmtpSettings(
        host=host,
        port=payload["port"],
        security=payload["security"],
        allow_insecure=payload["allowInsecure"],
        username=username,
        sender=sender,
        app_url=payload["appUrl"].strip(),
        timeout=payload["timeout"],
        email_appearance=appearance,
        source=source,
    )


def _smtp_security_from_env(env: dict[str, str]) -> tuple[str, bool]:
    """Resolve deployment-owned transport security, with the old boolean as compatibility input."""
    configured = (env.get("FORTIOS_SMTP_SECURITY") or "").strip().lower()
    if configured:
        security = configured if configured in {"starttls", "tls", "none"} else "starttls"
        return security, _env_bool(env, "FORTIOS_SMTP_ALLOW_INSECURE", False)
    starttls = _env_bool(env, "FORTIOS_SMTP_STARTTLS", True)
    # Legacy false explicitly requested plaintext, so preserve that behavior while deployments
    # migrate to FORTIOS_SMTP_SECURITY/FORTIOS_SMTP_ALLOW_INSECURE.
    return ("starttls", False) if starttls else ("none", True)


def _smtp_settings_from_env(env: dict[str, str]) -> SmtpSettings:
    security, allow_insecure = _smtp_security_from_env(env)
    return SmtpSettings(
        host=(env.get("FORTIOS_SMTP_HOST") or "").strip(),
        port=_env_int(env, "FORTIOS_SMTP_PORT", 587),
        security=security,
        allow_insecure=allow_insecure,
        username=(env.get("FORTIOS_SMTP_USERNAME") or "").strip(),
        sender=(env.get("FORTIOS_SMTP_FROM") or "").strip(),
        app_url=(
            env.get("FORTIOS_APP_URL") or "https://valdev.me:3001/app/"
        ).strip(),
        timeout=_env_int(env, "FORTIOS_SMTP_TIMEOUT", 10),
        email_appearance=_default_email_appearance(),
        source="environment",
    )


def _validate_microsoft365_identity(value: str, *, required: bool = False) -> str:
    normalized = value.strip()
    if not normalized and not required:
        return ""
    if not normalized or "\\" in normalized or "/" in normalized or any(
        character.isspace() or character in "\0\r\n" for character in normalized
    ):
        raise ValueError("Identité de boîte Microsoft 365 invalide.")
    if not (_GUID_RE.fullmatch(normalized) or "@" in normalized):
        raise ValueError("L'identité de boîte Microsoft 365 doit être un GUID ou un UPN.")
    if not _MICROSOFT365_IDENTITY_RE.fullmatch(normalized):
        raise ValueError("Identité de boîte Microsoft 365 invalide.")
    return normalized


def validate_email_transport_settings(payload: Any) -> EmailTransportSettings:
    expected = {"transport", "microsoft365"}
    if not isinstance(payload, dict) or set(payload) != expected:
        raise ValueError("Configuration du transport email invalide.")
    transport = payload["transport"]
    if transport not in {EMAIL_TRANSPORT_SMTP, EMAIL_TRANSPORT_MICROSOFT365}:
        raise ValueError("Transport email invalide.")
    graph = payload["microsoft365"]
    graph_expected = {"tenantId", "clientId", "from", "displayName", "mailboxIdentity"}
    if not isinstance(graph, dict) or set(graph) != graph_expected:
        raise ValueError("Configuration Microsoft 365 invalide.")
    if any(not isinstance(graph[key], str) for key in graph_expected):
        raise TypeError("Les champs Microsoft 365 doivent être des chaînes.")
    tenant_id = graph["tenantId"].strip()
    if tenant_id and not _MICROSOFT365_TENANT_RE.fullmatch(tenant_id):
        raise ValueError("Identifiant de tenant Microsoft 365 invalide.")
    client_id = graph["clientId"].strip()
    if client_id and not _MICROSOFT365_CLIENT_RE.fullmatch(client_id):
        raise ValueError("Identifiant client Microsoft 365 invalide.")
    sender = graph["from"].strip()
    if sender and not _EMAIL_ADDRESS_RE.fullmatch(sender):
        raise ValueError("Adresse expéditeur Microsoft 365 invalide.")
    display_name = graph["displayName"].strip()
    if display_name and (
        len(display_name) > 100
        or any(character in display_name for character in ("\0", "\r", "\n"))
    ):
        raise ValueError("Nom affiché Microsoft 365 invalide.")
    mailbox_identity = _validate_microsoft365_identity(graph["mailboxIdentity"])
    return EmailTransportSettings(
        transport=transport,
        tenant_id=tenant_id,
        client_id=client_id,
        sender=sender,
        display_name=display_name,
        mailbox_identity=mailbox_identity,
    )


def _default_email_transport_settings() -> EmailTransportSettings:
    return EmailTransportSettings()


def _load_saved_email_transport_settings(path: Path) -> EmailTransportSettings:
    if not os.path.lexists(path):
        return _default_email_transport_settings()
    try:
        if not path.is_file():
            raise OSError("transport settings is not a regular file")
        payload = json.loads(path.read_text(encoding="utf-8"))
        return validate_email_transport_settings(payload)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        # A present but malformed/unreadable sidecar is not a first run. Fail closed so a damaged
        # saved Graph choice cannot silently select a working SMTP fallback. Never rewrite or
        # archive the bytes here; an operator must restore/reconcile the sidecar explicitly.
        return EmailTransportSettings(transport=EMAIL_TRANSPORT_INVALID)


def _load_email_transport_settings_unlocked(
    path: Path, environment: dict[str, str]
) -> EmailTransportSettings:
    saved = _load_saved_email_transport_settings(path)
    if os.path.lexists(path):
        # Once the UI has saved a non-secret choice, it is authoritative. Deployment environment
        # values remain the source of secrets and timeouts, but must not silently override a later
        # SMTP -> Microsoft 365 (or reverse) selection or its saved mailbox identity.
        return saved
    configured_transport = _first_environment_value(environment, "FORTIOS_EMAIL_TRANSPORT").casefold()
    if configured_transport and configured_transport not in {
        EMAIL_TRANSPORT_SMTP,
        EMAIL_TRANSPORT_MICROSOFT365,
    }:
        # Preserve an invalid deployment choice as an incomplete transport rather than silently
        # sending through SMTP, which could disclose an alert to the wrong provider.
        transport = configured_transport
    else:
        transport = configured_transport or saved.transport

    def override(key: str, current: str) -> str:
        value = (environment.get(key) or "").strip()
        return value or current

    return EmailTransportSettings(
        transport=transport,
        tenant_id=override("FORTIOS_MICROSOFT365_TENANT_ID", saved.tenant_id),
        client_id=override("FORTIOS_MICROSOFT365_CLIENT_ID", saved.client_id),
        sender=override("FORTIOS_MICROSOFT365_FROM", saved.sender),
        display_name=override("FORTIOS_MICROSOFT365_DISPLAY_NAME", saved.display_name),
        mailbox_identity=override(
            "FORTIOS_MICROSOFT365_MAILBOX_IDENTITY", saved.mailbox_identity
        ),
    )


def load_email_transport_settings(
    path: Path = DEFAULT_EMAIL_TRANSPORT_SETTINGS_PATH,
    *,
    env: dict[str, str] | None = None,
) -> EmailTransportSettings:
    environment = dict(os.environ) if env is None else env
    with cross_process_lock(path):
        return _load_email_transport_settings_unlocked(path, environment)


def save_email_transport_settings(
    path: Path, payload: Any, *, env: dict[str, str] | None = None
) -> EmailTransportSettings:
    settings = validate_email_transport_settings(payload)
    with cross_process_lock(path):
        write_json(path, settings.to_payload())
    environment = dict(os.environ) if env is None else env
    return _load_email_transport_settings_unlocked(path, environment)


def _saved_email_appearance(path: Path) -> EmailAppearance:
    """Read only the non-secret appearance sidecar.

    Older releases stored transport fields and a web-managed password beside the appearance.
    Those fields are deliberately ignored: the deployment environment is the sole SMTP transport
    authority. A malformed or absent appearance falls back to the safe default without copying
    unknown fields into a response or a new file.
    """
    if not path.is_file():
        return _default_email_appearance()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        return _default_email_appearance()
    if not isinstance(payload, dict):
        return _default_email_appearance()
    appearance_payload = payload.get("emailAppearance", payload)
    try:
        return validate_email_appearance(appearance_payload)
    except (TypeError, ValueError):
        return _default_email_appearance()


def _invalid_smtp_settings(appearance: EmailAppearance | None = None) -> SmtpSettings:
    """Represent a malformed marked document without falling back to deployment values."""
    return SmtpSettings(
        host="",
        port=587,
        security="starttls",
        allow_insecure=False,
        username="",
        sender="",
        app_url="",
        timeout=10,
        email_appearance=appearance or _default_email_appearance(),
        source="saved-invalid",
    )


def _saved_smtp_settings_from_payload(payload: Any) -> SmtpSettings:
    if not isinstance(payload, dict) or payload.get("schemaVersion") != SMTP_SETTINGS_SCHEMA_VERSION:
        raise ValueError("Configuration SMTP marquée invalide.")
    document = dict(payload)
    del document["schemaVersion"]
    return validate_smtp_settings(document, source="saved")


def _load_smtp_document(path: Path) -> tuple[Any, bool, bool]:
    """Read settings and distinguish a missing file from an unreadable existing file."""
    if not os.path.lexists(path):
        return None, False, False
    if not path.is_file():
        return None, True, True
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        # An existing document may be a truncated/new-schema save. Never reactivate deployment
        # SMTP values when its schema cannot be determined.
        return None, True, True
    return payload, isinstance(payload, dict) and "schemaVersion" in payload, True


def _appearance_from_payload(payload: Any) -> EmailAppearance:
    if not isinstance(payload, dict):
        return _default_email_appearance()
    appearance_payload = payload.get("emailAppearance", payload)
    try:
        return validate_email_appearance(appearance_payload)
    except (TypeError, ValueError):
        return _default_email_appearance()


def _load_smtp_settings_unlocked(
    path: Path, environment: dict[str, str]
) -> SmtpSettings:
    payload, marked, present = _load_smtp_document(path)
    if not present:
        # A missing appearance sidecar bootstraps from deployment values.
        return replace(
            _smtp_settings_from_env(environment),
            email_appearance=_saved_email_appearance(path),
            source="environment",
        )
    if not isinstance(payload, dict):
        return _invalid_smtp_settings()
    if not marked:
        # Historical full documents are intentionally ignored. Their appearance remains readable,
        # but stale host/port/login/sender values never regain authority after an upgrade.
        return replace(
            _smtp_settings_from_env(environment),
            email_appearance=_appearance_from_payload(payload),
            source="environment",
        )
    try:
        return _saved_smtp_settings_from_payload(payload)
    except (TypeError, ValueError):
        return _invalid_smtp_settings(_appearance_from_payload(payload))


def load_smtp_settings(
    path: Path = DEFAULT_SMTP_SETTINGS_PATH,
    *,
    env: dict[str, str] | None = None,
) -> SmtpSettings:
    environment = dict(os.environ) if env is None else env
    with cross_process_lock(path):
        return _load_smtp_settings_unlocked(path, environment)


def _appearance_payload_from_settings(payload: Any) -> Any:
    if not isinstance(payload, dict) or set(payload) != {"emailAppearance"}:
        raise ValueError("Configuration SMTP invalide.")
    return payload["emailAppearance"]


def _existing_saved_smtp_settings_unlocked(path: Path) -> SmtpSettings | None:
    payload, marked, _present = _load_smtp_document(path)
    if not marked:
        return None
    try:
        return _saved_smtp_settings_from_payload(payload)
    except (TypeError, ValueError) as error:
        raise ValueError("Configuration SMTP marquée invalide.") from error


def _persist_email_appearance_unlocked(
    path: Path, appearance: EmailAppearance
) -> SmtpSettings | None:
    """Update appearance without discarding a valid marked SMTP document."""
    existing = _existing_saved_smtp_settings_unlocked(path)
    if existing is not None:
        updated = replace(existing, email_appearance=appearance)
        write_json(path, updated.to_saved_payload())
        return updated
    # Keep the historical appearance-only shape for first saves and legacy documents. It has no
    # infrastructure authority; a later full SMTP save adds the schema marker explicitly.
    write_json(path, {"emailAppearance": appearance.to_payload()})
    return None


def save_email_appearance(
    path: Path,
    payload: Any,
    *,
    env: dict[str, str] | None = None,
) -> SmtpSettings:
    """Persist appearance while retaining any valid saved SMTP infrastructure."""
    if isinstance(payload, dict) and set(payload) == {"emailAppearance"}:
        payload = payload["emailAppearance"]
    appearance = validate_email_appearance(payload)
    environment = dict(os.environ) if env is None else env
    with cross_process_lock(path):
        saved = _persist_email_appearance_unlocked(path, appearance)
    if saved is not None:
        return saved
    return replace(
        _smtp_settings_from_env(environment),
        email_appearance=appearance,
        source="environment",
    )


def save_smtp_settings(
    path: Path,
    payload: Any,
    *,
    password: str | None = None,
    env: dict[str, str] | None = None,
) -> SmtpSettings:
    """Persist validated non-secret SMTP settings with an explicit schema marker.

    The legacy appearance-only shape remains accepted for callers that only customize email
    rendering. Passwords are deliberately a separate, file-backed operation.
    """
    if password is not None:
        raise ValueError(
            "Le mot de passe SMTP doit provenir de FORTIOS_SMTP_PASSWORD_FILE."
        )
    if isinstance(payload, dict) and set(payload) == {"emailAppearance"}:
        return save_email_appearance(path, payload["emailAppearance"], env=env)
    settings = validate_smtp_settings(payload, source="saved")
    with cross_process_lock(path):
        write_json(path, settings.to_saved_payload())
    return settings


def save_email_configuration(
    appearance_path: Path,
    transport_path: Path,
    payload: Any,
    *,
    env: dict[str, str] | None = None,
) -> tuple[SmtpSettings, EmailTransportSettings]:
    """Persist Graph selection/appearance without wiping saved SMTP infrastructure."""
    base_keys = {"transport", "microsoft365", "emailAppearance"}
    allowed_keys = (base_keys, base_keys | {"smtp"})
    if not isinstance(payload, dict) or set(payload) not in allowed_keys:
        raise ValueError("Configuration email invalide.")
    appearance = validate_email_appearance(payload["emailAppearance"])
    transport = validate_email_transport_settings(
        {"transport": payload["transport"], "microsoft365": payload["microsoft365"]}
    )
    smtp_settings: SmtpSettings | None = None
    if "smtp" in payload:
        smtp_settings = validate_smtp_settings(payload["smtp"], source="saved")
        # The wrapper's appearance is the single value shared by both transports. This also
        # prevents a stale nested appearance from silently replacing a current Graph draft.
        smtp_settings = replace(smtp_settings, email_appearance=appearance)
    environment = dict(os.environ) if env is None else env
    # A Graph-only save must preserve a valid marked SMTP document and must not reactivate a
    # malformed one. A complete nested SMTP payload is an explicit repair, so it is validated above
    # and may replace a corrupt marked document.
    if smtp_settings is None:
        with cross_process_lock(appearance_path):
            _existing_saved_smtp_settings_unlocked(appearance_path)
    with cross_process_lock(transport_path):
        write_json(transport_path, transport.to_payload())
    with cross_process_lock(appearance_path):
        if smtp_settings is None:
            _persist_email_appearance_unlocked(appearance_path, appearance)
        else:
            write_json(appearance_path, smtp_settings.to_saved_payload())
    return load_smtp_settings(appearance_path, env=environment), transport


def delete_smtp_password(path: Path) -> None:
    """Reject the removed web-managed secret operation without changing persisted state."""
    del path
    raise ValueError(
        "Le mot de passe SMTP est géré par FORTIOS_SMTP_PASSWORD_FILE."
    )


def load_smtp_snapshot(
    env: dict[str, str] | None = None,
    *,
    settings: NotificationSettings | None = None,
    settings_path: Path = DEFAULT_NOTIFICATION_SETTINGS_PATH,
    smtp_settings_path: Path | None = None,
    email_transport_settings_path: Path | None = None,
) -> tuple[SmtpSettings, EmailConfig]:
    environment = dict(os.environ) if env is None else env
    settings = settings or load_notification_settings(settings_path, env=environment)
    smtp_path = smtp_settings_path or settings_path.with_name(
        DEFAULT_SMTP_SETTINGS_PATH.name
    )
    transport_path = email_transport_settings_path or smtp_path.with_name(
        DEFAULT_EMAIL_TRANSPORT_SETTINGS_PATH.name
    )
    transport_settings = load_email_transport_settings(transport_path, env=environment)
    with cross_process_lock(smtp_path):
        smtp = _load_smtp_settings_unlocked(smtp_path, environment)
        smtp_password, smtp_password_file, smtp_password_error = _env_secret(
            environment, "FORTIOS_SMTP_PASSWORD"
        )
        smtp_password_storage = _smtp_password_storage_status(environment)
        graph_secret, graph_secret_file, graph_secret_error, graph_secret_storage = (
            _load_microsoft365_client_secret(environment)
        )
        graph_timeout = _env_int(
            environment,
            "FORTIOS_MICROSOFT365_TIMEOUT",
            _env_int(environment, "FORTIOS_SMTP_TIMEOUT", 10),
        )
        config = EmailConfig(
            enabled=settings.enabled,
            smtp_host=smtp.host,
            smtp_port=smtp.port,
            smtp_username=smtp.username,
            smtp_password=smtp_password,
            smtp_from=smtp.sender,
            smtp_to=settings.recipients,
            smtp_starttls=smtp.security == "starttls",
            smtp_timeout=smtp.timeout,
            app_url=smtp.app_url,
            smtp_password_file=smtp_password_file,
            smtp_password_error=smtp_password_error,
            smtp_password_storage_state=smtp_password_storage.state,
            smtp_password_write_available=smtp_password_storage.can_write,
            smtp_security=smtp.security,
            smtp_allow_insecure=smtp.allow_insecure,
            email_appearance=smtp.email_appearance,
            transport=transport_settings.transport,
            graph_tenant_id=transport_settings.tenant_id,
            graph_client_id=transport_settings.client_id,
            graph_client_secret=graph_secret,
            graph_client_secret_file=graph_secret_file,
            graph_client_secret_error=graph_secret_error,
            graph_client_secret_storage_state=graph_secret_storage.state,
            graph_client_secret_write_available=graph_secret_storage.can_write,
            graph_sender=transport_settings.sender,
            graph_display_name=transport_settings.display_name,
            graph_mailbox_identity=transport_settings.mailbox_identity,
        )
        config.smtp_timeout = (
            graph_timeout if config.transport == EMAIL_TRANSPORT_MICROSOFT365 else smtp.timeout
        )
    return smtp, config


def load_smtp_preview_snapshot(
    env: dict[str, str] | None = None,
    *,
    smtp_settings_path: Path = DEFAULT_SMTP_SETTINGS_PATH,
    email_transport_settings_path: Path | None = None,
) -> tuple[SmtpSettings, EmailConfig]:
    """Load SMTP transport without reading or repairing functional notification state."""
    preview_settings = NotificationSettings(
        enabled=False,
        minimum_severity="high",
        products={},
        recipients=(),
    )
    return load_smtp_snapshot(
        env,
        settings=preview_settings,
        smtp_settings_path=smtp_settings_path,
        email_transport_settings_path=email_transport_settings_path,
    )


def load_email_config(
    env: dict[str, str] | None = None,
    *,
    settings: NotificationSettings | None = None,
    settings_path: Path = DEFAULT_NOTIFICATION_SETTINGS_PATH,
    smtp_settings_path: Path | None = None,
    email_transport_settings_path: Path | None = None,
) -> EmailConfig:
    _smtp, config = load_smtp_snapshot(
        env,
        settings=settings,
        settings_path=settings_path,
        smtp_settings_path=smtp_settings_path,
        email_transport_settings_path=email_transport_settings_path,
    )
    return config


def transport_prerequisite_state(config: EmailConfig, transport: str) -> str:
    """Prerequisite verdict for ``transport``, evaluated independently of the configured one.

    The configured transport decides what the collector actually sends with, but the admin page
    must show the verdict of the transport *currently selected in the form*. Each transport is
    therefore evaluated on its own, reusing the single authoritative ``EmailConfig.is_complete()``
    rules: an empty SMTP block never makes Microsoft 365 incomplete, and vice versa.
    """
    if transport not in (EMAIL_TRANSPORT_SMTP, EMAIL_TRANSPORT_MICROSOFT365):
        return "incomplete"
    candidate = (
        config if transport == config.transport else replace(config, transport=transport)
    )
    return "operational" if candidate.is_complete() else "incomplete"


def _microsoft365_public_status(config: EmailConfig) -> dict[str, Any]:
    return {
        "state": transport_prerequisite_state(config, EMAIL_TRANSPORT_MICROSOFT365),
        "tenantId": config.graph_tenant_id,
        "clientId": config.graph_client_id,
        "from": config.graph_sender,
        "displayName": config.graph_display_name or config.display_name,
        "mailboxIdentity": config.mailbox_identity,
        "clientSecretConfigured": bool(
            config.graph_client_secret and not config.graph_client_secret_error
        ),
        "clientSecretSource": "mounted-file"
        if config.graph_client_secret_file
        else "not-configured",
        "clientSecretStorageState": config.graph_client_secret_storage_state,
        "canSetClientSecret": config.graph_client_secret_write_available,
        "helpUrl": "/cert/microsoft365-help",
        "guideUrl": "/cert/microsoft365-guide.md",
    }


def smtp_public_status(config: EmailConfig) -> dict[str, Any]:
    public = {
        # ``state`` remains the verdict of the *configured* transport (what actually sends);
        # ``smtpState`` lets the admin page show SMTP's own verdict while SMTP is selected.
        "state": "operational" if config.is_complete() else "incomplete",
        "smtpState": transport_prerequisite_state(config, EMAIL_TRANSPORT_SMTP),
        "transport": config.transport,
        "host": config.smtp_host,
        "port": config.smtp_port,
        "starttls": config.smtp_starttls,
        "from": config.smtp_from,
    }
    public["microsoft365"] = _microsoft365_public_status(config)
    return public


def smtp_public_settings(
    settings: SmtpSettings, config: EmailConfig
) -> dict[str, Any]:
    preview_config = replace(config, smtp_to=("preview@example.invalid",))
    public = {
        **settings.to_payload(),
        "source": settings.source,
        # ``state`` is the verdict of the configured transport; ``smtpState`` is SMTP's own
        # verdict, so the admin page can show the selected transport's state (never the other
        # transport's prerequisites).
        "state": "operational" if config.is_complete() else "incomplete",
        "smtpState": transport_prerequisite_state(config, EMAIL_TRANSPORT_SMTP),
        "previewSendReady": preview_config.is_complete(),
        "passwordConfigured": bool(
            config.smtp_password and not config.smtp_password_error
        ),
        "passwordStorageState": config.smtp_password_storage_state,
        "canSetPassword": config.smtp_password_write_available,
        "transport": config.transport,
    }
    public["microsoft365"] = _microsoft365_public_status(config)
    return public


# --- Persistent state: sent-history dedup, pending outbox, EOL bootstrap state ------------
#
# All three live in one JSON file (data/fortios-notify-history.json by default) so they share a
# single cross_process_lock()'d read-modify-write cycle:
#   {"sentKeys": {dedup_key: sentAtIso, ...},
#    "outbox": [{"category", "dedupKey", "summary", "queuedAt", "claimedBy", "claimedAt"}, ...],
#    "eolState": {branch: isEolBooleanAsOfLastCheck, ...}}
#
# See the "Notifications email" section of README.md for the full outbox lifecycle and the
# recovery procedure for a corrupted state file.

_REQUIRED_OUTBOX_STRING_FIELDS = ("category", "dedupKey", "summary", "queuedAt")
_REQUIRED_OUTBOX_NULLABLE_STRING_FIELDS = ("claimedBy", "claimedAt")
_REQUIRED_OUTBOX_KEYS = (
    _REQUIRED_OUTBOX_STRING_FIELDS + _REQUIRED_OUTBOX_NULLABLE_STRING_FIELDS
)
_VALID_EVENT_CATEGORIES = frozenset(
    {CATEGORY_CRITICAL, CATEGORY_DAILY, CATEGORY_OPERATIONS}
)


def _is_valid_notify_timestamp(value: Any) -> bool:
    """Same rule as the health file's timestamps (see fortios_watch.parse_health_timestamp()):
    must be a real, timezone-aware ISO 8601 string, not just any non-empty string. A naive or
    garbled queuedAt/claimedAt must never reach the claim-staleness arithmetic in
    enqueue_and_claim() (a naive-vs-aware subtraction raises TypeError there just like it did in
    the health file)."""
    if not isinstance(value, str):
        return False
    try:
        parse_health_timestamp(value)
    except ValueError:
        return False
    return True


def _is_valid_outbox_entry(entry: Any) -> bool:
    """Every field below is read unconditionally elsewhere (enqueue_and_claim() builds a
    NotificationEvent straight from entry["category"]/entry["dedupKey"]/entry["summary"],
    finalize_sent_events() matches on entry["dedupKey"]) -- an entry missing one of them used to
    pass validation (only "dedupKey" was checked) and then raise KeyError the moment any of those
    functions touched it, permanently stuck since the notify pipeline never got a chance to
    self-heal past that entry.

    Beyond presence/type, this also rejects semantically inconsistent entries that the earlier,
    shallower validator let through:
    - `category` outside the three real values -- an unrecognized one would silently vanish from
      compose_email()'s critical/daily/operations grouping (neither shown nor ever cleaned up).
    - `queuedAt`/`claimedAt` that don't actually parse as timezone-aware timestamps.
    - `claimedBy` set while `claimedAt` is null (or vice versa) -- a claim with no timestamp can
      never be recognized as stale by enqueue_and_claim(), so it would stay reserved forever with
      no path to ever being retried.
    - empty or whitespace-only strings anywhere a real value is required.
    """
    if not isinstance(entry, dict):
        return False
    if not all(key in entry for key in _REQUIRED_OUTBOX_KEYS):
        return False

    for key in _REQUIRED_OUTBOX_STRING_FIELDS:
        value = entry[key]
        if not isinstance(value, str) or not value.strip():
            return False

    if entry["category"] not in _VALID_EVENT_CATEGORIES:
        return False
    if not _is_valid_notify_timestamp(entry["queuedAt"]):
        return False

    claimed_by = entry["claimedBy"]
    claimed_at = entry["claimedAt"]
    for value in (claimed_by, claimed_at):
        if value is not None and not isinstance(value, str):
            return False
    if claimed_by is not None and not claimed_by.strip():
        return False
    if claimed_at is not None and (
        not claimed_at.strip() or not _is_valid_notify_timestamp(claimed_at)
    ):
        return False
    severity = entry.get("severity")
    if severity is not None and severity not in _MONITORED_SEVERITIES:
        return False
    details = entry.get("details", {})
    if not isinstance(details, dict):
        return False
    next_attempt_at = entry.get("nextAttemptAt")
    if next_attempt_at is not None and not _is_valid_notify_timestamp(next_attempt_at):
        return False
    last_transport = entry.get("lastTransport")
    if last_transport is not None and last_transport not in {
        EMAIL_TRANSPORT_SMTP,
        EMAIL_TRANSPORT_MICROSOFT365,
    }:
        return False
    last_error_code = entry.get("lastErrorCode")
    if last_error_code is not None and (
        not isinstance(last_error_code, str)
        or not last_error_code.strip()
        or len(last_error_code) > 100
    ):
        return False
    # must be both-null (unclaimed) or both-set (claimed) -- never just one
    return (claimed_by is None) == (claimed_at is None)


def _is_valid_checkpoint(value: Any) -> bool:
    """None (absent) is fine -- first activation, or notifications never enabled yet, both fall
    back to the current run's own before/after snapshot (see main()'s wiring). Otherwise must be
    the exact shape commit_events_with_checkpoint() writes: versionsByProduct (product -> list of
    version strings), cvesById (cve id -> full CVE dict, needed to detect modifications, not just
    presence), health (source id -> health record dict, needed for derive_source_health_events()'s
    consecutiveFailures/lastSuccessAt comparison).
    """
    if value is None:
        return True
    if not isinstance(value, dict):
        return False

    versions_by_product = value.get("versionsByProduct", {})
    if not isinstance(versions_by_product, dict):
        return False
    for product, versions in versions_by_product.items():
        if not isinstance(product, str) or not isinstance(versions, list):
            return False
        if not all(isinstance(version, str) for version in versions):
            return False

    cves_by_id = value.get("cvesById", {})
    if not isinstance(cves_by_id, dict):
        return False
    if not all(
        isinstance(cve_id, str) and isinstance(cve, dict)
        for cve_id, cve in cves_by_id.items()
    ):
        return False

    health = value.get("health", {})
    if not isinstance(health, dict):
        return False
    return all(
        isinstance(source_id, str) and isinstance(record, dict)
        for source_id, record in health.items()
    )


def _is_valid_notify_state(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False

    sent_keys = payload.get("sentKeys", {})
    if not isinstance(sent_keys, dict):
        return False
    if not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in sent_keys.items()
    ):
        return False

    outbox = payload.get("outbox", [])
    if not isinstance(outbox, list) or not all(
        _is_valid_outbox_entry(entry) for entry in outbox
    ):
        return False

    eol_state = payload.get("eolState", {})
    if not isinstance(eol_state, dict):
        return False
    if not all(
        isinstance(key, str) and isinstance(value, bool)
        for key, value in eol_state.items()
    ):
        return False

    return _is_valid_checkpoint(payload.get("checkpoint"))


def _empty_notify_state() -> dict[str, Any]:
    return {"sentKeys": {}, "outbox": [], "eolState": {}, "checkpoint": None}


class NotifyStateError(RuntimeError):
    """The existing notification state cannot be trusted or read safely."""


def load_notify_state(path: Path) -> dict[str, Any]:
    """Load notification state without ever rewriting an existing untrusted file.

    Only a genuinely absent file is a first-run empty state. A present file that cannot be read or
    validated raises ``NotifyStateError`` so callers can isolate notifications without discarding
    a valid outbox or advancing a checkpoint from a fabricated empty state.
    """
    try:
        with path.open("r", encoding="utf-8") as handle:
            state = json.load(handle)
    except FileNotFoundError as error:
        # A missing path is the only first-run case. lexists() keeps a dangling symlink (an
        # existing but unreadable state entry) fail-closed instead of silently resetting it.
        if not os.path.lexists(path):
            return _empty_notify_state()
        raise NotifyStateError(
            f"État des notifications illisible ({type(error).__name__})."
        ) from error
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise NotifyStateError(
            f"État des notifications illisible ({type(error).__name__})."
        ) from error
    if not _is_valid_notify_state(state):
        raise NotifyStateError("État des notifications invalide.")
    return {
        "sentKeys": dict(state.get("sentKeys", {})),
        "outbox": [dict(entry) for entry in state.get("outbox", [])],
        "eolState": dict(state.get("eolState", {})),
        "checkpoint": state.get("checkpoint"),
    }


def load_notify_history(path: Path) -> dict[str, str]:
    return load_notify_state(path)["sentKeys"]


def prune_notify_history(
    history: dict[str, str], *, now: str | None = None
) -> dict[str, str]:
    now_dt = dt.datetime.fromisoformat((now or utc_now()).replace("Z", "+00:00"))
    cutoff = now_dt - dt.timedelta(days=NOTIFY_HISTORY_RETENTION_DAYS)
    pruned: dict[str, str] = {}
    for key, sent_at in history.items():
        try:
            sent_dt = dt.datetime.fromisoformat(sent_at.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue
        if sent_dt >= cutoff:
            pruned[key] = sent_at
    return pruned


def filter_new_events(
    events: list[NotificationEvent], history: dict[str, str]
) -> list[NotificationEvent]:
    """Only events whose dedup_key hasn't already been sent -- this is also what makes a first
    activation or a --cve-backfill safe: those never produce events in the first place (see
    derive_*_events() below, which only ever diffs this run's before/after), but this is the
    second line of defense against ever re-sending the same thing twice.
    """
    return [event for event in events if event.dedup_key not in history]


def _parse_iso(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _enqueue_new_events(
    outbox: list[dict[str, Any]],
    sent_keys: dict[str, str],
    new_events: list[NotificationEvent],
    now: str,
) -> None:
    """Mutates `outbox` in place, appending any of `new_events` not already sent or already
    queued. Shared by enqueue_and_claim() and commit_eol_transition() so both agree on exactly
    the same dedup rule, and so an EOL event can be queued under the very same lock/write that
    records the state transition that produced it (see commit_eol_transition()).
    """
    queued_keys = {entry["dedupKey"] for entry in outbox}
    for event in filter_new_events(new_events, sent_keys):
        if event.dedup_key in queued_keys:
            continue
        outbox.append(
            {
                "category": event.category,
                "dedupKey": event.dedup_key,
                "summary": event.summary,
                "severity": event.severity,
                "details": event.details,
                "queuedAt": now,
                "claimedBy": None,
                "claimedAt": None,
                "nextAttemptAt": None,
                "lastTransport": None,
                "lastErrorCode": None,
            }
        )
        queued_keys.add(event.dedup_key)


def _claim_outstanding(
    outbox: list[dict[str, Any]],
    *,
    claimant: str,
    now: str,
    now_dt: dt.datetime,
    transport: str | None = None,
) -> list[NotificationEvent]:
    """Claims every outbox entry not currently held by another still-live attempt, mutating
    `outbox` in place. A claim is "live" for CLAIM_STALE_SECONDS: long enough to cover any real
    SMTP timeout many times over, so only a genuinely crashed run's claim is ever stolen. Shared
    by enqueue_and_claim() and commit_events_with_checkpoint() so both agree on exactly the same
    claim rule.
    """
    claimed: list[NotificationEvent] = []
    for entry in outbox:
        next_attempt_at = _parse_iso(entry.get("nextAttemptAt"))
        blocked_by_cooldown = next_attempt_at is not None and next_attempt_at > now_dt
        if blocked_by_cooldown and not (
            transport and entry.get("lastTransport") not in {None, transport}
        ):
            continue
        claimed_at = _parse_iso(entry.get("claimedAt"))
        is_stale = (
            claimed_at is not None
            and (now_dt - claimed_at).total_seconds() > CLAIM_STALE_SECONDS
        )
        if entry.get("claimedBy") and not is_stale:
            continue  # actively held by another still-live attempt
        entry["claimedBy"] = claimant
        entry["claimedAt"] = now
        claimed.append(
            NotificationEvent(
                category=entry["category"],
                dedup_key=entry["dedupKey"],
                summary=entry["summary"],
                severity=entry.get("severity"),
                details=dict(entry.get("details") or {}),
            )
        )
    return claimed


def enqueue_and_claim(
    path: Path,
    new_events: list[NotificationEvent],
    *,
    claimant: str,
    now: str | None = None,
    transport: str | None = None,
) -> list[NotificationEvent]:
    """Atomically (a) add any of `new_events` not already sent or already queued to the
    persistent outbox -- BEFORE any attempt to send, so a crash or an SMTP failure right after
    this can never lose them -- then (b) claim every outbox entry not currently held by another
    still-live attempt for `claimant`, persisting the claim before returning.

    Two collections running at the same time can't both send the same batch -- the second one's
    claim step runs under the same cross_process_lock() and sees the first one's fresh claim
    already in place, so it claims nothing for those entries.

    Returns every event this caller just claimed (previously-queued retries AND brand-new events
    together) -- the caller should attempt to send all of them as one email, then call
    finalize_sent_events() on success or release_claim() on failure.

    Does NOT touch the notify checkpoint -- see commit_events_with_checkpoint() for the version
    that also advances it atomically alongside the events it produced (used by main()'s
    catalog-derived notifications specifically).
    """
    now = now or utc_now()
    now_dt = dt.datetime.fromisoformat(now.replace("Z", "+00:00"))
    with cross_process_lock(path):
        state = load_notify_state(path)
        _enqueue_new_events(state["outbox"], state["sentKeys"], new_events, now)
        claimed = _claim_outstanding(
            state["outbox"],
            claimant=claimant,
            now=now,
            now_dt=now_dt,
            transport=transport,
        )
        write_json(path, state)
    return claimed


def ensure_checkpoint(path: Path, bootstrap: dict[str, Any]) -> dict[str, Any]:
    """Returns the currently persisted notify checkpoint, bootstrapping it to `bootstrap` first
    if none exists yet (compare-and-set under the same lock, so two concurrent first-ever runs
    still agree on a single winner). Must be called BEFORE this run's own catalog collection
    starts (see main()'s wiring in fortios_watch.py) -- not merely when checkpoint happens to be
    missing at commit time.

    Why this can't just be "fall back to this run's own before/after when checkpoint is None":
    picture the very first run ever with email enabled, which ALSO happens to be the run that
    discovers a new CVE, and then crashes before commit_events_with_checkpoint() ever runs. If
    the checkpoint were only established at that (now-skipped) commit point, the NEXT run would
    still see checkpoint=None and would fall back to reading `before` fresh off disk -- but that
    `before` already reflects the first run's own (successful) catalog write, i.e. it already
    contains the CVE. The diff would then find nothing new, and the notification would be lost
    exactly like before this fix existed. Bootstrapping the checkpoint immediately, before
    collection can change anything, closes that one remaining crack: even if everything after it
    fails, the pre-collection baseline this run started from is already safely anchored.
    """
    with cross_process_lock(path):
        state = load_notify_state(path)
        if state["checkpoint"] is not None:
            return state["checkpoint"]
        state["checkpoint"] = bootstrap
        write_json(path, state)
        return bootstrap


def advance_checkpoint_silently(path: Path, checkpoint: dict[str, Any]) -> None:
    """Advance the diff baseline without enqueuing or claiming events.

    Used while persisted notification settings are disabled: collections performed during that
    period become the new baseline, while an older SMTP-failure outbox remains untouched for a
    future retry if the operator re-enables notifications.
    """
    with cross_process_lock(path):
        state = load_notify_state(path)
        state["checkpoint"] = checkpoint
        write_json(path, state)


def commit_disabled_notification_state(
    path: Path,
    eol_state: dict[str, bool],
    checkpoint: dict[str, Any],
) -> None:
    """Atomically advance every notification baseline while delivery is disabled."""
    with cross_process_lock(path):
        state = load_notify_state(path)
        state["eolState"] = eol_state
        state["checkpoint"] = checkpoint
        write_json(path, state)


def commit_events_with_checkpoint(
    path: Path,
    checkpoint: dict[str, Any],
    new_events: list[NotificationEvent],
    *,
    claimant: str,
    now: str | None = None,
    transport: str | None = None,
) -> list[NotificationEvent]:
    """Atomically (a) advance the persisted notify checkpoint to `checkpoint`, (b) enqueue
    `new_events` into the outbox, and (c) claim every outstanding entry for `claimant` -- all
    under a single cross_process_lock()/write_json(), for exactly the same reason
    commit_eol_transition() bundles its own state update with its events: the checkpoint is what
    the NEXT run diffs the catalog against to decide what's genuinely new (see main()'s wiring in
    fortios_watch.py), so advancing it in a write separate from queuing the events it was derived
    from would let a crash in between silently and permanently lose the notification -- the
    checkpoint would already reflect the new catalog state, so a later run's diff would find
    nothing new left to report.
    """
    now = now or utc_now()
    now_dt = dt.datetime.fromisoformat(now.replace("Z", "+00:00"))
    with cross_process_lock(path):
        state = load_notify_state(path)
        state["checkpoint"] = checkpoint
        _enqueue_new_events(state["outbox"], state["sentKeys"], new_events, now)
        claimed = _claim_outstanding(
            state["outbox"],
            claimant=claimant,
            now=now,
            now_dt=now_dt,
            transport=transport,
        )
        write_json(path, state)
    return claimed


def finalize_sent_events(
    path: Path, sent_events: list[NotificationEvent], *, now: str | None = None
) -> None:
    """After a successful send: remove `sent_events` from the outbox and record their dedup keys
    in sentKeys (so a future run's diff-derived duplicate is filtered out before it's even
    queued), pruning old history.
    """
    if not sent_events:
        return
    now = now or utc_now()
    sent_dedup_keys = {event.dedup_key for event in sent_events}
    with cross_process_lock(path):
        state = load_notify_state(path)
        state["outbox"] = [
            entry
            for entry in state["outbox"]
            if entry["dedupKey"] not in sent_dedup_keys
        ]
        for event in sent_events:
            state["sentKeys"][event.dedup_key] = now
        state["sentKeys"] = prune_notify_history(state["sentKeys"], now=now)
        write_json(path, state)


# Kept as the historical name for finalize_sent_events(): every existing caller/test refers to
# "recording sent events", and the behavior (dedup-history bookkeeping after a real send) is the
# same -- it just also clears any matching outbox entries now, which is a no-op if none exist.
record_sent_events = finalize_sent_events


def release_claim(
    path: Path,
    claimant: str,
    *,
    now: str | None = None,
    outcome: SmtpResult | None = None,
    transport: str | None = None,
) -> None:
    """Release a claim and persist a bounded retry decision.

    A failed Microsoft 365 configuration or permission request gets a durable cooldown instead of
    being retried on every scheduler pass. Provider throttling/server failures honour Retry-After
    when present; connection failures use a short bounded delay. The legacy SMTP path keeps its
    immediate retry behavior for transient failures when no outcome is supplied.
    """
    now = now or utc_now()
    now_dt = dt.datetime.fromisoformat(now.replace("Z", "+00:00"))
    with cross_process_lock(path):
        state = load_notify_state(path)
        changed = False
        for entry in state["outbox"]:
            if entry.get("claimedBy") != claimant:
                continue
            entry["claimedBy"] = None
            entry["claimedAt"] = None
            if outcome is None:
                entry["nextAttemptAt"] = None
                entry["lastTransport"] = None
                entry["lastErrorCode"] = None
            else:
                failed_transport = outcome.transport if outcome.transport in {
                    EMAIL_TRANSPORT_SMTP,
                    EMAIL_TRANSPORT_MICROSOFT365,
                } else transport if transport in {
                    EMAIL_TRANSPORT_SMTP,
                    EMAIL_TRANSPORT_MICROSOFT365,
                } else None
                entry["lastTransport"] = failed_transport
                entry["lastErrorCode"] = outcome.error_code or None
                if outcome.retryable:
                    if outcome.retry_after_seconds is not None:
                        delay = max(0, outcome.retry_after_seconds)
                    elif failed_transport == EMAIL_TRANSPORT_MICROSOFT365:
                        delay = GRAPH_TRANSIENT_RETRY_COOLDOWN_SECONDS
                    else:
                        delay = 0
                else:
                    delay = PERMANENT_RETRY_COOLDOWN_SECONDS
                if delay:
                    try:
                        next_attempt = now_dt + dt.timedelta(seconds=delay)
                    except (OverflowError, ValueError):
                        next_attempt = dt.datetime.max.replace(tzinfo=dt.UTC)
                    entry["nextAttemptAt"] = next_attempt.isoformat().replace("+00:00", "Z")
                else:
                    entry["nextAttemptAt"] = None
            changed = True
        if changed:
            write_json(path, state)


def prepare_retry_for_transport(path: Path, transport: str) -> None:
    """Make pending entries immediately eligible when an operator changes providers."""
    if transport not in {EMAIL_TRANSPORT_SMTP, EMAIL_TRANSPORT_MICROSOFT365}:
        raise ValueError("Transport email invalide.")
    with cross_process_lock(path):
        state = load_notify_state(path)
        changed = False
        for entry in state["outbox"]:
            if entry.get("lastTransport") not in {None, transport} and entry.get(
                "nextAttemptAt"
            ) is not None:
                entry["nextAttemptAt"] = None
                changed = True
        if changed:
            write_json(path, state)


def commit_eol_transition(
    path: Path,
    eol_state: dict[str, bool],
    events: list[NotificationEvent],
    *,
    now: str | None = None,
) -> None:
    """Persist an EOL state transition and the notification event(s) it produced in ONE atomic
    read-modify-write, under a single cross_process_lock() acquisition.

    Regression this fixes: eolState used to be saved by a separate save_eol_state() call BEFORE
    the resulting event was queued via enqueue_and_claim(). A crash (or the process simply being
    killed) between those two writes would leave eolState already marking the branch as handled
    while the event was never queued anywhere -- and since derive_eol_events() only ever fires on
    the False -> True transition of that exact persisted state, a future run would see `was_eol`
    already True and never regenerate the event. The notification would be permanently lost with
    no way to detect or recover it after the fact. Doing both under one lock/write removes the
    window entirely: either both land, or (if this call itself never completes) neither does, and
    the next run's derive_eol_events() will still see the pre-transition state and fire normally.
    """
    now = now or utc_now()
    with cross_process_lock(path):
        state = load_notify_state(path)
        state["eolState"] = eol_state
        _enqueue_new_events(state["outbox"], state["sentKeys"], events, now)
        write_json(path, state)


# --- Event derivation ---------------------------------------------------------------------


def derive_version_events(
    before_versions_by_product: dict[str, set[str]],
    after_versions_by_product: dict[str, set[str]],
    product_labels: dict[str, str],
) -> list[NotificationEvent]:
    events = []
    for product_id in NOTIFIABLE_VERSION_PRODUCTS:
        short_name = PRODUCT_SHORT_NAMES[product_id]
        new_versions = sorted(
            after_versions_by_product.get(product_id, set())
            - before_versions_by_product.get(product_id, set())
        )
        label = product_labels.get(product_id, product_id)
        for version in new_versions:
            events.append(
                NotificationEvent(
                    category=CATEGORY_DAILY,
                    dedup_key=f"new-version|{short_name}|{short_name}|{version}",
                    summary=f"Nouvelle version {label} {version}",
                )
            )
    return events


def _default_detection_settings() -> NotificationSettings:
    return validate_notification_settings(_default_notification_settings_payload())


def _selected_affected_entries(
    cve: dict[str, Any], settings: NotificationSettings
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for item in cve.get("affected", []) or []:
        if not isinstance(item, dict):
            continue
        product = item.get("product")
        filtered = dict(item)
        if product == "forticlient":
            models = [
                str(model)
                for model in (item.get("models") or [])
                if str(model) in _FORTICLIENT_PLATFORM_KEYS
                and settings.products["forticlient"][str(model)]
            ]
            if item.get("models") and not models:
                continue
            if not item.get("models") and not any(
                settings.products["forticlient"].values()
            ):
                continue
            filtered["models"] = models
        elif product in _SETTINGS_PRODUCT_KEYS:
            if not settings.products[product]:
                continue
        else:
            continue
        signature = (
            filtered.get("product"),
            tuple(filtered.get("models") or []),
            filtered.get("branch"),
            filtered.get("from"),
            filtered.get("to"),
        )
        if signature not in seen:
            selected.append(filtered)
            seen.add(signature)
    return selected


def _affected_product_labels(affected: list[dict[str, Any]]) -> list[str]:
    labels: list[str] = []
    for item in affected:
        product = str(item.get("product") or "")
        if product == "forticlient":
            models = item.get("models") or []
            item_labels = [
                PRODUCT_DISPLAY_LABELS[f"forticlient:{model}"]
                for model in models
                if f"forticlient:{model}" in PRODUCT_DISPLAY_LABELS
            ]
            if not item_labels:
                item_labels = ["FortiClient (plateforme non précisée)"]
        else:
            item_labels = [PRODUCT_DISPLAY_LABELS.get(product, product)]
        for label in item_labels:
            if label and label not in labels:
                labels.append(label)
    return labels


def _security_event(
    cve: dict[str, Any],
    affected: list[dict[str, Any]],
    *,
    dedup_key: str,
    change: str,
) -> NotificationEvent:
    severity = str(cve.get("severity") or "unknown").lower()
    labels = _affected_product_labels(affected)
    details = {
        "kind": "cve",
        "id": cve["id"],
        "severity": severity,
        "cvssScore": cve.get("cvssScore"),
        "title": str(cve.get("title") or "Résumé non disponible"),
        "url": str(cve.get("url") or ""),
        "affected": affected,
        "productLabels": labels,
        "change": change,
    }
    return NotificationEvent(
        category=CATEGORY_CRITICAL if severity == "critical" else CATEGORY_DAILY,
        dedup_key=dedup_key,
        summary=f"{cve['id']} — {', '.join(labels)} ({severity})",
        severity=severity,
        details=details,
    )


def derive_new_cve_events(
    newly_added_cves: list[dict[str, Any]],
    settings: NotificationSettings | None = None,
) -> list[NotificationEvent]:
    settings = settings or _default_detection_settings()
    events = []
    for cve in newly_added_cves:
        severity = (cve.get("severity") or "unknown").lower()
        if severity not in _MONITORED_SEVERITIES:
            continue
        affected = _selected_affected_entries(cve, settings)
        if not affected:
            continue
        events.append(
            _security_event(
                cve,
                affected,
                dedup_key=f"new-cve|psirt|{cve['id']}|{severity}",
                change="new",
            )
        )
    return events


def derive_cve_modification_events(
    cves_before_by_id: dict[str, dict[str, Any]],
    cves_after_by_id: dict[str, dict[str, Any]],
    settings: NotificationSettings | None = None,
) -> list[NotificationEvent]:
    """Notify only a severity escalation that reaches High/Critical.

    Re-publication, wording/CVSS/scope edits, and an unchanged High/Critical severity are silent.
    This keeps the PSIRT diff authoritative without turning every advisory refresh into a new
    security alert.
    """
    settings = settings or _default_detection_settings()
    events = []
    for cve_id, after in cves_after_by_id.items():
        before = cves_before_by_id.get(cve_id)
        if before is None:
            continue  # brand new (handled by derive_new_cve_events)

        before_severity = (before.get("severity") or "unknown").lower()
        after_severity = (after.get("severity") or "unknown").lower()
        if after_severity not in _MONITORED_SEVERITIES:
            continue
        if _SEVERITY_RANK.get(after_severity, 0) <= _SEVERITY_RANK.get(
            before_severity, 0
        ):
            continue
        affected = _selected_affected_entries(after, settings)
        if not affected:
            continue
        events.append(
            _security_event(
                after,
                affected,
                dedup_key=(
                    f"cve-severity|psirt|{cve_id}|"
                    f"{before_severity}-to-{after_severity}"
                ),
                change=f"{before_severity}-to-{after_severity}",
            )
        )
    return events


def derive_eol_events(
    after_lifecycle: dict[str, dict[str, Any]],
    eol_state: dict[str, bool],
    *,
    now: str | None = None,
) -> tuple[list[NotificationEvent], dict[str, bool]]:
    """Fires once when a FortiOS branch's support window naturally elapses.

    Comparing this run's before/after catalog snapshot for the same calendar day never catches
    this: the `support` date endoflife.date reports for a branch doesn't change from one run to
    the next -- only `now` moving past it does, and re-fetching the exact same date on both sides
    of a diff can never look like a change. So "is this branch EOL" is tracked here instead,
    persisted across runs in `eol_state` (branch -> EOL-ness as of the last time this ran).

    A branch seen for the very first time (not yet a key in `eol_state`) has its current EOL-ness
    recorded silently, with no event -- otherwise turning this on for the first time would
    immediately email every branch already long past its support date. After that, the event
    fires exactly once on the transition (False -> True), including correctly across a gap of
    several days without a single collection: whatever `eol_state` said last time this genuinely
    ran is what's compared against, not "yesterday".

    Returns (events, updated_eol_state) -- the caller must persist the updated state (see
    save_eol_state()) regardless of whether the email actually sends, since the crossing itself
    was correctly observed either way.
    """
    now_date = dt.datetime.fromisoformat(
        (now or utc_now()).replace("Z", "+00:00")
    ).date()
    updated_state = dict(eol_state)
    events: list[NotificationEvent] = []
    for branch, info in after_lifecycle.items():
        support_date = info.get("support")
        if not support_date:
            continue
        try:
            support_dt = dt.date.fromisoformat(support_date)
        except ValueError:
            continue

        is_eol_now = support_dt < now_date
        was_eol = eol_state.get(branch)
        if was_eol is None:
            updated_state[branch] = (
                is_eol_now  # first sighting: bootstrap silently, no event
            )
            continue
        if is_eol_now and not was_eol:
            events.append(
                NotificationEvent(
                    category=CATEGORY_DAILY,
                    dedup_key=f"support-eol|fortios|{branch}|{support_date}",
                    summary=f"FortiOS {branch} est passé en fin de support (depuis le {support_date})",
                )
            )
        updated_state[branch] = is_eol_now
    return events, updated_state


def derive_source_health_events(
    health_before: dict[str, dict[str, Any]],
    health_after: dict[str, dict[str, Any]],
    source_labels: dict[str, str],
) -> list[NotificationEvent]:
    events = []
    for source_id, after in health_after.items():
        if source_id == "daily-run":
            continue  # the aggregate summary, not a real source of its own
        before = health_before.get(source_id) or {}
        before_failures = before.get("consecutiveFailures") or 0
        after_failures = after.get("consecutiveFailures") or 0
        label = source_labels.get(source_id, source_id)

        if (
            after_failures >= CONSECUTIVE_FAILURE_NOTIFY_THRESHOLD
            and before_failures < CONSECUTIVE_FAILURE_NOTIFY_THRESHOLD
        ):
            events.append(
                NotificationEvent(
                    category=CATEGORY_OPERATIONS,
                    dedup_key=f"source-failure|{source_id}|consecutive|{after_failures}",
                    summary=f"Collecte {label} en échec depuis {after_failures} exécutions consécutives",
                )
            )
        elif (
            before_failures >= CONSECUTIVE_FAILURE_NOTIFY_THRESHOLD
            and after_failures == 0
            and after.get("lastSuccessAt")
        ):
            success_date = after["lastSuccessAt"][:10]
            events.append(
                NotificationEvent(
                    category=CATEGORY_OPERATIONS,
                    dedup_key=f"source-recovered|{source_id}|lastSuccessAt|{success_date}",
                    summary=f"Collecte {label} de nouveau opérationnelle (après {before_failures} échecs)",
                )
            )
    return events


# --- Email composition and sending ---------------------------------------------------------


def _format_event_lines(events: list[NotificationEvent]) -> list[str]:
    shown = events[:MAX_EVENTS_PER_SECTION]
    lines = [f"- {event.summary}" for event in shown]
    remaining = len(events) - len(shown)
    if remaining > 0:
        lines.append(f"... et {remaining} de plus (liste tronquée).")
    return lines


def _apply_email_appearance(
    text_body: str,
    html_body: str,
    appearance: EmailAppearance,
) -> tuple[str, str]:
    text_prefix = [appearance.display_name]
    if appearance.introduction:
        text_prefix.extend(("", appearance.introduction))
    rendered_text = "\n".join(text_prefix) + "\n\n" + text_body
    if appearance.signature:
        rendered_text += f"\n\n{appearance.signature}"

    html_header = (
        "<div style='font-family:Arial,sans-serif;margin:0 auto;max-width:680px;"
        "padding:20px 20px 0'>"
        f"<p style='margin:0 0 8px;font-size:18px;font-weight:700'>"
        f"{html.escape(appearance.display_name)}</p>"
    )
    if appearance.introduction:
        html_header += (
            f"<p style='margin:0'>{html.escape(appearance.introduction)}</p>"
        )
    html_header += "</div>"
    html_footer = ""
    if appearance.signature:
        html_footer = (
            "<div style='font-family:Arial,sans-serif;margin:0 auto;max-width:680px;"
            "padding:0 20px 20px'>"
            f"<p style='margin:0'>{html.escape(appearance.signature)}</p></div>"
        )
    body_position = html_body.find("<body")
    body_open_end = html_body.find(">", body_position)
    if body_position >= 0 and body_open_end >= 0:
        rendered_html = (
            html_body[: body_open_end + 1]
            + html_header
            + html_body[body_open_end + 1 :]
        )
        rendered_html = rendered_html.replace(
            "</body>", html_footer + "</body>", 1
        )
    else:
        rendered_html = html_header + html_body + html_footer
    return rendered_text, rendered_html


def compose_email(
    events: list[NotificationEvent],
    *,
    app_url: str,
    run_timestamp: str,
    appearance: EmailAppearance | None = None,
) -> tuple[str, str, str] | None:
    """Folds every event from a single run into one synthetic email (never one email per
    event, to avoid spamming) -- returns None if there's nothing to report.

    Security (CVE) events are rendered by scripts/fortios_email_render.py, the single
    authoritative renderer for the SNS identity. Non-security events (new versions, EOL,
    health) are folded in as an "Autres événements" section; when only those exist, the
    historical plain-text summary is kept unchanged.
    """
    if not events:
        return None

    security = [event for event in events if event.details.get("kind") == "cve"]
    if security:
        non_security = [event for event in events if event.details.get("kind") != "cve"]
        display_name = (
            appearance.display_name if appearance is not None else "FortiUpgrade"
        )
        introduction = appearance.introduction if appearance is not None else ""
        signature = appearance.signature if appearance is not None else ""
        return fortios_email_render.compose_email(
            security,
            app_url=app_url,
            run_timestamp=run_timestamp,
            other_events=non_security or None,
            display_name=display_name,
            introduction=introduction,
            signature=signature,
        )

    critical = [event for event in events if event.category == CATEGORY_CRITICAL]
    daily = [event for event in events if event.category == CATEGORY_DAILY]
    operations = [event for event in events if event.category == CATEGORY_OPERATIONS]
    if critical:
        subject = f"[FortiOS Upgrade Intelligence] {len(critical)} nouvelle(s) CVE critique(s)"
    elif operations:
        subject = f"[FortiOS Upgrade Intelligence] {len(operations)} evenement(s) operationnel(s)"
    else:
        subject = f"[FortiOS Upgrade Intelligence] Resume quotidien ({len(daily)} changement(s))"

    lines: list[str] = []
    if critical:
        plural = "s" if len(critical) > 1 else ""
        verb = "ont" if len(critical) > 1 else "a"
        lines.append(
            f"{len(critical)} nouvelle{plural} CVE critique{plural} {verb} été détectée{plural}."
        )
        lines.append("")
        lines.extend(_format_event_lines(critical))
        lines.append("")

    other = daily + operations
    if other:
        lines.append("Autres événements :" if critical else "Événements détectés :")
        lines.extend(_format_event_lines(other))
        lines.append("")

    lines.append(f"Application : {app_url}")
    lines.append(f"Collecte : {run_timestamp}")
    text_body = "\n".join(lines)
    html_body = (
        "<!doctype html><html><body><pre style='font-family:Arial,sans-serif;white-space:pre-wrap'>"
        f"{html.escape(text_body)}</pre></body></html>"
    )
    if appearance is not None:
        text_body, html_body = _apply_email_appearance(
            text_body, html_body, appearance
        )
    return subject, text_body, html_body


EMAIL_PREVIEW_SCENARIOS = frozenset({"single", "multiple", "multi-product"})


def build_email_preview_events(scenario: str) -> list[NotificationEvent]:
    """Build explicit, synthetic CVE fixtures in memory for the admin preview only."""
    if not isinstance(scenario, str) or scenario not in EMAIL_PREVIEW_SCENARIOS:
        raise ValueError("Scénario d'aperçu invalide.")

    fortios_branches = [
        {"product": "fortigate-fortios", "branch": "7.0"},
        {"product": "fortigate-fortios", "branch": "7.2"},
    ]
    cve_one_affected = list(fortios_branches)
    if scenario == "multi-product":
        cve_one_affected.append({"product": "fortimanager", "branch": "7.4"})

    cves: list[dict[str, Any]] = [
        {
            "id": "CVE-2026-00001",
            "severity": "critical",
            "cvssScore": 9.8,
            "title": "Exemple fictif de vulnérabilité critique Fortinet.",
            "url": "https://www.fortiguard.com/psirt/CVE-2026-00001",
            "affected": cve_one_affected,
        }
    ]
    if scenario != "single":
        cves.extend(
            [
                {
                    "id": "CVE-2026-00002",
                    "severity": "high",
                    "cvssScore": 8.1,
                    "title": "Exemple fictif de vulnérabilité High Fortinet.",
                    "url": "https://www.fortiguard.com/psirt/CVE-2026-00002",
                    "affected": [
                        (
                            {
                                "product": "forticlient",
                                "models": ["windows"],
                                "branch": "7.4",
                            }
                            if scenario == "multi-product"
                            else {"product": "fortigate-fortios", "branch": "7.4"}
                        )
                    ],
                },
                {
                    "id": "CVE-2026-00003",
                    "severity": "high",
                    "cvssScore": 7.5,
                    "title": "Exemple fictif de vulnérabilité High multi-branche.",
                    "url": "https://www.fortiguard.com/psirt/CVE-2026-00003",
                    "affected": (
                        [
                            {"product": "fortianalyzer", "branch": "7.2"},
                            {"product": "fortigate-fortios", "branch": "7.6"},
                        ]
                        if scenario == "multi-product"
                        else [{"product": "fortigate-fortios", "branch": "7.6"}]
                    ),
                },
            ]
        )
    return derive_new_cve_events(cves)


def compose_email_preview(
    scenario: str,
    *,
    app_url: str,
    run_timestamp: str,
    appearance: EmailAppearance,
) -> dict[str, str]:
    """Render a synthetic scenario exclusively through the production email composer."""
    if not _is_valid_notify_timestamp(run_timestamp):
        raise ValueError("Horodatage d'aperçu invalide.")
    composed = compose_email(
        build_email_preview_events(scenario),
        app_url=app_url,
        run_timestamp=run_timestamp,
        appearance=appearance,
    )
    if composed is None:  # Defensive invariant: every supported scenario contains events.
        raise ValueError("Le scénario d'aperçu ne contient aucun événement.")
    subject, text_body, html_body = composed
    return {
        "scenario": scenario,
        "runTimestamp": run_timestamp,
        "subject": subject,
        "text": text_body,
        "html": html_body,
    }


def _trusted_app_origin(app_url: str) -> str:
    if not isinstance(app_url, str) or any(character in app_url for character in "\r\n"):
        raise ValueError("URL FortiUpgrade invalide.")
    parsed = urllib.parse.urlsplit(app_url.strip())
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.netloc != parsed.netloc.strip()
    ):
        raise ValueError("URL FortiUpgrade invalide.")
    try:
        if parsed.hostname is None or parsed.port is not None and not (0 < parsed.port <= 65535):
            raise ValueError("URL FortiUpgrade invalide.")
    except ValueError as error:
        raise ValueError("URL FortiUpgrade invalide.") from error
    return f"{parsed.scheme}://{parsed.netloc}"


def prepare_recovery_email_config(config: EmailConfig, recipient: str) -> EmailConfig:
    """Bind one verified account recipient and validate the complete delivery path."""
    if not isinstance(recipient, str) or not _EMAIL_ADDRESS_RE.fullmatch(recipient.strip()):
        raise ValueError("Destinataire de récupération invalide.")
    prepared = replace(config, smtp_to=(recipient.strip(),))
    _trusted_app_origin(prepared.app_url)
    if not prepared.is_complete():
        raise ValueError("Configuration SMTP de récupération incomplète.")
    return prepared


def compose_recovery_email(
    purpose: str,
    token: str,
    app_url: str,
    expires_at: str,
    *,
    appearance: EmailAppearance | None = None,
) -> dict[str, str]:
    """Render a recovery email using only the trusted app origin and a fixed path."""
    paths = {
        "verify_recovery_email": "/cert/verify-email",
        "password_reset": "/cert/reset-password",
    }
    if purpose not in paths or not isinstance(token, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{43,128}", token
    ):
        raise ValueError("Paramètres du message de récupération invalides.")
    if not _is_valid_notify_timestamp(expires_at):
        raise ValueError("Expiration du message de récupération invalide.")
    link = f"{_trusted_app_origin(app_url)}{paths[purpose]}?{urllib.parse.urlencode({'token': token})}"
    if purpose == "verify_recovery_email":
        subject = "[FortiUpgrade] Vérifiez votre adresse de récupération"
        action = "vérifier votre adresse email de récupération"
    else:
        subject = "[FortiUpgrade] Réinitialisez votre mot de passe"
        action = "réinitialiser votre mot de passe"
    text_body = (
        "Une demande a été reçue pour "
        f"{action}.\n\n"
        f"Ouvrez ce lien dans les {30 if purpose == 'verify_recovery_email' else 15} prochaines minutes :\n"
        f"{link}\n\n"
        "Si vous n'êtes pas à l'origine de cette demande, ignorez cet email."
    )
    html_body = (
        "<!doctype html><html><body style='margin:0;padding:24px;background:#f8fafc;"
        "font-family:Arial,sans-serif;color:#101828'>"
        f"<h1 style='font-size:22px'>{html.escape(subject)}</h1>"
        f"<p>Une demande a été reçue pour {html.escape(action)}.</p>"
        f"<p><a href='{html.escape(link, quote=True)}' "
        "style='display:inline-block;padding:10px 14px;background:#175cd3;color:#fff;"
        "text-decoration:none;border-radius:6px'>Continuer</a></p>"
        f"<p>Ce lien expire le {html.escape(expires_at)}.</p>"
        "<p>Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.</p>"
        "</body></html>"
    )
    if appearance is not None:
        text_body, html_body = _apply_email_appearance(
            text_body, html_body, appearance
        )
    return {
        "purpose": purpose,
        "subject": subject,
        "text": text_body,
        "html": html_body,
        "link": link,
        "expiresAt": expires_at,
    }


def compose_account_recovery_email(
    purpose: str,
    token: str,
    app_url: str,
    expires_at: str,
    *,
    appearance: EmailAppearance | None = None,
) -> dict[str, str]:
    return compose_recovery_email(
        purpose,
        token,
        app_url,
        expires_at,
        appearance=appearance,
    )


@dataclass(frozen=True)
class SmtpResult:
    sent: bool
    message: str
    checks: tuple[str, ...] = ()
    error_code: str = ""
    retryable: bool = True
    retry_after_seconds: int | None = None
    transport: str = EMAIL_TRANSPORT_SMTP
    provider_status: int | None = None
    # HTTP 202 means Microsoft Graph accepted the request; it does not confirm final mailbox
    # delivery. SMTP's successful hand-off is also represented here as best-effort acceptance.
    delivery_confirmed: bool = False


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never follow identity-provider or Graph redirects with a bearer/secret-bearing request."""

    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


_GRAPH_OPENER = urllib.request.build_opener(_NoRedirectHandler)


def _graph_urlopen(request: urllib.request.Request, *, timeout: int) -> Any:
    return _GRAPH_OPENER.open(request, timeout=timeout)


def _aadsts_hint(error: urllib.error.HTTPError) -> str | None:
    """Return only a whitelisted AADSTS classification, never provider text."""
    try:
        raw = error.read(16 * 1024).decode("utf-8", errors="replace")
        payload = json.loads(raw)
        candidates = (
            payload.get("error_codes", []) if isinstance(payload, dict) else []
        )
        for candidate in candidates:
            hint = _AADSTS_HINTS.get(f"AADSTS{candidate}")
            if hint:
                return hint
        message = payload.get("error_description", "") if isinstance(payload, dict) else ""
        match = re.search(r"AADSTS\d{4,6}", message)
        return _AADSTS_HINTS.get(match.group(0)) if match else None
    except (OSError, UnicodeError, ValueError, AttributeError, TypeError):
        return None


def _retry_after_seconds(headers: Any) -> int | None:
    value = ""
    if headers is not None:
        try:
            value = str(headers.get("Retry-After", "")).strip()
        except (AttributeError, TypeError):
            value = ""
    if not value:
        return None
    try:
        seconds = int(value)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(value)
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=dt.UTC)
            seconds = int((retry_at - dt.datetime.now(dt.UTC)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return None
    return max(0, seconds)


def _graph_http_result(
    status: int, *, stage: str, headers: Any = None, message_hint: str | None = None
) -> SmtpResult:
    retry_after = _retry_after_seconds(headers)
    if stage == "token":
        if status in (400, 401):
            return SmtpResult(
                False,
                message_hint
                or "Jeton Microsoft 365 refusé : vérifiez le tenant, le client et le secret.",
                error_code="microsoft365_token_invalid",
                retryable=False,
                transport=EMAIL_TRANSPORT_MICROSOFT365,
                provider_status=status,
            )
        if status == 403:
            return SmtpResult(
                False,
                "Authentification Microsoft 365 refusée.",
                error_code="microsoft365_token_forbidden",
                retryable=False,
                transport=EMAIL_TRANSPORT_MICROSOFT365,
                provider_status=status,
            )
    elif status == 401:
        return SmtpResult(
            False,
            "Jeton Microsoft 365 non autorisé.",
            error_code="microsoft365_unauthorized",
            retryable=False,
            transport=EMAIL_TRANSPORT_MICROSOFT365,
            provider_status=status,
        )
    elif status == 403:
        return SmtpResult(
            False,
            "Permission Microsoft 365 refusée pour cette boîte.",
            error_code="microsoft365_forbidden",
            retryable=False,
            transport=EMAIL_TRANSPORT_MICROSOFT365,
            provider_status=status,
        )
    elif status == 404:
        return SmtpResult(
            False,
            "Boîte expéditrice Microsoft 365 introuvable.",
            error_code="microsoft365_sender_not_found",
            retryable=False,
            transport=EMAIL_TRANSPORT_MICROSOFT365,
            provider_status=status,
        )
    if status == 429:
        return SmtpResult(
            False,
            "Microsoft Graph limite temporairement les envois.",
            error_code="microsoft365_throttled",
            retryable=True,
            retry_after_seconds=retry_after,
            transport=EMAIL_TRANSPORT_MICROSOFT365,
            provider_status=status,
        )
    if status >= 500:
        return SmtpResult(
            False,
            "Microsoft Graph est temporairement indisponible.",
            error_code="microsoft365_server_error",
            retryable=True,
            retry_after_seconds=retry_after,
            transport=EMAIL_TRANSPORT_MICROSOFT365,
            provider_status=status,
        )
    if stage == "token":
        return SmtpResult(
            False,
            "Authentification Microsoft 365 impossible.",
            error_code="microsoft365_token_error",
            retryable=False,
            transport=EMAIL_TRANSPORT_MICROSOFT365,
            provider_status=status,
        )
    return SmtpResult(
        False,
        "Requête Microsoft Graph refusée.",
        error_code="microsoft365_request_rejected",
        retryable=False,
        transport=EMAIL_TRANSPORT_MICROSOFT365,
        provider_status=status,
    )


def _graph_exception_result(error: BaseException, *, stage: str) -> SmtpResult:
    if isinstance(error, urllib.error.HTTPError):
        return _graph_http_result(
            error.code,
            stage=stage,
            headers=error.headers,
            message_hint=_aadsts_hint(error) if stage == "token" else None,
        )
    if isinstance(error, TimeoutError) or (
        isinstance(error, urllib.error.URLError)
        and isinstance(error.reason, TimeoutError)
    ):
        return SmtpResult(
            False,
            "Connexion Microsoft Graph expirée." if stage == "delivery" else "Authentification Microsoft 365 expirée.",
            error_code="microsoft365_timeout",
            retryable=True,
            transport=EMAIL_TRANSPORT_MICROSOFT365,
        )
    if isinstance(error, urllib.error.URLError):
        return SmtpResult(
            False,
            "Connexion Microsoft Graph impossible.",
            error_code="microsoft365_connection_error",
            retryable=True,
            transport=EMAIL_TRANSPORT_MICROSOFT365,
        )
    if isinstance(error, OSError):
        return SmtpResult(
            False,
            "Connexion Microsoft Graph impossible.",
            error_code="microsoft365_connection_error",
            retryable=True,
            transport=EMAIL_TRANSPORT_MICROSOFT365,
        )
    return SmtpResult(
        False,
        "Échec de l'authentification Microsoft 365."
        if stage == "token"
        else "Envoi Microsoft Graph impossible.",
        error_code="microsoft365_token_error" if stage == "token" else "microsoft365_send_error",
        retryable=stage != "token",
        transport=EMAIL_TRANSPORT_MICROSOFT365,
    )


def _log_graph_result(stage: str, result: SmtpResult) -> None:
    """Emit an operationally useful Graph outcome without provider bodies, tokens, or secrets."""
    code = result.error_code if re.fullmatch(r"[a-z0-9_]{1,80}", result.error_code or "") else "normalized_error"
    status = str(result.provider_status) if isinstance(result.provider_status, int) else "none"
    retry_after = (
        str(result.retry_after_seconds)
        if isinstance(result.retry_after_seconds, int)
        else "none"
    )
    outcome = "accepted" if result.sent else "failed"
    sys.stderr.write(
        "Notification email: transport=microsoft365 provider=microsoft_graph "
        f"stage={stage}, success={str(result.sent).lower()}, outcome={outcome}, code={code}, status={status}, "
        f"retryable={str(result.retryable).lower()}, retry_after={retry_after}.\n"
    )


def _send_microsoft365_email(
    config: EmailConfig,
    subject: str,
    text_body: str,
    html_body: str | None,
    *,
    checks: list[str],
) -> SmtpResult:
    token_endpoint = MICROSOFT365_TOKEN_ENDPOINT.format(
        tenant=urllib.parse.quote(config.graph_tenant_id, safe="")
    )
    token_request = urllib.request.Request(
        token_endpoint,
        data=urllib.parse.urlencode(
            {
                "client_id": config.graph_client_id,
                "client_secret": config.graph_client_secret,
                "scope": MICROSOFT365_GRAPH_SCOPE,
                "grant_type": "client_credentials",
            }
        ).encode("ascii"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with _graph_urlopen(token_request, timeout=config.smtp_timeout) as response:
            token_payload = json.loads(response.read(64 * 1024).decode("utf-8"))
            access_token = token_payload.get("access_token") if isinstance(token_payload, dict) else None
            if not isinstance(access_token, str) or not access_token:
                result = SmtpResult(
                    False,
                    "Jeton Microsoft 365 invalide ou absent.",
                    error_code="microsoft365_token_invalid",
                    retryable=False,
                    transport=EMAIL_TRANSPORT_MICROSOFT365,
                )
                _log_graph_result("token", result)
                return result
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        OSError,
        TimeoutError,
        ValueError,
        UnicodeError,
        TypeError,
        AttributeError,
    ) as error:
        result = _graph_exception_result(error, stage="token")
        _log_graph_result("token", result)
        return result
    token_result = SmtpResult(
        True,
        "Jeton Microsoft 365 obtenu.",
        transport=EMAIL_TRANSPORT_MICROSOFT365,
    )
    _log_graph_result("token", token_result)
    checks.extend(("Client credentials Microsoft 365", "Jeton Microsoft 365 obtenu"))

    endpoint = MICROSOFT365_SENDMAIL_ENDPOINT.format(
        sender=urllib.parse.quote(config.mailbox_identity, safe="")
    )
    # Microsoft Graph sendMail uses JSON (body.contentType / body.content), never a pre-encoded
    # MIME/quoted-printable representation. We send the renderer's clean UTF-8 HTML directly and
    # attach any inline images (referenced by cid: in the HTML) as inline file attachments, so
    # there is no MIME/QP confusion on this transport.
    body_content_type = "HTML" if html_body else "Text"
    body_content = html_body if html_body else text_body
    message_payload: dict[str, Any] = {
        "subject": subject,
        "body": {"contentType": body_content_type, "content": body_content},
        "toRecipients": [
            {"emailAddress": {"address": address}} for address in config.smtp_to
        ],
    }
    attachments: list[dict[str, Any]] = []
    if html_body and "cid:" in html_body:
        for image in fortios_email_render.load_inline_images():
            attachments.append(
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "contentId": image.content_id,
                    "contentType": image.content_type,
                    "name": image.filename,
                    "contentBytes": base64.b64encode(image.content_bytes).decode(
                        "ascii"
                    ),
                    "isInline": True,
                }
            )
    if attachments:
        message_payload["attachments"] = attachments
    graph_request = urllib.request.Request(
        endpoint,
        data=json.dumps({"message": message_payload}, ensure_ascii=False).encode(
            "utf-8"
        ),
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with _graph_urlopen(graph_request, timeout=config.smtp_timeout) as response:
            status = response.getcode()
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        OSError,
        TimeoutError,
        ValueError,
        UnicodeError,
        TypeError,
        AttributeError,
    ) as error:
        result = _graph_exception_result(error, stage="delivery")
        _log_graph_result("delivery", result)
        return result
    if status != 202:
        result = _graph_http_result(status, stage="delivery")
        _log_graph_result("delivery", result)
        return result
    checks.extend(
        (
            "Message remis à Microsoft Graph",
            "HTTP 202 accepté (livraison finale non confirmée)",
        )
    )
    result = SmtpResult(
        True,
        "Email accepté par Microsoft Graph (HTTP 202 ; livraison finale non confirmée).",
        tuple(checks),
        transport=EMAIL_TRANSPORT_MICROSOFT365,
        provider_status=202,
        delivery_confirmed=False,
    )
    _log_graph_result("delivery", result)
    return result


def _build_smtp_message(
    config: EmailConfig,
    subject: str,
    text_body: str,
    html_body: str | None,
) -> Any:
    """Build a clean UTF-8 multipart message for SMTP.

    Structure: multipart/alternative -> [ text/plain, multipart/related -> [ text/html, inline
    images ] ]. Every text part uses ``Content-Transfer-Encoding: base64`` (never quoted-printable,
    whose ``=`` soft line breaks were the source of the historical ``For=iUpgrade``/``=C3=A9``
    corruption) and a ``policy.SMTP`` (CRLF line endings). Images referenced by ``cid:`` in the
    HTML are attached inline with the matching Content-ID.
    """
    message = EmailMessage(policy=SMTP_POLICY)
    message["Subject"] = subject
    message["From"] = config.smtp_from
    message["To"] = ", ".join(config.smtp_to)
    message.make_alternative()

    plain = EmailMessage(policy=SMTP_POLICY)
    plain.set_content(text_body, subtype="plain", cte="base64")
    message.attach(plain)

    if html_body:
        related = EmailMessage(policy=SMTP_POLICY)
        related.set_content(html_body, subtype="html", cte="base64")
        if "cid:" in html_body:
            for image in fortios_email_render.load_inline_images():
                maintype, subtype = image.content_type.split("/", 1)
                related.add_related(
                    image.content_bytes,
                    maintype=maintype,
                    subtype=subtype,
                    cid=image.content_id,
                )
        message.attach(related)
    return message


def send_email_result(
    config: EmailConfig,
    subject: str,
    text_body: str,
    html_body: str | None = None,
    *,
    force: bool = False,
) -> SmtpResult:
    """Never raises -- every failure mode (bad config, a malformed header, DNS, connection
    refused, STARTTLS, auth, timeout) is caught, logged without the password, and reported as a
    plain False so a broken mailbox can never break the actual data collection.

    Message construction happens INSIDE the protected block on purpose:
    EmailMessage.__setitem__ raises ValueError on a header value containing a stray newline
    (e.g. a fat-fingered FORTIOS_SMTP_FROM, or a "To" header injection attempt) -- building the
    message before the try block used to let exactly that kind of ValueError escape uncaught.
    """
    if not config.enabled and not force:
        result = SmtpResult(False, "Notifications désactivées.", transport=config.transport)
        if config.transport == EMAIL_TRANSPORT_MICROSOFT365:
            _log_graph_result("config", result)
        return result
    if not config.is_complete():
        transport_label = (
            "Microsoft 365" if config.transport == EMAIL_TRANSPORT_MICROSOFT365 else "SMTP"
        )
        sys.stderr.write(
            "Notification email ignorée : configuration "
            f"{transport_label} incomplète ou invalide.\n"
        )
        result = SmtpResult(
            False,
            f"Configuration {transport_label} incomplète.",
            error_code=(
                "microsoft365_incomplete"
                if config.transport == EMAIL_TRANSPORT_MICROSOFT365
                else "smtp_incomplete"
                if config.transport == EMAIL_TRANSPORT_SMTP
                else "invalid_transport"
            ),
            retryable=False,
            transport=config.transport,
        )
        if config.transport == EMAIL_TRANSPORT_MICROSOFT365:
            _log_graph_result("config", result)
        return result

    checks: list[str] = []
    stage = "message"
    security = config.smtp_security or (
        "starttls" if config.smtp_starttls else "none"
    )
    try:
        if config.transport == EMAIL_TRANSPORT_MICROSOFT365:
            return _send_microsoft365_email(
                config, subject, text_body, html_body, checks=checks
            )

        message = _build_smtp_message(
            config,
            subject,
            text_body,
            html_body,
        )

        stage = "connection"
        if security == "tls":
            smtp_client = smtplib.SMTP_SSL(
                config.smtp_host,
                config.smtp_port,
                timeout=config.smtp_timeout,
                context=ssl.create_default_context(),
            )
        else:
            smtp_client = smtplib.SMTP(
                config.smtp_host, config.smtp_port, timeout=config.smtp_timeout
            )
        checks.extend(("Résolution DNS", "Connexion TCP"))
        with smtp_client as client:
            if security == "tls":
                checks.append("TLS implicite")
            elif security == "starttls":
                stage = "starttls"
                client.starttls(context=ssl.create_default_context())
                checks.append("STARTTLS")
            else:
                checks.append("Sans chiffrement explicitement autorisé")
            if config.smtp_username:
                stage = "authentication"
                client.login(config.smtp_username, config.smtp_password)
                checks.append("Authentification")
            else:
                checks.append("Authentification non requise")
            stage = "delivery"
            client.send_message(message)
            checks.extend(
                (
                    "Expéditeur et destinataire acceptés",
                    "Message accepté par le serveur SMTP",
                )
            )
        return SmtpResult(
            True,
            "Email envoyé.",
            tuple(checks),
            transport=EMAIL_TRANSPORT_SMTP,
            delivery_confirmed=False,
        )
    except (
        smtplib.SMTPException,
        ConnectionError,
        TimeoutError,
        OSError,
        ValueError,
        TypeError,
        AttributeError,
    ) as error:
        if config.transport == EMAIL_TRANSPORT_MICROSOFT365:
            result = SmtpResult(
                False,
                "Message Microsoft 365 invalide.",
                tuple(checks),
                error_code="microsoft365_message_error",
                retryable=False,
                transport=EMAIL_TRANSPORT_MICROSOFT365,
            )
            _log_graph_result("message", result)
            return result
        sys.stderr.write(
            "Échec de l'envoi de l'email de notification : "
            f"étape={stage}, type={type(error).__name__}.\n"
        )
        if isinstance(error, smtplib.SMTPAuthenticationError):
            message = "Authentification SMTP refusée."
        elif isinstance(error, smtplib.SMTPSenderRefused):
            message = "Expéditeur refusé par le serveur SMTP."
        elif isinstance(error, smtplib.SMTPRecipientsRefused):
            message = "Destinataire refusé par le serveur SMTP."
        elif stage == "starttls":
            message = "Négociation STARTTLS impossible."
        elif isinstance(error, ssl.SSLError):
            message = "Certificat TLS SMTP invalide."
        elif isinstance(error, TimeoutError):
            message = "Connexion SMTP expirée."
        elif stage == "connection":
            message = "Connexion SMTP impossible."
        else:
            message = "Envoi SMTP impossible."
        permanent = isinstance(
            error,
            (
                smtplib.SMTPAuthenticationError,
                smtplib.SMTPSenderRefused,
                smtplib.SMTPRecipientsRefused,
            ),
        )
        return SmtpResult(
            False,
            message,
            tuple(checks),
            error_code=f"smtp_{stage}",
            retryable=not permanent,
            transport=EMAIL_TRANSPORT_SMTP,
        )


def send_email(
    config: EmailConfig,
    subject: str,
    text_body: str,
    html_body: str | None = None,
) -> bool:
    return send_email_result(config, subject, text_body, html_body).sent


def deliver_email_result(
    config: EmailConfig,
    subject: str,
    text_body: str,
    html_body: str | None = None,
) -> SmtpResult:
    """Deliver from collectors while retaining the legacy SMTP seam used by integrations.

    Microsoft 365 uses the structured result directly so retry metadata is durable. SMTP keeps
    the historical ``send_email`` boolean seam, which preserves existing tests and embedders that
    replace that function for a local relay or dry run.
    """
    transport = config.transport
    if isinstance(transport, str) and transport not in {
        EMAIL_TRANSPORT_SMTP,
        EMAIL_TRANSPORT_MICROSOFT365,
    }:
        return send_email_result(config, subject, text_body, html_body)
    if transport == EMAIL_TRANSPORT_MICROSOFT365:
        return send_email_result(config, subject, text_body, html_body)
    sent = send_email(config, subject, text_body, html_body)
    return SmtpResult(
        sent,
        "Email envoyé." if sent else "Envoi SMTP impossible.",
        error_code="" if sent else "smtp_delivery",
        retryable=not sent,
        transport=EMAIL_TRANSPORT_SMTP,
    )


def _config_for_test_recipient(config: EmailConfig, recipient: str) -> EmailConfig | None:
    if not isinstance(recipient, str):
        return None
    normalized_recipient = recipient.strip()
    if not _EMAIL_ADDRESS_RE.fullmatch(normalized_recipient):
        return None
    return replace(config, smtp_to=(normalized_recipient,))


def send_email_preview_result(
    config: EmailConfig,
    preview: dict[str, str],
    *,
    recipient: str,
) -> SmtpResult:
    preview_config = _config_for_test_recipient(config, recipient)
    if preview_config is None:
        return SmtpResult(
            False,
            "Destinataire de test invalide.",
            error_code="invalid_test_recipient",
            retryable=False,
            transport=config.transport,
        )
    return send_email_result(
        preview_config,
        preview["subject"],
        preview["text"],
        preview["html"],
        force=True,
    )


def send_test_email_result(
    config: EmailConfig,
    *,
    recipient: str | None = None,
    appearance: EmailAppearance | None = None,
) -> SmtpResult:
    if recipient is not None:
        recipient_config = _config_for_test_recipient(config, recipient)
        if recipient_config is None:
            return SmtpResult(
                False,
                "Destinataire de test invalide.",
                error_code="invalid_test_recipient",
                retryable=False,
                transport=config.transport,
            )
        config = recipient_config
    appearance = appearance or _default_email_appearance()
    transport_label = (
        "Microsoft 365"
        if config.transport == EMAIL_TRANSPORT_MICROSOFT365
        else "SMTP"
    )
    subject = f"[FortiUpgrade][TEST] Validation {transport_label}"
    text_parts = [appearance.display_name]
    if appearance.introduction:
        text_parts.extend(("", appearance.introduction))
    text_parts.extend(
        (
            "",
            "Ceci est un email de test envoyé depuis l’administration FortiUpgrade.",
            "Il ne correspond à aucune alerte de sécurité.",
            "",
            f"Application : {config.app_url}",
        )
    )
    if appearance.signature:
        text_parts.extend(("", appearance.signature))
    body = "\n".join(text_parts) + "\n"
    html_parts = [
        "<!doctype html><html><body>",
        f"<h1>{html.escape(appearance.display_name)}</h1>",
    ]
    if appearance.introduction:
        html_parts.append(f"<p>{html.escape(appearance.introduction)}</p>")
    html_parts.extend(
        (
            "<p><strong>Email de test FortiUpgrade.</strong><br>",
            "Il ne correspond à aucune alerte de sécurité.</p>",
            f"<p>Application : {html.escape(config.app_url)}</p>",
        )
    )
    if appearance.signature:
        html_parts.append(f"<p>{html.escape(appearance.signature)}</p>")
    html_parts.append("</body></html>")
    result = send_email_result(
        config,
        subject,
        body,
        "".join(html_parts),
        force=True,
    )
    if result.sent:
        return SmtpResult(
            True,
            result.message
            if result.transport == EMAIL_TRANSPORT_MICROSOFT365
            else "Email de test envoyé.",
            result.checks,
            transport=result.transport,
            provider_status=result.provider_status,
            delivery_confirmed=result.delivery_confirmed,
        )
    return result


def send_test_email(config: EmailConfig) -> bool:
    result = send_test_email_result(config)
    if result.sent:
        print(f"Email de test envoyé à {', '.join(config.smtp_to)}.")
    else:
        print(result.message, file=sys.stderr)
    return result.sent
