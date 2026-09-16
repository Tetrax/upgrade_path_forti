#!/usr/bin/env python3
"""Read a Trivy container-image report: presentation for CI, strict validation for ingestion.

Two responsibilities share this module because they share one format:

- ``render_summary()`` / ``main()`` present whatever the report holds, tolerantly, for the GitHub
  Actions step summary. A scan summary must never fail a run.
- ``validate_container_report()`` is the STRICT gate used before a report can influence
  notification state or an email. A report is untrusted input there: bounded size, checked types,
  whitelisted severities, validated URLs, bounded strings — and a report that violates any of it is
  refused AS A WHOLE, never partially ingested. A partially ingested report would corrupt the
  baseline (a finding silently dropped now would read as "new" later or as "fixed" incorrectly),
  which is worse than an explicitly refused scan.

The two must not be confused: tolerance is right for a human-readable summary, and wrong for
anything that decides whether an alert is sent.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# Bounded presentation: a summary is read by a human in the Actions UI, so a report with
# thousands of rows must not produce a thousands-row table.
MAX_ROWS = 100
# Most severe first — the order operators triage in.
SEVERITY_ORDER = ("CRITICAL", "HIGH")
DEFAULT_REPORT_NAME = "trivy.json"

# --- Ingestion limits and shapes (a report is untrusted input) --------------------------------
MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_FINDINGS = 5000
MAX_IDENTIFIER_CHARS = 200
MAX_VERSION_CHARS = 120
MAX_TITLE_CHARS = 300
# Every severity the report may carry, lower-cased. `unknown` is accepted because Trivy does emit
# it for a vulnerability with no score; it simply never passes a configured threshold.
ALLOWED_SEVERITIES = ("critical", "high", "medium", "low", "unknown")
SCHEMA_VERSION_MIN = 2
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
# Package and image identifiers are rebuilt into a dedup key and into HTML: an explicit character
# class keeps a hostile or exotic value out of both.
_PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:@/~-]{0,199}$")
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/~-]{0,254}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:~-]{0,119}$")


@dataclass(frozen=True)
class Finding:
    cve: str
    package: str
    installed_version: str
    fixed_version: str
    severity: str
    title: str


def load_report(path: Path) -> tuple[dict | None, list[Finding], str | None]:
    """Return ``(report, findings, unavailable_reason)``.

    ``unavailable_reason`` is a short, secret-free sentence the caller surfaces to the operator;
    ``report`` is the parsed document when there is one, so the caller does not read the file twice.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, [], f"aucun rapport produit ({path.name} absent)"
    except OSError as error:
        return None, [], f"rapport illisible ({type(error).__name__})"
    try:
        report = json.loads(raw)
    except ValueError:
        return None, [], "rapport illisible (JSON invalide)"
    if not isinstance(report, dict):
        return None, [], "rapport illisible (objet JSON attendu)"
    return report, _findings(report), None


def _findings(report: dict) -> list[Finding]:
    """Flatten ``Results[].Vulnerabilities[]``, tolerating any missing or misshapen field."""
    findings: list[Finding] = []
    for result in report.get("Results") or []:
        if not isinstance(result, dict):
            continue
        for item in result.get("Vulnerabilities") or []:
            if not isinstance(item, dict):
                continue
            findings.append(
                Finding(
                    cve=str(item.get("VulnerabilityID") or "?"),
                    package=str(item.get("PkgName") or "?"),
                    installed_version=str(item.get("InstalledVersion") or "—"),
                    fixed_version=str(item.get("FixedVersion") or "—"),
                    severity=str(item.get("Severity") or "UNKNOWN").upper(),
                    title=" ".join(str(item.get("Title") or "").split()),
                )
            )
    findings.sort(key=lambda finding: (severity_rank(finding.severity), finding.package, finding.cve))
    return findings


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(SEVERITY_ORDER)


def counts(findings: list[Finding]) -> dict[str, int]:
    return {severity: sum(1 for f in findings if f.severity == severity) for severity in SEVERITY_ORDER}


def _artifact_name(report: dict) -> str:
    return str(report.get("ArtifactName") or "image analysée")


def scan_context(report: dict) -> tuple[str, str]:
    """``(image, système)`` — the OS is what most fixes on a pinned base image come from."""
    metadata = report.get("Metadata") if isinstance(report.get("Metadata"), dict) else {}
    os_info = metadata.get("OS") if isinstance(metadata.get("OS"), dict) else {}
    family = str(os_info.get("Family") or "").strip()
    name = str(os_info.get("Name") or "").strip()
    system = " ".join(part for part in (family, name) if part) or "système non précisé"
    return _artifact_name(report), system


class ContainerReportError(ValueError):
    """The ingested report cannot be trusted. Refused as a whole, never partially ingested."""


@dataclass(frozen=True)
class ContainerFinding:
    """One actionable vulnerability of the image, as the ingestion keeps it."""

    cve: str
    package: str
    severity: str
    installed_version: str
    fixed_version: str
    title: str
    advisory_url: str

    @property
    def dedup_key(self) -> str:
        """Stable identity: CVE + package, deliberately WITHOUT the installed version.

        A rebuilt base image keeps the same CVE on the same package while the installed version
        moves (`u1` -> `u2`); including it would make every already-known CVE look brand new at
        each rebuild — exactly the flood this system exists to prevent. `FixedVersion` is content,
        refreshed in the state without creating an event.
        """
        return f"trivy|cve|{self.cve}|{self.package}"

    @property
    def severity_dedup_key_prefix(self) -> str:
        return f"trivy-severity|{self.cve}|{self.package}"


@dataclass(frozen=True)
class ContainerScan:
    """A validated report: the image it describes, and where it came from."""

    image: str
    commit: str
    scanned_at: str
    findings: tuple[ContainerFinding, ...]

    def counts(self) -> dict[str, int]:
        return {
            severity: sum(1 for finding in self.findings if finding.severity == severity)
            for severity in ALLOWED_SEVERITIES
        }


def load_container_report(path: Path) -> Any:
    """Read the report with a hard size cap before any parsing happens."""
    try:
        size = path.stat().st_size
    except FileNotFoundError as error:
        raise ContainerReportError(f"Rapport Trivy refusé : fichier absent ({path.name}).") from error
    except OSError as error:
        raise ContainerReportError(
            f"Rapport Trivy refusé : fichier illisible ({type(error).__name__})."
        ) from error
    if size > MAX_REPORT_BYTES:
        raise ContainerReportError(
            f"Rapport Trivy refusé : taille {size} octets au-delà de la limite "
            f"({MAX_REPORT_BYTES} octets)."
        )
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise ContainerReportError(
            f"Rapport Trivy refusé : JSON illisible ({type(error).__name__})."
        ) from error


def _text(
    value: Any,
    *,
    where: str,
    limit: int,
    pattern: re.Pattern[str] | None = None,
    truncate: bool = False,
) -> str:
    """A bounded, non-empty string, optionally constrained to a safe character class.

    Identity and state-carrying fields (CVE, package, version) are REFUSED when they exceed the
    limit: truncating them would build a baseline on a mangled identifier. Descriptive text is
    truncated instead (``truncate=True``), because a future Trivy that writes a longer advisory
    title must not be able to disable the whole control.

    The offending VALUE is never echoed into the error: a refused report is untrusted, and its
    content could reach a log line or the administration UI.
    """
    if not isinstance(value, str):
        raise ContainerReportError(f"Rapport Trivy refusé : {where} doit être une chaîne.")
    if not value:
        raise ContainerReportError(f"Rapport Trivy refusé : {where} est vide.")
    if len(value) > limit:
        if truncate:
            value = value[:limit]
        else:
            raise ContainerReportError(
                f"Rapport Trivy refusé : {where} dépasse {limit} caractères."
            )
    if pattern is not None and not pattern.fullmatch(value):
        raise ContainerReportError(
            f"Rapport Trivy refusé : {where} contient des caractères non autorisés."
        )
    return value


def _optional_text(
    value: Any,
    *,
    where: str,
    limit: int,
    pattern: re.Pattern[str] | None = None,
    truncate: bool = False,
) -> str:
    if value is None or value == "":
        return ""
    return _text(value, where=where, limit=limit, pattern=pattern, truncate=truncate)


def _advisory_url(value: Any) -> str:
    """An advisory link is only kept when it is a plain https URL.

    A link is decorative: an unusable one is dropped rather than failing the whole scan, but it is
    never rendered as-is — the renderer must never be handed an unvalidated `href`.
    """
    if not isinstance(value, str) or not value:
        return ""
    if len(value) > 500:
        return ""
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        return ""
    if any(character in value for character in ("\n", "\r", "\t", "<", ">", '"', "'")):
        return ""
    return value


def _scan_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ContainerReportError("Rapport Trivy refusé : CreatedAt manquant.")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ContainerReportError("Rapport Trivy refusé : CreatedAt illisible.") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ContainerReportError("Rapport Trivy refusé : CreatedAt sans fuseau horaire.")
    # Normalised to whole seconds: the engine compares and persists these timestamps, and Trivy
    # emits nanoseconds, which `fromisoformat` would silently truncate per platform.
    return parsed.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _finding(payload: Any, *, where: str) -> ContainerFinding:
    if not isinstance(payload, dict):
        raise ContainerReportError(f"Rapport Trivy refusé : {where} doit être un objet.")
    severity = payload.get("Severity")
    if not isinstance(severity, str) or severity.strip().lower() not in ALLOWED_SEVERITIES:
        raise ContainerReportError(f"Rapport Trivy refusé : {where}.Severity hors liste.")
    return ContainerFinding(
        cve=_text(
            payload.get("VulnerabilityID"),
            where=f"{where}.VulnerabilityID",
            limit=MAX_IDENTIFIER_CHARS,
            pattern=_CVE_RE,
        ),
        package=_text(
            payload.get("PkgName"),
            where=f"{where}.PkgName",
            limit=MAX_IDENTIFIER_CHARS,
            pattern=_PACKAGE_RE,
        ),
        severity=severity.strip().lower(),
        installed_version=_optional_text(
            payload.get("InstalledVersion"),
            where=f"{where}.InstalledVersion",
            limit=MAX_VERSION_CHARS,
            pattern=_VERSION_RE,
        ),
        fixed_version=_optional_text(
            payload.get("FixedVersion"),
            where=f"{where}.FixedVersion",
            limit=MAX_VERSION_CHARS,
            pattern=_VERSION_RE,
        ),
        # Descriptive, not identity-carrying: bounded by truncation (see _text).
        title=" ".join(
            _optional_text(
                payload.get("Title"),
                where=f"{where}.Title",
                limit=MAX_TITLE_CHARS,
                truncate=True,
            ).split()
        ),
        advisory_url=_advisory_url(payload.get("PrimaryURL")),
    )


def validate_container_report(payload: Any, *, commit: Any) -> ContainerScan:
    """Strictly validate a report and flatten it into findings. Raises ContainerReportError.

    ``commit`` comes from the ingestion context: the report itself carries no Git SHA (verified on
    the real artifact), so the caller must supply it, and an unusable one refuses the report —
    provenance is part of what makes the alert trustworthy.
    """
    if not isinstance(payload, dict):
        raise ContainerReportError("Rapport Trivy refusé : document JSON attendu.")
    schema = payload.get("SchemaVersion")
    if not isinstance(schema, int) or isinstance(schema, bool) or schema < SCHEMA_VERSION_MIN:
        raise ContainerReportError(
            f"Rapport Trivy refusé : SchemaVersion attendu >= {SCHEMA_VERSION_MIN}."
        )
    if payload.get("ArtifactType") != "container_image":
        raise ContainerReportError("Rapport Trivy refusé : ArtifactType attendu « container_image ».")
    image = _text(
        payload.get("ArtifactName"), where="ArtifactName", limit=255, pattern=_IMAGE_RE
    )
    scanned_at = _scan_timestamp(payload.get("CreatedAt"))
    normalised_commit = _text(
        commit, where="commit (contexte d'ingestion)", limit=40, pattern=_COMMIT_RE
    )

    results = payload.get("Results")
    if not isinstance(results, list):
        raise ContainerReportError("Rapport Trivy refusé : Results doit être une liste.")

    findings: list[ContainerFinding] = []
    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            raise ContainerReportError(
                f"Rapport Trivy refusé : Results[{result_index}] doit être un objet."
            )
        vulnerabilities = result.get("Vulnerabilities")
        # The real report writes `0` (not an empty list) for a result with no finding: both mean
        # "nothing here" and neither may be mistaken for a malformed document.
        if vulnerabilities in (None, 0, []):
            continue
        if not isinstance(vulnerabilities, list):
            raise ContainerReportError(
                f"Rapport Trivy refusé : Results[{result_index}].Vulnerabilities doit être une liste."
            )
        for finding_index, entry in enumerate(vulnerabilities):
            findings.append(
                _finding(
                    entry, where=f"Results[{result_index}].Vulnerabilities[{finding_index}]"
                )
            )

    if len(findings) > MAX_FINDINGS:
        raise ContainerReportError(
            f"Rapport Trivy refusé : {len(findings)} findings au-delà de la limite "
            f"({MAX_FINDINGS})."
        )

    # Deterministic order, so a re-ingested identical report produces an identical state: most
    # severe first, then package, then CVE.
    order = {severity: rank for rank, severity in enumerate(ALLOWED_SEVERITIES)}
    findings.sort(key=lambda f: (order[f.severity], f.package, f.cve))
    return ContainerScan(
        image=image,
        commit=normalised_commit,
        scanned_at=scanned_at,
        findings=tuple(findings),
    )


def parse_container_report(raw: bytes, *, commit: Any) -> ContainerScan:
    """Strictly validate the report's bytes — the single entry point for ingestion.

    Deliberately takes bytes, not a path: the caller verifies the download's checksum against the
    very bytes it hands over here. Reading the file twice would open a window where the checksummed
    content and the parsed content differ (the sync replaces the file atomically), and an alert
    built on an unverified report is worse than a refused one.
    """
    if len(raw) > MAX_REPORT_BYTES:
        raise ContainerReportError(
            f"Rapport Trivy refusé : taille {len(raw)} octets au-delà de la limite "
            f"({MAX_REPORT_BYTES} octets)."
        )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as error:
        raise ContainerReportError("Rapport Trivy refusé : encodage non UTF-8.") from error
    except ValueError as error:
        raise ContainerReportError("Rapport Trivy refusé : JSON invalide.") from error
    return validate_container_report(payload, commit=commit)


def ingest_container_report(path: Path, *, commit: Any) -> ContainerScan:
    """Read then strictly validate — convenience entry point for a report already on disk."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError as error:
        raise ContainerReportError(f"Rapport Trivy refusé : fichier absent ({path.name}).") from error
    except OSError as error:
        raise ContainerReportError(
            f"Rapport Trivy refusé : fichier illisible ({type(error).__name__})."
        ) from error
    return parse_container_report(raw, commit=commit)


def render_summary(
    findings: list[Finding], unavailable_reason: str | None, *, report: dict | None = None
) -> str:
    lines: list[str] = []

    if unavailable_reason is not None:
        lines.extend(
            [
                "## ⚠️ Sécurité de l'image Docker — rapport indisponible",
                "",
                f"Le contrôle Trivy n'a pas pu produire de rapport exploitable : {unavailable_reason}.",
                "",
                (
                    "**Ce job est informatif : il ne bloque pas la CI.** Le contrôle n'a donc pas "
                    "conclu — ce n'est PAS un « aucune vulnérabilité »."
                ),
                "",
            ]
        )
        return "\n".join(lines) + "\n"

    by_severity = counts(findings)
    if not findings:
        lines.extend(
            [
                "## ✅ Sécurité de l'image Docker — aucune vulnérabilité",
                "",
                (
                    "Aucune vulnérabilité **HIGH** ou **CRITICAL** corrigible n'a été détectée "
                    "(seuil `severity: HIGH,CRITICAL`, `ignore-unfixed: true`)."
                ),
                "",
            ]
        )
    else:
        lines.extend(
            [
                "## ⚠️ Sécurité de l'image Docker — vulnérabilités détectées — contrôle informatif",
                "",
                (
                    f"**{len(findings)} vulnérabilité{'s' if len(findings) > 1 else ''} corrigible"
                    f"{'s' if len(findings) > 1 else ''}** "
                    f"(CRITICAL **{by_severity['CRITICAL']}** · HIGH **{by_severity['HIGH']}**) — "
                    "toutes corrigibles (`ignore-unfixed: true`)."
                ),
                "",
                (
                    "**Ce job ne bloque pas la CI.** Les contrôles bloquants restent Ruff, les tests "
                    "unitaires, Playwright et la construction d'image. Le rapport JSON complet est "
                    "joint en artefact `trivy-report`."
                ),
                "",
            ]
        )

    if report is not None:
        image, system = scan_context(report)
        lines.extend([f"Image : `{image}` — système : `{system}`.", ""])

    if findings:
        shown = findings[:MAX_ROWS]
        lines.extend(
            [
                "| Sévérité | Package | CVE | Version installée | Version corrigée |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        lines.extend(
            f"| {f.severity} | `{f.package}` | {f.cve} | {f.installed_version} | {f.fixed_version} |"
            for f in shown
        )
        if len(findings) > len(shown):
            lines.extend(["", f"… et {len(findings) - len(shown)} autre(s) dans le rapport JSON."])
        lines.extend(
            [
                "",
                "<details><summary>Titres des vulnérabilités</summary>",
                "",
            ]
        )
        lines.extend(
            f"- **{f.cve}** (`{f.package}`) — {f.title or 'titre non fourni par le rapport'}"
            for f in shown
        )
        lines.extend(["", "</details>", ""])

    return "\n".join(lines) + "\n"


def render_annotations(
    findings: list[Finding], unavailable_reason: str | None, *, report: dict | None = None
) -> list[str]:
    """GitHub annotation commands for stdout — visible without failing the run."""
    if unavailable_reason is not None:
        return [
            (
                "::warning::Contrôle Trivy informatif : rapport indisponible — "
                f"{unavailable_reason}. Le run n'est pas bloqué."
            )
        ]
    if not findings:
        return []
    by_severity = counts(findings)
    summary = (
        f"{len(findings)} vulnérabilité(s) corrigible(s) : "
        f"{by_severity['CRITICAL']} CRITICAL, {by_severity['HIGH']} HIGH"
    )
    packages = sorted({finding.package for finding in findings})
    image = f" Image : {_artifact_name(report)}." if report is not None else ""
    return [
        "::warning title=Vulnérabilités de l'image (contrôle informatif)::"
        + f"{summary}. Packages : {', '.join(packages)}.{image} "
        + "Voir le résumé de l'étape et l'artefact trivy-report."
    ]


def parse_args(argv: list[str]) -> tuple[Path, Path | None]:
    report_path = Path(argv[1]) if len(argv) > 1 else Path(DEFAULT_REPORT_NAME)
    summary_file: Path | None = None
    if "--summary-file" in argv:
        index = argv.index("--summary-file")
        if index + 1 < len(argv):
            summary_file = Path(argv[index + 1])
    return report_path, summary_file


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv if argv is None else argv
    report_path, summary_file = parse_args(argv)
    report, findings, unavailable_reason = load_report(report_path)
    summary = render_summary(findings, unavailable_reason, report=report)
    if summary_file is not None:
        try:
            with summary_file.open("a", encoding="utf-8") as handle:
                handle.write(summary)
        except OSError as error:
            print(f"::warning::Impossible d'écrire le résumé d'étape ({type(error).__name__}).")
            print(summary, end="")
    else:
        print(summary, end="")
    for annotation in render_annotations(findings, unavailable_reason, report=report):
        print(annotation)
    # Informative by construction: reporting a finding is never a failed control.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
