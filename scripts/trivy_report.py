#!/usr/bin/env python3
"""Present a Trivy JSON report as a readable GitHub Actions summary.

The `security-scan` job runs Trivy with `format: json` and hands the report to this script,
which writes a Markdown summary to ``$GITHUB_STEP_SUMMARY`` and emits GitHub annotations on
stdout (annotations and the summary must therefore stay on separate streams: a ``::warning::``
line written into the summary file would be shown as literal text instead of an annotation).

The container image scan is INFORMATIVE: this script always exits 0 and never fails the run,
whatever the report contains — or omits. A missing or unreadable report is reported as such
(annotation + explicit summary line) rather than silently rendered as "no vulnerability", because
"the control did not run" and "the control found nothing" must never look alike.

The extraction below is deliberately TOLERANT: it presents whatever the report holds and says so
when something is missing. Validating a report before it can influence notification state or an
email is a DIFFERENT concern with different rules (a report is untrusted input there), and must
not reuse this tolerance.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

# Bounded presentation: a summary is read by a human in the Actions UI, so a report with
# thousands of rows must not produce a thousands-row table.
MAX_ROWS = 100
# Most severe first — the order operators triage in.
SEVERITY_ORDER = ("CRITICAL", "HIGH")
DEFAULT_REPORT_NAME = "trivy.json"


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
