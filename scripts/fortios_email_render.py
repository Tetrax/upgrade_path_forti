"""Rendering of FortiUpgrade notification emails — pure UTF-8 text/plain + HTML
with the SNS Security visual identity.

This module is deliberately free of any transport or persistent-state concern: it turns
NotificationEvent-like objects into (subject, text_body, html_body) plus the small set of
inline images the HTML references by Content-ID. ``scripts/fortios_notify.py`` owns transport
(SMTP multipart/related, Microsoft Graph JSON) and never mixes a pre-encoded MIME body back into
a renderer that already produced clean UTF-8.

Design constraints (Outlook desktop / Microsoft 365 first, then Gmail / Apple Mail / mobile):
- tables for layout, inline CSS only, no JS, no external CSS, no flex/grid dependency;
- all externally-sourced fields (CVE id, title, products, versions, URLs) are HTML-escaped;
- severity badges stay functional red/orange, never brand colors;
- critical information lives in real HTML text, never only inside an image (alt text + width/height).
"""

from __future__ import annotations

import base64
import datetime
import html
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# --- SNS Security palette ---------------------------------------------------
# Observed from the official site / logo: near-black anthracite, white, and a very
# pale SNS rose, with a slightly stronger rose reserved for accents.
SNS_BLACK = "#0B0B0D"
SNS_ANTHRACITE = "#141417"
SNS_ROSE_PALE = "#FED2F2"
SNS_ROSE = "#F4A8C9"
SNS_WHITE = "#FFFFFF"
SNS_GRAY_BORDER = "#E6E6EA"
SNS_GRAY_TEXT = "#6B6B73"
SNS_GRAY_BG = "#F7F7F8"

# Functional severity colors — used ONLY for severity, never as brand colors.
SEVERITY_CRITICAL_BG = "#B42318"
SEVERITY_CRITICAL_TEXT = "#B42318"
SEVERITY_HIGH_BG = "#B54708"
SEVERITY_HIGH_TEXT = "#B54708"
# Medium/Low were added when the notification threshold became configurable: a batch may now
# legitimately contain them, and a badge or counter that showed them as HIGH would be a false
# statement inside a security email. Same functional family as the two above — dark, saturated,
# legible with white text — and still reserved for severity, never used as a brand colour.
SEVERITY_MEDIUM_BG = "#9A6700"
SEVERITY_MEDIUM_TEXT = "#9A6700"
SEVERITY_LOW_BG = "#3F6212"
SEVERITY_LOW_TEXT = "#3F6212"

# The severity levels the Fortinet catalog genuinely publishes, most severe first. Anything else
# (a missing severity, or the `unknown` fallback for an unscored CVE) keeps its historical HIGH
# presentation instead of losing its badge or its counter.
BADGE_SEVERITY_LEVELS = ("critical", "high", "medium", "low")
_SEVERITY_BADGE_COLORS = {
    "CRITICAL": SEVERITY_CRITICAL_BG,
    "HIGH": SEVERITY_HIGH_BG,
    "MEDIUM": SEVERITY_MEDIUM_BG,
    "LOW": SEVERITY_LOW_BG,
}

_ASSET_DIR = Path(__file__).resolve().parent / "email_assets"

LOGO_CID = "sns-logo"
PANTHER_CID = "sns-panther"


@dataclass(frozen=True)
class InlineImage:
    content_id: str
    filename: str
    content_type: str
    content_bytes: bytes


def load_inline_images() -> list[InlineImage]:
    """Return the inline images the email HTML references, or [] when assets are absent.

    Loading is best-effort and silent: a missing/optimized-away asset must never break the
    notification pipeline. The HTML still renders correctly without images (alt text + real text).
    """
    images: list[InlineImage] = []
    logo = _ASSET_DIR / "logo-pink.png"
    panther = _ASSET_DIR / "panthere.jpg"
    if logo.is_file():
        images.append(
            InlineImage(
                LOGO_CID,
                "sns-logo.png",
                "image/png",
                logo.read_bytes(),
            )
        )
    if panther.is_file():
        images.append(
            InlineImage(
                PANTHER_CID,
                "sns-panthere.jpg",
                "image/jpeg",
                panther.read_bytes(),
            )
        )
    return images


def _severity_upper(event: Any) -> str:
    severity = (event.severity or "high").lower()
    return severity.upper() if severity in BADGE_SEVERITY_LEVELS else "HIGH"


def _severity_counts(security_events: list[Any]) -> dict[str, int]:
    """Occurrences of each published severity in the batch.

    Counters and the subject used to derive the non-Critical figure as ``total - critical``, which
    was only ever equivalent to "number of High" while High/Critical were the only CVEs that could
    reach this renderer. The threshold is configurable now, so the breakdown is counted per level.
    """
    counts = {level: 0 for level in BADGE_SEVERITY_LEVELS}
    for event in security_events:
        severity = (event.severity or "").lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def severity_rank(severity: str) -> int:
    """Index in BADGE_SEVERITY_LEVELS (most severe first); an unknown level ranks last."""
    try:
        return BADGE_SEVERITY_LEVELS.index(severity)
    except ValueError:
        return len(BADGE_SEVERITY_LEVELS)


def _plural(n: int) -> str:
    return "" if n == 1 else "s"


def _product_counts(security_events: list[Any]) -> list[tuple[str, int]]:
    """Number of CVEs affecting each product label (a CVE touching several products counts
    once per product), in first-appearance order for stable, readable output."""
    counts: dict[str, int] = {}
    order: list[str] = []
    for event in security_events:
        for label in event.details.get("productLabels") or []:
            label = str(label)
            if label not in counts:
                counts[label] = 0
                order.append(label)
            counts[label] += 1
    return [(label, counts[label]) for label in order]


def compose_subject(security_events: list[Any]) -> str:
    """Deterministic subject: volume first, then the batch's own severity breakdown.

    Every level the batch actually contains is named; with a High/Critical-only batch (still the
    default `high` threshold) the produced subject is byte-for-byte the historical one.
    """
    total = len(security_events)
    counts = _severity_counts(security_events)
    critical = counts["critical"]
    plural = _plural(total)

    if total == 1 and critical == 1:
        products = ", ".join(
            str(label) for label in security_events[0].details.get("productLabels") or []
        )
        if products:
            return f"[FortiUpgrade] 1 nouvelle vulnérabilité Critical — {products}"
        return "[FortiUpgrade] 1 nouvelle vulnérabilité Critical"

    breakdown = " / ".join(
        f"{counts[level]} {level.capitalize()}"
        for level in BADGE_SEVERITY_LEVELS
        if counts[level] > 0
    )
    if not breakdown:  # Defensive: an unlabelled batch keeps the historical wording.
        breakdown = f"{total} High"
    return f"[FortiUpgrade] {total} nouvelle{plural} vulnérabilité{plural} — {breakdown}"


def _hero_title(total: int) -> str:
    plural = _plural(total)
    return (
        f"{total} nouvelle{plural} vulnérabilité{plural} "
        f"détectée{plural} sur vos équipements Fortinet."
    )


def _affected_version_line(item: dict[str, Any], product_labels: list[str]) -> str:
    label = ", ".join(product_labels) or str(item.get("product") or "Produit")
    from_version = item.get("from")
    to_version = item.get("to")
    branch = item.get("branch")
    if from_version and to_version and from_version != to_version:
        scope = f"{from_version} à {to_version}"
    elif from_version:
        scope = str(from_version)
    elif branch:
        scope = f"branche {branch}"
    else:
        scope = "versions non précisées"
    return f"{label} : {scope}"


def _single_event_product_labels(event: Any) -> list[str]:
    return [str(label) for label in event.details.get("productLabels") or []]


def _other_events_text(other_events: list[Any] | None) -> list[str]:
    """Shared text rendering of the non-security section, used by every composer."""
    other_events = other_events or []
    if not other_events:
        return []
    shown = other_events[:20]
    lines = ["Autres événements :"]
    lines.extend(f"- {event.summary}" for event in shown)
    if len(other_events) > len(shown):
        lines.append(f"... et {len(other_events) - len(shown)} de plus (liste tronquée).")
    lines.append("")
    return lines


def _other_events_html(other_events: list[Any] | None) -> str:
    """Shared HTML rendering of the non-security section, used by every composer."""
    other_events = other_events or []
    if not other_events:
        return ""
    shown = other_events[:20]
    items = "".join(
        f"<li style='margin:0 0 6px;font-size:14px;color:{SNS_BLACK}'>"
        f"{html.escape(event.summary)}</li>"
        for event in shown
    )
    if len(other_events) > len(shown):
        items += (
            f"<li style='margin:0;font-size:14px;color:{SNS_GRAY_TEXT}'>"
            f"… et {len(other_events) - len(shown)} de plus (liste tronquée).</li>"
        )
    return (
        "<tr><td style='padding:0 20px 20px'>"
        f"<div style='font-size:12px;font-weight:700;color:{SNS_GRAY_TEXT};letter-spacing:1px;"
        "margin:0 0 10px'>AUTRES ÉVÉNEMENTS</div>"
        f"<ul style='margin:0;padding:0 0 0 18px'>{items}</ul>"
        "</td></tr>"
    )


def _document_head() -> str:
    """Outer document shell: doctype, responsive style, MSO container, inner 680px table."""
    return (
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' "
        "content='width=device-width,initial-scale=1'>"
        "<style>"
        "@media only screen and (max-width:600px){"
        ".hero-col{display:block!important;width:100%!important;box-sizing:border-box!important;"
        "padding:20px!important;text-align:left!important}"
        ".hero-col img{max-width:160px!important}"
        ".hero-col .panther-img{max-width:200px!important}"
        "}"
        "</style></head>"
        "<body style='margin:0;padding:0;background:#ececee;"
        f"font-family:Arial,Helvetica,sans-serif;color:{SNS_BLACK}'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0'>"
        "<tr><td align='center' style='padding:20px 12px'>"
        # Bulletproof container: width:100% + max-width for modern clients and mobile;
        # the conditional MSO table forces the 680px fixed width for Outlook desktop.
        "<!--[if mso]><table role='presentation' width='680' cellpadding='0' cellspacing='0'><tr><td><![endif]-->"
        f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' "
        f"style='border-collapse:collapse;background:{SNS_WHITE};width:100%;max-width:680px'>"
    )


def _document_tail() -> str:
    return (
        "</table>"
        "<!--[if mso]></td></tr></table><![endif]-->"
        "</td></tr>"
        "</table>"
        "</body></html>"
    )


def _hero_html(*, display_name: str, hero_title: str, run_date: str) -> str:
    """Black SNS hero: logo, ALERTE INTERNE / FORTIUPGRADE identity, title, panther."""
    return (
        f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' "
        f"style='border-collapse:collapse;background:{SNS_BLACK}'>"
        "<tr>"
        "<td class='hero-col' width='58%' style='padding:28px 28px 26px;vertical-align:top'>"
        "<img src='cid:sns-logo' alt='SNS SECURITY' width='180' height='83' "
        "style='display:block;border:0;width:100%;max-width:180px;height:auto'>"
        "<div style='margin-top:22px;font-size:11px;font-weight:700;color:#f5c6dd;"
        "letter-spacing:2px'>ALERTE INTERNE</div>"
        f"<div style='margin-top:6px;font-size:18px;font-weight:800;color:{SNS_WHITE}'>"
        f"{html.escape(display_name)}</div>"
        "<div style='margin-top:2px;font-size:11px;color:#9a9aa3;letter-spacing:2px'>"
        "FORTIUPGRADE</div>"
        f"<div style='margin-top:20px;font-size:26px;line-height:1.25;font-weight:700;"
        f"color:{SNS_WHITE}'>{html.escape(hero_title)}</div>"
        f"<div style='margin-top:10px;font-size:13px;color:#b9b9c2'>Collecte : "
        f"{html.escape(run_date)}</div>"
        "</td>"
        "<td class='hero-col' width='42%' style='padding:28px 28px 26px 0;"
        "text-align:right;vertical-align:middle'>"
        "<img class='panther-img' src='cid:sns-panther' alt='' width='200' height='94' "
        "style='display:inline-block;border:0;width:100%;max-width:200px;height:auto'>"
        "</td>"
        "</tr>"
        "</table>"
    )


def _introduction_html(introduction: str) -> str:
    """Optional custom appearance: introduction paragraph after the hero."""
    if not introduction:
        return ""
    return (
        "<tr><td style='padding:22px 20px 0'>"
        f"<div style='font-size:14px;color:{SNS_BLACK};line-height:1.5'>"
        f"{html.escape(introduction)}</div>"
        "</td></tr>"
    )


def _cta_html(app_url: str) -> str:
    return (
        "<tr><td style='padding:8px 20px 22px'>"
        f"<div style='font-size:13px;color:{SNS_GRAY_TEXT};line-height:1.5'>"
        "Cet email a été généré automatiquement par FortiUpgrade.<br>"
        "Merci de ne pas répondre à cet email.</div>"
        f"<div style='margin-top:16px'><a href='{html.escape(app_url, quote=True)}' "
        f"style='display:inline-block;background:{SNS_BLACK};color:{SNS_WHITE};"
        "font-size:14px;font-weight:700;text-decoration:none;padding:12px 22px;border-radius:3px'>"
        "OUVRIR FORTIUPGRADE →</a></div>"
        "</td></tr>"
    )


def _footer_html(signature: str) -> str:
    signature_html = ""
    if signature:
        signature_html = (
            f"<div style='font-size:12px;color:#9a9aa3;margin-top:10px'>"
            f"{html.escape(signature)}</div>"
        )
    return (
        "<tr><td style='padding:26px 20px 26px;background:#0B0B0D'>"
        "<img src='cid:sns-logo' alt='SNS SECURITY' width='140' height='65' "
        "style='display:block;border:0;width:100%;max-width:140px;height:auto;margin:0 0 14px'>"
        f"<div style='font-size:12px;font-weight:700;color:{SNS_WHITE};letter-spacing:1px'>"
        "ÉQUIPE SUPPORT</div>"
        f"<div style='font-size:12px;color:#9a9aa3;margin-top:4px'>"
        "Veille • Expertise • Réactivité</div>"
        f"{signature_html}"
        "</td></tr>"
    )




def compose_text_body(
    security_events: list[Any],
    *,
    app_url: str,
    run_timestamp: str,
    other_events: list[Any] | None = None,
    display_name: str,
    introduction: str = "",
    signature: str = "",
) -> str:
    counts = _severity_counts(security_events)
    total = len(security_events)
    product_counts = _product_counts(security_events)

    lines: list[str] = [display_name]
    if introduction:
        lines.extend(["", introduction])
    # Critical/High lines are always printed (a zero High is itself information); Medium/Low only
    # when the configured threshold actually let some through, which keeps a High/Critical-only
    # batch byte-for-byte identical to the historical body.
    lines.extend(
        [
            "",
            _hero_title(total),
            "",
            f"Critical : {counts['critical']}",
            f"High     : {counts['high']}",
        ]
    )
    for level in ("medium", "low"):
        if counts[level]:
            lines.append(f"{level.capitalize():<8} : {counts[level]}")
    lines.extend(
        [
            f"Total    : {total}",
            "",
            "Produits concernés (nombre de CVE par produit)",
        ]
    )
    lines.extend(f"{label} : {count} CVE" for label, count in product_counts)
    lines.append("")

    for event in security_events:
        details = event.details
        labels = _single_event_product_labels(event)
        severity = _severity_upper(event)
        cvss = details.get("cvssScore")
        cvss_text = str(cvss) if cvss is not None else "Non précisé"
        url = details.get("url") or ""
        lines.extend(
            [
                f"{severity} — {details.get('id', '?')}",
                f"CVSS : {cvss_text}",
                "",
                "Produits concernés",
            ]
        )
        lines.extend(labels)
        lines.extend(["", "Versions affectées"])
        lines.extend(
            _affected_version_line(item, [str(item.get("product") or "Produit")])
            for item in details.get("affected") or []
        )
        lines.extend(
            [
                "",
                "Versions corrigées",
                "Non précisées dans le flux CVRF — consulter l’advisory Fortinet.",
                "",
                "Résumé",
                str(details.get("title") or "Résumé non disponible"),
                "",
                "Fortinet PSIRT",
                f"→ {url or app_url}",
                "",
            ]
        )

    lines.extend(_other_events_text(other_events))

    lines.extend(
        [
            "Cet email a été généré automatiquement par FortiUpgrade.",
            "Merci de ne pas répondre à cet email.",
            "",
            f"FortiUpgrade : {app_url}",
            f"Collecte : {run_timestamp}",
        ]
    )
    if signature:
        lines.extend(["", signature])
    return "\n".join(lines)


def _severity_badge(severity: str) -> str:
    """One badge per published level, coloured by that level.

    The historical implementation painted everything that was not CRITICAL with the HIGH colour
    and the literal text "HIGH", which was only correct while a batch could not contain any other
    level. An unrecognised label keeps the historical HIGH rendering rather than losing its badge.
    """
    background = _SEVERITY_BADGE_COLORS.get(severity, SEVERITY_HIGH_BG)
    return (
        f"<td style='padding:5px 12px;background:{background};color:#ffffff;"
        f"font-size:12px;font-weight:700;letter-spacing:1px;border-radius:3px'>{severity}</td>"
    )


def compose_html_body(
    security_events: list[Any],
    *,
    app_url: str,
    run_timestamp: str,
    other_events: list[Any] | None = None,
    display_name: str,
    introduction: str = "",
    signature: str = "",
) -> str:
    counts = _severity_counts(security_events)
    total = len(security_events)
    product_counts = _product_counts(security_events)
    hero_title = _hero_title(total)

    # --- Summary counters ---------------------------------------------------
    # One cell per level present (shared markup, see _counter_cell). CRITICAL/HIGH/AU TOTAL keep
    # their exact historical markup, so a High/Critical-only batch renders the same three cells as
    # before; Medium/Low cells are only added when the configurable threshold retained such a CVE.
    counter_cells = _counter_cell(counts["critical"], "CRITICAL", SEVERITY_CRITICAL_TEXT)
    counter_cells += _counter_cell(counts["high"], "HIGH", SEVERITY_HIGH_TEXT)
    if counts["medium"]:
        counter_cells += _counter_cell(counts["medium"], "MEDIUM", SEVERITY_MEDIUM_TEXT)
    if counts["low"]:
        counter_cells += _counter_cell(counts["low"], "LOW", SEVERITY_LOW_TEXT)
    counter_cells += _counter_cell(total, "AU TOTAL", SNS_BLACK)

    product_rows = "".join(
        "<tr>"
        f"<td style='padding:8px 14px;font-size:14px;color:{SNS_BLACK}'>{html.escape(label)}</td>"
        f"<td style='padding:8px 14px;text-align:right;font-size:14px;font-weight:700;"
        f"color:{SNS_BLACK}'>{count}"
        f"<span style='font-size:12px;font-weight:400;color:{SNS_GRAY_TEXT}'> CVE</span></td>"
        "</tr>"
        for label, count in product_counts
    )

    # --- Per-CVE sections ---------------------------------------------------
    sections: list[str] = []
    for event in security_events:
        details = event.details
        severity = _severity_upper(event)
        labels = _single_event_product_labels(event)
        cvss = details.get("cvssScore")
        cvss_text = str(cvss) if cvss is not None else "Non précisé"
        url = str(details.get("url") or app_url)
        products_html = "<br>".join(html.escape(label) for label in labels)
        affected_html = "<br>".join(
            html.escape(_affected_version_line(item, [str(item.get("product") or "Produit")]))
            for item in details.get("affected") or []
        )
        sections.append(
            "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' "
            f"style='border-collapse:collapse;border:1px solid {SNS_GRAY_BORDER};"
            "margin:0 0 16px'>"
            "<tr>"
            f"{_severity_badge(severity)}"
            f"<td style='padding:5px 14px;text-align:right;font-size:13px;color:{SNS_GRAY_TEXT}'>"
            f"CVSS {html.escape(cvss_text)}</td>"
            "</tr>"
            "<tr>"
            f"<td colspan='2' style='padding:14px 14px 4px;font-size:16px;font-weight:700;"
            f"color:{SNS_BLACK}'>{html.escape(str(details.get('id', '?')))}</td>"
            "</tr>"
            "<tr><td colspan='2' style='padding:0 14px 12px'>"
            f"<div style='font-size:12px;font-weight:700;color:{SNS_GRAY_TEXT};letter-spacing:1px;"
            "margin:0 0 4px'>PRODUITS CONCERNÉS</div>"
            f"<div style='font-size:14px;color:{SNS_BLACK};line-height:1.5'>{products_html}</div>"
            "</td></tr>"
            "<tr><td colspan='2' style='padding:0 14px 12px'>"
            f"<div style='font-size:12px;font-weight:700;color:{SNS_GRAY_TEXT};letter-spacing:1px;"
            "margin:0 0 4px'>VERSIONS AFFECTÉES</div>"
            f"<div style='font-size:14px;color:{SNS_BLACK};line-height:1.5'>{affected_html}</div>"
            "</td></tr>"
            "<tr><td colspan='2' style='padding:0 14px 12px'>"
            f"<div style='font-size:12px;font-weight:700;color:{SNS_GRAY_TEXT};letter-spacing:1px;"
            "margin:0 0 4px'>VERSIONS CORRIGÉES</div>"
            f"<div style='font-size:14px;color:{SNS_BLACK};line-height:1.5'>"
            "Non précisées dans le flux CVRF — consulter l’advisory Fortinet.</div>"
            "</td></tr>"
            "<tr><td colspan='2' style='padding:0 14px 12px'>"
            f"<div style='font-size:12px;font-weight:700;color:{SNS_GRAY_TEXT};letter-spacing:1px;"
            "margin:0 0 4px'>RÉSUMÉ</div>"
            f"<div style='font-size:14px;color:{SNS_BLACK};line-height:1.5'>"
            f"{html.escape(str(details.get('title') or 'Résumé non disponible'))}</div>"
            "</td></tr>"
            "<tr><td colspan='2' style='padding:4px 14px 14px'>"
            f"<a href='{html.escape(url, quote=True)}' style='color:{SNS_BLACK};"
            "font-size:14px;font-weight:700;text-decoration:underline'>"
            "Voir l’advisory Fortinet →</a>"
            "</td></tr>"
            "</table>"
        )

    other_html = _other_events_html(other_events)

    run_date = run_timestamp[:10]

    run_date = run_timestamp[:10]
    hero = _hero_html(display_name=display_name, hero_title=hero_title, run_date=run_date)
    introduction_html = _introduction_html(introduction)

    return (
        _document_head()
        + f"<tr><td>{hero}</td></tr>"
        + introduction_html
        # Summary
        + "<tr><td style='padding:26px 20px 10px'>"
        + f"<div style='font-size:12px;font-weight:700;color:{SNS_GRAY_TEXT};letter-spacing:1px;"
        "margin:0 0 12px'>SYNTHÈSE</div>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' "
        f"style='border-collapse:collapse;border:1px solid {SNS_GRAY_BORDER}'>"
        f"<tr>{counter_cells}</tr>"
        "</table>"
        "</td></tr>"
        # Products concerned (SNS pale rose background)
        # The per-product figure is a number of CVEs, not a share of the total: the explicit
        # unit plus the subtitle remove the "these numbers should add up to the total" reading.
        + "<tr><td style='padding:22px 20px 6px'>"
        + f"<div style='background:{SNS_ROSE_PALE};padding:18px 16px'>"
        f"<div style='font-size:12px;font-weight:700;color:{SNS_BLACK};letter-spacing:1px;"
        "margin:0 0 2px'>PRODUITS CONCERNÉS</div>"
        f"<div style='font-size:12px;color:{SNS_GRAY_TEXT};margin:0 0 10px'>"
        "Nombre de CVE par produit</div>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' "
        "style='border-collapse:collapse'>"
        f"{product_rows}"
        "</table>"
        "</div>"
        "</td></tr>"
        # Detail per CVE
        + "<tr><td style='padding:24px 20px 6px'>"
        + f"<div style='font-size:12px;font-weight:700;color:{SNS_GRAY_TEXT};letter-spacing:1px;"
        "margin:0 0 14px'>DÉTAIL DES VULNÉRABILITÉS</div>"
        f"{''.join(sections)}"
        "</td></tr>"
        + other_html
        # Automatic message + CTA
        + _cta_html(app_url)
        # Footer (black)
        + _footer_html(signature)
        + _document_tail()
    )


def compose_email(
    security_events: list[Any],
    *,
    app_url: str,
    run_timestamp: str,
    other_events: list[Any] | None = None,
    display_name: str,
    introduction: str = "",
    signature: str = "",
) -> tuple[str, str, str]:
    """Render a batch of High/Critical CVE events into (subject, text_body, html_body).

    The caller (fortios_notify.compose_email) is responsible for splitting its event list into
    ``security_events`` (kind == "cve") and ``other_events`` (daily/operations), so this module
    stays transport- and category-agnostic.
    """
    subject = compose_subject(security_events)
    text_body = compose_text_body(
        security_events,
        app_url=app_url,
        run_timestamp=run_timestamp,
        other_events=other_events,
        display_name=display_name,
        introduction=introduction,
        signature=signature,
    )
    html_body = compose_html_body(
        security_events,
        app_url=app_url,
        run_timestamp=run_timestamp,
        other_events=other_events,
        display_name=display_name,
        introduction=introduction,
        signature=signature,
    )
    return subject, text_body, html_body


def image_data_uri(image: InlineImage) -> str:
    """Base64 data URI for a given inline image (used by transports that can't do CID)."""
    return (
        f"data:{image.content_type};base64,"
        f"{base64.b64encode(image.content_bytes).decode('ascii')}"
    )


def inline_image_data_uris(html_body: str) -> str:
    """Return ``html_body`` with every ``cid:`` reference replaced by a ``data:`` URI.

    Only the admin preview uses this: the preview document is served under a strict CSP with
    no network image allowed, so the renderer's own assets must travel inside the document
    itself. The email transports keep real ``Content-ID`` parts (SMTP ``multipart/related``,
    Graph inline ``fileAttachment``) — never call this on a message that is going to be sent.
    """
    for image in load_inline_images():
        html_body = html_body.replace(f"cid:{image.content_id}", image_data_uri(image))
    return html_body


# --- Release ("nouvelle version") email -------------------------------------
# Reuses the SNS shell above (hero, CTA, footer, palette, inline assets) but none of the
# CVE-specific business components: no severity badge, no Critical/High counters and no
# per-product CVE breakdown. A release has no severity, so rendering it through the CVE
# composer would print "0 nouvelle vulnérabilité détectée".

_RELEASE_MONTHS = (
    "janvier",
    "février",
    "mars",
    "avril",
    "mai",
    "juin",
    "juillet",
    "août",
    "septembre",
    "octobre",
    "novembre",
    "décembre",
)


def _french_date(value: str) -> str:
    """Return an ISO timestamp as ``16 septembre 2026``, or '' when it cannot be parsed.

    Empty means "unknown": every caller then falls back to a value it really has instead of
    inventing or guessing a date.
    """
    if not value:
        return ""
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return ""
    return f"{parsed.day} {_RELEASE_MONTHS[parsed.month - 1]} {parsed.year}"


def _safe_link_url(value: str) -> str:
    """Only an absolute http(s) URL without credentials may become an href; otherwise ''."""
    if not value:
        return ""
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return ""
    if (
        parsed.scheme in {"http", "https"}
        and parsed.netloc
        and not parsed.username
        and not parsed.password
    ):
        return value
    return ""


@dataclass(frozen=True)
class ReleaseItem:
    """A detected release, resolved from a release event's structured details.

    ``fallback_summary`` is the event's own pre-formatted summary: an event queued by an
    older build (or read back from a pending outbox entry) carries no structured details, and
    the email must still show what it really knows rather than an empty card.
    """

    product_label: str
    version: str
    detected_at: str
    release_notes_url: str
    fallback_summary: str

    def display_title(self) -> str:
        if self.product_label and self.version:
            return f"{self.product_label} {self.version}"
        return self.fallback_summary or self.version or self.product_label or "Nouvelle version"


def _release_detail(details: dict[str, Any], key: str) -> str:
    value = details.get(key)
    return value.strip() if isinstance(value, str) else ""


def release_items(events: list[Any]) -> list[ReleaseItem]:
    items: list[ReleaseItem] = []
    for event in events:
        details = getattr(event, "details", None)
        details = details if isinstance(details, dict) else {}
        items.append(
            ReleaseItem(
                product_label=_release_detail(details, "productLabel"),
                version=_release_detail(details, "version"),
                detected_at=_release_detail(details, "detectedAt"),
                release_notes_url=_safe_link_url(_release_detail(details, "releaseNotesUrl")),
                fallback_summary=str(getattr(event, "summary", "") or "").strip(),
            )
        )
    return items


MAX_RELEASES_PER_EMAIL = 20
# A scan can report dozens of findings; the email stays readable, and the rest stays in the
# artifact the CTA points at.
MAX_FINDINGS_PER_EMAIL = 20


def _counter_cell(value: int, label: str, color: str) -> str:
    """One summary-counter cell. Shared by the CVE and container-security emails."""
    return (
        "<td style='text-align:center;padding:18px 12px'>"
        f"<div style='font-size:34px;font-weight:800;color:{color};line-height:1'>"
        f"{value}</div>"
        f"<div style='margin-top:6px;font-size:12px;font-weight:700;color:{SNS_GRAY_TEXT};"
        f"letter-spacing:1px'>{label}</div></td>"
    )


# --- Container image security (Trivy) --------------------------------------------------------

# The report page is the only external target this email may link to, and it always comes from the
# CI that produced the report. Restricting the host keeps a hostile report OR ingestion metadata
# from turning the CTA into an arbitrary outbound link.
_REPORT_HOST = "github.com"


def _report_url(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return ""
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.netloc.lower() not in (_REPORT_HOST, f"www.{_REPORT_HOST}"):
        return ""
    return value


def _container_hero_title(total: int) -> str:
    plural = _plural(total)
    return (
        f"FortiUpgrade a détecté {total} nouvelle{plural} vulnérabilité{plural} "
        f"corrigible{plural} dans l'image Docker."
    )


def container_security_items(events: list[Any]) -> list[Any]:
    """The container events, most severe first, so the email always leads with what matters."""
    return sorted(
        events,
        key=lambda event: (
            severity_rank((event.severity or "unknown").lower()),
            str(event.details.get("package") or ""),
            str(event.details.get("id") or ""),
        ),
    )


def _resolved_count(events: list[Any]) -> int:
    """Findings fixed since the previous scan, carried by every event of the batch."""
    for event in events:
        value = event.details.get("resolvedCount")
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    return 0


def compose_container_security_subject(events: list[Any]) -> str:
    total = len(events)
    plural = _plural(total)
    return (
        f"[FortiUpgrade] Sécurité de l'image — {total} nouvelle{plural} "
        f"vulnérabilité{plural}"
    )


def _container_finding_text(event: Any) -> list[str]:
    details = event.details
    lines = [
        f"{_severity_upper(event)} — {details.get('id', '?')}",
        f"Package : {details.get('package') or '—'}",
        f"Sévérité : {_severity_upper(event)}",
        f"Version installée : {details.get('installedVersion') or '—'}",
        f"Version corrigée : {details.get('fixedVersion') or '—'}",
    ]
    title = str(details.get("title") or "").strip()
    if title:
        lines.append(title)
    url = _report_url(details.get("url")) or str(details.get("url") or "")
    if url:
        lines.append(f"Advisory : {url}")
    lines.append("")
    return lines


def _container_context_text(events: list[Any]) -> list[str]:
    details = events[0].details
    lines = []
    image = str(details.get("image") or "").strip()
    commit = str(details.get("commit") or "").strip()
    scanned_at = str(details.get("scannedAt") or "").strip()
    if image:
        lines.append(f"Image : {image}")
    if commit:
        lines.append(f"Commit : {commit}")
    if scanned_at:
        lines.append(f"Scan : {scanned_at}")
    if lines:
        lines.append("")
    return lines


def compose_container_security_text_body(
    events: list[Any],
    *,
    app_url: str,
    run_timestamp: str,
    other_events: list[Any] | None = None,
    display_name: str,
    introduction: str = "",
    signature: str = "",
) -> str:
    items = container_security_items(events)
    counts = _severity_counts(items)
    resolved = _resolved_count(items)

    lines: list[str] = [display_name]
    if introduction:
        lines.extend(["", introduction])
    lines.extend(["", _container_hero_title(len(items)), ""])
    lines.extend(
        [
            f"Critical : {counts['critical']}",
            f"High     : {counts['high']}",
            f"Total    : {len(items)}",
            "",
        ]
    )
    if resolved:
        lines.extend(
            [
                f"Vulnérabilités corrigées depuis le dernier scan : {resolved}",
                "",
            ]
        )
    shown = items[:MAX_FINDINGS_PER_EMAIL]
    for event in shown:
        lines.extend(_container_finding_text(event))
    if len(items) > len(shown):
        lines.extend([f"... et {len(items) - len(shown)} autres (liste tronquée).", ""])
    lines.extend(_container_context_text(items))
    lines.extend(_other_events_text(other_events))
    lines.extend(
        [
            "Cet email a été généré automatiquement par FortiUpgrade.",
            "Merci de ne pas répondre à cet email.",
            "",
            f"FortiUpgrade : {app_url}",
            f"Collecte : {run_timestamp}",
        ]
    )
    if signature:
        lines.extend(["", signature])
    return "\n".join(lines)


def _container_card_html(event: Any) -> str:
    details = event.details
    severity = _severity_upper(event)
    title = str(details.get("title") or "").strip()
    title_row = ""
    if title:
        title_row = (
            "<tr><td colspan='2' style='padding:0 14px 10px'>"
            f"<div style='font-size:13px;color:{SNS_BLACK};line-height:1.5'>"
            f"{html.escape(title)}</div>"
            "</td></tr>"
        )
    url = _report_url(details.get("url"))
    link_row = ""
    if url:
        link_row = (
            "<tr><td colspan='2' style='padding:4px 14px 14px'>"
            f"<a href='{html.escape(url, quote=True)}' style='color:{SNS_BLACK};"
            "font-size:14px;font-weight:700;text-decoration:underline'>"
            "Voir l’advisory →</a>"
            "</td></tr>"
        )
    version_row = (
        "<tr><td colspan='2' style='padding:0 14px 12px'>"
        f"<div style='font-size:13px;color:{SNS_GRAY_TEXT};line-height:1.6'>"
        f"Version installée : {html.escape(str(details.get('installedVersion') or '—'))}<br>"
        f"Version corrigée : {html.escape(str(details.get('fixedVersion') or '—'))}"
        "</div></td></tr>"
    )
    return (
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' "
        f"style='border-collapse:collapse;border:1px solid {SNS_GRAY_BORDER};margin:0 0 16px'>"
        "<tr>"
        f"{_severity_badge(severity)}"
        f"<td style='padding:5px 14px;text-align:right;font-size:13px;color:{SNS_GRAY_TEXT}'>"
        f"{html.escape(str(details.get('package') or ''))}</td>"
        "</tr>"
        "<tr><td colspan='2' style='padding:14px 14px 6px;font-size:16px;font-weight:700;"
        f"color:{SNS_BLACK}'>{html.escape(str(details.get('id') or '?'))}</td></tr>"
        f"{version_row}{title_row}{link_row}"
        "</table>"
    )


def _container_context_html(events: list[Any]) -> str:
    details = events[0].details
    rows = [
        ("Image analysée", str(details.get("image") or "")),
        ("Commit", str(details.get("commit") or "")),
        ("Date du scan", str(details.get("scannedAt") or "")),
    ]
    cells = "".join(
        f"<div style='font-size:13px;color:{SNS_BLACK};line-height:1.6'>"
        f"<span style='color:{SNS_GRAY_TEXT}'>{html.escape(label)} : </span>"
        f"{html.escape(value or '—')}</div>"
        for label, value in rows
        if label != "Commit" or value
    )
    resolved = _resolved_count(events)
    resolved_html = ""
    if resolved:
        resolved_html = (
            f"<div style='margin-top:10px;font-size:13px;color:{SEVERITY_LOW_TEXT};"
            "font-weight:700'>"
            f"Vulnérabilités corrigées depuis le dernier scan : {resolved}</div>"
        )
    return (
        "<tr><td style='padding:0 20px 12px'>"
        f"<div style='background:{SNS_GRAY_BG};padding:16px 16px'>"
        f"<div style='font-size:12px;font-weight:700;color:{SNS_GRAY_TEXT};letter-spacing:1px;"
        "margin:0 0 8px'>CONTEXTE DU SCAN</div>"
        f"{cells}{resolved_html}"
        "</div></td></tr>"
    )


def _container_cta_html(events: list[Any], app_url: str) -> str:
    report_url = _report_url(events[0].details.get("reportUrl"))
    target = report_url or app_url
    label = "VOIR LE RAPPORT TRIVY →" if report_url else "OUVRIR FORTIUPGRADE →"
    return (
        "<tr><td style='padding:8px 20px 22px'>"
        f"<div style='font-size:13px;color:{SNS_GRAY_TEXT};line-height:1.5'>"
        "Cet email a été généré automatiquement par FortiUpgrade.<br>"
        "Merci de ne pas répondre à cet email.</div>"
        f"<div style='margin-top:16px'><a href='{html.escape(target, quote=True)}' "
        f"style='display:inline-block;background:{SNS_BLACK};color:{SNS_WHITE};"
        "font-size:14px;font-weight:700;text-decoration:none;padding:12px 22px;border-radius:3px'>"
        f"{label}</a></div>"
        "</td></tr>"
    )


def compose_container_security_html_body(
    events: list[Any],
    *,
    app_url: str,
    run_timestamp: str,
    other_events: list[Any] | None = None,
    display_name: str,
    introduction: str = "",
    signature: str = "",
) -> str:
    items = container_security_items(events)
    counts = _severity_counts(items)
    run_date = run_timestamp[:10]
    hero = _hero_html(
        display_name=display_name,
        hero_title=_container_hero_title(len(items)),
        run_date=run_date,
    )
    counters = _counter_cell(counts["critical"], "CRITICAL", SEVERITY_CRITICAL_TEXT)
    counters += _counter_cell(counts["high"], "HIGH", SEVERITY_HIGH_TEXT)
    if counts["medium"]:
        counters += _counter_cell(counts["medium"], "MEDIUM", SEVERITY_MEDIUM_TEXT)
    if counts["low"]:
        counters += _counter_cell(counts["low"], "LOW", SEVERITY_LOW_TEXT)
    counters += _counter_cell(len(items), "AU TOTAL", SNS_BLACK)

    shown = items[:MAX_FINDINGS_PER_EMAIL]
    cards = "".join(_container_card_html(event) for event in shown)
    if len(items) > len(shown):
        cards += (
            "<div style='margin:0 0 16px;font-size:13px;"
            f"color:{SNS_GRAY_TEXT}'>… et {len(items) - len(shown)} autres "
            "(liste tronquée).</div>"
        )
    return (
        _document_head()
        + f"<tr><td>{hero}</td></tr>"
        + _introduction_html(introduction)
        + "<tr><td style='padding:26px 20px 10px'>"
        + f"<div style='font-size:12px;font-weight:700;color:{SNS_GRAY_TEXT};letter-spacing:1px;"
        "margin:0 0 12px'>SYNTHÈSE</div>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' "
        f"style='border-collapse:collapse;border:1px solid {SNS_GRAY_BORDER}'>"
        f"<tr>{counters}</tr>"
        "</table>"
        "</td></tr>"
        "<tr><td style='padding:24px 20px 6px'>"
        + f"<div style='font-size:12px;font-weight:700;color:{SNS_GRAY_TEXT};letter-spacing:1px;"
        "margin:0 0 14px'>DÉTAIL DES VULNÉRABILITÉS</div>"
        + cards
        + "</td></tr>"
        + _container_context_html(items)
        + _other_events_html(other_events)
        + _container_cta_html(items, app_url)
        + _footer_html(signature)
        + _document_tail()
    )


def compose_container_security_email(
    events: list[Any],
    *,
    app_url: str,
    run_timestamp: str,
    other_events: list[Any] | None = None,
    display_name: str,
    introduction: str = "",
    signature: str = "",
) -> tuple[str, str, str]:
    """Render container image findings into (subject, text_body, html_body) with the SNS identity.

    Structurally separate from the Fortinet CVE email: no CVE badge component, no product
    breakdown, and its own hero sentence. Only the identity (hero, logo, panther, palette, CTA,
    Support footer) is shared, exactly like the release email.
    """
    if not events:
        raise ValueError("Aucun événement de sécurité conteneur à rendre.")
    subject = compose_container_security_subject(events)
    text_body = compose_container_security_text_body(
        events,
        app_url=app_url,
        run_timestamp=run_timestamp,
        other_events=other_events,
        display_name=display_name,
        introduction=introduction,
        signature=signature,
    )
    html_body = compose_container_security_html_body(
        events,
        app_url=app_url,
        run_timestamp=run_timestamp,
        other_events=other_events,
        display_name=display_name,
        introduction=introduction,
        signature=signature,
    )
    return subject, text_body, html_body


def _release_hero_title(total: int) -> str:
    """Automatic release headline: the renderer's own introduction, plural-aware.

    Used whenever no dedicated release introduction is configured, so the sentence always agrees
    with the number of releases actually reported in the email.
    """
    if total <= 1:
        return "FortiUpgrade a détecté une nouvelle version Fortinet disponible au téléchargement."
    return (
        f"FortiUpgrade a détecté {total} nouvelles versions Fortinet "
        "disponibles au téléchargement."
    )


def _detection_label(item: ReleaseItem, run_timestamp: str) -> str:
    french = _french_date(item.detected_at)
    if french:
        return f"Détectée le {french}"
    return f"Détectée lors de la collecte du {_french_date(run_timestamp) or run_timestamp[:10]}"


def _release_card_html(item: ReleaseItem, *, run_timestamp: str) -> str:
    identity = item.product_label or item.fallback_summary or "Nouvelle version détectée"
    if item.version:
        identity_rows = (
            "<tr><td colspan='2' style='padding:0 14px 12px'>"
            f"<div style='font-size:22px;font-weight:800;color:{SNS_BLACK};line-height:1.2'>"
            f"{html.escape(item.version)}</div>"
            "</td></tr>"
        )
    elif item.product_label and item.fallback_summary:
        identity_rows = (
            "<tr><td colspan='2' style='padding:0 14px 12px'>"
            f"<div style='font-size:14px;color:{SNS_GRAY_TEXT};line-height:1.5'>"
            f"{html.escape(item.fallback_summary)}</div>"
            "</td></tr>"
        )
    else:
        identity_rows = ""

    link_row = ""
    if item.release_notes_url:
        link_row = (
            "<tr><td colspan='2' style='padding:4px 14px 14px'>"
            f"<a href='{html.escape(item.release_notes_url, quote=True)}' style='color:{SNS_BLACK};"
            "font-size:14px;font-weight:700;text-decoration:underline'>"
            "Notes de version Fortinet →</a>"
            "</td></tr>"
        )

    return (
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' "
        f"style='border-collapse:collapse;border:1px solid {SNS_GRAY_BORDER};margin:0 0 16px'>"
        "<tr>"
        f"<td style='padding:5px 12px;background:{SNS_ROSE_PALE};color:{SNS_BLACK};"
        "font-size:12px;font-weight:700;letter-spacing:1px;border-radius:3px'>NOUVELLE VERSION</td>"
        f"<td style='padding:5px 14px;text-align:right;font-size:13px;color:{SNS_GRAY_TEXT}'>"
        f"{html.escape(_detection_label(item, run_timestamp))}</td>"
        "</tr>"
        "<tr><td colspan='2' style='padding:14px 14px 4px;font-size:16px;font-weight:700;"
        f"color:{SNS_BLACK}'>{html.escape(identity)}</td></tr>"
        f"{identity_rows}"
        f"{link_row}"
        "</table>"
    )


def compose_release_subject(release_events: list[Any]) -> str:
    items = release_items(release_events)
    if len(items) == 1:
        return f"[FortiUpgrade] Nouvelle version — {items[0].display_title()}"
    return f"[FortiUpgrade] {len(items)} nouvelles versions Fortinet"


def compose_release_text_body(
    release_events: list[Any],
    *,
    app_url: str,
    run_timestamp: str,
    other_events: list[Any] | None = None,
    display_name: str,
    introduction: str = "",
    signature: str = "",
) -> str:
    items = release_items(release_events)
    lines: list[str] = [display_name]
    if introduction:
        lines.extend(["", introduction])
    lines.extend(["", _release_hero_title(len(items)), ""])
    lines.append("Version détectée" if len(items) == 1 else f"{len(items)} versions détectées")
    shown = items[:MAX_RELEASES_PER_EMAIL]
    for item in shown:
        if item.product_label and item.version:
            lines.append(f"{item.product_label} — {item.version}")
        else:
            lines.append(item.fallback_summary or item.product_label or "Nouvelle version")
        lines.append(_detection_label(item, run_timestamp))
        if item.release_notes_url:
            lines.append(f"Notes de version : {item.release_notes_url}")
    if len(items) > len(shown):
        lines.append(f"... et {len(items) - len(shown)} de plus (liste tronquée).")
    lines.append("")
    lines.extend(_other_events_text(other_events))
    lines.extend(
        [
            "Cet email a été généré automatiquement par FortiUpgrade.",
            "Merci de ne pas répondre à cet email.",
            "",
            f"FortiUpgrade : {app_url}",
            f"Collecte : {run_timestamp}",
        ]
    )
    if signature:
        lines.extend(["", signature])
    return "\n".join(lines)


def compose_release_html_body(
    release_events: list[Any],
    *,
    app_url: str,
    run_timestamp: str,
    other_events: list[Any] | None = None,
    display_name: str,
    introduction: str = "",
    signature: str = "",
) -> str:
    items = release_items(release_events)
    run_date = run_timestamp[:10]
    hero = _hero_html(
        display_name=display_name,
        hero_title=_release_hero_title(len(items)),
        run_date=run_date,
    )
    section_label = "VERSION DÉTECTÉE" if len(items) == 1 else "VERSIONS DÉTECTÉES"
    shown = items[:MAX_RELEASES_PER_EMAIL]
    cards = "".join(
        _release_card_html(item, run_timestamp=run_timestamp) for item in shown
    )
    if len(items) > len(shown):
        cards += (
            "<div style='margin:0 0 16px;font-size:13px;"
            f"color:{SNS_GRAY_TEXT}'>… et {len(items) - len(shown)} de plus "
            "(liste tronquée).</div>"
        )
    return (
        _document_head()
        + f"<tr><td>{hero}</td></tr>"
        + _introduction_html(introduction)
        + "<tr><td style='padding:24px 20px 6px'>"
        + f"<div style='font-size:12px;font-weight:700;color:{SNS_GRAY_TEXT};letter-spacing:1px;"
        "margin:0 0 14px'>"
        + section_label
        + "</div>"
        + cards
        + "</td></tr>"
        + _other_events_html(other_events)
        + _cta_html(app_url)
        + _footer_html(signature)
        + _document_tail()
    )


def compose_release_email(
    release_events: list[Any],
    *,
    app_url: str,
    run_timestamp: str,
    other_events: list[Any] | None = None,
    display_name: str,
    introduction: str = "",
    signature: str = "",
) -> tuple[str, str, str]:
    """Render release events into (subject, text_body, html_body) with the SNS identity."""
    if not release_events:
        raise ValueError("Aucun événement de nouvelle version à rendre.")
    subject = compose_release_subject(release_events)
    text_body = compose_release_text_body(
        release_events,
        app_url=app_url,
        run_timestamp=run_timestamp,
        other_events=other_events,
        display_name=display_name,
        introduction=introduction,
        signature=signature,
    )
    html_body = compose_release_html_body(
        release_events,
        app_url=app_url,
        run_timestamp=run_timestamp,
        other_events=other_events,
        display_name=display_name,
        introduction=introduction,
        signature=signature,
    )
    return subject, text_body, html_body
