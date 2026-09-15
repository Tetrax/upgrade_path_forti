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
import html
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
    return severity.upper() if severity in ("critical", "high") else "HIGH"


def _is_critical(event: Any) -> bool:
    return (event.severity or "").lower() == "critical"


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
    """Deterministic subject: volume first, Critical when present, products only when short."""
    total = len(security_events)
    critical = sum(1 for event in security_events if _is_critical(event))
    high = total - critical
    plural = _plural(total)

    if total == 1 and critical == 1:
        products = ", ".join(
            str(label) for label in security_events[0].details.get("productLabels") or []
        )
        if products:
            return f"[FortiUpgrade] 1 nouvelle vulnérabilité Critical — {products}"
        return "[FortiUpgrade] 1 nouvelle vulnérabilité Critical"

    if critical > 0:
        if high > 0:
            return (
                f"[FortiUpgrade] {total} nouvelles vulnérabilités "
                f"— {critical} Critical / {high} High"
            )
        return (
            f"[FortiUpgrade] {total} nouvelle{plural} vulnérabilité{plural} "
            f"— {critical} Critical"
        )
    return (
        f"[FortiUpgrade] {total} nouvelle{plural} vulnérabilité{plural} — {high} High"
    )


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
    total = len(security_events)
    critical = sum(1 for event in security_events if _is_critical(event))
    high = total - critical
    product_counts = _product_counts(security_events)

    lines: list[str] = [display_name]
    if introduction:
        lines.extend(["", introduction])
    lines.extend(
        [
            "",
            _hero_title(total),
            "",
            f"Critical : {critical}",
            f"High     : {high}",
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

    other_events = other_events or []
    if other_events:
        shown = other_events[:20]
        lines.append("Autres événements :")
        lines.extend(f"- {event.summary}" for event in shown)
        if len(other_events) > len(shown):
            lines.append(f"... et {len(other_events) - len(shown)} de plus (liste tronquée).")
        lines.append("")

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
    if severity == "CRITICAL":
        return (
            f"<td style='padding:5px 12px;background:{SEVERITY_CRITICAL_BG};color:#ffffff;"
            "font-size:12px;font-weight:700;letter-spacing:1px;border-radius:3px'>CRITICAL</td>"
        )
    return (
        f"<td style='padding:5px 12px;background:{SEVERITY_HIGH_BG};color:#ffffff;"
        "font-size:12px;font-weight:700;letter-spacing:1px;border-radius:3px'>HIGH</td>"
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
    total = len(security_events)
    critical = sum(1 for event in security_events if _is_critical(event))
    high = total - critical
    product_counts = _product_counts(security_events)
    hero_title = _hero_title(total)

    # --- Summary counters ---------------------------------------------------
    counter_critical = (
        f"<td style='text-align:center;padding:18px 12px'>"
        f"<div style='font-size:34px;font-weight:800;color:{SEVERITY_CRITICAL_TEXT};line-height:1'>"
        f"{critical}</div>"
        f"<div style='margin-top:6px;font-size:12px;font-weight:700;color:{SNS_GRAY_TEXT};"
        f"letter-spacing:1px'>CRITICAL</div></td>"
    )
    counter_high = (
        f"<td style='text-align:center;padding:18px 12px'>"
        f"<div style='font-size:34px;font-weight:800;color:{SEVERITY_HIGH_TEXT};line-height:1'>"
        f"{high}</div>"
        f"<div style='margin-top:6px;font-size:12px;font-weight:700;color:{SNS_GRAY_TEXT};"
        f"letter-spacing:1px'>HIGH</div></td>"
    )
    counter_total = (
        f"<td style='text-align:center;padding:18px 12px'>"
        f"<div style='font-size:34px;font-weight:800;color:{SNS_BLACK};line-height:1'>{total}</div>"
        f"<div style='margin-top:6px;font-size:12px;font-weight:700;color:{SNS_GRAY_TEXT};"
        f"letter-spacing:1px'>AU TOTAL</div></td>"
    )

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

    other_html = ""
    other_events = other_events or []
    if other_events:
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
        other_html = (
            "<tr><td style='padding:0 20px 20px'>"
            f"<div style='font-size:12px;font-weight:700;color:{SNS_GRAY_TEXT};letter-spacing:1px;"
            "margin:0 0 10px'>AUTRES ÉVÉNEMENTS</div>"
            f"<ul style='margin:0;padding:0 0 0 18px'>{items}</ul>"
            "</td></tr>"
        )

    run_date = run_timestamp[:10]

    # --- Hero (black) -------------------------------------------------------
    # Two-column on desktop (text left, panther right); the .hero-col media query
    # stacks them full-width on narrow screens so the title never clips.
    hero = (
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

    # Optional custom appearance: introduction paragraph after the hero, signature in the footer.
    introduction_html = ""
    if introduction:
        introduction_html = (
            "<tr><td style='padding:22px 20px 0'>"
            f"<div style='font-size:14px;color:{SNS_BLACK};line-height:1.5'>"
            f"{html.escape(introduction)}</div>"
            "</td></tr>"
        )
    signature_html = ""
    if signature:
        signature_html = (
            f"<div style='font-size:12px;color:#9a9aa3;margin-top:10px'>"
            f"{html.escape(signature)}</div>"
        )

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
        f"<tr><td>{hero}</td></tr>"

        f"{introduction_html}"

        # Summary
        "<tr><td style='padding:26px 20px 10px'>"
        f"<div style='font-size:12px;font-weight:700;color:{SNS_GRAY_TEXT};letter-spacing:1px;"
        "margin:0 0 12px'>SYNTHÈSE</div>"
        f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' "
        f"style='border-collapse:collapse;border:1px solid {SNS_GRAY_BORDER}'>"
        f"<tr>{counter_critical}{counter_high}{counter_total}</tr>"
        "</table>"
        "</td></tr>"

        # Products concerned (SNS pale rose background)
        # The per-product figure is a number of CVEs, not a share of the total: the explicit
        # unit plus the subtitle remove the "these numbers should add up to the total" reading.
        "<tr><td style='padding:22px 20px 6px'>"
        f"<div style='background:{SNS_ROSE_PALE};padding:18px 16px'>"
        f"<div style='font-size:12px;font-weight:700;color:{SNS_BLACK};letter-spacing:1px;"
        "margin:0 0 2px'>PRODUITS CONCERNÉS</div>"
        f"<div style='font-size:12px;color:{SNS_GRAY_TEXT};margin:0 0 10px'>"
        "Nombre de CVE par produit</div>"
        f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' "
        "style='border-collapse:collapse'>"
        f"{product_rows}"
        "</table>"
        "</div>"
        "</td></tr>"

        # Detail per CVE
        "<tr><td style='padding:24px 20px 6px'>"
        f"<div style='font-size:12px;font-weight:700;color:{SNS_GRAY_TEXT};letter-spacing:1px;"
        "margin:0 0 14px'>DÉTAIL DES VULNÉRABILITÉS</div>"
        f"{''.join(sections)}"
        "</td></tr>"

        f"{other_html}"

        # Automatic message + CTA
        "<tr><td style='padding:8px 20px 22px'>"
        f"<div style='font-size:13px;color:{SNS_GRAY_TEXT};line-height:1.5'>"
        "Cet email a été généré automatiquement par FortiUpgrade.<br>"
        "Merci de ne pas répondre à cet email.</div>"
        f"<div style='margin-top:16px'><a href='{html.escape(app_url, quote=True)}' "
        f"style='display:inline-block;background:{SNS_BLACK};color:{SNS_WHITE};"
        "font-size:14px;font-weight:700;text-decoration:none;padding:12px 22px;border-radius:3px'>"
        "OUVRIR FORTIUPGRADE →</a></div>"
        "</td></tr>"

        # Footer (black)
        "<tr><td style='padding:26px 20px 26px;background:#0B0B0D'>"
        "<img src='cid:sns-logo' alt='SNS SECURITY' width='140' height='65' "
        "style='display:block;border:0;width:100%;max-width:140px;height:auto;margin:0 0 14px'>"
        f"<div style='font-size:12px;font-weight:700;color:{SNS_WHITE};letter-spacing:1px'>"
        "ÉQUIPE SUPPORT</div>"
        f"<div style='font-size:12px;color:#9a9aa3;margin-top:4px'>"
        "Veille • Expertise • Réactivité</div>"
        f"{signature_html}"
        "</td></tr>"

        "</table>"
        "<!--[if mso]></td></tr></table><![endif]-->"
        "</td></tr>"
        "</table>"
        "</body></html>"
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
