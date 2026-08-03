#!/usr/bin/env python3
"""Génère le PDF du tutoriel Upgrade Path à partir du fichier Markdown.

Format tutoriel FortiFlow : page de garde (À propos), sommaire, revue de code,
architecture, déploiement, HTTPS (options A/B), maintenance, dépannage, checklist.

Charte graphique : NAVY=#0F2747 BLUE=#1976D2 DARK_TEXT=#263238 GRAY=#52606D.
Polices : DejaVuSans, DejaVuSans-Bold, DejaVuSansMono.
"""

from __future__ import annotations

import re
from html import escape as html_escape
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
    KeepTogether, PageBreak, XPreformatted,
)

# ── Chemins ──────────────────────────────────────────────────────────
MD_PATH = Path("/workspace/upgrade_path/docs/upgrade-path-tutoriel.md")
OUT = Path("/workspace/upgrade_path/docs/pdf/upgrade-path-tutoriel.pdf")
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

pdfmetrics.registerFont(TTFont("DejaVu", FONT))
pdfmetrics.registerFont(TTFont("DejaVu-Bold", FONT_BOLD))
pdfmetrics.registerFont(TTFont("DejaVuMono", FONT_MONO))

# ── Dimensions (charte graphique unifiée) ────────────────────────────
PW, PH = A4
MX = 1.4 * cm
MT = 1.35 * cm
MB = 1.7 * cm
CW = PW - 2 * MX  # colonne largeur utile (~17.2 cm)

# ── Couleurs (palette unifiée) ─────────────────────────────────────
NAVY = colors.HexColor("#0F2747")
BLUE = colors.HexColor("#1976D2")
LIGHT_BLUE = colors.HexColor("#EAF3FF")
LIGHT_GREEN = colors.HexColor("#EAF8F1")
ORANGE_BG = colors.HexColor("#FFF3E0")
GRAY = colors.HexColor("#52606D")
BORDER = colors.HexColor("#D9E2EC")
LINE = colors.HexColor("#BCCCDC")
DARK_TEXT = colors.HexColor("#263238")
CODE_BG = colors.HexColor("#F4F7FA")
CODE_TEXT = colors.HexColor("#13293D")
AMBER = colors.HexColor("#E6960C")
TEAL = colors.HexColor("#00897B")
AMBER_BG = colors.HexColor("#FFF8E7")
TEAL_BG = colors.HexColor("#E6F7F5")
PURPLE = colors.HexColor("#7C4DFF")
PURPLE_BG = colors.HexColor("#F3EEFF")

# ── Styles ───────────────────────────────────────────────────────────
styles = getSampleStyleSheet()

styles.add(ParagraphStyle(
    name="CoverTitle", parent=styles["Title"],
    fontName="DejaVu-Bold", fontSize=22, leading=29,
    textColor=NAVY, alignment=TA_CENTER, spaceAfter=10,
))
styles.add(ParagraphStyle(
    name="Subtitle", parent=styles["Normal"],
    fontName="DejaVu", fontSize=10, leading=15,
    textColor=GRAY, alignment=TA_CENTER, spaceAfter=16,
))
styles.add(ParagraphStyle(
    name="H1x", parent=styles["Heading1"],
    fontName="DejaVu-Bold", fontSize=16, leading=21,
    textColor=NAVY, spaceBefore=18, spaceAfter=8,
))
styles.add(ParagraphStyle(
    name="H2x", parent=styles["Heading2"],
    fontName="DejaVu-Bold", fontSize=12, leading=16,
    textColor=BLUE, spaceBefore=12, spaceAfter=5,
))
styles.add(ParagraphStyle(
    name="Bodyx", parent=styles["BodyText"],
    fontName="DejaVu", fontSize=9.4, leading=14,
    textColor=DARK_TEXT, spaceAfter=6,
))
styles.add(ParagraphStyle(
    name="Codex", parent=styles["Code"],
    fontName="DejaVuMono", fontSize=7.8, leading=11,
    textColor=CODE_TEXT,
))
styles.add(ParagraphStyle(
    name="TableHead", parent=styles["BodyText"],
    fontName="DejaVu-Bold", fontSize=9, leading=12,
    textColor=colors.white,
))
styles.add(ParagraphStyle(
    name="Bulletx", parent=styles["BodyText"],
    fontName="DejaVu", fontSize=9.2, leading=13,
    leftIndent=13, firstLineIndent=-10, spaceAfter=3,
))
styles.add(ParagraphStyle(
    name="Small", parent=styles["BodyText"],
    fontName="DejaVu", fontSize=8, leading=11, textColor=GRAY,
))
styles.add(ParagraphStyle(
    name="H4x", parent=styles["Heading3"],
    fontName="DejaVu-Bold", fontSize=10, leading=14,
    textColor=NAVY, spaceBefore=8, spaceAfter=4,
))
styles.add(ParagraphStyle(
    name="OptionLabel", parent=styles["BodyText"],
    fontName="DejaVu-Bold", fontSize=10, leading=14,
    textColor=colors.white,
))
styles.add(ParagraphStyle(
    name="TOCEntry", parent=styles["BodyText"],
    fontName="DejaVu", fontSize=9.4, leading=18,
    textColor=DARK_TEXT, leftIndent=8,
))
styles.add(ParagraphStyle(
    name="TOCHeader", parent=styles["Heading1"],
    fontName="DejaVu-Bold", fontSize=16, leading=21,
    textColor=NAVY, spaceBefore=0, spaceAfter=12,
))

# ── Helpers ──────────────────────────────────────────────────────────

def p(text, style="Bodyx"):
    return Paragraph(text, styles[style])


def code_block(text):
    """Bloc de code avec fond gris et bordure — XPreformatted."""
    text = sanitize_unicode(text)
    content = XPreformatted(html_escape(text), styles["Codex"])
    table = Table([[content]], colWidths=[CW])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return table


def callout(title, body, background=LIGHT_BLUE):
    table = Table([[p(f"<b>{title}</b><br/>{body}", "Bodyx")]], colWidths=[CW])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), background),
        ("BOX", (0, 0), (-1, -1), 0.7, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return table


def option_box(option_id, label, body, accent_color):
    data = [
        [p(f"<b>{option_id}</b>  {label}", "OptionLabel")],
        [p(f"{body}", "Bodyx")],
    ]
    table = Table(data, colWidths=[CW])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), accent_color),
        ("BACKGROUND", (0, 1), (-1, -1), AMBER_BG if "A" in option_id else TEAL_BG),
        ("BOX", (0, 0), (-1, -1), 0.8, accent_color),
        ("LINEBELOW", (0, 0), (-1, 0), 0.4, accent_color),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return table


def repo_callout(title, body, icon="", accent=PURPLE):
    header = f"<b>{icon}  {title}</b>" if icon else f"<b>{title}</b>"
    data = [
        [p(header, "H4x")],
        [p(body, "Bodyx")],
    ]
    table = Table(data, colWidths=[CW])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PURPLE_BG),
        ("BOX", (0, 0), (-1, -1), 0.8, accent),
        ("LINEBELOW", (0, 0), (-1, 0), 0.4, accent),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return table


def bullet(text):
    return p("•  " + text, "Bulletx")


def numbered_bullet(num, text):
    return p(f"{num}.  {text}", "Bulletx")


def make_table(headers, rows):
    head_row = [p(h, "TableHead") for h in headers]
    data_rows = [[p(cell, "Bodyx") for cell in row] for row in rows]
    data = [head_row] + data_rows
    ncols = len(headers)
    col_width = CW / ncols
    t = Table(data, colWidths=[col_width] * ncols, repeatRows=1)
    tbl_style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "DejaVu-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            tbl_style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#FAFBFC")))
        else:
            tbl_style.append(("BACKGROUND", (0, i), (-1, i), colors.white))
    t.setStyle(TableStyle(tbl_style))
    return t


def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(LINE)
    canvas.line(MX, MB - 0.45 * cm, PW - MX, MB - 0.45 * cm)
    canvas.setFont("DejaVu", 7.5)
    canvas.setFillColor(GRAY)
    canvas.drawString(MX, MB - 0.9 * cm, "Upgrade Path — Guide complet")
    canvas.drawRightString(PW - MX, MB - 0.9 * cm, f"Page {doc.page}")
    canvas.restoreState()


# ── Parser Markdown ──────────────────────────────────────────────────

def parse_markdown(text):
    lines = text.split("\n")
    elements = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("# ") and not line.startswith("## "):
            elements.append({"type": "h1", "text": line[2:].strip()})
            i += 1; continue
        if line.startswith("## "):
            elements.append({"type": "h2", "text": line[3:].strip()})
            i += 1; continue
        if line.startswith("### "):
            elements.append({"type": "h3", "text": line[4:].strip()})
            i += 1; continue
        if line.startswith("#### "):
            elements.append({"type": "h4", "text": line[5:].strip()})
            i += 1; continue
        if line.strip() == "---":
            elements.append({"type": "hr"})
            i += 1; continue
        if line.strip().startswith("```"):
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i])
                i += 1
            if i < len(lines):
                i += 1
            code_text = "\n".join(code_lines).strip()
            if code_text:
                elements.append({"type": "code", "text": code_text})
            continue
        if "|" in line and i + 1 < len(lines) and re.match(r'^\|?[\s\-:|]+\|', lines[i + 1].strip()):
            headers = [c.strip() for c in line.strip().strip("|").split("|")]
            i += 2
            rows = []
            while i < len(lines) and "|" in lines[i]:
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                rows.append(cells)
                i += 1
            elements.append({"type": "table", "headers": headers, "rows": rows})
            continue
        if line.strip().startswith("> "):
            quote_lines = []
            while i < len(lines) and lines[i].strip().startswith("> "):
                quote_lines.append(lines[i].strip()[2:])
                i += 1
            elements.append({"type": "blockquote", "text": " ".join(quote_lines).strip()})
            continue
        if line.strip().startswith("- "):
            bullet_lines = []
            while i < len(lines) and lines[i].strip().startswith("- "):
                bullet_lines.append(lines[i].strip()[2:])
                i += 1
            elements.append({"type": "bullets", "items": bullet_lines})
            continue
        if re.match(r'^\d+\.\s', line.strip()):
            num_lines = []
            while i < len(lines) and re.match(r'^\d+\.\s', lines[i].strip()):
                num_lines.append(re.sub(r'^\d+\.\s+', '', lines[i].strip()))
                i += 1
            elements.append({"type": "numbered", "items": num_lines})
            continue
        para_lines = []
        while i < len(lines) and lines[i].strip() \
                and not lines[i].strip().startswith("#") \
                and not lines[i].strip().startswith("```") \
                and not lines[i].strip().startswith("- ") \
                and not re.match(r'^\d+\.\s', lines[i].strip()) \
                and not lines[i].strip().startswith("> ") \
                and lines[i].strip() != "---":
            para_lines.append(lines[i].strip())
            i += 1
        if para_lines:
            raw = " ".join(para_lines).strip()
            if raw:
                elements.append({"type": "p", "text": raw})
        else:
            i += 1
    return elements


def sanitize_unicode(text):
    replacements = {
        "\u2705": "[OK]", "\u2714": "[OK]", "\u2713": "[OK]",
        "\u274c": "[KO]", "\u26a0": "[!]",
        "\u2795": "+", "\u2796": "-",
        "\u2013": "-", "\u2014": "--",
        "\u2018": "'", "\u2019": "'",
        "\u201c": '"', "\u201d": '"',
        "\u2026": "...", "\u00a0": " ",
    }
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    return text


def md_to_html(text):
    text = sanitize_unicode(text)
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'\*(.+?)\*', r'<i>\1</i>', text)
    text = re.sub(r'`([^`]+)`', r'<font face="DejaVuMono" size="8" color="#13293D">\1</font>', text)
    return text


# ── Table des matières ───────────────────────────────────────────────

def build_toc(elements):
    """Construit une page de sommaire à partir des titres H1/H2."""
    toc_items = [p("Sommaire", "TOCHeader"), Spacer(1, 0.3 * cm)]
    for elem in elements:
        if elem["type"] == "h1":
            text = md_to_html(elem["text"])
            toc_items.append(p(f"<b>{text}</b>", "TOCEntry"))
        elif elem["type"] == "h2":
            text = md_to_html(elem["text"])
            toc_items.append(p(f"    {text}", "TOCEntry"))
    toc_items.append(Spacer(1, 0.5 * cm))
    return toc_items


# ── Construction du document ─────────────────────────────────────────

md_text = MD_PATH.read_text(encoding="utf-8")

lines = md_text.split("\n")
subtitle_found = ""
for ln in lines[1:10]:
    stripped = ln.strip()
    if stripped.startswith("> "):
        subtitle_found = md_to_html(stripped[2:].strip())
        break

# BaseDocTemplate
doc = BaseDocTemplate(
    str(OUT),
    pagesize=A4,
    leftMargin=MX, rightMargin=MX,
    topMargin=MT, bottomMargin=MB,
    title="Upgrade Path — Guide complet : Revue, Déploiement & HTTPS",
    author="Hermes Agent",
    subject="Guide de déploiement Upgrade Path avec Portainer, Docker et HTTPS",
)
frame = Frame(MX, MB, CW, PH - MT - MB, id="main")
doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=footer)])

story = []

# ── Page de garde ───────────────────────────────────────────────────
story += [Spacer(1, 1.8 * cm)]
story.append(p("Upgrade Path", "CoverTitle"))
story.append(p(subtitle_found if subtitle_found else "Guide complet : Revue, Déploiement & HTTPS", "Subtitle"))
story.append(Spacer(1, 0.3 * cm))
story.append(callout(
    "À propos",
    "Upgrade Path est une application d'intelligence de mise à jour <b>FortiOS</b> pour les ingénieurs réseau. "
    "Ce guide couvre l'ensemble du cycle de vie : revue de code, déploiement Docker/Portainer, configuration HTTPS et maintenance.",
    LIGHT_GREEN,
))
story.append(PageBreak())

# ── Parsing ──────────────────────────────────────────────────────────
elements = parse_markdown(md_text)

# ── Page sommaire ────────────────────────────────────────────────────
story += build_toc(elements)
story.append(PageBreak())

# ── Rendu ────────────────────────────────────────────────────────────
skip_first_h1 = True

i = 0
while i < len(elements):
    elem = elements[i]
    t = elem["type"]

    if t == "h1":
        if skip_first_h1:
            skip_first_h1 = False
            i += 1; continue
        story.append(p(md_to_html(elem["text"]), "H1x"))
        i += 1

    elif t == "h2":
        text = md_to_html(elem["text"])
        if "portainer" in text.lower() or "déploiement" in text.lower():
            story.append(Spacer(1, 0.2 * cm))
            story.append(repo_callout(
                title="Déploiement",
                body=f"<b>{text}</b> — déploiement via image Docker locale dans Portainer",
                accent=BLUE,
            ))
            story.append(Spacer(1, 0.1 * cm))
        elif "mise à jour" in text.lower() or "maintenance" in text.lower():
            story.append(Spacer(1, 0.2 * cm))
            story.append(repo_callout(
                title="Maintenance",
                body=f"<b>{text}</b> — procédure de montée de version et renouvellement",
                accent=TEAL,
            ))
            story.append(Spacer(1, 0.1 * cm))
        else:
            story.append(p(text, "H2x"))
        i += 1

    elif t == "h3":
        text = elem["text"]
        html_text = md_to_html(text)
        if "étape" in text.lower():
            # ÉTAPE X — Titre → format badge numéroté
            story.append(p(f"<b>{html_text}</b>", "H4x"))
        else:
            story.append(p(f"<b>{html_text}</b>", "Bodyx"))
        i += 1

    elif t == "h4":
        text = elem["text"]
        html_text = md_to_html(text)
        is_option_a = text.strip().lower().startswith("option a")
        is_option_b = text.strip().lower().startswith("option b")
        if is_option_a or is_option_b:
            accent = AMBER if is_option_a else TEAL
            label = re.sub(r'^Option\s+[AB]\s*[—\-\–]\s*', '', text.strip(), flags=re.IGNORECASE)
            body_text = ""
            if i + 1 < len(elements) and elements[i + 1]["type"] == "p":
                body_text = elements[i + 1]["text"]
                i += 1
            story.append(Spacer(1, 0.2 * cm))
            story.append(option_box(
                option_id="Option A" if is_option_a else "Option B",
                label=label,
                body=md_to_html(body_text) if body_text else "",
                accent_color=accent,
            ))
            story.append(Spacer(1, 0.1 * cm))
        else:
            story.append(p(f"<b>{html_text}</b>", "H4x"))
        i += 1

    elif t == "p":
        raw_html = md_to_html(elem["text"])
        story.append(p(raw_html, "Bodyx"))
        i += 1

    elif t == "code":
        code_text = elem["text"]
        story.append(code_block(code_text))
        story.append(Spacer(1, 0.2 * cm))
        i += 1

    elif t == "table":
        story.append(Spacer(1, 0.15 * cm))
        story.append(make_table(elem["headers"], elem["rows"]))
        story.append(Spacer(1, 0.3 * cm))
        i += 1

    elif t == "hr":
        story.append(Spacer(1, 0.3 * cm))
        i += 1

    elif t == "blockquote":
        body = md_to_html(elem["text"])
        if "sécurité" in body.lower() or "fail" in body.lower():
            bg = ORANGE_BG
        elif "interne" in body.lower() or "déploiement" in body.lower():
            bg = LIGHT_BLUE
        elif "version" in body.lower() or "août" in body.lower():
            bg = LIGHT_BLUE
        else:
            bg = LIGHT_BLUE
        story.append(callout("Note", body, bg))
        story.append(Spacer(1, 0.1 * cm))
        i += 1

    elif t == "bullets":
        first = True
        for item in elem["items"]:
            if not first:
                story.append(Spacer(1, 0.05 * cm))
            story.append(bullet(md_to_html(item)))
            first = False
        story.append(Spacer(1, 0.15 * cm))
        i += 1

    elif t == "numbered":
        for idx, item in enumerate(elem["items"], 1):
            story.append(numbered_bullet(idx, md_to_html(item)))
        story.append(Spacer(1, 0.15 * cm))
        i += 1

    else:
        i += 1


# ── Génération du PDF ────────────────────────────────────────────────
doc.build(story)
print(f"[OK] PDF généré : {OUT}")
print(f"     Taille : {OUT.stat().st_size:,} octets")
