#!/usr/bin/env python3
"""Génère un guide opérationnel PDF depuis le Markdown du dépôt."""

from __future__ import annotations

import re
from html import escape as html_escape
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    XPreformatted,
)

ROOT = Path(__file__).resolve().parents[1]
if Path(__file__).stem == "create_fortiflow_pdf":
    PROJECT = "FortiFlow"
    MD_PATH = ROOT / "docs" / "TUTORIEL.md"
    OUT_PATH = ROOT / "docs" / "fortiflow-tutoriel.pdf"
    SUMMARY = (
        "Déployer un conteneur FortiFlow avec Portainer Repository, "
        "valider son état de santé et publier le service en HTTPS."
    )
else:
    PROJECT = "Upgrade Path"
    MD_PATH = ROOT / "docs" / "upgrade-path-tutoriel.md"
    OUT_PATH = ROOT / "docs" / "pdf" / "upgrade-path-tutoriel.pdf"
    SUMMARY = (
        "Déployer les services web et scheduler avec Portainer Repository, "
        "valider leur fonctionnement et publier le service en HTTPS."
    )

FONT_REGULAR = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
pdfmetrics.registerFont(TTFont("DejaVu", FONT_REGULAR))
pdfmetrics.registerFont(TTFont("DejaVu-Bold", FONT_BOLD))
pdfmetrics.registerFont(TTFont("DejaVuMono", FONT_MONO))

PAGE_W, PAGE_H = A4
MARGIN_X = 1.45 * cm
MARGIN_TOP = 1.4 * cm
MARGIN_BOTTOM = 1.75 * cm
CONTENT_W = PAGE_W - 2 * MARGIN_X

NAVY = colors.HexColor("#0F2747")
BLUE = colors.HexColor("#1976D2")
TEAL = colors.HexColor("#00897B")
GRAY = colors.HexColor("#52606D")
DARK_TEXT = colors.HexColor("#263238")
BORDER = colors.HexColor("#D9E2EC")
LIGHT_BLUE = colors.HexColor("#EAF3FF")
LIGHT_GREEN = colors.HexColor("#EAF8F1")
ORANGE_BG = colors.HexColor("#FFF3E0")
CODE_BG = colors.HexColor("#F4F7FA")
CODE_TEXT = colors.HexColor("#13293D")
ROW_ALT = colors.HexColor("#FAFBFC")

styles = getSampleStyleSheet()
styles.add(
    ParagraphStyle(
        name="CoverTitle",
        parent=styles["Title"],
        fontName="DejaVu-Bold",
        fontSize=24,
        leading=30,
        textColor=NAVY,
        alignment=TA_CENTER,
        spaceAfter=10,
    )
)
styles.add(
    ParagraphStyle(
        name="CoverSubtitle",
        parent=styles["Normal"],
        fontName="DejaVu",
        fontSize=10.5,
        leading=15,
        textColor=GRAY,
        alignment=TA_CENTER,
        spaceAfter=18,
    )
)
styles.add(
    ParagraphStyle(
        name="TOCTitle",
        parent=styles["Heading1"],
        fontName="DejaVu-Bold",
        fontSize=17,
        leading=22,
        textColor=NAVY,
        spaceAfter=14,
    )
)
styles.add(
    ParagraphStyle(
        name="TOCEntry",
        parent=styles["BodyText"],
        fontName="DejaVu",
        fontSize=10.2,
        leading=20,
        textColor=DARK_TEXT,
        leftIndent=8,
    )
)
styles.add(
    ParagraphStyle(
        name="H1",
        parent=styles["Heading1"],
        fontName="DejaVu-Bold",
        fontSize=16,
        leading=21,
        textColor=NAVY,
        spaceBefore=16,
        spaceAfter=8,
        keepWithNext=True,
    )
)
styles.add(
    ParagraphStyle(
        name="H2",
        parent=styles["Heading2"],
        fontName="DejaVu-Bold",
        fontSize=11.5,
        leading=15,
        textColor=BLUE,
        spaceBefore=10,
        spaceAfter=5,
        keepWithNext=True,
    )
)
styles.add(
    ParagraphStyle(
        name="Body",
        parent=styles["BodyText"],
        fontName="DejaVu",
        fontSize=9.2,
        leading=13.5,
        textColor=DARK_TEXT,
        spaceAfter=6,
    )
)
styles.add(
    ParagraphStyle(
        name="Bulletx",
        parent=styles["BodyText"],
        fontName="DejaVu",
        fontSize=9.1,
        leading=13,
        textColor=DARK_TEXT,
        leftIndent=13,
        firstLineIndent=-10,
        spaceAfter=3,
    )
)
styles.add(
    ParagraphStyle(
        name="Codex",
        parent=styles["Code"],
        fontName="DejaVuMono",
        fontSize=7.2,
        leading=10.2,
        textColor=CODE_TEXT,
    )
)
styles.add(
    ParagraphStyle(
        name="TableHead",
        parent=styles["BodyText"],
        fontName="DejaVu-Bold",
        fontSize=8.4,
        leading=11,
        textColor=colors.white,
    )
)
styles.add(
    ParagraphStyle(
        name="TableBody",
        parent=styles["BodyText"],
        fontName="DejaVu",
        fontSize=8.2,
        leading=11,
        textColor=DARK_TEXT,
    )
)


def sanitize(text: str) -> str:
    replacements = {
        "\u00a0": " ",
        "\u2011": "-",
        "\u2013": "-",
        "\u2014": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2026": "...",
        "\u2192": "->",
        "\u2265": ">=",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    return text


def inline(text: str) -> str:
    text = html_escape(sanitize(text), quote=False)
    text = re.sub(
        r"`([^`]+)`",
        r'<font face="DejaVuMono" size="8" color="#13293D">\1</font>',
        text,
    )
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"\*(.+?)\*", r"<i>\1</i>", text)
    return text


def para(text: str, style: str = "Body") -> Paragraph:
    return Paragraph(text, styles[style])


def parse_markdown(text: str) -> list[dict]:
    lines = text.splitlines()
    elements: list[dict] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if line.startswith("# "):
            elements.append({"type": "title", "text": line[2:].strip()})
            index += 1
            continue
        if line.startswith("## "):
            elements.append({"type": "h1", "text": line[3:].strip()})
            index += 1
            continue
        if line.startswith("### "):
            elements.append({"type": "h2", "text": line[4:].strip()})
            index += 1
            continue
        if stripped.startswith("```"):
            code_lines: list[str] = []
            index += 1
            while index < len(lines) and not lines[index].strip().startswith("```"):
                code_lines.append(lines[index])
                index += 1
            index += 1
            elements.append({"type": "code", "text": "\n".join(code_lines)})
            continue
        if (
            "|" in line
            and index + 1 < len(lines)
            and re.match(r"^\|?[\s\-:|]+\|?$", lines[index + 1].strip())
        ):
            headers = [cell.strip() for cell in line.strip().strip("|").split("|")]
            index += 2
            rows: list[list[str]] = []
            while index < len(lines) and "|" in lines[index]:
                rows.append(
                    [cell.strip() for cell in lines[index].strip().strip("|").split("|")]
                )
                index += 1
            elements.append(
                {"type": "table", "headers": headers, "rows": rows}
            )
            continue
        if stripped.startswith("> "):
            quote_lines: list[str] = []
            while index < len(lines) and lines[index].strip().startswith("> "):
                quote_lines.append(lines[index].strip()[2:])
                index += 1
            elements.append({"type": "quote", "text": " ".join(quote_lines)})
            continue
        if stripped.startswith("- "):
            items: list[str] = []
            while index < len(lines) and lines[index].strip().startswith("- "):
                items.append(lines[index].strip()[2:])
                index += 1
            elements.append({"type": "bullets", "items": items})
            continue
        if re.match(r"^\d+\.\s", stripped):
            items = []
            while index < len(lines) and re.match(r"^\d+\.\s", lines[index].strip()):
                items.append(re.sub(r"^\d+\.\s+", "", lines[index].strip()))
                index += 1
            elements.append({"type": "numbered", "items": items})
            continue
        if stripped == "---":
            elements.append({"type": "rule"})
            index += 1
            continue
        if not stripped:
            index += 1
            continue

        paragraph_lines = [stripped]
        index += 1
        while index < len(lines) and lines[index].strip():
            candidate = lines[index].strip()
            if (
                candidate.startswith("#")
                or candidate.startswith("```")
                or candidate.startswith("> ")
                or candidate.startswith("- ")
                or re.match(r"^\d+\.\s", candidate)
                or candidate == "---"
                or (
                    "|" in lines[index]
                    and index + 1 < len(lines)
                    and re.match(r"^\|?[\s\-:|]+\|?$", lines[index + 1].strip())
                )
            ):
                break
            paragraph_lines.append(candidate)
            index += 1
        elements.append({"type": "paragraph", "text": " ".join(paragraph_lines)})
    return elements


def code_block(text: str) -> Table:
    block = XPreformatted(html_escape(sanitize(text)), styles["Codex"])
    table = Table([[block]], colWidths=[CONTENT_W])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return table


def callout(title: str, body: str, background=LIGHT_BLUE) -> Table:
    table = Table(
        [[para(f"<b>{title}</b><br/>{body}")]],
        colWidths=[CONTENT_W],
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), background),
                ("BOX", (0, 0), (-1, -1), 0.7, BORDER),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return table


def markdown_table(headers: list[str], rows: list[list[str]]) -> Table:
    column_count = len(headers)
    if column_count == 2:
        widths = [CONTENT_W * 0.34, CONTENT_W * 0.66]
    else:
        widths = [CONTENT_W / column_count] * column_count
    data = [[para(inline(cell), "TableHead") for cell in headers]]
    for row in rows:
        padded = (row + [""] * column_count)[:column_count]
        data.append([para(inline(cell), "TableBody") for cell in padded])
    table = Table(data, colWidths=widths, repeatRows=1)
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]
    for row_index in range(1, len(data)):
        commands.append(
            (
                "BACKGROUND",
                (0, row_index),
                (-1, row_index),
                ROW_ALT if row_index % 2 == 0 else colors.white,
            )
        )
    table.setStyle(TableStyle(commands))
    return table


def footer(canvas, document) -> None:
    canvas.saveState()
    canvas.setStrokeColor(BORDER)
    canvas.line(
        MARGIN_X,
        MARGIN_BOTTOM - 0.43 * cm,
        PAGE_W - MARGIN_X,
        MARGIN_BOTTOM - 0.43 * cm,
    )
    canvas.setFont("DejaVu", 7.5)
    canvas.setFillColor(GRAY)
    canvas.drawString(
        MARGIN_X,
        MARGIN_BOTTOM - 0.88 * cm,
        f"{PROJECT} - Guide opérationnel",
    )
    canvas.drawRightString(
        PAGE_W - MARGIN_X,
        MARGIN_BOTTOM - 0.88 * cm,
        f"Page {document.page}",
    )
    canvas.restoreState()


def build_story(elements: list[dict]) -> list:
    chapters = [element for element in elements if element["type"] == "h1"]
    story: list = [Spacer(1, 2.0 * cm)]
    story.append(para(PROJECT, "CoverTitle"))
    story.append(
        para(
            "GUIDE OPÉRATIONNEL<br/>Portainer Repository • GHCR • HTTPS",
            "CoverSubtitle",
        )
    )
    story.append(Spacer(1, 0.25 * cm))
    story.append(callout("OBJECTIF", inline(SUMMARY), LIGHT_GREEN))
    story.append(Spacer(1, 0.65 * cm))
    story.append(
        callout(
            "MÉTHODE",
            "Dépôt GitHub public, image GHCR et redéploiement depuis Portainer. "
            "Déploiement reproductible depuis le dépôt et le registre.",
            LIGHT_BLUE,
        )
    )
    story.append(PageBreak())

    story.append(para("SOMMAIRE", "TOCTitle"))
    story.append(Spacer(1, 0.1 * cm))
    for chapter in chapters:
        story.append(para(inline(chapter["text"]), "TOCEntry"))
    story.append(PageBreak())

    body_started = False
    for element in elements:
        kind = element["type"]
        if kind == "h1":
            body_started = True
            story.append(para(inline(element["text"]), "H1"))
        elif not body_started:
            continue
        elif kind == "h2":
            story.append(para(inline(element["text"]), "H2"))
        elif kind == "paragraph":
            story.append(para(inline(element["text"])))
        elif kind == "code":
            story.append(code_block(element["text"]))
            story.append(Spacer(1, 0.18 * cm))
        elif kind == "table":
            story.append(markdown_table(element["headers"], element["rows"]))
            story.append(Spacer(1, 0.22 * cm))
        elif kind == "quote":
            text = inline(element["text"])
            background = ORANGE_BG if "jamais" in element["text"].lower() else LIGHT_BLUE
            story.append(callout("NOTE", text, background))
            story.append(Spacer(1, 0.1 * cm))
        elif kind == "bullets":
            for item in element["items"]:
                story.append(para("•  " + inline(item), "Bulletx"))
            story.append(Spacer(1, 0.08 * cm))
        elif kind == "numbered":
            for item_index, item in enumerate(element["items"], start=1):
                story.append(para(f"{item_index}.  {inline(item)}", "Bulletx"))
            story.append(Spacer(1, 0.08 * cm))
        elif kind == "rule":
            story.append(Spacer(1, 0.2 * cm))
    return story


def main() -> None:
    markdown = MD_PATH.read_text(encoding="utf-8")
    elements = parse_markdown(markdown)
    chapters = [element["text"] for element in elements if element["type"] == "h1"]
    expected = [
        "1. Prérequis",
        "2. Préparer le serveur cible",
        "3. Déployer avec Portainer",
        "4. Vérifier le déploiement",
        "5. Configurer HTTPS",
        "6. Mettre à jour",
        "7. Dépannage",
        "8. Checklist finale",
    ]
    if chapters != expected:
        raise ValueError(f"Chapitres invalides : {chapters!r}")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    document = BaseDocTemplate(
        str(OUT_PATH),
        pagesize=A4,
        leftMargin=MARGIN_X,
        rightMargin=MARGIN_X,
        topMargin=MARGIN_TOP,
        bottomMargin=MARGIN_BOTTOM,
        title=f"{PROJECT} - Guide opérationnel",
        author="Documentation technique",
        subject="Déploiement Portainer, HTTPS et mise à jour",
    )
    frame = Frame(
        MARGIN_X,
        MARGIN_BOTTOM,
        CONTENT_W,
        PAGE_H - MARGIN_TOP - MARGIN_BOTTOM,
        id="content",
    )
    document.addPageTemplates(
        [PageTemplate(id="guide", frames=[frame], onPage=footer)]
    )
    document.build(build_story(elements))
    print(f"[OK] PDF généré : {OUT_PATH}")
    print(f"     Taille : {OUT_PATH.stat().st_size:,} octets")


if __name__ == "__main__":
    main()
