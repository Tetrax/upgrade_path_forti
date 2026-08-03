from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    KeepTogether, PageBreak,
)

OUT = "/opt/data/upgrade-path-migration-portainer.pdf"
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
pdfmetrics.registerFont(TTFont("DejaVu", FONT))
pdfmetrics.registerFont(TTFont("DejaVu-Bold", FONT_BOLD))
pdfmetrics.registerFont(TTFont("DejaVuMono", FONT_MONO))

NAVY = colors.HexColor("#0F2747")
BLUE = colors.HexColor("#1976D2")
LIGHT_BLUE = colors.HexColor("#EAF3FF")
LIGHT_GREEN = colors.HexColor("#EAF8F1")
ORANGE = colors.HexColor("#FFF3E0")
GRAY = colors.HexColor("#52606D")
BORDER = colors.HexColor("#D9E2EC")

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="CoverTitle", parent=styles["Title"], fontName="DejaVu-Bold", fontSize=24, leading=30, textColor=NAVY, alignment=TA_CENTER, spaceAfter=12))
styles.add(ParagraphStyle(name="Subtitle", parent=styles["Normal"], fontName="DejaVu", fontSize=11, leading=16, textColor=GRAY, alignment=TA_CENTER, spaceAfter=20))
styles.add(ParagraphStyle(name="H1x", parent=styles["Heading1"], fontName="DejaVu-Bold", fontSize=16, leading=21, textColor=NAVY, spaceBefore=16, spaceAfter=8))
styles.add(ParagraphStyle(name="H2x", parent=styles["Heading2"], fontName="DejaVu-Bold", fontSize=12, leading=16, textColor=BLUE, spaceBefore=11, spaceAfter=5))
styles.add(ParagraphStyle(name="Bodyx", parent=styles["BodyText"], fontName="DejaVu", fontSize=9.4, leading=14, textColor=colors.HexColor("#263238"), spaceAfter=6))
styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontName="DejaVu", fontSize=8, leading=11, textColor=GRAY))
styles.add(ParagraphStyle(name="Codex", parent=styles["Code"], fontName="DejaVuMono", fontSize=8.3, leading=12, textColor=colors.HexColor("#13293D")))
styles.add(ParagraphStyle(name="TableHead", parent=styles["BodyText"], fontName="DejaVu-Bold", fontSize=9, leading=12, textColor=colors.white))
styles.add(ParagraphStyle(name="Bulletx", parent=styles["BodyText"], fontName="DejaVu", fontSize=9.2, leading=13, leftIndent=13, firstLineIndent=-10, spaceAfter=3))


def p(text, style="Bodyx"):
    return Paragraph(text, styles[style])


def code(text):
    escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>")
    table = Table([[Paragraph(escaped, styles["Codex"])]], colWidths=[17.2 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F4F7FA")),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return table


def callout(title, body, background=LIGHT_BLUE):
    table = Table([[p(f"<b>{title}</b><br/>{body}", "Bodyx")]], colWidths=[17.2 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), background),
        ("BOX", (0, 0), (-1, -1), 0.7, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return table


def bullet(text):
    return p("• " + text, "Bulletx")


def numbered_bullet(num, text):
    return p(f"{num}.  {text}", "Bulletx")


def make_table(headers, rows):
    """Crée un tableau avec en-tête bleu marine et rayures alternées."""
    head_row = [p(h, "TableHead") for h in headers]
    data_rows = [[p(cell, "Bodyx") for cell in row] for row in rows]
    data = [head_row] + data_rows

    ncols = len(headers)
    col_width = 17.2 * cm / ncols

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


def sanitize_unicode(text):
    """Remplace les caractères Unicode absents des polices DejaVu."""
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


def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(BORDER)
    canvas.line(1.4 * cm, 1.25 * cm, 19.6 * cm, 1.25 * cm)
    canvas.setFont("DejaVu", 7.5)
    canvas.setFillColor(GRAY)
    canvas.drawString(1.4 * cm, 0.8 * cm, "Upgrade Path — migration Portainer")
    canvas.drawRightString(19.6 * cm, 0.8 * cm, f"Page {doc.page}")
    canvas.restoreState()


doc = SimpleDocTemplate(OUT, pagesize=A4, rightMargin=1.4 * cm, leftMargin=1.4 * cm, topMargin=1.35 * cm, bottomMargin=1.7 * cm, title="Migration Upgrade Path vers Portainer")
story = []
story += [Spacer(1, 1.5 * cm), p("Upgrade Path", "CoverTitle"), p("Migration vers une VM interne via Portainer Community Edition", "Subtitle")]
story.append(callout("Objectif", "Déployer l'application <b>sans Nginx interne</b>, accessible depuis le LAN sur <b>http://IP_LOCALE_VM:8000/app/</b>. Les données actuelles sont transportées dans l'image initiale puis conservées dans des volumes Docker nommés.", LIGHT_GREEN))
story += [Spacer(1, 0.5 * cm), p("Pré-requis", "H1x")]
for item in [
    "Une VM interne avec Docker et Portainer Community Edition fonctionnels.",
    "Un poste ouvrant l'interface web Portainer et disposant de suffisamment d'espace disque pour l'image exportée.",
    "Un accès LAN à la VM interne, avec une règle firewall autorisant TCP/8000 uniquement depuis les sous-réseaux nécessaires.",
    "Ne pas arrêter l'instance source avant la validation complète de la cible.",
]: story.append(bullet(item))
story += [p("Fichiers nécessaires", "H2x")]
data = [[p("Fichier", "TableHead"), p("Origine", "TableHead"), p("Utilisation", "TableHead")],
        [p("docker-compose.portainer-import.yml", "Bodyx"), p("Téléchargé depuis Hermes", "Bodyx"), p("Import de la Stack dans Portainer", "Bodyx")],
        [p("fortios-upgrade-intelligence.tar", "Bodyx"), p("Exporté depuis la VM source", "Bodyx"), p("Import de l'image dans Portainer", "Bodyx")]]
t = Table(data, colWidths=[5.3 * cm, 5.3 * cm, 6.6 * cm], repeatRows=1)
t.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), NAVY), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("FONTNAME", (0,0), (-1,0), "DejaVu-Bold"), ("GRID", (0,0), (-1,-1), 0.4, BORDER), ("VALIGN", (0,0), (-1,-1), "TOP"), ("LEFTPADDING", (0,0), (-1,-1), 7), ("RIGHTPADDING", (0,0), (-1,-1), 7), ("TOPPADDING", (0,0), (-1,-1), 6), ("BOTTOMPADDING", (0,0), (-1,-1), 6), ("BACKGROUND", (0,1), (-1,-1), colors.white)]))
story += [t, Spacer(1, 0.35 * cm), callout("Important", "Garder l'archive image au format <b>.tar</b>. Ne pas la compresser en <b>.tar.gz</b> : l'action <b>Import</b> de Portainer attend l'archive produite par <b>docker save</b>.", ORANGE), PageBreak()]

story += [p("1. Préparer l'image sur la VM source", "H1x"), p("Depuis le répertoire du projet, construire puis exporter une image contenant l'application et les données présentes au moment de la construction.")]
story += [code("cd ~/workspace/upgrade_path\n\ndocker build -t fortios-upgrade-intelligence:local .\n\ndocker save fortios-upgrade-intelligence:local \\\n  -o ~/fortios-upgrade-intelligence.tar"), Spacer(1, 0.2 * cm)]
story += [bullet("Télécharger ou transférer ensuite <b>~/fortios-upgrade-intelligence.tar</b> sur le poste qui ouvre Portainer."), bullet("Télécharger également le fichier <b>docker-compose.portainer-import.yml</b> depuis Hermes sur ce même poste."), callout("Contenu transféré", "L'image initiale contient le catalogue, CVE, alertes, compatibilités, état de santé, historique de notifications, rapports et images d'alertes. Elle n'intègre ni certificat TLS ni secret SMTP.", LIGHT_BLUE)]

story += [p("2. Importer l'image dans Portainer", "H1x")]
for item in [
    "Ouvrir Portainer et sélectionner l'environnement Docker cible, par exemple <b>local</b>.",
    "Dans le menu latéral, ouvrir <b>Images</b> — ne pas aller dans <b>Registries</b>.",
    "Au-dessus de la liste des images, cliquer <b>Import</b>, entre <b>Remove</b> et <b>Export</b>.",
    "Sélectionner <b>fortios-upgrade-intelligence.tar</b>, puis confirmer l'import.",
    "Attendre la fin de l'opération et vérifier que le tag <b>fortios-upgrade-intelligence:local</b> est visible dans la liste.",
]: story.append(bullet(item))

story += [p("3. Déployer la Stack", "H1x")]
for item in [
    "Dans le menu latéral, ouvrir <b>Stacks</b>, puis cliquer <b>Add stack</b>.",
    "Nommer la Stack <b>upgrade-path</b>.",
    "Choisir <b>Upload</b>, puis sélectionner <b>docker-compose.portainer-import.yml</b> téléchargé à l'étape initiale.",
    "Dans la section <b>Environment variables</b>, ajouter les variables ci-dessous.",
]: story.append(bullet(item))
story += [code("PUID=1000\nPGID=1000\n\nFORTIOS_HTTP_BIND_ADDRESS=0.0.0.0\nFORTIOS_HTTP_PORT=8000\n\nFORTIOS_RUN_ON_START=0\n\nFORTIOS_EMAIL_ENABLED=false"), Spacer(1, 0.18 * cm)]
story += [bullet("Cliquer <b>Deploy the stack</b>."), callout("Notifications email", "Conserver <b>FORTIOS_EMAIL_ENABLED=false</b> pour la migration initiale. Ajouter les variables <b>FORTIOS_SMTP_*</b> uniquement si les notifications doivent être activées ; ne jamais mettre de secrets dans l'image ou dans Git.", ORANGE)]

story += [p("4. Vérifier le démarrage", "H1x")]
for item in [
    "Dans <b>Containers</b>, vérifier que <b>upgrade-path-web-1</b> et <b>upgrade-path-scheduler-1</b> sont démarrés.",
    "Ouvrir les logs de <b>upgrade-path-web-1</b> : une ligne proche de <b>FortiOS Upgrade Intelligence: http://0.0.0.0:8000/app/</b> doit apparaître.",
    "Ouvrir les logs de <b>upgrade-path-scheduler-1</b> : il doit annoncer le prochain créneau de collecte.",
    "Conserver <b>FORTIOS_RUN_ON_START=0</b>. Le scheduler attendra automatiquement 07:00 (collecte complète) et 15:30 (CVE), heure Europe/Paris.",
]: story.append(bullet(item))

story += [p("5. Accès LAN sans Nginx", "H1x")]
story += [callout("URL d'accès", "Depuis un poste autorisé du réseau interne, ouvrir :<br/><b>http://IP_LOCALE_DE_LA_VM:8000/app/</b><br/><br/>Utiliser l'adresse IP de la VM Docker, jamais l'adresse IP interne d'un conteneur.", LIGHT_GREEN)]
story += [Spacer(1, 0.2 * cm)]
for item in [
    "Autoriser TCP/8000 sur le firewall de la VM uniquement depuis les VLAN ou sous-réseaux internes nécessaires.",
    "Ne jamais publier TCP/8000 vers Internet.",
    "Ce fonctionnement est en HTTP : il n'y a pas d'alerte de certificat, mais les échanges ne sont pas chiffrés.",
    "Pour HTTPS, un nom DNS interne et un certificat approuvé, ajouter plus tard un reverse proxy avec certificat de PKI interne.",
]: story.append(bullet(item))

story += [p("6. Données persistantes et maintenance", "H1x")]
story += [p("La Stack crée deux volumes Docker nommés, généralement <b>upgrade-path_fortios-data</b> et <b>upgrade-path_fortios-docs</b>. Ils reçoivent les données de l'image lors du premier démarrage et conservent ensuite les nouvelles collectes.")]
story.append(callout("Ne pas supprimer les volumes", "Tu peux redémarrer les conteneurs ou redéployer la Stack, mais ne supprime pas ces deux volumes : cela supprimerait les données accumulées depuis la migration. Conserver le VPS source en fonctionnement jusqu'à validation complète de la VM interne.", ORANGE))

doc.build(story, onFirstPage=footer, onLaterPages=footer)
print(OUT)
