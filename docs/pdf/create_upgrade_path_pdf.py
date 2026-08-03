from __future__ import annotations

from html import escape
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Frame, KeepTogether, PageBreak, PageTemplate,
    Paragraph, Spacer, Table, TableStyle, XPreformatted,
)

OUTPUT = Path("/opt/data/upgrade-path-migration-portainer-tls.pdf")
PW, PH = A4
MX, MT, MB = 1.4 * cm, 1.35 * cm, 1.7 * cm
CW = PW - 2 * MX
NAVY = colors.HexColor("#0F2747")
BLUE = colors.HexColor("#1976D2")
INK = colors.HexColor("#243B53")
MUTED = colors.HexColor("#627D98")
LINE = colors.HexColor("#BCCCDC")
PALE_BLUE = colors.HexColor("#EAF3FB")
PALE_CYAN = colors.HexColor("#E8F7F8")
PALE_YELLOW = colors.HexColor("#FFF8DB")
PALE_RED = colors.HexColor("#FDECEC")
CODE_BG = colors.HexColor("#F4F7FA")

FONT_DIR = "/usr/share/fonts/truetype/dejavu"
pdfmetrics.registerFont(TTFont("DV", f"{FONT_DIR}/DejaVuSans.ttf"))
pdfmetrics.registerFont(TTFont("DV-B", f"{FONT_DIR}/DejaVuSans-Bold.ttf"))
pdfmetrics.registerFont(TTFont("DVM", f"{FONT_DIR}/DejaVuSansMono.ttf"))

S = {
    "title": ParagraphStyle("title", fontName="DV-B", fontSize=24, leading=30,
                            textColor=NAVY, spaceAfter=7 * mm),
    "subtitle": ParagraphStyle("subtitle", fontName="DV", fontSize=11.5, leading=17,
                               textColor=MUTED, spaceAfter=6 * mm),
    "h1": ParagraphStyle("h1", fontName="DV-B", fontSize=16.5, leading=21,
                         textColor=NAVY, spaceAfter=4 * mm),
    "h2": ParagraphStyle("h2", fontName="DV-B", fontSize=12, leading=15,
                         textColor=BLUE, spaceBefore=3 * mm, spaceAfter=2 * mm),
    "body": ParagraphStyle("body", fontName="DV", fontSize=9, leading=13,
                           textColor=INK, spaceAfter=2.4 * mm),
    "small": ParagraphStyle("small", fontName="DV", fontSize=7.7, leading=10.2,
                            textColor=MUTED, spaceAfter=1.5 * mm),
    "bullet": ParagraphStyle("bullet", fontName="DV", fontSize=9, leading=12.5,
                             textColor=INK, leftIndent=5 * mm, firstLineIndent=-3.5 * mm,
                             bulletIndent=0, spaceAfter=1.3 * mm),
    "code": ParagraphStyle("code", fontName="DVM", fontSize=6.8, leading=9.1,
                           textColor=colors.HexColor("#1F2933")),
    "boxTitle": ParagraphStyle("boxTitle", fontName="DV-B", fontSize=9.2,
                               leading=12, textColor=NAVY, spaceAfter=1.3 * mm),
}


def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(LINE)
    canvas.line(MX, 11 * mm, PW - MX, 11 * mm)
    canvas.setFont("DV", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(MX, 6.5 * mm, "Upgrade Path — migration Portainer et TLS direct")
    canvas.drawRightString(PW - MX, 6.5 * mm, f"Page {doc.page}")
    canvas.restoreState()


def para(text, style="body"):
    return Paragraph(text, S[style])


def h(text, level=1):
    return para(text, "h1" if level == 1 else "h2")


def bullet(text):
    return Paragraph(text, S["bullet"], bulletText="•")


def code(text):
    content = XPreformatted(escape(text.strip()), S["code"])
    table = Table([[content]], colWidths=[CW])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
        ("BOX", (0, 0), (-1, -1), 0.6, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return KeepTogether([table, Spacer(1, 3 * mm)])


def callout(title, body, color=PALE_BLUE):
    table = Table([[[para(title, "boxTitle"), para(body)]]], colWidths=[CW])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("BOX", (0, 0), (-1, -1), 0.7,
         colors.HexColor("#C62828") if color == PALE_RED else BLUE),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return KeepTogether([table, Spacer(1, 4 * mm)])


def step(number, title, body):
    badge_style = ParagraphStyle(f"badge{number}{title[:3]}", fontName="DV-B",
                                 fontSize=11, leading=14, textColor=colors.white,
                                 alignment=1)
    table = Table([[Paragraph(f"<b>{number}</b>", badge_style),
                    [para(title, "boxTitle"), para(body)]]],
                  colWidths=[12 * mm, CW - 12 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), BLUE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (0, 0), 4),
        ("RIGHTPADDING", (0, 0), (0, 0), 4),
        ("TOPPADDING", (0, 0), (0, 0), 5),
        ("BOTTOMPADDING", (0, 0), (0, 0), 5),
        ("LEFTPADDING", (1, 0), (1, 0), 7),
        ("RIGHTPADDING", (1, 0), (1, 0), 0),
        ("TOPPADDING", (1, 0), (1, 0), 1),
    ]))
    return KeepTogether([table, Spacer(1, 3 * mm)])


doc = BaseDocTemplate(
    str(OUTPUT), pagesize=A4, leftMargin=MX, rightMargin=MX,
    topMargin=MT, bottomMargin=MB,
    title="Migration Upgrade Path vers Portainer et activation TLS",
    author="Hermes Agent",
    subject="Procédure Docker, Portainer et certificats pour Upgrade Path",
)
frame = Frame(MX, MB, CW, PH - MT - MB, id="main")
doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=footer)])

story = [
    Spacer(1, 15 * mm),
    para("PROCÉDURE D'EXPLOITATION", "small"),
    para("Migration Upgrade Path vers Docker / Portainer", "title"),
    para("Import d'une image <b>.tar</b>, déploiement d'une Stack à deux services, puis installation et activation d'un certificat TLS interne sans Nginx ni Caddy.", "subtitle"),
    callout("Architecture finale",
            "La Stack contient exactement <b>web</b> et <b>scheduler</b>. Le serveur Python utilise un listener unique : <b>HTTP sur le port hôte 8000</b> pendant l'amorçage, ou <b>HTTPS sur le port hôte 443</b> après activation TLS. Les deux protocoles ne sont jamais exposés en parallèle.", PALE_CYAN),
    callout("FQDN utilisé dans les exemples",
            "Cette procédure utilise <b>upgrade-path.sns-security.lan</b>. Le remplacer partout si le FQDN définitif est différent. Le certificat doit contenir ce nom dans un SAN DNS explicite.", PALE_YELLOW),
    h("Sommaire", 2),
    para("1. Prérequis et sécurité<br/>2. Construire et exporter l'image Docker<br/>3. Importer l'image et déployer la Stack Portainer<br/>4. Vérifier l'installation initiale en HTTP<br/>5. Installer un certificat PFX/P12<br/>6. Installer certificat, clé et chaîne séparés<br/>7. Activer et vérifier HTTPS<br/>8. Renouvellement et dépannage"),
    Spacer(1, 8 * mm),
    para("Version du document : 29 juillet 2026", "small"),
    PageBreak(),

    h("1. Prérequis et points de sécurité"),
    bullet("Une machine source équipée d'un moteur Docker fonctionnel pour construire et exporter l'image."),
    bullet("Une VM Docker interne administrée dans Portainer Community Edition."),
    bullet("Le fichier <b>docker-compose.portainer-import.yml</b> et l'archive Docker <b>.tar</b> accessibles depuis le poste qui ouvre Portainer."),
    bullet("Des règles firewall limitant TCP/8000 pendant l'amorçage et TCP/443 en production aux réseaux internes autorisés."),
    bullet("Pour HTTPS : DNS interne, certificat de la PKI interne, clé privée et chaîne d'émission éventuelle."),
    callout("Ne jamais transporter de secret dans Git ou dans l'image",
            "Les clés privées, certificats internes, mots de passe PFX et mots de passe SMTP restent hors du dépôt et hors du contexte de build. Le matériel TLS est stocké dans un volume Docker persistant séparé.", PALE_RED),
    h("Formats acceptés", 2),
    bullet("PKCS#12 : <b>.pfx</b>, <b>.p12</b>, protégé ou non par mot de passe."),
    bullet("Certificat PEM ou DER avec clé PEM/PKCS#8 séparée, chiffrée ou non."),
    bullet("Chaîne PEM, DER ou PKCS#7 : <b>.p7b</b> / <b>.p7c</b>."),
    h("Contrôles réalisés par fortios-certctl", 2),
    bullet("SAN DNS et correspondance avec le FQDN ; un CN seul est refusé."),
    bullet("Dates, usage TLS serveur, paire certificat/clé et cohérence cryptographique de la chaîne."),
    bullet("Activation atomique, verrou interprocessus et suppression des générations remplacées."),
    bullet("Dans le conteneur, la clé reste propriété de root et n'est lisible que par le groupe applicatif."),
    callout("PKI interne obligatoire pour .lan",
            "Let's Encrypt ne signe normalement pas un suffixe privé <b>.lan</b>. La CA interne doit être distribuée aux postes, typiquement par GPO ou MDM. Un certificat valdev.me ne couvre pas sns-security.lan.", PALE_YELLOW),
    PageBreak(),

    h("2. Construire et exporter l'image Docker"),
    para("Exécuter sur la machine source, depuis la version validée du dépôt. Ne pas arrêter l'ancienne instance à ce stade."),
    code("""cd /chemin/vers/upgrade_path

git status --short
docker build --pull \\
  -t fortios-upgrade-intelligence:local .

docker image inspect fortios-upgrade-intelligence:local \\
  --format '{{.Id}} {{.Created}}'

docker save \\
  -o ~/fortios-upgrade-intelligence.tar \\
  fortios-upgrade-intelligence:local

sha256sum ~/fortios-upgrade-intelligence.tar \\
  > ~/fortios-upgrade-intelligence.tar.sha256
ls -lh ~/fortios-upgrade-intelligence.tar*"""),
    callout("Archive attendue",
            "Conserver le format <b>.tar</b> produit par <b>docker save</b>. Ne pas convertir l'archive en <b>.tar.gz</b> pour l'import Portainer."),
    h("Fichiers à transférer vers le poste Portainer", 2),
    bullet("<b>fortios-upgrade-intelligence.tar</b>"),
    bullet("<b>docker-compose.portainer-import.yml</b>"),
    bullet("Le fichier <b>.sha256</b>, facultatif mais recommandé pour contrôler le transfert."),
    code("sha256sum -c fortios-upgrade-intelligence.tar.sha256"),
    PageBreak(),

    h("3. Importer l'image et déployer la Stack"),
    step("1", "Importer l'image", "Dans Portainer, ouvrir l'environnement Docker cible, puis <b>Images</b>. Cliquer <b>Import</b>, sélectionner l'archive .tar et attendre la fin."),
    step("2", "Contrôler l'image", "Vérifier la présence exacte de <b>fortios-upgrade-intelligence:local</b>. Aucun registre ni pull n'est nécessaire pour cette image locale."),
    step("3", "Créer la Stack", "Ouvrir <b>Stacks → Add stack</b>, saisir <b>upgrade-path</b>, choisir <b>Upload</b> et sélectionner <b>docker-compose.portainer-import.yml</b>."),
    step("4", "Ajouter les variables initiales", "Dans <b>Environment variables</b>, saisir les valeurs ci-dessous. PUID et PGID doivent être strictement supérieurs à zéro."),
    code("""PUID=1000
PGID=1000
FORTIOS_HTTP_BIND_ADDRESS=0.0.0.0
FORTIOS_HTTP_PORT=8000
FORTIOS_TLS_CERT=
FORTIOS_TLS_KEY=
FORTIOS_TLS_HOSTNAME=
FORTIOS_RUN_ON_START=0
FORTIOS_EMAIL_ENABLED=false
FORTIOS_APP_URL=http://IP_LAN_VM:8000/app/"""),
    step("5", "Déployer", "Cliquer <b>Deploy the stack</b>. La Stack doit créer uniquement les services <b>web</b> et <b>scheduler</b>."),
    callout("Volumes à préserver",
            "Ne jamais supprimer les volumes <b>fortios-data</b>, <b>fortios-docs</b> et <b>fortios-certificates</b> pendant une mise à jour ou une recréation de Stack.", PALE_RED),
    para("Pour SMTP, ne pas placer le mot de passe dans les variables visibles de la Stack. Monter un fichier secret en lecture seule et utiliser <b>FORTIOS_SMTP_PASSWORD_FILE</b>.", "small"),
    PageBreak(),

    h("4. Vérifier le déploiement HTTP initial"),
    step("1", "Contrôler les conteneurs", "Dans <b>Containers</b>, vérifier que web et scheduler sont en cours d'exécution et que web devient <b>healthy</b>."),
    step("2", "Contrôler les logs", "Le service web doit annoncer HTTP sur le listener interne 8000. Le scheduler doit annoncer 07:00 et 15:30, fuseau Europe/Paris."),
    step("3", "Tester depuis le LAN", "Ouvrir <b>http://IP_LAN_VM:8000/app/</b>. Autoriser le port 8000 uniquement depuis les réseaux internes nécessaires."),
    h("Contrôles depuis la VM Docker", 2),
    code("""docker ps --filter label=com.docker.compose.project=upgrade-path

WEB_CONTAINER="$(docker ps \\
  --filter label=com.docker.compose.project=upgrade-path \\
  --filter label=com.docker.compose.service=web \\
  --format '{{.Names}}')"

printf 'Conteneur web : %s\n' "$WEB_CONTAINER"
docker logs --tail 50 "$WEB_CONTAINER"
docker inspect --format '{{.State.Health.Status}}' \\
  "$WEB_CONTAINER"""),
    callout("Résultat obligatoire",
            "WEB_CONTAINER doit contenir un seul nom. S'il est vide ou contient plusieurs lignes, vérifier le nom réel de la Stack avant de poursuivre.", PALE_YELLOW),
    para("Conserver normalement <b>FORTIOS_RUN_ON_START=0</b>. Pour une collecte initiale contrôlée, le passer temporairement à 1, redémarrer scheduler, attendre la fin dans les logs, puis le remettre à 0."),
    PageBreak(),

    h("5. Installer un certificat PFX / P12"),
    callout("À exécuter en SSH sur la VM Docker",
            "Utiliser un shell SSH sur la VM, pas la console web Portainer pour ces blocs multilignes. Adapter le chemin et le FQDN avant de coller les commandes.", PALE_CYAN),
    h("5.1 Identifier le conteneur web", 2),
    code("""FQDN='upgrade-path.sns-security.lan'
WEB_CONTAINER="$(docker ps \\
  --filter label=com.docker.compose.project=upgrade-path \\
  --filter label=com.docker.compose.service=web \\
  --format '{{.Names}}')"

printf 'Conteneur web : %s\n' "$WEB_CONTAINER"
test -n "$WEB_CONTAINER"""),
    h("5.2 Copier puis installer un PFX protégé", 2),
    code("""docker cp /chemin/serveur-interne.pfx \\
  "$WEB_CONTAINER":/tmp/certificat.pfx

read -rsp 'Mot de passe PFX : ' PFX_PASSWORD; echo
printf '%s' "$PFX_PASSWORD" | \\
  docker exec -i "$WEB_CONTAINER" \\
  sh -c 'umask 077; cat > /tmp/cert-password'
unset PFX_PASSWORD

docker exec "$WEB_CONTAINER" fortios-certctl install \\
  /tmp/certificat.pfx \\
  --password-file /tmp/cert-password \\
  --hostname "$FQDN" \\
  --output-dir /opt/fortios/certificates/active
INSTALL_RC=$?

docker exec "$WEB_CONTAINER" rm -f \\
  /tmp/certificat.pfx /tmp/cert-password

test "$INSTALL_RC" -eq 0"""),
    para("Pour un PFX sans mot de passe, omettre la création de <b>/tmp/cert-password</b> et l'option <b>--password-file</b>.", "small"),
    PageBreak(),

    h("6. Installer certificat, clé et chaîne séparés"),
    para("Méthode pour les certificats PEM ou DER, les clés PEM/PKCS#8 et les chaînes PEM, DER ou PKCS#7."),
    h("6.1 Copier les fichiers", 2),
    code("""FQDN='upgrade-path.sns-security.lan'

docker cp /chemin/serveur.crt \\
  "$WEB_CONTAINER":/tmp/serveur.crt
docker cp /chemin/serveur.key \\
  "$WEB_CONTAINER":/tmp/serveur.key
docker cp /chemin/chaine.p7b \\
  "$WEB_CONTAINER":/tmp/chaine.p7b"""),
    h("6.2 Installer et nettoyer", 2),
    code("""docker exec "$WEB_CONTAINER" fortios-certctl install \\
  /tmp/serveur.crt \\
  --key /tmp/serveur.key \\
  --chain /tmp/chaine.p7b \\
  --hostname "$FQDN" \\
  --output-dir /opt/fortios/certificates/active
INSTALL_RC=$?

docker exec "$WEB_CONTAINER" rm -f \\
  /tmp/serveur.crt /tmp/serveur.key /tmp/chaine.p7b

test "$INSTALL_RC" -eq 0"""),
    para("Sans chaîne séparée, omettre <b>--chain</b>. Pour une clé chiffrée, créer <b>/tmp/cert-password</b> comme pour le PFX et ajouter <b>--password-file /tmp/cert-password</b>.", "small"),
    h("6.3 Vérifier sans afficher la clé", 2),
    code("""docker exec "$WEB_CONTAINER" openssl x509 \\
  -in /opt/fortios/certificates/active/fullchain.pem \\
  -noout -subject -issuer -dates \\
  -ext subjectAltName,extendedKeyUsage

docker exec "$WEB_CONTAINER" test -r \\
  /opt/fortios/certificates/active/privkey.pem"""),
    callout("Ne jamais afficher la clé privée",
            "Contrôler les métadonnées du certificat et la lisibilité du fichier. Ne jamais imprimer le contenu de privkey.pem dans le terminal ou les logs.", PALE_RED),
    PageBreak(),

    h("7. Activer HTTPS dans Portainer"),
    step("1", "Ouvrir l'éditeur", "Dans Portainer : <b>Stacks → upgrade-path → Editor</b>, puis la section des variables d'environnement."),
    step("2", "Définir le port et les chemins TLS", "Le port hôte 443 sera mappé vers l'unique listener interne 8000."),
    code("""FORTIOS_HTTP_BIND_ADDRESS=0.0.0.0
FORTIOS_HTTP_PORT=443
FORTIOS_TLS_CERT=/opt/fortios/certificates/active/fullchain.pem
FORTIOS_TLS_KEY=/opt/fortios/certificates/active/privkey.pem
FORTIOS_TLS_HOSTNAME=upgrade-path.sns-security.lan
FORTIOS_APP_URL=https://upgrade-path.sns-security.lan/app/"""),
    step("3", "Mettre à jour la Stack", "Cliquer <b>Update the stack</b>. Laisser le re-pull désactivé puisque l'image est locale. Ne supprimer aucun volume."),
    step("4", "Contrôler web", "Attendre le redémarrage, puis vérifier le statut healthy et les logs HTTPS."),
    code("""WEB_CONTAINER="$(docker ps \\
  --filter label=com.docker.compose.project=upgrade-path \\
  --filter label=com.docker.compose.service=web \\
  --format '{{.Names}}')"

docker logs --tail 50 "$WEB_CONTAINER"
docker inspect --format '{{.State.Health.Status}}' \\
  "$WEB_CONTAINER"""),
    callout("Absence volontaire de listener HTTP parallèle",
            "Après le passage à 443 avec les deux chemins TLS, l'application sert uniquement HTTPS. Le port hôte 8000 ne doit plus être publié : les API ne sont pas contournables en HTTP."),
    PageBreak(),

    h("7.1 Vérifier HTTPS depuis un poste approuvé"),
    para("Le poste doit résoudre le FQDN vers l'IP LAN de la VM et faire confiance à la CA interne."),
    code("""FQDN='upgrade-path.sns-security.lan'
CA_FILE='/chemin/vers/ca-interne.pem'

curl --fail --silent --show-error \\
  --cacert "$CA_FILE" \\
  "https://$FQDN/app/" >/dev/null

openssl s_client \\
  -connect "$FQDN:443" \\
  -servername "$FQDN" \\
  -CAfile "$CA_FILE" \\
  -verify_hostname "$FQDN" \\
  -verify_return_error </dev/null"""),
    para("Dans le navigateur : <b>https://upgrade-path.sns-security.lan/app/</b>. L'absence d'alerte exige un SAN correct et une CA interne approuvée."),
    h("7.2 Vérifier que HTTP/8000 n'est plus exposé", 2),
    code("""VM_IP='IP_LAN_VM'

if curl --fail --silent --max-time 3 \\
  "http://$VM_IP:8000/app/" >/dev/null; then
  echo 'ERREUR : HTTP/8000 est encore accessible'
else
  echo 'OK : aucun listener HTTP parallèle exposé'
fi"""),
    h("7.3 Contrôler le firewall", 2),
    bullet("Autoriser TCP/443 uniquement depuis les VLAN ou sous-réseaux internes attendus."),
    bullet("Retirer l'autorisation TCP/8000 après validation HTTPS."),
    bullet("Ne pas publier 443 ou 8000 sur Internet."),
    callout("Si le navigateur affiche une alerte",
            "Contrôler DNS, SAN, dates, chaîne envoyée et surtout l'installation de la CA interne dans le magasin de confiance du poste. Le conteneur ne peut pas déployer cette confiance côté clients.", PALE_YELLOW),
    PageBreak(),

    h("8. Renouvellement, retour HTTP et dépannage"),
    h("Renouveler le certificat", 2),
    bullet("Répéter la procédure PFX ou certificat/clé/chaîne avec le nouveau matériel."),
    bullet("Une installation invalide conserve la version active."),
    bullet("Après succès, dans <b>Containers</b>, sélectionner uniquement web et cliquer <b>Restart</b>. Ne pas recréer les volumes."),
    bullet("Contrôler healthy, les logs et le certificat présenté avec openssl s_client."),
    h("Revenir temporairement en HTTP", 2),
    code("""FORTIOS_HTTP_PORT=8000
FORTIOS_TLS_CERT=
FORTIOS_TLS_KEY=
FORTIOS_TLS_HOSTNAME=
FORTIOS_APP_URL=http://IP_LAN_VM:8000/app/"""),
    para("Cliquer <b>Update the stack</b> sans supprimer les volumes. HTTP et HTTPS ne doivent jamais être actifs simultanément."),
    h("Causes courantes d'un rejet", 2),
    bullet("Aucun SAN DNS, SAN ne couvrant pas le FQDN ou wildcard utilisé sur plusieurs labels."),
    bullet("Certificat expiré, pas encore valide ou limité à clientAuth."),
    bullet("Clé privée ne correspondant pas au certificat."),
    bullet("Chaîne incomplète, en double ou incohérente avec l'émetteur."),
    h("Rappels", 2),
    bullet("Ne jamais utiliser PUID=0 ou PGID=0."),
    bullet("Ne jamais intégrer clé, certificat privé ou mot de passe dans Git, l'image ou les variables visibles de la Stack."),
    bullet("Ne jamais supprimer les volumes persistants pendant une mise à jour."),
    bullet("Conserver l'ancienne instance jusqu'à la validation complète de la nouvelle VM."),
    callout("Fin de migration",
            "La migration est terminée lorsque l'image locale est déployée, les deux services sont stables, web est healthy, HTTPS présente le bon certificat, HTTP/8000 est inaccessible et les données historiques sont présentes.", PALE_CYAN),
]

doc.build(story)
print(OUTPUT)
