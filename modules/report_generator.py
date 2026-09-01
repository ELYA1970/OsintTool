"""
modules/report_generator.py
Génération du rapport PDF final regroupant les 4 piliers,
avec en-tête au logo de l'entreprise (DataProtect).
"""

import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, PageBreak, HRFlowable,
)
from reportlab.lib.enums import TA_CENTER

from config import LOGO_PATH, OUTPUT_DIR, timestamp

RED = colors.HexColor("#E30613")
DARK = colors.HexColor("#1a1a1a")
GREY = colors.HexColor("#666666")
LIGHT_GREY = colors.HexColor("#f2f2f2")


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("TitleRed", parent=ss["Title"], textColor=RED, fontSize=22))
    ss.add(ParagraphStyle("H2Red", parent=ss["Heading2"], textColor=RED, spaceBefore=16, spaceAfter=8))
    ss.add(ParagraphStyle("H3Dark", parent=ss["Heading3"], textColor=DARK, spaceBefore=10, spaceAfter=4))
    ss.add(ParagraphStyle("Body", parent=ss["BodyText"], textColor=DARK, fontSize=9.5, leading=13))
    ss.add(ParagraphStyle("Small", parent=ss["BodyText"], textColor=GREY, fontSize=8))
    ss.add(ParagraphStyle("Center", parent=ss["BodyText"], alignment=TA_CENTER))
    return ss


def _header_footer(canvas, doc):
    canvas.saveState()
    # Filet rouge en bas de chaque page + numéro de page
    canvas.setStrokeColor(RED)
    canvas.setLineWidth(1)
    canvas.line(2 * cm, 1.5 * cm, A4[0] - 2 * cm, 1.5 * cm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(GREY)
    canvas.drawString(2 * cm, 1.1 * cm, "DataProtect - Rapport confidentiel de reconnaissance externe")
    canvas.drawRightString(A4[0] - 2 * cm, 1.1 * cm, f"Page {doc.page}")
    canvas.restoreState()


def _table(data, col_widths=None):
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), RED),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GREY]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def build_report(domain, subdomain_data, fingerprint_data, osint_data, credential_data, output_path=None):
    ss = _styles()
    story = []

    output_path = output_path or os.path.join(OUTPUT_DIR, f"rapport_recon_{domain}_{timestamp()}.pdf")

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=1.8 * cm, bottomMargin=2 * cm,
        title=f"Rapport de reconnaissance externe - {domain}",
    )

    # ---------------- Page de garde ----------------
    if os.path.exists(LOGO_PATH):
        story.append(Image(LOGO_PATH, width=6 * cm, height=6 * cm * 0.4, kind="proportional"))
    story.append(Spacer(1, 2 * cm))
    story.append(Paragraph("Rapport de Reconnaissance", ss["TitleRed"]))
    story.append(Paragraph("Surface d'Attaque Externe (OSINT / Red Team)", ss["Center"]))
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph(f"<b>Cible :</b> {domain}", ss["Center"]))
    story.append(Paragraph(f"<b>Date :</b> {datetime.now().strftime('%d/%m/%Y %H:%M')}", ss["Center"]))
    story.append(Spacer(1, 2 * cm))
    story.append(Paragraph(
        "Document confidentiel - à usage exclusif du client dans le cadre "
        "d'un engagement de sécurité autorisé. Toute diffusion non "
        "autorisée est interdite.", ss["Small"]
    ))
    story.append(PageBreak())

    # ---------------- Pilier 1 : Sous-domaines ----------------
    story.append(Paragraph("1. Énumération de sous-domaines", ss["H2Red"]))
    if subdomain_data.get("gobuster_error"):
        story.append(Paragraph(f"⚠ {subdomain_data['gobuster_error']}", ss["Body"]))
    story.append(Paragraph(
        f"Total de sous-domaines uniques identifiés : <b>{subdomain_data.get('total_found', 0)}</b> "
        f"(gobuster + crt.sh)", ss["Body"]
    ))
    story.append(Spacer(1, 0.3 * cm))

    subs = subdomain_data.get("subdomains", [])
    if subs:
        table_data = [["Sous-domaine", "IP", "HTTP", "HTTPS", "Code"]]
        for s in subs[:80]:
            table_data.append([
                s.get("subdomain", ""), s.get("ip") or "-",
                "Oui" if s.get("http") else "-", "Oui" if s.get("https") else "-",
                str(s.get("status_code") or "-"),
            ])
        story.append(_table(table_data, col_widths=[6.5 * cm, 3.5 * cm, 1.8 * cm, 1.8 * cm, 1.8 * cm]))
        if len(subs) > 80:
            story.append(Paragraph(f"... et {len(subs) - 80} autres (voir export JSON complet).", ss["Small"]))
    else:
        story.append(Paragraph("Aucun sous-domaine trouvé.", ss["Body"]))
    story.append(PageBreak())

    # ---------------- Pilier 2 : Fingerprinting ----------------
    story.append(Paragraph("2. Fingerprinting des technologies", ss["H2Red"]))
    whois_info = fingerprint_data.get("whois", {})
    story.append(Paragraph("<b>WHOIS du domaine principal</b>", ss["H3Dark"]))
    whois_table = [["Champ", "Valeur"]]
    for k in ("registrar", "creation_date", "expiration_date", "org"):
        whois_table.append([k, str(whois_info.get(k, "-"))])
    story.append(_table(whois_table, col_widths=[4 * cm, 11 * cm]))
    story.append(Spacer(1, 0.4 * cm))

    story.append(Paragraph("<b>Technologies détectées par cible</b>", ss["H3Dark"]))
    for target in fingerprint_data.get("targets_fingerprinted", []):
        story.append(Paragraph(f"<b>{target.get('host')}</b> — statut HTTP: {target.get('status_code', '-')}", ss["Body"]))
        techs = ", ".join(target.get("technologies_detected", [])) or "Aucune signature reconnue"
        story.append(Paragraph(f"Technologies : {techs}", ss["Body"]))
        server = target.get("server_header") or "-"
        story.append(Paragraph(f"Header Server : {server} | X-Powered-By : {target.get('x_powered_by') or '-'}", ss["Body"]))
        tls = target.get("tls", {})
        if tls and not tls.get("error"):
            story.append(Paragraph(
                f"TLS — Émetteur : {tls.get('issuer', {}).get('organizationName', '-')} | "
                f"Expire le : {tls.get('not_after', '-')}", ss["Body"]
            ))
        story.append(Spacer(1, 0.25 * cm))
    story.append(PageBreak())

    # ---------------- Pilier 3 : OSINT employés ----------------
    story.append(Paragraph("3. OSINT sur les employés / l'entreprise", ss["H2Red"]))
    harvester = osint_data.get("theharvester", {})
    if harvester.get("error"):
        story.append(Paragraph(f"⚠ {harvester['error']}", ss["Body"]))
    emails = harvester.get("emails", [])
    story.append(Paragraph(f"<b>Emails identifiés (theHarvester) : {len(emails)}</b>", ss["H3Dark"]))
    if emails:
        email_table = [["Email"]] + [[e] for e in emails[:60]]
        story.append(_table(email_table, col_widths=[15 * cm]))
    else:
        story.append(Paragraph("Aucun email trouvé via les sources gratuites interrogées.", ss["Body"]))
    story.append(Spacer(1, 0.4 * cm))

    sherlock = osint_data.get("sherlock", {}).get("results", {})
    story.append(Paragraph("<b>Recherche de pseudos (Sherlock)</b>", ss["H3Dark"]))
    if sherlock:
        for user, urls in sherlock.items():
            story.append(Paragraph(f"<b>{user}</b> — {len(urls)} profil(s) trouvé(s)", ss["Body"]))
            for u in urls[:15]:
                story.append(Paragraph(f"• {u}", ss["Small"]))
    else:
        story.append(Paragraph("Aucun username fourni pour cette analyse.", ss["Body"]))
    story.append(Spacer(1, 0.4 * cm))

    story.append(Paragraph("<b>Dorks LinkedIn / recherche manuelle recommandée</b>", ss["H3Dark"]))
    story.append(Paragraph(
        "LinkedIn ne peut pas être interrogé automatiquement sans API payante. "
        "Requêtes à exécuter manuellement dans un moteur de recherche :", ss["Body"]
    ))
    for d in osint_data.get("linkedin_dorks", []):
        story.append(Paragraph(f"• {d}", ss["Small"]))
    story.append(PageBreak())

    # ---------------- Pilier 4 : Fuite de credentiels ----------------
    story.append(Paragraph("4. Fuite de credentiels", ss["H2Red"]))
    story.append(Paragraph(
        "Vérification via l'API gratuite HIBP « Pwned Passwords » "
        "(k-anonymity, aucun mot de passe transmis en clair).", ss["Body"]
    ))
    pw_checks = credential_data.get("password_checks", [])
    if pw_checks:
        pw_table = [["Mot de passe (masqué)", "Occurrences dans des fuites", "Compromis ?"]]
        for r in pw_checks:
            pw_table.append([
                r.get("password_masked", "-"),
                str(r.get("count", "-")),
                "OUI ⚠" if r.get("compromised") else "Non",
            ])
        story.append(_table(pw_table, col_widths=[6 * cm, 6 * cm, 3 * cm]))
    else:
        story.append(Paragraph("Aucun mot de passe de test fourni pour vérification.", ss["Body"]))

    story.append(Spacer(1, 0.4 * cm))
    for note in credential_data.get("email_notes", []):
        story.append(Paragraph(f"• {note['email']} : {note['note']}", ss["Small"]))

    local_matches = credential_data.get("local_corpus_matches", {}).get("matches", [])
    if local_matches:
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("<b>Correspondances trouvées dans le corpus local fourni</b>", ss["H3Dark"]))
        for m in local_matches:
            story.append(Paragraph(f"• {m['credential']} → {m['match_line']}", ss["Small"]))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return output_path
