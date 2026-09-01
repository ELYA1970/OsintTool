#!/usr/bin/env python3
"""
main.py
DataProtect - RedTeam OSINT Recon Toolkit
Outil de reconnaissance de surface externe, 100% basé sur des outils
et services gratuits (aucune clé API requise).

4 piliers :
  1. Enumeration de sous-domaines (gobuster + crt.sh)
  2. Fingerprinting des technologies (headers, TLS, WHOIS, signatures)
  3. OSINT employés / entreprise (theHarvester, Sherlock, dorks LinkedIn)
  4. Fuite de credentiels (HIBP Pwned Passwords - k-anonymity, gratuit)

Génère un rapport PDF final avec le logo de l'entreprise.

Exemple d'utilisation :
    python3 main.py --domain exemple.com \\
        --wordlist wordlists/subdomains.txt \\
        --usernames jdupont mdurand \\
        --passwords "MotDePasseTest123"

Avertissement légal :
    Cet outil est destiné exclusivement à des audits de sécurité
    AUTORISÉS (pentest / red team sous contrat / bug bounty avec scope
    validé). Ne l'utilisez jamais sur une cible sans autorisation écrite
    explicite.
"""

import argparse
import json
import os
import sys
import urllib3

from config import ensure_dirs, DEFAULT_WORDLIST, OUTPUT_DIR, timestamp
from modules import subdomain_enum, fingerprint, osint_employees, credential_leak, report_generator

# On désactive les warnings TLS (scan actif volontaire sur certs auto-signés)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


BANNER = r"""
 _____        _        _____           _            _
|  __ \      | |      |  __ \         | |          | |
| |  | | __ _| |_ __ _| |__) | __ ___ | |_ ___  ___| |_
| |  | |/ _` | __/ _` |  ___/ '__/ _ \| __/ _ \/ __| __|
| |__| | (_| | || (_| | |   | | | (_) | ||  __/ (__| |_
|_____/ \__,_|\__\__,_|_|   |_|  \___/ \__\___|\___|\__|

        RedTeam OSINT Recon Toolkit - 100% Free Tools
"""


def parse_args():
    p = argparse.ArgumentParser(
        description="DataProtect - Outil de reconnaissance externe Red Team OSINT"
    )
    p.add_argument("--domain", required=True, help="Domaine cible (ex: exemple.com)")
    p.add_argument("--wordlist", default=DEFAULT_WORDLIST,
                    help=f"Chemin vers la wordlist gobuster (défaut: {DEFAULT_WORDLIST})")
    p.add_argument("--company-name", default=None,
                    help="Nom de l'entreprise cible (pour les dorks OSINT), défaut = domaine")
    p.add_argument("--usernames", nargs="*", default=[],
                    help="Liste de pseudos/usernames employés à vérifier via Sherlock")
    p.add_argument("--passwords", nargs="*", default=[],
                    help="Mots de passe de TEST (fournis par le client) à vérifier via HIBP")
    p.add_argument("--emails", nargs="*", default=[],
                    help="Emails à documenter dans le rapport (vérif manuelle HIBP conseillée)")
    p.add_argument("--local-breach-corpus", default=None,
                    help="Chemin vers un corpus de breach local autorisé (optionnel)")
    p.add_argument("--skip-subdomains", action="store_true", help="Ignorer le pilier 1")
    p.add_argument("--skip-fingerprint", action="store_true", help="Ignorer le pilier 2")
    p.add_argument("--skip-osint", action="store_true", help="Ignorer le pilier 3")
    p.add_argument("--skip-credentials", action="store_true", help="Ignorer le pilier 4")
    p.add_argument("--output-pdf", default=None, help="Chemin de sortie du rapport PDF")
    return p.parse_args()


def main():
    print(BANNER)
    args = parse_args()
    ensure_dirs()

    domain = args.domain.strip().lower()
    print(f"[+] Cible : {domain}")
    print("[!] Rappel : usage exclusivement dans le cadre d'un engagement AUTORISÉ.\n")

    # ---------------- Pilier 1 ----------------
    subdomain_data = {"domain": domain, "subdomains": [], "total_found": 0, "gobuster_error": None}
    if not args.skip_subdomains:
        if not os.path.exists(args.wordlist):
            print(f"[!] Wordlist introuvable : {args.wordlist} — pilier 1 en mode passif (crt.sh) seulement.")
        subdomain_data = subdomain_enum.run(domain, args.wordlist)
    else:
        print("[*] Pilier 1 ignoré (--skip-subdomains)")

    # ---------------- Pilier 2 ----------------
    fingerprint_data = {"domain": domain, "whois": {}, "targets_fingerprinted": []}
    if not args.skip_fingerprint:
        fingerprint_data = fingerprint.run(domain, subdomain_data.get("subdomains"))
    else:
        print("[*] Pilier 2 ignoré (--skip-fingerprint)")

    # ---------------- Pilier 3 ----------------
    osint_data = {"domain": domain, "theharvester": {}, "sherlock": {}, "linkedin_dorks": []}
    if not args.skip_osint:
        osint_data = osint_employees.run(domain, args.company_name, args.usernames)
    else:
        print("[*] Pilier 3 ignoré (--skip-osint)")

    # ---------------- Pilier 4 ----------------
    credential_data = {"password_checks": [], "email_notes": [], "local_corpus_matches": {}}
    if not args.skip_credentials:
        credential_data = credential_leak.run(
            passwords_to_check=args.passwords,
            emails_to_check=args.emails or osint_data.get("theharvester", {}).get("emails", []),
            local_corpus_path=args.local_breach_corpus,
        )
    else:
        print("[*] Pilier 4 ignoré (--skip-credentials)")

    # ---------------- Export JSON brut (données complètes) ----------------
    raw_json_path = os.path.join(OUTPUT_DIR, f"raw_data_{domain}_{timestamp()}.json")
    with open(raw_json_path, "w") as f:
        json.dump({
            "domain": domain,
            "subdomains": subdomain_data,
            "fingerprint": fingerprint_data,
            "osint": osint_data,
            "credentials": credential_data,
        }, f, indent=2, default=str)
    print(f"\n[+] Données brutes exportées : {raw_json_path}")

    # ---------------- Génération du rapport PDF ----------------
    print("[*] Génération du rapport PDF...")
    pdf_path = report_generator.build_report(
        domain, subdomain_data, fingerprint_data, osint_data, credential_data,
        output_path=args.output_pdf,
    )
    print(f"[+] Rapport PDF généré : {pdf_path}")
    print("\n[✓] Reconnaissance terminée.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrompu par l'utilisateur.")
        sys.exit(1)
