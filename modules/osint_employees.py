"""
modules/osint_employees.py
Pilier 3 : OSINT sur les employés / l'entreprise cible

Outils gratuits utilisés :
 - theHarvester : collecte d'emails, sous-domaines, noms via moteurs de
   recherche publics et sources OSINT gratuites (aucune clé API requise
   pour les sources de base : DuckDuckGo, crt.sh, Bing, etc.)
 - Sherlock : recherche d'un pseudo/username sur des centaines de
   plateformes (réseaux sociaux, forums...) - gratuit, open source
 - Dorks Google/LinkedIn : LinkedIn ne peut pas être scrappé légalement
   sans API payante -> on génère des requêtes ("dorks") que l'opérateur
   peut lancer manuellement dans un moteur de recherche pour identifier
   les profils employés publics (pratique standard en Red Team OSINT).
"""

import subprocess
import shutil
import json
import os

from config import OUTPUT_DIR, GOBUSTER_TIMEOUT


def check_tool_installed(name):
    return shutil.which(name) is not None


def run_theharvester(domain, timeout=600):
    """
    Lance theHarvester sur des sources 100% gratuites (pas de clé API
    nécessaire) : duckduckgo, crtsh, bing, otx, threatminer.
    """
    binary = None
    for candidate in ("theHarvester", "theharvester"):
        if check_tool_installed(candidate):
            binary = candidate
            break

    if not binary:
        return {
            "error": "theHarvester n'est pas installé ou introuvable dans le PATH. "
                     "Installation: pipx install theHarvester  (ou git clone du repo officiel)",
            "emails": [],
            "hosts": [],
        }

    out_file = os.path.join(OUTPUT_DIR, f"theharvester_{domain}.json")
    cmd = [
        binary,
        "-d", domain,
        "-b", "duckduckgo,crtsh,bing,otx,threatminer",  # sources gratuites, sans clé
        "-f", out_file.replace(".json", ""),  # theHarvester ajoute lui-même l'extension
    ]

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": "theHarvester a dépassé le timeout imparti.", "emails": [], "hosts": []}
    except Exception as e:
        return {"error": str(e), "emails": [], "hosts": []}

    emails, hosts = [], []
    json_path = out_file if out_file.endswith(".json") else out_file + ".json"
    if os.path.exists(json_path):
        try:
            with open(json_path, "r") as f:
                data = json.load(f)
            emails = data.get("emails", [])
            hosts = data.get("hosts", [])
        except Exception:
            pass

    return {"error": None, "emails": emails, "hosts": hosts}


def run_sherlock(usernames, timeout=300):
    """
    Lance Sherlock pour chaque username/pseudo fourni (ex: identifiants
    d'employés supposés). Retourne les plateformes où le pseudo existe.
    """
    if not check_tool_installed("sherlock"):
        return {
            "error": "sherlock n'est pas installé ou introuvable dans le PATH. "
                     "Installation: pipx install sherlock-project",
            "results": {},
        }

    results = {}
    for user in usernames:
        cmd = ["sherlock", user, "--print-found", "--timeout", "10"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            found_urls = [
                line.split(" ")[-1].strip()
                for line in proc.stdout.splitlines()
                if line.strip().startswith("[+]")
            ]
            results[user] = found_urls
        except subprocess.TimeoutExpired:
            results[user] = ["ERREUR: timeout"]
        except Exception as e:
            results[user] = [f"ERREUR: {e}"]

    return {"error": None, "results": results}


def generate_linkedin_dorks(company_name, domain):
    """
    LinkedIn interdit le scraping automatisé dans ses CGU et l'API
    officielle est payante/restreinte. On génère donc des dorks
    (requêtes moteur de recherche) que l'opérateur exécute manuellement
    -- méthode standard, légale et gratuite en Red Team OSINT.
    """
    dorks = [
        f'site:linkedin.com/in "{company_name}"',
        f'site:linkedin.com/in "{company_name}" "IT" OR "sysadmin" OR "security"',
        f'site:linkedin.com/company "{company_name}"',
        f'"{domain}" site:linkedin.com',
        f'"@{domain}" -site:linkedin.com',  # emails exposés hors LinkedIn
        f'site:github.com "{domain}"',
        f'site:pastebin.com "{domain}"',
    ]
    return dorks


def run(domain, company_name=None, usernames=None):
    """
    Point d'entrée du pilier 3.
    """
    print(f"[*] [Pilier 3] OSINT employés / entreprise pour {domain} ...")

    company_name = company_name or domain.split(".")[0]
    usernames = usernames or []

    harvester_result = run_theharvester(domain)
    print(f"    -> theHarvester: {len(harvester_result.get('emails', []))} email(s) trouvé(s)")

    sherlock_result = {"error": None, "results": {}}
    if usernames:
        sherlock_result = run_sherlock(usernames)
        print(f"    -> Sherlock: {len(usernames)} pseudo(s) analysé(s)")
    else:
        print("    -> Sherlock: aucun username fourni, étape ignorée (voir --usernames)")

    dorks = generate_linkedin_dorks(company_name, domain)

    return {
        "domain": domain,
        "company_name": company_name,
        "theharvester": harvester_result,
        "sherlock": sherlock_result,
        "linkedin_dorks": dorks,
    }
