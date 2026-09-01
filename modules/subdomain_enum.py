"""
modules/subdomain_enum.py
Pilier 1 : Enumeration de sous-domaines

- Actif  : gobuster (mode dns) avec une wordlist fournie par l'utilisateur
- Passif : crt.sh (transparence des certificats, gratuit, sans clé API)
           utile pour compléter gobuster avec des sous-domaines déjà
           vus dans des certificats SSL publics

Resultat : liste dédupliquée + statut "live/dead" (résolution DNS + HTTP)
"""

import subprocess
import shutil
import socket
import json
import time
import requests

from config import HTTP_TIMEOUT, USER_AGENT, GOBUSTER_THREADS, GOBUSTER_TIMEOUT


def check_gobuster_installed():
    """Vérifie que le binaire gobuster est disponible dans le PATH."""
    return shutil.which("gobuster") is not None


def run_gobuster_dns(domain, wordlist_path):
    """
    Lance gobuster en mode DNS sur le domaine cible.
    Retourne une liste de sous-domaines découverts.
    """
    if not check_gobuster_installed():
        return {
            "error": "gobuster n'est pas installé ou introuvable dans le PATH. "
                     "Installez-le via: apt install gobuster  (ou https://github.com/OJ/gobuster)",
            "found": [],
        }

    cmd = [
        "gobuster", "dns",
        "-d", domain,
        "-w", wordlist_path,
        "-t", str(GOBUSTER_THREADS),
        "-q",  # quiet, pas de banniere
    ]

    found = []
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=GOBUSTER_TIMEOUT,
        )
        for line in proc.stdout.splitlines():
            line = line.strip()

            # on ignore les lignes de bruit: erreurs de lookup, progress bar, vide
            if not line or line.startswith("[") or line.lower().startswith("progress:"):
                continue

            # format reel gobuster v3.8.x dns: "sub.domain.com ip1,ip2,ip3..."
            # (le vieux format "Found: sub.domain.com" n'existe plus dans les versions recentes)
            if line.lower().startswith("found:"):
                sub = line.split(":", 1)[1].strip()
                if sub:
                    found.append(sub.lower())
                continue

            parts = line.split()
            if len(parts) >= 1 and "." in parts[0]:
                found.append(parts[0].lower())
    except subprocess.TimeoutExpired:
        return {"error": "gobuster a dépassé le timeout imparti.", "found": found}
    except Exception as e:
        return {"error": str(e), "found": found}

    return {"error": None, "found": sorted(set(found))}


def query_crtsh(domain):
    """
    Interroge crt.sh (base de données de certificats SSL publics, gratuite,
    sans clé API) pour trouver des sous-domaines historiquement émis.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subs = set()

    # crt.sh est connu pour etre instable (502/404/429 transitoires sous charge,
    # cf. rapports recurrents sur son groupe Google et son repo GitHub).
    # On retente donc plusieurs fois avant d'abandonner, au lieu de considerer
    # un premier echec comme definitif.
    max_retries = 3
    backoff = 5  # secondes, doublees a chaque tentative

    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=90)
        except requests.exceptions.Timeout:
            print(f"    [!] crt.sh: timeout (tentative {attempt}/{max_retries})")
            resp = None
        except requests.exceptions.RequestException as e:
            print(f"    [!] crt.sh: erreur réseau ({e}) (tentative {attempt}/{max_retries})")
            resp = None

        if resp is not None:
            if resp.status_code == 200 and resp.text.strip():
                break  # succes, on sort de la boucle de retry
            elif resp.status_code in (404, 429, 500, 502, 503, 504):
                print(f"    [!] crt.sh: statut HTTP {resp.status_code} — connu pour être "
                      f"instable, nouvelle tentative ({attempt}/{max_retries})")
            else:
                print(f"    [!] crt.sh: statut HTTP {resp.status_code} inattendu")
                return sorted(subs)  # erreur non-transitoire, inutile de retenter

        if attempt < max_retries:
            time.sleep(backoff)
            backoff *= 2
    else:
        print(f"    [!] crt.sh: échec après {max_retries} tentatives, "
              f"le service est probablement en surcharge. On continue sans lui.")
        return sorted(subs)

    if resp is None or resp.status_code != 200 or not resp.text.strip():
        return sorted(subs)

    try:
        data = json.loads(resp.text)
    except json.JSONDecodeError:
        print(f"    [!] crt.sh: JSON invalide/tronqué reçu")
        return sorted(subs)

    for entry in data:
        name_value = entry.get("name_value", "")
        for line in name_value.split("\n"):
            line = line.strip().lower()
            if line.endswith(domain) and "*" not in line:
                subs.add(line)

    return sorted(subs)


def resolve_and_probe(subdomains, domain):
    """
    Pour chaque sous-domaine trouvé :
      - tente une résolution DNS (A record)
      - tente une requête HTTP/HTTPS pour voir si un service répond
    Retourne une liste de dicts enrichis.
    """
    results = []
    for sub in subdomains:
        entry = {"subdomain": sub, "ip": None, "http": False, "https": False, "status_code": None}
        try:
            entry["ip"] = socket.gethostbyname(sub)
        except Exception:
            entry["ip"] = None

        if entry["ip"]:
            for scheme in ("https", "http"):
                try:
                    r = requests.get(
                        f"{scheme}://{sub}",
                        headers={"User-Agent": USER_AGENT},
                        timeout=HTTP_TIMEOUT,
                        verify=False,
                        allow_redirects=True,
                    )
                    entry[scheme] = True
                    entry["status_code"] = r.status_code
                    break  # inutile de tester les deux si l'un répond
                except Exception:
                    entry[scheme] = False

        results.append(entry)
    return results


def run(domain, wordlist_path):
    """
    Point d'entrée du pilier 1.
    Combine gobuster (actif) + crt.sh (passif), déduplique, puis probe.
    """
    print(f"[*] [Pilier 1] Enumeration de sous-domaines pour {domain} ...")

    gobuster_result = run_gobuster_dns(domain, wordlist_path)
    if gobuster_result.get("error"):
        print(f"    [!] gobuster: {gobuster_result['error']}")

    crtsh_result = query_crtsh(domain)

    all_subs = set(gobuster_result.get("found", [])) | set(crtsh_result)
    all_subs.discard(domain)  # on garde le focus sur les sous-domaines

    print(f"    -> {len(gobuster_result.get('found', []))} via gobuster, "
          f"{len(crtsh_result)} via crt.sh, {len(all_subs)} uniques au total.")

    probed = resolve_and_probe(sorted(all_subs), domain)

    return {
        "domain": domain,
        "gobuster_error": gobuster_result.get("error"),
        "total_found": len(all_subs),
        "subdomains": probed,
    }
