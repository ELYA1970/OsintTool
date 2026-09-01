"""
modules/fingerprint.py
Pilier 2 : Fingerprinting des technologies

Approche 100% gratuite / sans clé API :
 - Analyse des headers HTTP (Server, X-Powered-By, cookies, etc.)
 - Analyse du HTML (meta generator, chemins JS/CSS connus)
 - Détection de CMS/frameworks courants via signatures regex
 - Informations du certificat TLS (émetteur, SAN, expiration)
 - WHOIS du domaine (via la librairie python-whois, gratuite)
"""

import re
import ssl
import socket
import requests
import whois as pywhois

from config import HTTP_TIMEOUT, USER_AGENT

# Signatures simplifiées façon "Wappalyzer maison" -- gratuites, locales,
# pas besoin d'API. Basées sur des motifs présents dans le HTML/headers.
TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r'name="generator" content="WordPress'],
    "Joomla": [r"/media/jui/", r'name="generator" content="Joomla'],
    "Drupal": [r"sites/default/files", r'Drupal\.settings'],
    "Magento": [r"Mage\.Cookies", r"/skin/frontend/"],
    "Shopify": [r"cdn\.shopify\.com", r"Shopify\.theme"],
    "React": [r"__REACT_DEVTOOLS", r"react-dom", r"data-reactroot"],
    "Angular": [r"ng-version", r"angular\.js"],
    "Vue.js": [r"__VUE__", r"vue\.js"],
    "jQuery": [r"jquery(\.min)?\.js"],
    "Bootstrap": [r"bootstrap(\.min)?\.css"],
    "Laravel": [r"laravel_session"],
    "Django": [r"csrfmiddlewaretoken"],
    "Nginx (via contenu par défaut)": [r"Welcome to nginx"],
    "IIS (via contenu par défaut)": [r"IIS Windows Server"],
    "Cloudflare": [r"cloudflare"],
    "Apache Tomcat": [r"Apache Tomcat"],
}


def get_headers_info(url):
    """Récupère les headers HTTP bruts, utiles pour le fingerprinting serveur."""
    try:
        r = requests.get(
            url, headers={"User-Agent": USER_AGENT},
            timeout=HTTP_TIMEOUT, verify=False, allow_redirects=True,
        )
        return {
            "final_url": r.url,
            "status_code": r.status_code,
            "server": r.headers.get("Server"),
            "x_powered_by": r.headers.get("X-Powered-By"),
            "cookies": [c.name for c in r.cookies],
            "headers": dict(r.headers),
            "html": r.text[:200000],  # on limite la taille analysée
        }
    except Exception as e:
        return {"error": str(e)}


def detect_technologies(html, headers):
    """Applique les signatures regex sur le HTML + headers combinés."""
    haystack = (html or "") + " " + " ".join(f"{k}:{v}" for k, v in (headers or {}).items())
    detected = []
    for tech, patterns in TECH_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, haystack, re.IGNORECASE):
                detected.append(tech)
                break
    return sorted(set(detected))


def get_tls_info(hostname, port=443):
    """Extrait les infos de certificat TLS (émetteur, validité, SAN)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        return {
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": [v for k, v in cert.get("subjectAltName", [])],
        }
    except Exception as e:
        return {"error": str(e)}


def get_whois_info(domain):
    """WHOIS gratuit via python-whois (aucune clé API nécessaire)."""
    try:
        w = pywhois.whois(domain)
        return {
            "registrar": w.get("registrar"),
            "creation_date": str(w.get("creation_date")),
            "expiration_date": str(w.get("expiration_date")),
            "name_servers": w.get("name_servers"),
            "org": w.get("org"),
            "emails": w.get("emails"),
        }
    except Exception as e:
        return {"error": str(e)}


def fingerprint_target(hostname):
    """
    Fingerprint complet d'une cible (domaine principal ou sous-domaine) :
    headers, technologies détectées, TLS, WHOIS.
    """
    url_https = f"https://{hostname}"
    info = get_headers_info(url_https)

    if "error" in info:
        # on retente en http si https échoue
        info = get_headers_info(f"http://{hostname}")

    technologies = []
    if "html" in info:
        technologies = detect_technologies(info.get("html"), info.get("headers"))

    tls_info = get_tls_info(hostname)

    return {
        "host": hostname,
        "final_url": info.get("final_url"),
        "status_code": info.get("status_code"),
        "server_header": info.get("server"),
        "x_powered_by": info.get("x_powered_by"),
        "cookies": info.get("cookies"),
        "technologies_detected": technologies,
        "tls": tls_info,
        "error": info.get("error"),
    }


def run(domain, live_subdomains=None):
    """
    Point d'entrée du pilier 2.
    Fingerprint le domaine principal + tous les sous-domaines "live"
    détectés au pilier 1.
    """
    print(f"[*] [Pilier 2] Fingerprinting des technologies pour {domain} ...")

    targets = [domain]
    if live_subdomains:
        targets += [s["subdomain"] for s in live_subdomains if s.get("http") or s.get("https")]

    results = []
    for t in targets:
        print(f"    -> fingerprint de {t}")
        results.append(fingerprint_target(t))

    whois_info = get_whois_info(domain)

    return {
        "domain": domain,
        "whois": whois_info,
        "targets_fingerprinted": results,
    }
