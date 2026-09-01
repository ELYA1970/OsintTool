"""
config.py - Configuration centrale du toolkit RedTeam OSINT
DataProtect - Reconnaissance de surface externe
"""

import os
from datetime import datetime

# ----------------------------------------------------------------------
# Chemins de base
# ----------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
WORDLIST_DIR = os.path.join(BASE_DIR, "wordlists")

LOGO_PATH = os.path.join(ASSETS_DIR, "logo.jpg")

# Wordlist utilisée par gobuster pour l'énumération DNS.
# Placez votre fichier "subdomains.txt" ici (ou passez --wordlist en CLI).
DEFAULT_WORDLIST = os.path.join(WORDLIST_DIR, "subdomains.txt")

# ----------------------------------------------------------------------
# Timeouts & threads
# ----------------------------------------------------------------------
HTTP_TIMEOUT = 8            # secondes, pour toutes les requêtes HTTP
GOBUSTER_THREADS = 50
GOBUSTER_TIMEOUT = 900      # 15 min max pour l'énumération DNS

# ----------------------------------------------------------------------
# User-Agent générique (évite d'être bloqué par certains WAF pendant
# les phases passives de fingerprinting)
# ----------------------------------------------------------------------
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 DataProtect-ReconBot"
)

# ----------------------------------------------------------------------
# Divers
# ----------------------------------------------------------------------
def timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def ensure_dirs():
    for d in (ASSETS_DIR, OUTPUT_DIR, WORDLIST_DIR):
        os.makedirs(d, exist_ok=True)
