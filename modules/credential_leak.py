"""
modules/credential_leak.py
Pilier 4 : Fuite de credentiels

Méthode 100% gratuite, sans clé API :
 - API "Pwned Passwords" de Have I Been Pwned, basée sur le modèle de
   k-anonymity : on envoie seulement les 5 premiers caractères du hash
   SHA-1 du mot de passe, jamais le mot de passe ni le hash complet.
   C'est la seule partie de l'écosystème HIBP qui reste gratuite et
   sans clé API (la recherche de breach par email nécessite désormais
   une clé payante -> non utilisée ici, voir note plus bas).

Bonnes pratiques :
 - Ne JAMAIS logger les mots de passe en clair
 - Toujours privilégier les mots de passe de TEST fournis par le client
   dans un cadre d'engagement autorisé, jamais des mots de passe réels
   d'utilisateurs sans consentement explicite.
"""

import hashlib
import requests

from config import USER_AGENT, HTTP_TIMEOUT

PWNED_PASSWORDS_API = "https://api.pwnedpasswords.com/range/"


def check_password_pwned(password):
    """
    Vérifie si un mot de passe apparaît dans des fuites de données connues
    via l'API k-anonymity de HIBP (gratuite, sans clé API).
    Retourne le nombre d'occurrences (0 = jamais vu dans une fuite connue).
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        r = requests.get(
            PWNED_PASSWORDS_API + prefix,
            headers={"User-Agent": USER_AGENT},
            timeout=HTTP_TIMEOUT,
        )
        r.raise_for_status()
    except Exception as e:
        return {"password_masked": _mask(password), "error": str(e), "count": None}

    count = 0
    for line in r.text.splitlines():
        hash_suffix, occurrences = line.split(":")
        if hash_suffix == suffix:
            count = int(occurrences)
            break

    return {
        "password_masked": _mask(password),
        "error": None,
        "count": count,
        "compromised": count > 0,
    }


def _mask(password):
    """Masque le mot de passe pour l'affichage/rapport (jamais en clair)."""
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]


def check_email_breach_note(email):
    """
    NOTE IMPORTANTE :
    Depuis fin 2023, l'API HIBP "breachedaccount" (recherche par email)
    nécessite une clé API payante. Comme demandé, cet outil n'utilise
    QUE des services gratuits, donc cette vérification par email n'est
    PAS effectuée automatiquement ici.

    Alternative gratuite recommandée :
     - Vérifier manuellement sur https://haveibeenpwned.com/ (interface
       web gratuite, limitée à un email à la fois, sans clé API)
     - Si le client dispose d'un corpus de breach autorisé (ex: obtenu
       légalement dans le cadre d'un pentest), utilisez plutôt une
       recherche locale (voir check_local_breach_corpus ci-dessous).
    """
    return {
        "email": email,
        "note": (
            "Vérification automatique par email désactivée (API HIBP "
            "payante). Vérifiez manuellement sur haveibeenpwned.com "
            "(gratuit, sans clé, un email à la fois)."
        ),
    }


def check_local_breach_corpus(credentials, corpus_path):
    """
    Optionnel : si l'utilisateur dispose d'un corpus de breach LOCAL
    obtenu légalement (ex: dump autorisé dans le cadre d'un audit),
    on peut faire un matching local sans dépendre d'un service tiers.
    `corpus_path` doit pointer vers un fichier texte (un identifiant
    par ligne, format email:password ou similaire).
    """
    if not corpus_path:
        return {"error": "Aucun corpus local fourni.", "matches": []}

    matches = []
    try:
        with open(corpus_path, "r", errors="ignore") as f:
            corpus_lines = set(line.strip() for line in f)
        for cred in credentials:
            for line in corpus_lines:
                if cred.lower() in line.lower():
                    matches.append({"credential": cred, "match_line": _mask(line)})
    except Exception as e:
        return {"error": str(e), "matches": []}

    return {"error": None, "matches": matches}


def run(passwords_to_check=None, emails_to_check=None, local_corpus_path=None):
    """
    Point d'entrée du pilier 4.

    passwords_to_check : liste de mots de passe de TEST à vérifier
                          (fournis par le client dans le cadre de
                          l'engagement, JAMAIS de mots de passe réels
                          d'utilisateurs sans consentement)
    emails_to_check     : liste d'emails à documenter (vérif manuelle
                           conseillée, voir note)
    local_corpus_path   : chemin optionnel vers un corpus de breach local
    """
    print("[*] [Pilier 4] Vérification de fuite de credentiels (HIBP Pwned Passwords, gratuit)...")

    passwords_to_check = passwords_to_check or []
    emails_to_check = emails_to_check or []

    password_results = [check_password_pwned(pw) for pw in passwords_to_check]
    email_notes = [check_email_breach_note(e) for e in emails_to_check]

    local_results = {"error": None, "matches": []}
    if local_corpus_path:
        local_results = check_local_breach_corpus(
            passwords_to_check + emails_to_check, local_corpus_path
        )

    compromised_count = sum(1 for r in password_results if r.get("compromised"))
    print(f"    -> {compromised_count}/{len(password_results)} mot(s) de passe testé(s) compromis")

    return {
        "password_checks": password_results,
        "email_notes": email_notes,
        "local_corpus_matches": local_results,
    }
