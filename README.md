# DataProtect — RedTeam OSINT Recon Toolkit

Outil de reconnaissance de surface externe basé **exclusivement sur des
outils/services gratuits et sans clé API**, structuré autour de 4 piliers :

1. **Énumération de sous-domaines** — `gobuster` (mode DNS) + `crt.sh` (passif)
2. **Fingerprinting des technologies** — headers HTTP, TLS, WHOIS, signatures CMS/JS
3. **OSINT employés / entreprise** — `theHarvester`, `Sherlock`, dorks LinkedIn
4. **Fuite de credentiels** — API gratuite HIBP *Pwned Passwords* (k-anonymity)

En sortie : un **rapport PDF** avec le logo DataProtect + un export JSON brut.

---

## ⚠️ Avertissement légal

Cet outil est destiné **exclusivement** à des audits de sécurité
**autorisés par écrit** (pentest / red team sous contrat, bug bounty avec
scope validé). Toute utilisation contre une cible sans autorisation
explicite est illégale. DataProtect et l'auteur de cet outil déclinent
toute responsabilité en cas d'usage non autorisé.

---

## 1. Installation

### 1.1 Dépendances Python

```bash
cd redteam_osint_tool
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 1.2 Outils externes (gratuits, à installer séparément)

| Outil | Rôle | Installation |
|---|---|---|
| `gobuster` | Enumeration DNS (Pilier 1) | `apt install gobuster` ou [releases GitHub](https://github.com/OJ/gobuster) |
| `theHarvester` | OSINT emails/hosts (Pilier 3) | `pipx install theHarvester` ou `git clone https://github.com/laramies/theHarvester` |
| `sherlock` | Recherche de pseudos (Pilier 3) | `pipx install sherlock-project` |

> Si un outil n'est pas installé, le pilier correspondant continue avec
> les sources disponibles et affiche un message d'avertissement clair
> dans le rapport (le scan ne plante jamais entièrement).

### 1.3 Wordlist pour gobuster

Placez votre fichier de sous-domaines ici :

```
redteam_osint_tool/wordlists/subdomains.txt
```

(un sous-domaine candidat par ligne, ex: `www`, `mail`, `vpn`, `api`...)
Vous pouvez aussi utiliser des wordlists connues comme celles de
[SecLists](https://github.com/danielmiessler/SecLists) (gratuites).

---

## 2. Utilisation

```bash
python3 main.py \
  --domain exemple.com \
  --wordlist wordlists/subdomains.txt \
  --company-name "Exemple SA" \
  --usernames jdupont mdurand \
  --passwords "MotDeTestFourniParLeClient123"
```

### Options principales

| Option | Description |
|---|---|
| `--domain` | **(requis)** domaine cible |
| `--wordlist` | chemin vers la wordlist gobuster |
| `--company-name` | nom de l'entreprise (pour les dorks OSINT) |
| `--usernames` | pseudos employés à tester avec Sherlock |
| `--passwords` | mots de passe de **test** à vérifier (HIBP) |
| `--emails` | emails à documenter dans le rapport |
| `--local-breach-corpus` | corpus de breach local autorisé (optionnel) |
| `--skip-subdomains` / `--skip-fingerprint` / `--skip-osint` / `--skip-credentials` | ignorer un pilier |
| `--output-pdf` | chemin de sortie personnalisé du rapport |

### Sorties générées

- `output/rapport_recon_<domain>_<date>.pdf` → rapport final avec logo
- `output/raw_data_<domain>_<date>.json` → toutes les données brutes

---

## 3. Détails sur la partie "gratuite, sans clé API"

- **crt.sh** : base publique de transparence des certificats, aucune clé.
- **theHarvester** : configuré ici pour utiliser uniquement les sources
  gratuites (`duckduckgo, crtsh, bing, otx, threatminer`) — pas Shodan,
  Hunter.io etc. qui nécessitent une clé payante.
- **Sherlock** : totalement gratuit et open source.
- **LinkedIn** : pas d'API gratuite disponible pour du scraping —
  l'outil génère des *dorks* (requêtes moteur de recherche) à exécuter
  manuellement, ce qui est la pratique standard et légale en OSINT.
- **HIBP Pwned Passwords** : la seule API HIBP encore gratuite (modèle
  k-anonymity, aucune donnée sensible transmise). La recherche de breach
  **par email** nécessite désormais une clé payante côté HIBP — elle
  n'est donc pas automatisée ici ; le rapport indique comment la faire
  manuellement (gratuit, un email à la fois sur haveibeenpwned.com).

---

## 4. Structure du projet

```
redteam_osint_tool/
├── main.py                     # orchestrateur CLI
├── config.py                   # configuration centrale
├── requirements.txt
├── assets/
│   └── logo.jpg                # logo DataProtect (rapport PDF)
├── wordlists/
│   └── subdomains.txt          # à fournir par vous
├── modules/
│   ├── subdomain_enum.py       # Pilier 1
│   ├── fingerprint.py          # Pilier 2
│   ├── osint_employees.py      # Pilier 3
│   ├── credential_leak.py      # Pilier 4
│   └── report_generator.py     # Génération PDF
└── output/                     # rapports + JSON générés
```

---

## 5. Idées d'évolution (non incluses par défaut)

- Ajout de sources OSINT passives supplémentaires (ex: Wayback Machine,
  gratuite, pour découvrir d'anciens sous-domaines/URLs)
- Détection de shadow-IT via recherche de CNAME pointant vers des SaaS
  connus (AWS S3, Azure, GitHub Pages...) — utile pour du takeover
- Export du rapport en HTML en plus du PDF
