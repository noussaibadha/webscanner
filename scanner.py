import requests
from rapport import generer_rapport
from bs4 import BeautifulSoup
from urllib.parse import urljoin

HEADERS_SECURITE = {
    "Content-Security-Policy": {
        "description": "Protège contre les attaques XSS",
        "criticite": "HAUTE"
    },
    "X-Frame-Options": {
        "description": "Protège contre le clickjacking",
        "criticite": "MOYENNE"
    },
    "X-Content-Type-Options": {
        "description": "Empêche le MIME sniffing",
        "criticite": "MOYENNE"
    },
    "Strict-Transport-Security": {
        "description": "Force HTTPS (HSTS)",
        "criticite": "HAUTE"
    },
    "Referrer-Policy": {
        "description": "Contrôle les infos envoyées au referrer",
        "criticite": "FAIBLE"
    },
    "Permissions-Policy": {
        "description": "Restreint l'accès aux APIs du navigateur",
        "criticite": "FAIBLE"
    },
}

PAYLOADS_XSS = [
    '<script>alert("xss")</script>',
    '"><img src=x onerror=alert(1)>',
    "';alert(1);//",
]

PAYLOADS_SQLI = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
]


def analyser_headers(response):
    print("\n--- Analyse des headers de sécurité ---\n")
    vulnerabilites = []

    for header, info in HEADERS_SECURITE.items():
        if header not in response.headers:
            print(f"[!] MANQUANT [{info['criticite']}] {header}")
            print(f"    → {info['description']}\n")
            vulnerabilites.append({
                "header": header,
                "criticite": info["criticite"],
                "description": info["description"]
            })
        else:
            print(f"[+] OK   {header}: {response.headers[header][:60]}")

    return vulnerabilites


def extraire_formulaires(url, response):
    soup = BeautifulSoup(response.text, "html.parser")
    formulaires = []

    for form in soup.find_all("form"):
        action = form.attrs.get("action", "")
        methode = form.attrs.get("method", "get").lower()
        champs = []

        for input_tag in form.find_all("input"):
            nom = input_tag.attrs.get("name")
            if nom:
                champs.append({"nom": nom})

        formulaires.append({
            "action": urljoin(url, action),
            "methode": methode,
            "champs": champs
        })

    return formulaires


def tester_xss(url, formulaires, session):
    print("\n--- Test XSS ---\n")
    resultats = []

    if not formulaires:
        print("[*] Aucun formulaire trouvé sur cette page\n")
        return resultats

    for form in formulaires:
        for payload in PAYLOADS_XSS:
            data = {champ["nom"]: payload for champ in form["champs"]}

            try:
                if form["methode"] == "post":
                    r = session.post(form["action"], data=data, timeout=10)
                else:
                    r = session.get(form["action"], params=data, timeout=10)

                if payload in r.text:
                    print(f"[!] XSS POTENTIEL sur {form['action']}")
                    print(f"    Payload : {payload}\n")
                    resultats.append({"type": "XSS", "url": form["action"], "payload": payload})
                else:
                    print(f"[+] OK - payload filtré sur {form['action']}")

            except Exception as e:
                print(f"[-] Erreur : {e}")

    return resultats


def tester_sqli(url, formulaires, session):
    print("\n--- Test SQL Injection ---\n")
    erreurs_sql = ["sql", "mysql", "syntax error", "ORA-", "pg_query", "sqlite"]
    resultats = []

    if not formulaires:
        print("[*] Aucun formulaire trouvé sur cette page\n")
        return resultats

    for form in formulaires:
        for payload in PAYLOADS_SQLI:
            data = {champ["nom"]: payload for champ in form["champs"]}

            try:
                if form["methode"] == "post":
                    r = session.post(form["action"], data=data, timeout=10)
                else:
                    r = session.get(form["action"], params=data, timeout=10)

                for erreur in erreurs_sql:
                    if erreur.lower() in r.text.lower():
                        print(f"[!] SQLI POTENTIELLE sur {form['action']}")
                        print(f"    Payload : {payload} → erreur : '{erreur}'\n")
                        resultats.append({"type": "SQLi", "url": form["action"], "payload": payload})
                        break

            except Exception as e:
                print(f"[-] Erreur : {e}")

    return resultats


def scan(url):
    print(f"\n[*] Scan de : {url}\n")
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (scanner educatif)"})

    try:
        response = session.get(url, timeout=10)
        print(f"[+] Statut HTTP : {response.status_code}")
        print(f"[+] Serveur     : {response.headers.get('Server', 'Non communiqué')}")

        vulns_headers = analyser_headers(response)

        formulaires = extraire_formulaires(url, response)
        print(f"[*] {len(formulaires)} formulaire(s) trouvé(s) sur la page")

        vulns_xss = tester_xss(url, formulaires, session)
        vulns_sqli = tester_sqli(url, formulaires, session)

        total = len(vulns_headers) + len(vulns_xss) + len(vulns_sqli)
        print("\n--- Résumé final ---")
        print(f"Headers manquants : {len(vulns_headers)}")
        print(f"XSS potentiels    : {len(vulns_xss)}")
        print(f"SQLi potentielles : {len(vulns_sqli)}")
        print(f"Total             : {total} vulnérabilité(s) détectée(s)")

        generer_rapport(url, vulns_headers, vulns_xss, vulns_sqli)

    except requests.exceptions.ConnectionError:
        print("[-] Erreur : impossible de se connecter")
    except requests.exceptions.Timeout:
        print("[-] Erreur : timeout")


if __name__ == "__main__":
    url = input("Entre une URL à scanner : ")
    scan(url)