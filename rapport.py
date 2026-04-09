from jinja2 import Template
from datetime import datetime

TEMPLATE = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport de sécurité</title>
<style>
  body { font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; }
  h1 { color: #0f6e56; border-bottom: 2px solid #0f6e56; padding-bottom: 10px; }
  h2 { color: #333; margin-top: 30px; }
  .meta { color: #666; font-size: 14px; margin-bottom: 30px; }
  .stats { display: flex; gap: 20px; margin: 20px 0; }
  .stat { padding: 15px 25px; border-radius: 8px; text-align: center; }
  .stat .num { font-size: 28px; font-weight: bold; }
  .stat .label { font-size: 13px; margin-top: 4px; }
  .stat.rouge { background: #fcebeb; color: #791f1f; }
  .stat.orange { background: #faeeda; color: #633806; }
  .stat.vert { background: #eaf3de; color: #27500a; }
  table { width: 100%; border-collapse: collapse; margin-top: 15px; }
  th { background: #0f6e56; color: white; padding: 10px 14px; text-align: left; }
  td { padding: 9px 14px; border-bottom: 1px solid #eee; font-size: 14px; }
  tr:hover { background: #f9f9f9; }
  .haute { background: #fcebeb; color: #791f1f; padding: 2px 10px; border-radius: 20px; font-size: 12px; font-weight: bold; }
  .moyenne { background: #faeeda; color: #633806; padding: 2px 10px; border-radius: 20px; font-size: 12px; font-weight: bold; }
  .faible { background: #eaf3de; color: #27500a; padding: 2px 10px; border-radius: 20px; font-size: 12px; font-weight: bold; }
  code { background: #f4f4f4; padding: 2px 7px; border-radius: 4px; font-size: 13px; }
  .footer { margin-top: 40px; color: #999; font-size: 13px; text-align: center; }
</style>
</head>
<body>
  <h1>Rapport de sécurité</h1>
  <p class="meta">
    URL analysée : <strong>{{ url }}</strong><br>
    Date : {{ date }}
  </p>

  <div class="stats">
    <div class="stat rouge">
      <div class="num">{{ vulns_xss }}</div>
      <div class="label">XSS potentiels</div>
    </div>
    <div class="stat rouge">
      <div class="num">{{ vulns_sqli }}</div>
      <div class="label">SQLi potentielles</div>
    </div>
    <div class="stat orange">
      <div class="num">{{ vulns_headers }}</div>
      <div class="label">Headers manquants</div>
    </div>
    <div class="stat vert">
      <div class="num">{{ total }}</div>
      <div class="label">Total vulnérabilités</div>
    </div>
  </div>

  {% if headers %}
  <h2>Headers de sécurité manquants</h2>
  <table>
    <tr><th>Header</th><th>Criticité</th><th>Description</th></tr>
    {% for h in headers %}
    <tr>
      <td><code>{{ h.header }}</code></td>
      <td><span class="{{ h.criticite | lower }}">{{ h.criticite }}</span></td>
      <td>{{ h.description }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}

  {% if xss %}
  <h2>Vulnérabilités XSS</h2>
  <table>
    <tr><th>URL</th><th>Payload détecté</th></tr>
    {% for v in xss %}
    <tr>
      <td>{{ v.url }}</td>
      <td><code>{{ v.payload }}</code></td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}

  {% if sqli %}
  <h2>Injections SQL potentielles</h2>
  <table>
    <tr><th>URL</th><th>Payload détecté</th></tr>
    {% for v in sqli %}
    <tr>
      <td>{{ v.url }}</td>
      <td><code>{{ v.payload }}</code></td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}

  <div class="footer">Noussaiba Dhaou</div>
</body>
</html>"""

def generer_rapport(url, vulns_headers, vulns_xss, vulns_sqli):
    template = Template(TEMPLATE)
    html = template.render(
        url=url,
        date=datetime.now().strftime("%d/%m/%Y à %H:%M"),
        headers=vulns_headers,
        xss=vulns_xss,
        sqli=vulns_sqli,
        vulns_headers=len(vulns_headers),
        vulns_xss=len(vulns_xss),
        vulns_sqli=len(vulns_sqli),
        total=len(vulns_headers) + len(vulns_xss) + len(vulns_sqli)
    )

    nom_fichier = "rapport.html"
    with open(nom_fichier, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n[+] Rapport généré : {nom_fichier}")
    return nom_fichier