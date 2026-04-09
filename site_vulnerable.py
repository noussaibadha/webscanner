from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

HTML = """<!DOCTYPE html>
<html>
<head><title>Site de test vulnérable</title></head>
<body>
  <h1>Page de login</h1>
  <form method="POST" action="/login">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Connexion</button>
  </form>

  <h1>Recherche</h1>
  <form method="GET" action="/search">
    <input type="text" name="q" placeholder="Rechercher...">
    <button type="submit">Chercher</button>
  </form>
</body>
</html>"""

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        q = params.get("q", [""])[0]

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        if "/search" in self.path:
            # Volontairement vulnérable : on réaffiche le paramètre sans filtrage
            response = f"<html><body><h1>Résultats pour : {q}</h1></body></html>"
        else:
            response = HTML

        self.wfile.write(response.encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        params = parse_qs(body)
        username = params.get("username", [""])[0]

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        # Volontairement vulnérable : affiche le username sans filtrage
        response = f"<html><body><h1>Bonjour {username} !</h1><p>sql syntax error near '{username}'</p></body></html>"
        self.wfile.write(response.encode())

    def log_message(self, format, *args):
        pass  # Silencieux

if __name__ == "__main__":
    print("[*] Site vulnérable démarré sur http://localhost:8080")
    HTTPServer(("", 8080), Handler).serve_forever()