from http.server import BaseHTTPRequestHandler, HTTPServer
import json


class TestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        host = self.headers.get("Host", "").split(":")[0]

        if host == "admin.zyntra.test":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body>Admin Virtual Host</body></html>"
            )

        elif self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b'<html><body><a href="/page">Home</a></body></html>'
            )

        elif self.path == "/api":
            data = {"status": "ok"}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())

        elif self.path == "/static/app.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(
                b'const api = "/api"; const api_key = "TEST-12345";'
            )

        elif self.path == "/page":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b'<html><body><script src="/static/app.js"></script>'
                b'<a href="/api">API</a></body></html>'
            )

        else:
            self.send_response(404)
            self.end_headers()

server = HTTPServer(("127.0.0.1", 8080), TestHandler)

print("[+] Test server running on http://127.0.0.1:8080")

server.serve_forever()
