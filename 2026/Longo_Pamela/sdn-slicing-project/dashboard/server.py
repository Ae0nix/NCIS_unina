#!/usr/bin/env python3
"""Dashboard web minimale (solo libreria standard, nessun Flask da installare).

    python3 dashboard/server.py            # poi apri http://localhost:8080
    python3 dashboard/server.py --port 8081   # se la 8080 è occupata

Legge logs/state.json, scritto ogni secondo dal controller, e lo serve alla pagina.
"""
import argparse
import http.server
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_STATE = os.path.join(HERE, "..", "logs", "state.json")


def make_handler(state_file):
    class Handler(http.server.BaseHTTPRequestHandler):
        def _send(self, code, ctype, body):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                with open(os.path.join(HERE, "index.html"), "rb") as f:
                    self._send(200, "text/html; charset=utf-8", f.read())
            elif self.path == "/api/state":
                try:
                    with open(state_file, "rb") as f:
                        self._send(200, "application/json", f.read())
                except OSError:
                    self._send(200, "application/json", json.dumps({"waiting": True}).encode())
            else:
                self._send(404, "text/plain", b"not found")

        def log_message(self, *args):
            pass

    return Handler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--state", default=os.environ.get("SLICE_STATE_FILE", DEFAULT_STATE))
    args = ap.parse_args()
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", args.port), make_handler(args.state))
    print("dashboard su http://localhost:%d  (stato: %s)" % (args.port, os.path.abspath(args.state)))
    srv.serve_forever()


if __name__ == "__main__":
    main()
