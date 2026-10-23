"""Records HTTP requests of Azure clients and answers like Entra ID, IMDS and the Logs Ingestion API.

Usage: python3 -I capture.py <out.jsonl> <tls-dir>
HTTPS on 127.0.0.1:18443 (authority + data collection endpoint), plain HTTP on 127.0.0.1:18080 (IMDS).
"""
import gzip, json, ssl, sys, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qsl

OUT, TLS = sys.argv[1], sys.argv[2]
lock = threading.Lock()
AUTH = "https://localhost:18443"


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _record(self, body):
        u = urlsplit(self.path)
        raw = body
        if self.headers.get("Content-Encoding", "").lower() == "gzip":
            raw = gzip.decompress(body)
        rec = {"t": time.time(), "port": self.server.server_address[1], "method": self.command, "path": u.path,
               "query": parse_qsl(u.query, keep_blank_values=True), "headers": {k.lower(): v for k, v in self.headers.items()},
               "body_len": len(body), "decoded_len": len(raw)}
        ctype = self.headers.get("Content-Type", "")
        if "x-www-form-urlencoded" in ctype:
            rec["form"] = parse_qsl(raw.decode(), keep_blank_values=True)
        elif raw:
            try:
                rec["json"] = json.loads(raw)
            except Exception:
                rec["text"] = raw[:2000].decode("utf-8", "replace")
        with lock, open(OUT, "a") as f:
            f.write(json.dumps(rec) + "\n")
        return rec

    def _send(self, code, obj=None, headers=None):
        data = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(code)
        if obj is not None:
            self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def handle_any(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        rec = self._record(body)
        p = rec["path"]
        if p.endswith("/.well-known/openid-configuration"):
            tenant = p.split("/")[1]
            return self._send(200, {"token_endpoint": f"{AUTH}/{tenant}/oauth2/v2.0/token", "issuer": f"{AUTH}/{tenant}/v2.0",
                                    "authorization_endpoint": f"{AUTH}/{tenant}/oauth2/v2.0/authorize",
                                    "jwks_uri": f"{AUTH}/{tenant}/discovery/v2.0/keys", "token_endpoint_auth_methods_supported": ["client_secret_post", "private_key_jwt", "client_secret_basic"],
                                    "tenant_region_scope": "EU"})
        if p.endswith("/oauth2/v2.0/token"):
            return self._send(200, {"token_type": "Bearer", "expires_in": 3599, "ext_expires_in": 3599, "access_token": "eyJ.fake." + uuid.uuid4().hex})
        if p == "/metadata/identity/oauth2/token":
            if self.headers.get("Metadata") != "true":
                return self._send(400, {"error": "invalid_request", "error_description": "Required metadata header not specified"})
            now = int(time.time())
            return self._send(200, {"access_token": "eyJ.imds." + uuid.uuid4().hex, "client_id": "uami", "expires_in": "86399",
                                    "expires_on": str(now + 86399), "ext_expires_in": "86399", "not_before": str(now),
                                    "resource": dict(rec["query"]).get("resource", ""), "token_type": "Bearer"})
        if p.startswith("/dataCollectionRules/"):
            return self._send(204)
        return self._send(404, {"error": "not found"})

    do_GET = do_POST = do_PUT = handle_any


def serve(port, tls):
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(f"{TLS}/server.pem", f"{TLS}/server.key")
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


threading.Thread(target=serve, args=(18080, False), daemon=True).start()
serve(18443, True)
