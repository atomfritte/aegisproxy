"""Minimal OIDC IdP for UI tests (stdlib only): discovery document and an authorize endpoint that
redirects back to the client's redirect_uri with error=access_denied (exercises the sso_error path)."""
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, urlencode

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18491
ISS = f"http://127.0.0.1:{PORT}"
# A 2048-bit public modulus (the mock never signs tokens; the control-plane only checks the JWKS is usable).
import base64, os
MOD = base64.urlsafe_b64encode(bytes([0xC0]) + os.urandom(254) + bytes([0x01])).rstrip(b"=").decode()

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/.well-known/openid-configuration":
            body = json.dumps({"issuer": ISS, "authorization_endpoint": ISS + "/authorize", "token_endpoint": ISS + "/token", "jwks_uri": ISS + "/jwks",
                               "response_types_supported": ["code"], "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["RS256"],
                               "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"]}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        elif u.path == "/jwks":
            body = json.dumps({"keys": [{"kty": "RSA", "kid": "mock-1", "use": "sig", "alg": "RS256", "n": MOD, "e": "AQAB"}]}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body)
        elif u.path == "/authorize":
            q = parse_qs(u.query)
            target = q["redirect_uri"][0] + "?" + urlencode({"error": "access_denied", "error_description": "The user cancelled", "state": q.get("state", [""])[0]})
            self.send_response(302); self.send_header("Location", target); self.end_headers()
        else:
            self.send_response(404); self.end_headers()

ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
