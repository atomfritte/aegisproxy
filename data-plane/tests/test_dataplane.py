"""Unit tests for the mitmproxy-independent data-plane modules.

Run:  python3 -I -m unittest discover -s data-plane/tests -t data-plane
"""

import asyncio
import base64
import hashlib
import hmac
import inspect
import json
import os
import struct
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from aegis_dp import clamav  # noqa: E402
from aegis_dp.content import detect_file_type, scan_dlp  # noqa: E402
from aegis_dp.controlplane import sign_block_token  # noqa: E402
from aegis_dp.policy import (  # noqa: E402
    Policy, RedirectGrants, canonicalize_path, hash_token, match_path, VERDICT_ALLOWED, VERDICT_BLOCKED,
    VERDICT_POLICY, VERDICT_THREAT, VERDICT_TLS_BYPASS, VERDICT_LEARNING, VERDICT_REDIRECT, VERDICT_QUARANTINED,
)
from aegis_dp.threatintel import ThreatSnapshot, normalize_url  # noqa: E402

FUTURE = "2099-01-01T00:00:00.123456789Z"

BUNDLE = {
    "revision": 7,
    "security_policy": {"threat_intel_mode": "block", "block_ip_literals": True, "block_private_destinations": True,
                        "allowed_ports": [80, 443], "punycode_mode": "monitor"},
    "internal_domains": [".internal.corp", ".local"],
    "groups": [{"id": "grp-ci", "cidrs": ["10.1.0.0/16"]}, {"id": "grp-vault", "cidrs": ["10.9.0.0/16"], "strict_isolation": True}],
    "servers": [{"id": "srv-ci-1", "hostname": "ci-1", "ip": "10.1.0.5", "proxy_auth_user": "svc-ci-1",
                 "proxy_auth_token_hash": hash_token("s3cret-token"), "group_ids": ["grp-ci"]},
                {"id": "srv-vault-1", "hostname": "vault-1", "ip": "10.9.0.5", "group_ids": ["grp-vault"]}],
    "rules": [
        {"id": "r-gh", "name": "gh", "action": "ALLOW", "host_pattern": "github.com", "path_pattern": "/microsoft/**",
         "methods": ["GET", "HEAD"], "follow_redirects": True, "group_ids": ["grp-ci"], "enabled": True},
        {"id": "r-block", "name": "no secrets", "action": "BLOCK", "host_pattern": "github.com", "path_pattern": "/microsoft/secret/**",
         "group_ids": ["*"], "enabled": True},
        {"id": "r-exp", "name": "expired", "action": "ALLOW", "host_pattern": "old.example", "path_pattern": "/**",
         "group_ids": ["grp-ci"], "enabled": True, "expires_at": "2001-01-01T00:00:00Z"},
        {"id": "r-ip", "name": "explicit ip", "action": "ALLOW", "host_pattern": "203.0.113.10", "path_pattern": "/**",
         "group_ids": ["grp-ci"], "enabled": True},
        {"id": "r-wild", "name": "wild", "action": "ALLOW", "host_pattern": "*", "path_pattern": "/**", "group_ids": ["grp-ci"],
         "enabled": True, "expires_at": FUTURE},
    ],
    "tls_bypass": [{"id": "tls-wu", "pattern": "*.windowsupdate.com", "enabled": True}],
    "sessions": [],
}

THREATS = {
    "version": "t1",
    "sources": [{"id": "f1", "name": "Feed", "category": "malware"}, {"id": "f2", "name": "DROP", "category": "hijacked_network"}],
    "domains": {"evil.example": 0}, "domains_sub": {"phish.example": 0}, "urls": {"https://cdn.example/x.exe": 0},
    "ips": {"198.51.100.9": 1}, "cidrs": [["192.0.2.0/24", 1]], "hashes": {"a" * 64: 0},
    "exceptions": {"domains": ["ok.phish.example"], "urls": [], "ips": [], "hashes": []},
}


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.p = Policy(BUNDLE)
        self.t = ThreatSnapshot(THREATS)
        self.g = RedirectGrants()

    def ev(self, host, path="/", method="GET", port=443, ip="10.1.0.5", auth="", url=None):
        return self.p.evaluate(ip, auth, method, host, port, path, url or f"https://{host}{path}", self.t, self.g)

    def test_canonicalization(self):
        self.assertEqual(canonicalize_path("/a/%2e%2e/b"), ("/b", True))
        self.assertEqual(canonicalize_path("/a/%252e%252e/b")[0], "/b")
        self.assertFalse(canonicalize_path("/a%00b")[1])
        self.assertFalse(canonicalize_path("/a\\b")[1])
        self.assertTrue(match_path("/microsoft/**", "/microsoft/vscode/x"))
        self.assertFalse(match_path("/microsoft/**", "/microsoftx/vscode"))
        self.assertFalse(match_path("/microsoft/**", "/microsoft/../torvalds/linux"))

    def test_evaluation_order_matches_control_plane(self):
        cases = [
            ("github.com", "/microsoft/vscode", 443, VERDICT_ALLOWED, ""),
            ("github.com", "/microsoft/secret/a", 443, VERDICT_BLOCKED, "block_rule"),
            ("evil.example", "/", 443, VERDICT_THREAT, "threat_intel"),
            ("login.phish.example", "/", 443, VERDICT_THREAT, "threat_intel"),
            ("ok.phish.example", "/", 443, VERDICT_ALLOWED, ""),  # exception -> falls through to catch-all
            ("192.0.2.77", "/", 443, VERDICT_THREAT, "threat_intel"),
            ("8.8.8.8", "/", 443, VERDICT_POLICY, "ip_literal"),
            ("203.0.113.10", "/", 443, VERDICT_ALLOWED, ""),  # explicit IP rule
            ("169.254.169.254", "/latest", 80, VERDICT_POLICY, "forbidden_destination"),
            ("db.internal.corp", "/", 443, VERDICT_POLICY, "internal_destination"),
            ("example.org", "/", 8443, VERDICT_POLICY, "port_not_allowed"),
            ("github.com", "/x%00", 443, VERDICT_POLICY, "malformed_path"),
        ]
        for host, path, port, verdict, reason in cases:
            r = self.ev(host, path, port=port)
            self.assertEqual((r.verdict, r.block_reason if reason else ""), (verdict, reason), f"{host}{path}:{port} -> {r}")
        self.assertIn("THREAT", self.ev("cdn.example", "/x.exe").verdict)
        self.assertEqual(self.ev("xn--pple-43d.com").security_flags, ["PUNYCODE"])

    def test_identity(self):
        self.assertFalse(self.ev("github.com", "/microsoft/x", ip="192.0.2.200").allowed)  # unknown source
        r = self.ev("github.com", "/microsoft/x", ip="192.0.2.200", auth="svc-ci-1:s3cret-token")
        self.assertEqual((r.server_id, r.verdict), ("srv-ci-1", VERDICT_ALLOWED))
        r = self.ev("github.com", "/microsoft/x", ip="192.0.2.200", auth="svc-ci-1")  # bare user, wrong IP
        self.assertNotEqual(r.server_id, "srv-ci-1")
        self.assertEqual(self.ev("github.com", "/microsoft/x", ip="10.1.99.99").server_id, "srv-auto-10-1-99-99")

    def test_tls_bypass_and_strict_isolation(self):
        self.assertEqual(self.ev("x.windowsupdate.com", method="CONNECT").verdict, VERDICT_TLS_BYPASS)
        self.assertNotEqual(self.ev("x.windowsupdate.com", method="CONNECT", ip="10.9.0.5").verdict, VERDICT_TLS_BYPASS)

    def test_connect_semantics(self):
        # Path-specific BLOCK rules must not block the CONNECT; host-level ALLOW lets the tunnel through.
        self.assertEqual(self.ev("github.com", method="CONNECT").verdict, VERDICT_ALLOWED)

    def test_redirect_grants_and_sessions(self):
        self.g.register("10.1.0.5", "https://objects.example/asset.tgz", "https://github.com/microsoft/x", "r-gh", "gh")
        p = Policy({**BUNDLE, "rules": BUNDLE["rules"][:2]})
        r = p.evaluate("10.1.0.5", "", "GET", "objects.example", 443, "/asset.tgz", "", self.t, self.g)
        self.assertEqual(r.verdict, VERDICT_REDIRECT)
        r = p.evaluate("10.1.0.5", "", "POST", "objects.example", 443, "/asset.tgz", "", self.t, self.g)
        self.assertEqual(r.verdict, VERDICT_BLOCKED)  # grants are read-only
        self.assertFalse(self.g.register("10.1.0.5", "http://127.0.0.1/x", "https://github.com/", "r", "n"))
        sess = {**BUNDLE, "rules": [], "sessions": [{"id": "s1", "server_id": "srv-ci-1", "mode": "record_and_allow",
                                                    "status": "active", "expires_at": FUTURE, "name": "rec"}]}
        r = Policy(sess).evaluate("10.1.0.5", "", "GET", "pypi.org", 443, "/simple/", "", self.t, self.g)
        self.assertEqual(r.verdict, VERDICT_LEARNING)
        r = Policy(sess).evaluate("10.1.0.5", "", "GET", "8.8.8.8", 443, "/", "", self.t, self.g)
        self.assertEqual(r.verdict, VERDICT_POLICY)  # sessions never open IP literals

    def test_expired_rule_ignored(self):
        p = Policy({**BUNDLE, "rules": [BUNDLE["rules"][2]]})
        self.assertFalse(p.evaluate("10.1.0.5", "", "GET", "old.example", 443, "/", "", self.t, self.g).allowed)


class ThreatTests(unittest.TestCase):
    def test_normalize_url(self):
        self.assertEqual(normalize_url("HTTPS://Evil.Example:443/a?b=1#f"), "https://evil.example/a?b=1")
        self.assertIsNone(normalize_url("ftp://x/"))

    def test_hash_and_ip(self):
        t = ThreatSnapshot(THREATS)
        self.assertIsNotNone(t.match_hash("A" * 64))
        self.assertEqual(t.match_host("198.51.100.9").category, "hijacked_network")
        self.assertIsNone(t.match_host("good.example"))


class BlockTokenTests(unittest.TestCase):
    def test_format_and_signature(self):
        key = "k" * 40
        tok = sign_block_token(key, {"ip": "10.1.0.5", "url": "https://x.example/", "m": "GET", "tid": "flw-1"})
        body, sig = tok.rsplit(".", 1)
        self.assertTrue(body.startswith("v1."))
        sub = hmac.new(key.encode(), b"aegis-block-token-v1", hashlib.sha256).digest()
        want = base64.urlsafe_b64encode(hmac.new(sub, body.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
        self.assertEqual(sig, want)
        claims = json.loads(base64.urlsafe_b64decode(body[3:] + "=" * (-len(body[3:]) % 4)))
        self.assertGreater(claims["exp"], time.time())


class ContentTests(unittest.TestCase):
    def test_dlp(self):
        all_d = ["private_key", "aws_access_key", "github_token", "credit_card", "unix_shadow", "slack_token"]
        self.assertEqual(scan_dlp([b"key=AKIAIOSFODNN7EXAMPLE"], all_d), ["aws_access_key"])
        self.assertEqual(scan_dlp([b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc"], all_d), ["private_key"])
        self.assertEqual(scan_dlp([b"card 4111 1111 1111 1111 exp"], all_d), ["credit_card"])
        self.assertEqual(scan_dlp([b"order 4111 1111 1111 1112"], all_d), [])  # Luhn fails
        self.assertEqual(scan_dlp([b"root:$6$saltsalt$hashhashhashhash:19000:0:99999:7:::"], all_d), ["unix_shadow"])
        self.assertEqual(scan_dlp([b"AKIAIOSFODNN7EXAMPLE"], ["private_key"]), [])  # detector disabled

    def test_file_types(self):
        self.assertEqual(detect_file_type(b"MZ\x90\x00"), "pe")
        self.assertEqual(detect_file_type(b"\x7fELF\x02\x01"), "elf")
        self.assertEqual(detect_file_type(b"#!/bin/sh\necho"), "script")
        self.assertEqual(detect_file_type(b"\xca\xfe\xba\xbe\x00\x00\x00\x02"), "macho")
        self.assertEqual(detect_file_type(b"\xca\xfe\xba\xbe\x00\x00\x00\x34"), "java_class")
        self.assertEqual(detect_file_type(b"PK\x03\x04....word/vbaProject.bin"), "office_macro")
        self.assertEqual(detect_file_type(b"\x1f\x8b\x08\x00"), "archive")
        self.assertEqual(detect_file_type(b"Write-Host hi", "https://x.example/setup.ps1"), "script")
        self.assertIsNone(detect_file_type(b"{\"json\": true}", "https://x.example/api"))


EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class ClamdTests(unittest.TestCase):
    def test_parse_reply(self):
        self.assertEqual(clamav.parse_reply("stream: OK").status, "clean")
        r = clamav.parse_reply("stream: Eicar-Test-Signature FOUND")
        self.assertEqual((r.status, r.signature), ("infected", "Eicar-Test-Signature"))
        self.assertEqual(clamav.parse_reply("INSTREAM size limit exceeded. ERROR").status, "error")
        self.assertEqual(clamav.parse_address("tcp://clamav:3310"), ("tcp", "clamav", 3310))
        self.assertEqual(clamav.parse_address("unix:///run/clamd.ctl"), ("unix", "/run/clamd.ctl", 0))

    def test_instream_against_fake_clamd(self):
        async def handler(reader, writer):
            cmd = await reader.readuntil(b"\0")
            if cmd == b"zPING\0":
                writer.write(b"PONG\0")
            else:
                data = b""
                while True:
                    (n,) = struct.unpack("!I", await reader.readexactly(4))
                    if n == 0:
                        break
                    data += await reader.readexactly(n)
                writer.write(b"stream: Eicar-Test-Signature FOUND\0" if b"EICAR" in data else b"stream: OK\0")
            await writer.drain()
            writer.close()

        async def run():
            server = await asyncio.start_server(handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            c = clamav.ClamdClient(f"tcp://127.0.0.1:{port}", timeout=5)
            self.assertTrue(await c.ping())
            self.assertEqual((await c.scan(EICAR)).status, "infected")
            self.assertEqual((await c.scan(b"x" * 200_000)).status, "clean")
            server.close()
            await server.wait_closed()
            bad = clamav.ClamdClient("tcp://127.0.0.1:1", timeout=2)
            self.assertEqual((await bad.scan(b"x")).status, "error")

        asyncio.run(run())


class PolicySetSemanticsTest(unittest.TestCase):
    def test_quarantine_and_wildcard_scope(self):
        bundle = json.loads(json.dumps(BUNDLE))
        bundle["servers"][0]["quarantined"] = True
        bundle["rules"].append({"id": "r-base", "name": "baseline updates", "action": "ALLOW", "host_pattern": "updates.example",
                                "path_pattern": "/**", "group_ids": ["*"], "server_ids": ["*"], "enabled": True})
        p = Policy(bundle)
        ti, g = ThreatSnapshot({}), RedirectGrants()
        r = p.evaluate("10.1.0.5", "", "GET", "github.com", 443, "/microsoft/x", "https://github.com/microsoft/x", ti, g)
        self.assertEqual(r.verdict, VERDICT_QUARANTINED)
        self.assertFalse(r.allowed)
        r = p.evaluate("10.9.0.5", "", "GET", "updates.example", 443, "/a", "https://updates.example/a", ti, g)
        self.assertTrue(r.allowed, "baseline must apply to registered servers")
        r = p.evaluate("192.0.2.200", "", "GET", "updates.example", 443, "/a", "https://updates.example/a", ti, g)
        self.assertFalse(r.allowed, "baseline must never apply to unregistered sources")


class BrandedBlockPageTest(unittest.TestCase):
    SHELL = ('<html lang="x"><style nonce="%%AEGIS:nonce%%"></style><h1>%%AEGIS:server_hostname%%</h1>'
             '<a href="%%AEGIS:portal_url%%">p</a><img src="%%AEGIS:logo%%"><p>%%AEGIS:url%%</p>'
             '<script type="application/json">%%AEGIS:data_json%%</script>')

    def bundle(self):
        shells = lambda tag: {"request_html": tag + self.SHELL, "threat_html": tag + "THREAT %%AEGIS:reason%%",
                              "request_cli": tag + "CLI %%AEGIS:url%% %%AEGIS:cli_payload%%", "threat_cli": tag + "TCLI"}
        return {"default_template_id": "bp-default", "group_templates": {"grp-pci": "bp-pci"}, "templates": {
            "bp-default": {"default_locale": "en", "logo": "data:image/png;base64,iVBORw0KGgo=", "allowed_scopes": ["exact_path"],
                           "allowed_durations": ["1h"], "shells": {"en": shells("EN"), "de": shells("DE")}},
            "bp-pci": {"default_locale": "de", "logo": "javascript:alert(1)", "shells": {"de": shells("PCI")}}}}

    def ctx(self, verdict="BLOCKED"):
        return {"status": "403", "verdict": verdict, "reason": "<b>r</b>", "server_hostname": "<img src=x onerror=alert(1)>",
                "server_ip": "10.1.0.5", "method": "GET", "url": "https://x.example/%%AEGIS:nonce%%\x1b[31m", "trace_id": "t1",
                "block_token": "v1.a.b", "public_url": "https://aegis.example", "dashboard_url": "https://console.example",
                "suggested": "x.example/**", "suggested_host": "x.example"}

    def test_render(self):
        from aegis_dp.blockpage import pick_locale, render_branded
        self.assertEqual(pick_locale("fr-FR,de;q=0.8,en;q=0.5", ["en", "de"], "en"), "de")
        self.assertEqual(pick_locale("", ["en", "de"], "de"), "de")
        self.assertEqual(pick_locale("en;q=0,de", ["en", "de"], "en"), "de")
        body, csp = render_branded(self.bundle(), self.ctx(), ["grp-ci"], "de-DE,de;q=0.9", False)
        self.assertTrue(body.startswith("DE"))
        self.assertNotIn("<img src=x", body)
        self.assertIn("&lt;img src=x", body)
        self.assertIn("%%AEGIS:nonce%%", body.split("<p>")[1], "values must not be re-scanned for placeholders")
        self.assertNotIn("\x1b", body)
        nonce = csp.split("'nonce-")[1].split("'")[0]
        self.assertIn(f'nonce="{nonce}"', body)
        self.assertIn('src="data:image/png;base64,iVBORw0KGgo="', body)
        self.assertIn("https://console.example/?portal=block&amp;bt=v1.a.b", body)
        cli, _ = render_branded(self.bundle(), self.ctx(), ["grp-ci"], "", True)
        self.assertTrue(cli.startswith("ENCLI"))
        self.assertIn('"requested_scope": "exact_path"', cli)
        self.assertIn('"duration": "1h"', cli)
        pci, _ = render_branded(self.bundle(), self.ctx(), ["grp-ci", "grp-pci"], "en", False)
        self.assertTrue(pci.startswith("PCI"), "group template and its only locale must be used")
        self.assertIn('src=""', pci, "invalid logo must be dropped")
        threat, _ = render_branded(self.bundle(), self.ctx("QUARANTINED"), ["grp-ci"], "en", False)
        self.assertEqual(threat, "ENTHREAT &lt;b&gt;r&lt;/b&gt;")
        self.assertIsNone(render_branded({}, self.ctx(), [], "en", False))


class AccessLogTest(unittest.TestCase):
    REC = {"id": "flw-1", "server_ip": "10.1.0.5", "proxy_auth_user": "svc-ci", "method": "GET", "host": "pypi.org", "port": 443,
           "full_url": "https://pypi.org/simple/x y/", "status_code": 200, "verdict": "ALLOWED", "bytes_sent": 100,
           "bytes_received": 2048, "latency_ms": 42, "resolved_ip": "151.101.0.223", "content_type": "text/html; charset=utf-8",
           "user_agent": 'pip/24 "x"'}

    def test_formats(self):
        from aegis_dp.accesslog import format_record
        sq = format_record(self.REC, "squid", now=1761134400.5)
        self.assertEqual(sq.split()[:9], ["1761134400.500", "42", "10.1.0.5", "TCP_MISS/200", "2148", "GET",
                                          "https://pypi.org/simple/x%20y/", "svc-ci", "HIER_DIRECT/151.101.0.223"])
        denied = format_record(dict(self.REC, verdict="BLOCKED", status_code=403), "squid", now=0)
        self.assertIn("TCP_DENIED/403", denied)
        self.assertIn("HIER_NONE/-", denied)
        tunnel = format_record(dict(self.REC, verdict="TLS_BYPASS", method="CONNECT", status_code=0), "squid", now=0)
        self.assertIn("TCP_TUNNEL/200", tunnel)
        self.assertIn("CONNECT pypi.org:443", tunnel)
        clf = format_record(self.REC, "combined", now=0)
        self.assertTrue(clf.startswith('10.1.0.5 - svc-ci [01/Jan/1970:00:00:00 +0000] "GET https://pypi.org/simple/x%20y/ HTTP/1.1" 200 2148'))
        self.assertIn('"pip/24 \'x\'"', clf)
        js = json.loads(format_record(self.REC, "json", now=0))
        self.assertEqual(js["verdict"], "ALLOWED")
        self.assertEqual(js["log_type"], "aegisproxy.access")
        injected = format_record(dict(self.REC, full_url="https://x/\nFAKE LINE"), "squid", now=0)
        self.assertNotIn("\n", injected)

    def test_file_destination(self):
        import tempfile
        from aegis_dp.accesslog import AccessLog
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "access.log")
            al = AccessLog(path, "json")
            al.write(self.REC)
            al.write(dict(self.REC, verdict="BLOCKED"))
            al.flush()
            for h in al.logger.handlers:
                h.flush()
            with open(path, encoding="utf-8") as f:
                lines = f.read().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertFalse(AccessLog("off").enabled)
            al.close()  # Windows cannot delete a file that is still open

    def test_file_rotation_by_size(self):
        # Windows default: the worker rotates the file itself (an open file cannot be renamed externally).
        import tempfile
        from aegis_dp.accesslog import AccessLog
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "access.log")
            al = AccessLog(path, "json", rotate_bytes=600, keep=2)
            for i in range(12):
                al.write(dict(self.REC, id=f"flow-{i}"))
            al.flush()
            al.close()
            names = sorted(os.listdir(d))
            self.assertEqual(names, ["access.log", "access.log.1", "access.log.2"])
            for n in names:
                self.assertLessEqual(os.path.getsize(os.path.join(d, n)), 600 + 2048)
            with open(path, encoding="utf-8") as f:
                newest = [json.loads(line)["id"] for line in f.read().splitlines()]
            self.assertEqual(newest[-1], "flow-11")
            self.assertFalse(al.enabled)

    def test_access_log_rotation_config(self):
        from aegis_dp.config import Config, ConfigError
        base = {"AEGIS_DATAPLANE_KEY": "k" * 40}
        old = dict(os.environ)
        try:
            os.environ.update(base)
            os.environ.pop("AEGIS_ACCESS_LOG_ROTATE_MB", None)
            cfg = Config.from_env()
            self.assertEqual(cfg.access_log_rotate_mb, 100 if os.name == "nt" else 0)
            self.assertEqual(cfg.access_log_keep, 10)
            os.environ["AEGIS_ACCESS_LOG_ROTATE_MB"] = "-1"
            with self.assertRaises(ConfigError):
                Config.from_env()
            os.environ["AEGIS_ACCESS_LOG_ROTATE_MB"] = "50"
            os.environ["AEGIS_ACCESS_LOG_KEEP"] = "0"
            with self.assertRaises(ConfigError):
                Config.from_env()
            os.environ["AEGIS_ACCESS_LOG_KEEP"] = "3"
            cfg = Config.from_env()
            self.assertEqual((cfg.access_log_rotate_mb, cfg.access_log_keep), (50, 3))
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_unreachable_tcp_syslog_never_raises(self):
        import socket as s
        from aegis_dp.accesslog import AccessLog
        srv = s.socket()
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.close()  # nothing listens here
        al = AccessLog(f"syslog+tcp://127.0.0.1:{port}", "squid")
        al.write(self.REC)
        al.flush()
        self.assertEqual(al.dropped, 1)
        lsock = s.socket()
        lsock.bind(("127.0.0.1", 0))
        lsock.listen(1)
        al2 = AccessLog(f"syslog+tcp://127.0.0.1:{lsock.getsockname()[1]}", "json")
        al2.write(self.REC)
        conn, _ = lsock.accept()
        conn.settimeout(3)
        data = conn.recv(65536).decode()
        conn.close()
        lsock.close()
        self.assertTrue(data.startswith("<174>aegisproxy-access: {") and data.endswith("\n"))


class IcapTest(unittest.TestCase):
    """Fake ICAP server speaking RFC 3507 framing (204, 200 with infection header, 200 with sanitized body)."""

    def run_server(self, behaviour):
        async def handler(reader, writer):
            head = await reader.readuntil(b"\r\n\r\n")
            text = head.decode("latin-1")
            method = text.split(" ", 1)[0]
            if method == "OPTIONS":
                writer.write(b"ICAP/1.0 200 OK\r\nMethods: RESPMOD, REQMOD\r\nISTag: \"t1\"\r\nAllow: 204\r\nEncapsulated: null-body=0\r\n\r\n")
                await writer.drain(); writer.close(); return
            enc = dict(p.strip().split("=") for p in text.split("Encapsulated:")[1].split("\r\n")[0].split(","))
            hdr_len = int(enc.get("res-body", enc.get("req-body", enc.get("null-body", "0"))))
            hdrs = await reader.readexactly(hdr_len)
            body = b""
            if "res-body" in enc or "req-body" in enc:
                while True:
                    size = int((await reader.readuntil(b"\r\n")).strip() or b"0", 16)
                    if size == 0:
                        await reader.readuntil(b"\r\n"); break
                    body += await reader.readexactly(size); await reader.readexactly(2)
            self.seen.append((method, hdrs, body))
            writer.write(behaviour(method, body))
            await writer.drain(); writer.close()

        async def go(client_coro):
            server = await asyncio.start_server(handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            try:
                return await client_coro(port)
            finally:
                server.close(); await server.wait_closed()
        self.seen = []
        return go

    def test_icap_results(self):
        from aegis_dp.icap import IcapClient, parse_icap_url
        self.assertEqual(parse_icap_url("icap://av.corp:1344/avscan"), ("av.corp", 1344, "/avscan", False))
        self.assertEqual(parse_icap_url("icaps://av.corp/x")[1], 11344)
        with self.assertRaises(ValueError):
            parse_icap_url("http://x/")

        def behaviour(method, body):
            if b"EICAR" in body:
                page = b"<html>blocked</html>"
                res_hdr = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n"
                return (b"ICAP/1.0 200 OK\r\nX-Infection-Found: Type=0; Resolution=2; Threat=Eicar-Test-Signature;\r\n"
                        b"Encapsulated: res-hdr=0, res-body=%d\r\n\r\n" % len(res_hdr) + res_hdr + b"%x\r\n" % len(page) + page + b"\r\n0\r\n\r\n")
            if b"MACRO" in body:
                clean = b"sanitized"
                res_hdr = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n"
                return (b"ICAP/1.0 200 OK\r\nEncapsulated: res-hdr=0, res-body=%d\r\n\r\n" % len(res_hdr) + res_hdr + b"9\r\n" + clean + b"\r\n0\r\n\r\n")
            if b"SECRET" in body and method == "REQMOD":
                res_hdr = b"HTTP/1.1 403 Forbidden\r\n\r\n"
                return b"ICAP/1.0 200 OK\r\nX-Violations-Found: 1\r\nEncapsulated: res-hdr=0, null-body=%d\r\n\r\n" % len(res_hdr) + res_hdr
            return b"ICAP/1.0 204 No Content\r\nEncapsulated: null-body=0\r\n\r\n"

        go = self.run_server(behaviour)

        async def scenario(port):
            c = IcapClient(f"icap://127.0.0.1:{port}/avscan", timeout=5)
            out = {"options": await c.options()}
            hdrs = [("User-Agent", "curl/8"), ("Authorization", "Bearer must-not-leak")]
            out["clean"] = await c.respmod("GET", "https://x.example/a.bin", hdrs, 200, [("Content-Type", "application/octet-stream")], b"hello")
            out["infected"] = await c.respmod("GET", "https://x.example/e.com", hdrs, 200, [], EICAR)
            out["modified"] = await c.respmod("GET", "https://x.example/d.docx", hdrs, 200, [], b"MACRO payload")
            out["dlp"] = await c.reqmod("POST", "https://paste.example/upload", hdrs, b"SECRET=hunter2")
            out["upload_ok"] = await c.reqmod("POST", "https://api.example/v1", hdrs, b"{}")
            return out

        out = asyncio.run(go(scenario))
        self.assertTrue(out["options"])
        self.assertEqual(out["clean"].status, "clean")
        self.assertEqual(out["infected"].status, "infected")
        self.assertEqual(out["infected"].threat, "Eicar-Test-Signature")
        self.assertEqual(out["modified"].status, "modified")
        self.assertEqual(out["modified"].body, b"sanitized")
        self.assertEqual(out["dlp"].status, "infected")
        self.assertEqual(out["upload_ok"].status, "clean")
        for _, hdrs, _ in self.seen:
            self.assertNotIn(b"must-not-leak", hdrs, "credentials must not be forwarded to the ICAP service")

        async def unreachable():
            c = IcapClient("icap://127.0.0.1:1/x", timeout=2)
            return await c.respmod("GET", "https://x/", [], 200, [], b"x")
        self.assertEqual(asyncio.run(unreachable()).status, "error")


class YaraTest(unittest.TestCase):
    def test_yara_engine(self):
        from aegis_dp import yara_scan
        eng = yara_scan.YaraEngine()
        if not eng.available:
            self.skipTest("no YARA engine installed (yara-x is installed in the data-plane image)")
        eng.configure([{"id": "rs1", "source": 'rule Eicar_Test { strings: $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $a }', "enabled": True}])
        self.assertEqual(eng.status, "ok")
        self.assertEqual(eng.scan(EICAR), ["Eicar_Test"])
        self.assertEqual(eng.scan(b"harmless"), [])
        good = {"id": "rs1", "name": "EICAR", "source": 'rule Eicar_Test { strings: $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $a }', "enabled": True}
        other = {"id": "rs3", "name": "Harmless", "source": 'rule Harmless_Marker { strings: $a = "harmless" condition: $a }', "enabled": True}
        # A broken set is skipped; the other sets stay active.
        eng.configure([good, {"id": "rs2", "name": "Broken", "source": "rule broken { condition: ", "enabled": True}, other])
        hb = eng.heartbeat()
        self.assertTrue(hb.startswith("error:1 of 3 rule sets failed: Broken:"), hb)
        self.assertIn("skipped", hb)
        self.assertEqual(eng.scan(EICAR), ["Eicar_Test"])
        self.assertEqual(eng.scan(b"harmless"), ["Harmless_Marker"])
        # A broken edit of a working set keeps its previous version active.
        eng.configure([dict(good, source="rule Eicar_Test { condition: "), other])
        self.assertIn("previous version stays active", eng.heartbeat())
        self.assertEqual(eng.scan(EICAR), ["Eicar_Test"], "previous version must stay active after a broken edit")
        # Fixed again -> ok; removed -> no longer active.
        eng.configure([other])
        self.assertEqual(eng.status, "ok")
        self.assertEqual(eng.scan(EICAR), [])



# ---------------------------------------------------------------------------
# Security review 2.1: fail-closed hooks, content decoding, destination binding, ICAP hardening
# ---------------------------------------------------------------------------

import gzip  # noqa: E402
import zlib  # noqa: E402

from aegis_dp import decoding  # noqa: E402
from aegis_dp.config import Config  # noqa: E402
from aegis_dp.destination import DnsCache, check_binding  # noqa: E402
from aegis_dp.policy import parse_ip, printable  # noqa: E402

try:
    from mitmproxy import connection as mconn, http as mhttp, options as moptions, tls as mtls  # noqa: E402
    from mitmproxy.proxy import context as mcontext, mode_specs, server_hooks  # noqa: E402
    from mitmproxy.test import tflow, tutils  # noqa: E402
    HAVE_MITMPROXY = True
except ImportError:  # local runs without mitmproxy: addon tests run in the data-plane image
    HAVE_MITMPROXY = False

PE = b"MZ\x90\x00" + b"EVIL-PE-PAYLOAD-" * 64


class HostileInputTest(unittest.TestCase):
    def test_hash_token_never_raises(self):
        # mitmproxy hands undecodable header bytes over as lone surrogates (surrogateescape).
        self.assertEqual(hash_token("\udcff"), hashlib.sha256(b"\xff").hexdigest())
        self.assertEqual(hash_token("s3cret-token"), hashlib.sha256(b"s3cret-token").hexdigest())
        hash_token("\ud800")  # any other lone surrogate must not raise either
        p = Policy(BUNDLE)
        r = p.evaluate("192.0.2.200", "\udcff", "GET", "github.com", 443, "/microsoft/x", "https://github.com/microsoft/x",
                       ThreatSnapshot(THREATS), RedirectGrants())
        self.assertFalse(r.allowed)
        r = p.evaluate("192.0.2.200", "svc-ci-1:\udcff", "GET", "github.com", 443, "/", "", ThreatSnapshot(THREATS), RedirectGrants())
        self.assertFalse(r.allowed)

    def test_printable(self):
        self.assertEqual(printable("http://a\udcff/\x1b[31m"), "http://a%FF/%1B[31m")
        self.assertEqual(printable("https://x.example/a%20b?q=1"), "https://x.example/a%20b?q=1")
        printable("\ud800").encode("ascii")

    def test_block_page_and_access_log_with_bad_bytes(self):
        from aegis_dp.accesslog import AccessLog
        from aegis_dp.blockpage import render_cli, render_html
        ctx = BrandedBlockPageTest.ctx(BrandedBlockPageTest())
        ctx.update(url="http://a\udcff/x", server_hostname="h\udcff")
        render_html(ctx, [])[0].encode("utf-8")
        render_cli(ctx, []).encode("utf-8")
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            al = AccessLog(os.path.join(d, "a.log"), "squid")
            al.write(dict(AccessLogTest.REC, user_agent="Mozilla \udcff", full_url="http://a\udcff/"))
            al.flush()
            self.assertEqual(al.dropped, 0)
            for h in al.logger.handlers:
                h.close()


class DecodingTest(unittest.TestCase):
    def dec(self, data, ce, limit=1 << 20):
        return decoding.decode_body(data, decoding.parse_codings(ce), limit)

    def test_codings_and_members(self):
        self.assertEqual(self.dec(gzip.compress(PE), "x-gzip")[0], PE)
        self.assertEqual(self.dec(gzip.compress(gzip.compress(PE)), "gzip, gzip")[0], PE)
        self.assertEqual(self.dec(gzip.compress(gzip.compress(PE)), "gzip, x-gzip")[0], PE)
        # Multi-member gzip: clients decode every member, so must the scanner.
        self.assertEqual(self.dec(gzip.compress(b"harmless\n") + gzip.compress(PE), "gzip")[0], b"harmless\n" + PE)
        self.assertEqual(self.dec(gzip.compress(PE) + b"\0\0", "gzip")[0], PE)
        self.assertEqual(self.dec(zlib.compress(PE), "deflate")[0], PE)
        co = zlib.compressobj(wbits=-15)
        self.assertEqual(self.dec(co.compress(PE) + co.flush(), "deflate")[0], PE)
        self.assertEqual(self.dec(PE, "identity")[0], PE)
        if "zstd" in decoding.supported_codings():
            z = decoding.zstd
            self.assertEqual(self.dec(z.compress(b"a") + z.compress(PE), "zstd")[0], b"a" + PE)
        if "br" in decoding.supported_codings():
            self.assertEqual(self.dec(gzip.compress(decoding.brotli.compress(PE)), "br, gzip")[0], PE)

    def test_undecodable(self):
        for data, ce in ((gzip.compress(PE), "compress"), (gzip.compress(PE), "gzip, gzip, gzip, gzip, gzip"),
                         (gzip.compress(PE) + b"trailing", "gzip"), (b"not gzip at all", "gzip"), (PE, "deflate")):
            with self.assertRaises(decoding.UndecodableContent, msg=ce):
                self.dec(data, ce)
        self.assertFalse(decoding.decodable(["compress"]))
        self.assertTrue(decoding.decodable(["gzip", "gzip"]))

    def test_bombs_are_capped(self):
        bomb = gzip.compress(b"\0" * (128 << 20), compresslevel=9)
        started = time.time()
        out, truncated = self.dec(bomb, "gzip", 1 << 20)
        self.assertEqual((len(out), truncated), (1 << 20, True))
        self.assertLess(time.time() - started, 2)
        out, truncated = self.dec(gzip.compress(bomb), "gzip, gzip", 1 << 20)  # nested bomb
        self.assertEqual((len(out), truncated), (1 << 20, True))
        if "br" in decoding.supported_codings():
            br = decoding.brotli.compress(b"\0" * (64 << 20), quality=5)
            out, truncated = self.dec(br, "br", 1 << 20)
            self.assertEqual((len(out), truncated), (1 << 20, True))
        if "zstd" in decoding.supported_codings():
            out, truncated = self.dec(decoding.zstd.compress(b"\0" * (64 << 20)), "zstd", 1 << 20)
            self.assertEqual((len(out), truncated), (1 << 20, True))

    def test_accept_encoding(self):
        f = decoding.filter_accept_encoding
        self.assertEqual(f("gzip, deflate, compress, sdch"), "gzip, deflate")
        self.assertEqual(f("compress"), "identity")
        self.assertIsNone(f(None))
        self.assertTrue(f("*").startswith("gzip, deflate"))
        self.assertEqual(f("gzip;q=0.5, x-gzip"), "gzip;q=0.5, x-gzip")


class DestinationBindingTest(unittest.TestCase):
    def dns(self, answers):
        calls = []

        async def lookup(host, port):
            calls.append(host)
            ans = answers[host] if not callable(answers.get(host)) else answers[host]()
            if isinstance(ans, Exception):
                raise ans
            return [parse_ip(a) for a in ans]
        cache = DnsCache(lookup=lookup)
        cache.calls = calls
        return cache

    def check(self, name, dest, answers, block_private=True):
        return asyncio.run(check_binding(name, dest, 443, self.dns(answers), block_private, (".internal.corp",)))

    def test_binding(self):
        self.assertIsNone(self.check("dl.example", "93.184.215.14", {"dl.example": ["93.184.215.14", "93.184.215.15"]}))
        self.assertEqual(self.check("dl.example", "185.199.108.153", {"dl.example": ["93.184.215.14"]})[0], "host_mismatch")
        self.assertEqual(self.check("nx.example", "185.199.108.153", {"nx.example": OSError("NXDOMAIN")})[0], "host_mismatch")
        self.assertEqual(self.check("a\udcff", "185.199.108.153", {"a\udcff": UnicodeError("idna")})[0], "host_mismatch")
        self.assertIsNone(self.check("185.199.108.153", "185.199.108.153", {}))  # Host is the destination itself
        self.assertEqual(self.check("185.199.108.154", "185.199.108.153", {})[0], "host_mismatch")
        # A public name resolving to an internal destination is DNS rebinding; internal names need a rule upstream.
        self.assertEqual(self.check("dl.example", "10.0.0.5", {"dl.example": ["10.0.0.5"]})[0], "dns_rebinding")
        self.assertIsNone(self.check("dl.example", "10.0.0.5", {"dl.example": ["10.0.0.5"]}, block_private=False))
        self.assertIsNone(self.check("git.internal.corp", "10.0.0.5", {"git.internal.corp": ["10.0.0.5"]}))
        self.assertEqual(self.check("meta.example", "169.254.169.254", {"meta.example": ["169.254.169.254"]})[0],
                         "forbidden_destination")
        self.assertEqual(self.check("dl.example", "backend.example", {})[0], "host_mismatch")

    def test_rotating_answers_and_cache(self):
        seq = iter([["198.51.100.1"], ["198.51.100.2"], ["198.51.100.3"]])
        cache = self.dns({"rr.example": lambda: next(seq)})

        async def run():
            from aegis_dp.destination import bound
            first = await bound("rr.example", parse_ip("198.51.100.2"), 443, cache)  # cached miss -> fresh lookup
            again = await bound("rr.example", parse_ip("198.51.100.1"), 443, cache)  # merged answers, cache hit
            return first, again
        self.assertEqual(asyncio.run(run()), (True, True))
        self.assertEqual(len(cache.calls), 2)
        small = DnsCache(max_entries=8)
        for i in range(50):
            small.remember(f"h{i}.example", [parse_ip("198.51.100.1")])
        self.assertLessEqual(len(small._entries), 8)


class IcapHardeningTest(unittest.TestCase):
    def serve(self, handler, scenario):
        async def go():
            server = await asyncio.start_server(handler, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            try:
                return await asyncio.wait_for(scenario(port), 20)
            finally:
                server.close()
        return asyncio.run(go())

    def test_deadline_covers_sending(self):
        from aegis_dp.icap import IcapClient

        async def never_reads(reader, writer):
            await asyncio.sleep(15)
            writer.close()

        async def scenario(port):
            started = time.time()
            r = await IcapClient(f"icap://127.0.0.1:{port}/av", timeout=1).respmod("GET", "https://x/", [], 200, [], b"x" * (32 << 20))
            return r, time.time() - started
        res, took = self.serve(never_reads, scenario)
        self.assertEqual(res.status, "error")
        self.assertLess(took, 5, "the payload upload must be covered by the ICAP timeout")

    def test_protocol_garbage_is_an_error_result(self):
        from aegis_dp.icap import IcapClient

        async def garbage(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"garbage\r\n\r\n")
            await writer.drain()
            writer.close()

        async def scenario(port):
            c = IcapClient(f"icap://127.0.0.1:{port}/av", timeout=3)
            return [await c.respmod("GET", "https://x/", [], 200, [], b"body"), await c.reqmod("POST", "https://x/", [], b"body"),
                    await c.respmod("GET", "http://[::1/", [], 200, [], b"body")]
        for r in self.serve(garbage, scenario):
            self.assertEqual(r.status, "error")

    def test_single_content_length_and_reqmod_modified(self):
        from aegis_dp.icap import IcapClient
        seen = []

        async def handler(reader, writer):
            head = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1")
            enc = dict(p.strip().split("=") for p in head.split("Encapsulated:")[1].split("\r\n")[0].split(","))
            body_key = "res-body" if "res-body" in enc else "req-body"
            hdrs = await reader.readexactly(int(enc[body_key]))
            seen.append(hdrs)
            size = int((await reader.readuntil(b"\r\n")).strip(), 16)
            await reader.readexactly(size + 2)
            await reader.readuntil(b"\r\n")
            if head.startswith("REQMOD"):
                req_hdr = b"POST /upload HTTP/1.1\r\nHost: x\r\n\r\n"
                writer.write(b"ICAP/1.0 200 OK\r\nEncapsulated: req-hdr=0, req-body=%d\r\n\r\n" % len(req_hdr) + req_hdr
                             + b"5\r\nclean\r\n0\r\n\r\n")
            else:
                writer.write(b"ICAP/1.0 204 No Content\r\nEncapsulated: null-body=0\r\n\r\n")
            await writer.drain()
            writer.close()

        async def scenario(port):
            c = IcapClient(f"icap://127.0.0.1:{port}/av", timeout=3)
            a = await c.respmod("GET", "https://x/a", [], 200, [("Content-Length", "999"), ("Content-Type", "text/plain")], b"hello")
            b = await c.reqmod("POST", "https://x/upload", [("Content-Length", "6")], b"SECRET")
            return a, b
        clean, modified = self.serve(handler, scenario)
        self.assertEqual(clean.status, "clean")
        self.assertEqual(seen[0].lower().count(b"content-length:"), 1)
        self.assertIn(b"Content-Length: 5\r\n", seen[0])
        self.assertEqual((modified.status, modified.body), ("modified", b"clean"))


ADDON_BUNDLE = {
    "revision": 3,
    "security_policy": {"threat_intel_mode": "block", "block_ip_literals": True, "block_private_destinations": True,
                        "allowed_ports": [80, 443], "blocked_file_types": ["pe"], "dlp_mode": "block",
                        "dlp_detectors": ["aws_access_key"], "av_max_scan_bytes": 1 << 20},
    "internal_domains": [".internal.corp"],
    "groups": [{"id": "g1"}],
    "servers": [{"id": "srv-1", "hostname": "testsrv", "ip": "10.1.0.5", "group_ids": ["g1"]}],
    "rules": [
        {"id": "r1", "name": "downloads", "action": "ALLOW", "host_pattern": "dl.example", "path_pattern": "/**", "group_ids": ["g1"], "enabled": True},
        {"id": "r2", "name": "git", "action": "ALLOW", "host_pattern": "git.internal.corp", "path_pattern": "/**", "group_ids": ["g1"], "enabled": True},
    ],
    "tls_bypass": [{"id": "tb1", "pattern": "update.example", "enabled": True, "group_ids": ["g1"]}],
    "sessions": [],
}


@unittest.skipUnless(HAVE_MITMPROXY, "mitmproxy not installed (runs in the data-plane image)")
class AddonSecurityTest(unittest.TestCase):
    """Hook-level regression tests with mitmproxy test flows (security review 2.1)."""

    @classmethod
    def setUpClass(cls):
        import logging
        cls._level = logging.getLogger("aegis").level
        logging.getLogger("aegis").setLevel(logging.CRITICAL)  # the tests trigger hook failures on purpose

    @classmethod
    def tearDownClass(cls):
        import logging
        logging.getLogger("aegis").setLevel(cls._level)

    def addon(self, answers=None, **security):
        from aegis_dp.addon import AegisAddon
        a = AegisAddon(Config(control_plane_url="http://127.0.0.1:1", dataplane_key="k" * 40, worker_id="test", ops_addr=""))
        bundle = json.loads(json.dumps(ADDON_BUNDLE))
        bundle["security_policy"].update(security)
        a.cp.policy = Policy(bundle)

        async def lookup(host, port):
            if host not in (answers or {}):
                raise OSError("NXDOMAIN")
            return [parse_ip(x) for x in answers[host]]
        a.dns = DnsCache(lookup=lookup)
        return a

    def flow(self, host, path="/file.bin", method="GET", headers=(), mode="regular", body=b"", port=80, scheme="http", sni=None):
        client = tflow.tclient_conn()
        client.peername = ("10.1.0.5", 40000)
        client.sni = sni
        client.proxy_mode = mode_specs.ProxyMode.parse(mode)
        hdrs = mhttp.Headers([(k.encode(), v.encode("utf-8", "surrogateescape")) for k, v in headers])
        req = tutils.treq(host=host, port=port, scheme=scheme.encode(), method=method.encode(), path=path.encode(),
                          headers=hdrs, content=body)
        return tflow.tflow(client_conn=client, req=req)

    @staticmethod
    def call(a, hook, data):
        r = getattr(a, hook)(data)
        if inspect.isawaitable(r):
            asyncio.run(r)

    def exchange(self, a, f, resp_headers=(), content=b"", status=200):
        """Runs the HTTP hook sequence like mitmproxy; returns (response, body bytes delivered to the client)."""
        for hook in ("requestheaders", "request"):
            self.call(a, hook, f)
        if f.response is not None:  # answered locally: mitmproxy emulates responseheaders
            self.call(a, "responseheaders", f)
            self.call(a, "response", f)
            return f.response, f.response.raw_content
        f.response = tutils.tresp(status_code=status, content=content,
                                  headers=mhttp.Headers([(k.encode(), v.encode()) for k, v in resp_headers]))
        self.call(a, "responseheaders", f)
        stream = f.response.stream
        if stream:
            # streamed: chunks are relayed as they arrive (through the stream callable) and not stored
            f.response.raw_content = b""
            delivered = (stream(content) + stream(b"")) if callable(stream) else content
            self.call(a, "response", f)
            return f.response, delivered
        self.call(a, "response", f)
        return f.response, f.response.raw_content

    def records(self, a):
        return list(a.cp._queue)

    # -- C1 -------------------------------------------------------------------
    def test_c1_undecodable_proxy_authorization(self):
        a = self.addon()
        f = self.flow("10.0.1.158", "/secret", headers=[("Proxy-Authorization", "Bearer \udcff"), ("Host", "10.0.1.158")])
        self.call(a, "requestheaders", f)
        self.assertEqual(f.response.status_code, 403)
        self.assertEqual(self.records(a)[-1]["block_reason"], "ip_literal")
        c = self.flow("10.0.1.158", "", method="CONNECT", headers=[("Proxy-Authorization", "Bearer \udcff")], port=443)
        self.call(a, "http_connect", c)
        self.assertEqual(c.response.status_code, 403)

    def test_c1_undecodable_host_header(self):
        a = self.addon()
        for ua in ("curl/8", "Mozilla/5.0"):
            f = self.flow("dl.example", "/secret", headers=[("Host", "a\udcff"), ("User-Agent", ua), ("Accept", "text/html")])
            self.call(a, "requestheaders", f)
            self.assertEqual(f.response.status_code, 403, ua)
            self.assertEqual(self.records(a)[-1]["block_reason"], "malformed_host")
            self.assertIn(b"a%FF", f.response.raw_content)

    def test_c1_generic_guard(self):
        a = self.addon()

        def boom(*_a, **_k):
            raise RuntimeError("evaluation exploded")
        a.cp.policy.evaluate = boom
        f = self.flow("dl.example", headers=[("Host", "dl.example")])
        self.call(a, "requestheaders", f)
        self.assertEqual((f.response.status_code, f.response.headers["X-Aegis-Verdict"]), (403, "POLICY_BLOCKED"))
        self.assertEqual(self.records(a)[-1]["block_reason"], "internal_error")
        self.assertIn('aegis_dp_hook_errors_total{hook="requestheaders"} 1', a.metrics.render({}))
        # the remaining hooks pass the locally generated block through unchanged
        self.call(a, "request", f)
        self.call(a, "responseheaders", f)
        self.call(a, "response", f)
        self.assertEqual(f.response.status_code, 403)

        def unreachable(*_a, **_k):
            raise ConnectionRefusedError("engine down")
        a.cp.policy.evaluate = unreachable
        f = self.flow("dl.example", headers=[("Host", "dl.example")])
        self.call(a, "requestheaders", f)
        self.assertEqual(f.response.status_code, 503, "infrastructure errors answer 503")
        c = self.flow("dl.example", "", method="CONNECT", port=443)
        self.call(a, "http_connect", c)
        self.assertEqual(c.response.status_code, 503)

    def test_c1_exceptions_in_later_hooks(self):
        a = self.addon()
        f = self.flow("dl.example", headers=[("Host", "dl.example")])
        self.call(a, "requestheaders", f)
        self.assertIsNone(f.response)
        a._inspect_body = None  # any bug in the inspection path
        resp, body = self.exchange(a, f, [("Content-Type", "application/octet-stream")], b"data")
        self.assertEqual(resp.status_code, 403)
        self.assertNotIn(b"data", body)
        self.assertIn('hook="response"', a.metrics.render({}))
        # DLP stage
        f = self.flow("dl.example", method="POST", headers=[("Host", "dl.example")], body=b"x")
        self.call(a, "requestheaders", f)
        a.cp.policy.security["dlp_max_scan_bytes"] = "broken"
        self.call(a, "request", f)
        self.assertEqual(f.response.status_code, 403)

    def test_c1_unevaluated_flows_are_blocked(self):
        a = self.addon()
        f = self.flow("dl.example", headers=[("Host", "dl.example")])  # requestheaders never completed
        self.call(a, "request", f)
        self.assertEqual(f.response.status_code, 403)
        f = self.flow("dl.example", headers=[("Host", "dl.example")])
        f.response = tutils.tresp(content=PE)
        self.call(a, "responseheaders", f)
        self.assertEqual(f.response.status_code, 403)
        self.assertNotIn(b"EVIL", f.response.stream(PE))
        self.call(a, "response", f)
        f = self.flow("dl.example", headers=[("Host", "dl.example")])
        f.response = tutils.tresp(content=PE)
        self.call(a, "response", f)
        self.assertEqual(f.response.status_code, 403)
        self.assertNotIn(b"EVIL", f.response.raw_content)

    def test_c1_tls_and_server_connect_guards(self):
        a = self.addon()
        client = tflow.tclient_conn()
        client.sni = "update.example"
        cx = mcontext.Context(client, moptions.Options())
        cx.server = mconn.Server(address=("update.example", 443))
        data = mtls.ClientHelloData(cx, None)
        a.cp.policy.evaluate = lambda *_a, **_k: 1 / 0
        self.call(a, "tls_clienthello", data)
        self.assertFalse(data.ignore_connection)
        a.cp.policy = Policy(ADDON_BUNDLE)
        f = self.flow("dl.example", headers=[("Host", "dl.example")])
        f.client_conn = client
        self.call(a, "requestheaders", f)
        self.assertEqual((f.response.status_code, self.records(a)[-1]["block_reason"]), (403, "internal_error"))
        sc = server_hooks.ServerConnectionHookData(server=mconn.Server(address=("93.184.215.14", 443)), client=client)
        a._regular_like = None  # break the hook
        self.call(a, "server_connect", sc)
        self.assertIn("fail-closed", sc.server.error)

    # -- H5 / H7 ------------------------------------------------------------
    def test_h5_encoded_downloads_are_decoded(self):
        a = self.addon()
        variants = [("x-gzip", gzip.compress(PE)), ("gzip, gzip", gzip.compress(gzip.compress(PE))),
                    ("gzip", gzip.compress(b"") + gzip.compress(PE)), ("deflate", zlib.compress(PE))]
        if "br" in decoding.supported_codings():
            variants.append(("br", decoding.brotli.compress(PE)))
        if "zstd" in decoding.supported_codings():
            variants.append(("zstd", decoding.zstd.compress(b"") + decoding.zstd.compress(PE)))
        for ce, data in variants:
            f = self.flow("dl.example", headers=[("Host", "dl.example"), ("Accept-Encoding", "gzip, deflate, br, zstd, compress")])
            resp, body = self.exchange(a, f, [("Content-Encoding", ce), ("Content-Type", "application/octet-stream")], data)
            self.assertEqual(resp.status_code, 403, ce)
            self.assertNotIn(b"EVIL", body)
            self.assertEqual(self.records(a)[-1]["verdict"], "FILETYPE_BLOCKED", ce)
            self.assertNotIn("compress", f.request.headers["Accept-Encoding"].split(", "))
        # every gzip member is scanned: the digest covers what the client decodes, not just the first member
        f = self.flow("dl.example", headers=[("Host", "dl.example")])
        resp, body = self.exchange(a, f, [("Content-Encoding", "gzip")], gzip.compress(b"harmless\n") + gzip.compress(b"tail"))
        self.assertEqual(self.records(a)[-1]["content_sha256"], hashlib.sha256(b"harmless\ntail").hexdigest())
        # harmless encoded content still flows, unchanged on the wire
        f = self.flow("dl.example", headers=[("Host", "dl.example")])
        data = gzip.compress(b"plain text " * 100)
        resp, body = self.exchange(a, f, [("Content-Encoding", "gzip"), ("Content-Type", "text/plain")], data)
        self.assertEqual((resp.status_code, body), (200, data))
        self.assertEqual(self.records(a)[-1]["content_sha256"], hashlib.sha256(b"plain text " * 100).hexdigest())

    def test_h5_undecodable_downloads_are_blocked(self):
        a = self.addon()
        f = self.flow("dl.example", headers=[("Host", "dl.example")])
        resp, body = self.exchange(a, f, [("Content-Encoding", "compress"), ("Content-Type", "application/octet-stream")], PE)
        self.assertEqual(resp.status_code, 403)
        self.assertNotIn(b"EVIL", body)
        self.assertEqual(self.records(a)[-1]["block_reason"], "undecodable_content")
        f = self.flow("dl.example", headers=[("Host", "dl.example")])
        resp, body = self.exchange(a, f, [("Content-Encoding", "gzip")], gzip.compress(PE) + b"junk")
        self.assertEqual((resp.status_code, self.records(a)[-1]["block_reason"]), (403, "undecodable_content"))
        # without inspection nothing is decoded or blocked
        b = self.addon(blocked_file_types=[], threat_intel_mode="off")
        f = self.flow("dl.example", headers=[("Host", "dl.example"), ("Accept-Encoding", "compress")])
        resp, body = self.exchange(b, f, [("Content-Encoding", "compress")], PE)
        self.assertEqual((resp.status_code, body), (200, PE))
        self.assertEqual(f.request.headers["Accept-Encoding"], "compress")

    def test_h5_encoded_uploads(self):
        a = self.addon()
        f = self.flow("dl.example", method="POST", headers=[("Host", "dl.example"), ("Content-Encoding", "gzip")],
                      body=gzip.compress(b"key=AKIAIOSFODNN7EXAMPLE"))
        self.call(a, "requestheaders", f)
        self.call(a, "request", f)
        self.assertEqual((f.response.status_code, self.records(a)[-1]["verdict"]), (403, "DLP_BLOCKED"))
        f = self.flow("dl.example", method="POST", headers=[("Host", "dl.example"), ("Content-Encoding", "compress")], body=b"x")
        self.call(a, "requestheaders", f)
        self.call(a, "request", f)
        self.assertEqual((f.response.status_code, self.records(a)[-1]["block_reason"]), (403, "undecodable_content"))
        m = self.addon(dlp_mode="monitor")
        f = self.flow("dl.example", method="POST", headers=[("Host", "dl.example"), ("Content-Encoding", "compress")], body=b"x")
        self.call(m, "requestheaders", f)
        self.call(m, "request", f)
        self.assertIsNone(f.response)
        self.assertIn("DLP_UNSCANNED:undecodable", f.metadata["aegis"]["res"].security_flags)

    def test_h7_decompression_bomb(self):
        bomb = gzip.compress(b"\0" * (64 << 20), compresslevel=9)
        a = self.addon()
        f = self.flow("dl.example", headers=[("Host", "dl.example")])
        started = time.time()
        resp, body = self.exchange(a, f, [("Content-Encoding", "gzip"), ("Content-Type", "text/plain")], bomb)
        self.assertLess(time.time() - started, 3)
        self.assertEqual((resp.status_code, body), (200, bomb))  # av_oversize_action=allow: delivered unscanned, flagged
        self.assertIn("AV_UNSCANNED:oversize", self.records(a)[-1]["security_flags"])
        self.assertNotIn("content_sha256", self.records(a)[-1])
        b = self.addon(av_oversize_action="block")
        f = self.flow("dl.example", headers=[("Host", "dl.example")])
        resp, body = self.exchange(b, f, [("Content-Encoding", "gzip"), ("Content-Type", "text/plain")], bomb)
        self.assertEqual((resp.status_code, self.records(b)[-1]["block_reason"]), (403, "av_oversize"))
        # a PE hidden at the start of an oversized stream is still recognised (file type runs on the prefix)
        f = self.flow("dl.example", headers=[("Host", "dl.example")])
        resp, body = self.exchange(a, f, [("Content-Encoding", "gzip")], gzip.compress(PE + b"\0" * (4 << 20)))
        self.assertEqual(resp.status_code, 403)

    # -- H6 / M5 ------------------------------------------------------------
    def test_h6_event_stream_is_inspected(self):
        a = self.addon()
        f = self.flow("dl.example", headers=[("Host", "dl.example")])
        resp, body = self.exchange(a, f, [("Content-Type", "text/event-stream"), ("Content-Disposition", "attachment; filename=x.exe")], PE)
        self.assertEqual(resp.status_code, 403)
        self.assertNotIn(b"EVIL", body)
        b = self.addon(blocked_file_types=[], threat_intel_mode="off")
        f = self.flow("dl.example", headers=[("Host", "dl.example")])
        self.call(b, "requestheaders", f)
        self.call(b, "request", f)
        f.response = tutils.tresp(headers=mhttp.Headers([(b"Content-Type", b"text/event-stream")]), content=b"data: 1\n\n")
        self.call(b, "responseheaders", f)
        self.assertTrue(f.response.stream, "without inspection event streams are relayed unbuffered")

    def test_m5_ranges(self):
        a = self.addon()
        f = self.flow("dl.example", headers=[("Host", "dl.example"), ("Range", "bytes=0-99"), ("If-Range", '"e1"')])
        self.call(a, "requestheaders", f)
        self.assertNotIn("Range", f.request.headers)
        self.assertNotIn("If-Range", f.request.headers)
        self.assertIn("RANGE_STRIPPED", f.metadata["aegis"]["res"].security_flags)
        resp, body = self.exchange(a, f, [("Content-Range", "bytes 4-99/1000")], PE[4:100], status=206)
        self.assertEqual(resp.status_code, 403)
        self.assertNotIn(b"EVIL", body)
        self.assertNotIn("Content-Range", resp.headers)
        self.assertEqual(self.records(a)[-1]["block_reason"], "partial_content")
        b = self.addon(blocked_file_types=[], threat_intel_mode="off")
        f = self.flow("dl.example", headers=[("Host", "dl.example"), ("Range", "bytes=0-99")])
        self.call(b, "requestheaders", f)
        self.assertEqual(f.request.headers["Range"], "bytes=0-99")

    # -- H8 -----------------------------------------------------------------
    def test_h8_transparent_destination_binding(self):
        a = self.addon(answers={"dl.example": ["93.184.215.14"], "evil.example": ["10.0.0.9"]})
        # Host names an allowed site, the connection goes elsewhere
        f = self.flow("185.199.108.153", mode="transparent", headers=[("Host", "dl.example")])
        self.call(a, "requestheaders", f)
        self.assertEqual((f.response.status_code, self.records(a)[-1]["block_reason"]), (403, "host_mismatch"))
        f = self.flow("93.184.215.14", mode="transparent", headers=[("Host", "dl.example")])
        self.call(a, "requestheaders", f)
        self.assertIsNone(f.response, "bound destination is allowed")
        # SOCKS5 behaves like transparent mode; regular-mode semantics are unchanged
        f = self.flow("185.199.108.153", mode="socks5", headers=[("Host", "dl.example")])
        self.call(a, "requestheaders", f)
        self.assertEqual(f.response.status_code, 403)
        # literal destination: internal addresses are checked for transparent connections too
        sc = server_hooks.ServerConnectionHookData(server=mconn.Server(address=("10.0.0.9", 80)), client=f.client_conn)
        self.call(a, "server_connect", sc)
        self.assertIn("internal address", sc.server.error or "")
        reg = self.flow("10.0.0.9", mode="regular")
        sc = server_hooks.ServerConnectionHookData(server=mconn.Server(address=("10.0.0.9", 80)), client=reg.client_conn)
        self.call(a, "server_connect", sc)
        self.assertIsNone(sc.server.error, "regular mode: the literal itself was evaluated by policy (explicit rule)")
        # internal name bound to its internal address (explicit rule) works end to end
        b = self.addon(answers={"git.internal.corp": ["10.0.0.7"]})
        f = self.flow("10.0.0.7", mode="transparent", headers=[("Host", "git.internal.corp")])
        self.call(b, "requestheaders", f)
        self.assertIsNone(f.response)
        sc = server_hooks.ServerConnectionHookData(server=mconn.Server(address=("10.0.0.7", 80)), client=f.client_conn)
        self.call(b, "server_connect", sc)
        self.assertIsNone(sc.server.error)

    def test_h8_tls_passthrough_needs_binding(self):
        a = self.addon(answers={"update.example": ["140.82.112.3"]})
        for dest, expected in (("185.199.108.153", False), ("140.82.112.3", True)):
            client = tflow.tclient_conn()
            client.peername = ("10.1.0.5", 40000)
            client.sni = "update.example"
            client.proxy_mode = mode_specs.ProxyMode.parse("transparent")
            cx = mcontext.Context(client, moptions.Options())
            cx.server = mconn.Server(address=(dest, 443))
            data = mtls.ClientHelloData(cx, None)
            self.call(a, "tls_clienthello", data)
            self.assertEqual(data.ignore_connection, expected, dest)
        sc = server_hooks.ServerConnectionHookData(server=mconn.Server(address=("140.82.112.3", 443)), client=client)
        self.call(a, "server_connect", sc)
        self.assertIsNone(sc.server.error)

    # -- ICAP (addon side) --------------------------------------------------
    def test_icap_reqmod_modified_and_fail_closed(self):
        from aegis_dp.icap import IcapResult
        a = self.addon(icap_reqmod_url="icap://icap.example:1344/dlp", dlp_mode="off")

        async def sanitized(*_args):
            return IcapResult("modified", body=b"clean")
        a._icap_call = sanitized
        f = self.flow("dl.example", method="POST", headers=[("Host", "dl.example"), ("Content-Encoding", "gzip")],
                      body=gzip.compress(b"SECRET payload"))
        self.call(a, "requestheaders", f)
        self.call(a, "request", f)
        self.assertIsNone(f.response)
        self.assertEqual((f.request.raw_content, f.request.headers["Content-Length"]), (b"clean", "5"))
        self.assertNotIn("Content-Encoding", f.request.headers)
        b = self.addon(icap_reqmod_url="icap://icap.example:1344/dlp", dlp_mode="off", icap_allow_modified=False)
        b._icap_call = sanitized
        f = self.flow("dl.example", method="POST", headers=[("Host", "dl.example")], body=b"SECRET")
        self.call(b, "requestheaders", f)
        self.call(b, "request", f)
        self.assertEqual(f.response.status_code, 403)
        # an invalid service URL is an ICAP error, which icap_fail_mode=closed turns into a block
        c = self.addon(icap_reqmod_url="http://not-icap/", icap_fail_mode="closed", dlp_mode="off")
        f = self.flow("dl.example", method="POST", headers=[("Host", "dl.example")], body=b"upload")
        self.call(c, "requestheaders", f)
        self.call(c, "request", f)
        self.assertEqual((f.response.status_code, self.records(c)[-1]["block_reason"]), (503, "icap_error"))
        d = self.addon(icap_respmod_url="http://not-icap/", icap_fail_mode="closed", blocked_file_types=[])
        f = self.flow("dl.example", headers=[("Host", "dl.example")])
        resp, body = self.exchange(d, f, [("Content-Type", "application/octet-stream")], b"harmless")
        self.assertEqual(resp.status_code, 503)

    def test_bounded_connection_state(self):
        from aegis_dp import addon as addon_mod
        a = self.addon()
        for i in range(addon_mod.MAX_TRACKED_CONNECTIONS + 10):
            addon_mod._bounded_put(a.conn_auth, f"c{i}", "u:t")
        self.assertEqual(len(a.conn_auth), addon_mod.MAX_TRACKED_CONNECTIONS)
        self.assertNotIn("c0", a.conn_auth)

if __name__ == "__main__":
    unittest.main()
