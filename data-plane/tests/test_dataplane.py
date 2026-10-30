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
    Policy, RedirectGrants, canonicalize_path, hash_token, match_path, normalize_host, request_origin, VERDICT_ALLOWED, VERDICT_BLOCKED,
    VERDICT_POLICY, VERDICT_THREAT, VERDICT_TLS_BYPASS, VERDICT_LEARNING, VERDICT_REDIRECT, VERDICT_QUARANTINED,
)
from aegis_dp.threatintel import ThreatSnapshot, normalize_url  # noqa: E402

FUTURE = "2099-01-01T00:00:00.123456789Z"
VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "testdata", "normalization_vectors.json")

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

    def test_normalization_vectors_shared_with_control_plane(self):
        # The same file drives engine.NormalizeHost/CanonicalizePath tests in the control-plane.
        with open(VECTORS, encoding="utf-8") as fh:
            vectors = json.load(fh)
        self.assertTrue(vectors["hosts"] and vectors["paths"])
        for v in vectors["hosts"]:
            self.assertEqual(normalize_host(v["in"]), v["out"], repr(v["in"]))
        for v in vectors["paths"]:
            self.assertEqual(canonicalize_path(v["in"]), (v["out"], v["ok"]), repr(v["in"]))
        self.assertFalse(canonicalize_path("/a\udcffb")[1], "undecodable path bytes (surrogateescape)")

    def test_path_vectors_shared_with_control_plane(self):
        # The same file drives engine.MatchPath / engine.LegacyPathPattern tests in the control-plane.
        with open(os.path.join(os.path.dirname(VECTORS), "path_vectors.json"), encoding="utf-8") as fh:
            vectors = json.load(fh)
        self.assertTrue(vectors["match"])
        for v in vectors["match"]:
            self.assertEqual(match_path(v["pattern"], v["path"]), v["match"], f'{v["pattern"]!r} vs {v["path"]!r}')
        for v in vectors["legacy"]:  # rewritten legacy patterns keep their meaning in this matcher too
            for path, matched in v["old"]:
                self.assertEqual(match_path(v["out"], path), matched, f'{v["out"]!r} vs {path!r}')
        # linear time: a hostile path against a wildcard-heavy pattern
        start = time.monotonic()
        self.assertFalse(match_path("/" + "*a" * 40 + "/x", "/" + "a" * 8000))
        self.assertLess(time.monotonic() - start, 5)

    def test_identity_vectors_shared_with_control_plane(self):
        # The same file drives store.Identify/Evaluate tests in the control-plane (NAT separation, temporary
        # grants bound to the server identity, proxy token enforcement).
        with open(os.path.join(os.path.dirname(VECTORS), "identity_vectors.json"), encoding="utf-8") as fh:
            v = json.load(fh)
        servers = [{**{k: x for k, x in s.items() if k != "token"}, "proxy_auth_token_hash": hash_token(s["token"])} for s in v["servers"]]
        rules = [{**r, "enabled": True} for r in v["rules"]]
        sessions = [{**s, "status": "active", "expires_at": FUTURE} for s in v["sessions"]]
        p = Policy({**BUNDLE, "groups": v["groups"], "servers": servers, "rules": rules, "sessions": sessions, "tls_bypass": []})
        grants = RedirectGrants()
        for g in v["grants"]:
            self.assertTrue(grants.register(g["server_id"], g["location"], g["parent_url"], g["rule_id"], g["rule_name"]))
        self.assertTrue(v["cases"])
        for c in v["cases"]:
            scheme, port = c.get("scheme", "https"), c.get("port", 443)
            origin = c["host"] if port == {"http": 80, "https": 443}[scheme] else f'{c["host"]}:{port}'
            res = p.evaluate(c["ip"], c["auth"], c["method"], c["host"], port, c["path"], f'{scheme}://{origin}{c["path"]}', self.t, grants)
            self.assertEqual((res.verdict, res.server_id), (c["verdict"], c["server_id"]), c["name"])
            if "block_reason" in c:
                self.assertEqual(res.block_reason, c["block_reason"], c["name"])
            self.assertEqual(res.allowed, c["verdict"] in ("ALLOWED", "LEARNING_ALLOWED", "REDIRECT_OBJECT_ALLOWED"), c["name"])

    def test_auth_failed_block_page(self):
        from aegis_dp.blockpage import render_branded, render_cli, render_html
        res = self.ev("github.com", auth="svc-ci-1:wrong")
        self.assertEqual((res.verdict, res.block_reason, res.group_ids), ("AUTH_FAILED", "invalid_proxy_token", []))
        ctx = {"status": "407", "verdict": res.verdict, "reason": res.matched_rule_name, "server_hostname": res.server_hostname,
               "server_ip": "10.1.0.5", "method": "GET", "url": "https://github.com/", "trace_id": "t", "block_token": "bt",
               "public_url": "https://aegis.example", "dashboard_url": "https://aegis.example", "suggested": "", "suggested_host": ""}
        cli = render_cli(ctx, [])
        self.assertIn("HTTP 407", cli)
        self.assertIn("Rotate token", cli)
        self.assertNotIn("api/public/requests", cli)  # no self-service request for a failed authentication
        page, _ = render_html(ctx, [])
        self.assertIn("Proxy authentication failed", page)
        self.assertNotIn('id="rq"', page)
        tpl = {"default_template_id": "t", "templates": {"t": {"shells": {"en": {"threat_cli": "custom", "request_cli": "custom"}}}}}
        self.assertIsNone(render_branded(tpl, ctx, [], "", True))

    def test_destination_vectors_shared_with_control_plane(self):
        # The same file drives engine.IsInternalAddr / store.alwaysForbiddenAddr tests in the control-plane.
        from aegis_dp.policy import is_forbidden_addr, is_internal_addr, parse_ip
        with open(os.path.join(os.path.dirname(VECTORS), "destination_vectors.json"), encoding="utf-8") as fh:
            vectors = json.load(fh)["addresses"]
        self.assertTrue(vectors)
        for v in vectors:
            addr = parse_ip(v["addr"])
            self.assertEqual((is_internal_addr(addr), is_forbidden_addr(addr)), (v["internal"], v["forbidden"]), v["addr"])
        # Azure WireServer: no rule opens it, by address or by an allowed name resolving to it (review round 2)
        p = Policy({"revision": 1, "security_policy": {"allowed_ports": [80, 443]}, "groups": [{"id": "g1"}],
                    "servers": [{"id": "s1", "ip": "10.1.0.5", "group_ids": ["g1"]}],
                    "rules": [{"id": "r1", "action": "ALLOW", "host_pattern": "168.63.129.16", "path_pattern": "/**",
                               "group_ids": ["g1"], "enabled": True}]})
        res = p.evaluate("10.1.0.5", "", "GET", "168.63.129.16", 80, "/machine", "http://168.63.129.16/machine", self.t, self.g)
        self.assertEqual((res.allowed, res.block_reason), (False, "forbidden_destination"))
        # ... nor its NAT64 / 6to4 encodings, and a wildcard rule never opens them either (review round 3)
        wide = Policy({"revision": 1, "security_policy": {"allowed_ports": [80, 443], "block_ip_literals": False},
                       "groups": [{"id": "g1"}], "servers": [{"id": "s1", "ip": "10.1.0.5", "group_ids": ["g1"]}],
                       "rules": [{"id": "r1", "action": "ALLOW", "host_pattern": "*", "path_pattern": "/**",
                                  "group_ids": ["g1"], "enabled": True}]})
        for host, reason in (("[64:ff9b::a83f:8110]", "forbidden_destination"), ("[2002:a9fe:a9fe::1]", "forbidden_destination"),
                             ("[64:ff9b::a00:5]", "internal_destination"), ("[::a00:5]", "internal_destination")):
            res = wide.evaluate("10.1.0.5", "", "GET", host, 80, "/", "", self.t, self.g)
            self.assertEqual((res.allowed, res.block_reason), (False, reason), host)
        self.assertTrue(wide.evaluate("10.1.0.5", "", "GET", "[64:ff9b::808:808]", 80, "/", "", self.t, self.g).allowed)

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
        self.g.register("srv-ci-1", "https://objects.example/asset.tgz", "https://github.com/microsoft/x", "r-gh", "gh")
        p = Policy({**BUNDLE, "rules": BUNDLE["rules"][:2]})
        r = p.evaluate("10.1.0.5", "", "GET", "objects.example", 443, "/asset.tgz", "", self.t, self.g)
        self.assertEqual(r.verdict, VERDICT_REDIRECT)
        r = p.evaluate("10.1.0.5", "", "POST", "objects.example", 443, "/asset.tgz", "", self.t, self.g)
        self.assertEqual(r.verdict, VERDICT_BLOCKED)  # grants are read-only
        self.assertFalse(self.g.register("srv-ci-1", "http://127.0.0.1/x", "https://github.com/", "r", "n"))
        # rule.redirect_hosts limits the targets that receive a grant
        limited = Policy({**BUNDLE, "rules": [{**BUNDLE["rules"][0], "redirect_hosts": ["*.cdn.example"]}]})
        hosts = limited.evaluate("10.1.0.5", "", "GET", "github.com", 443, "/microsoft/x", "", self.t, self.g).redirect_hosts
        self.assertEqual(hosts, ["*.cdn.example"])
        self.assertFalse(self.g.register("srv-ci-1", "https://evil.example/x", "https://github.com/", "r", "n", allowed_hosts=hosts))
        self.assertTrue(self.g.register("srv-ci-1", "https://eu.cdn.example/x", "https://github.com/", "r", "n", allowed_hosts=hosts))
        self.assertIsNone(self.g.check("srv-ci-1", "evil.example", "/x", "GET"))
        self.assertIsNone(self.g.check("10.1.0.5", "eu.cdn.example", "/x", "GET"))  # keyed by server identity, not address
        # A grant covers exactly the target's origin (scheme, host, effective port); relative targets resolve
        # against the redirecting URL.
        self.assertTrue(self.g.register("srv-ci-1", "https://alt.example:8443/o.bin", "https://github.com/", "r", "n"))
        self.assertTrue(self.g.register("srv-ci-1", "//plain.example/p.bin", "http://github.com/x", "r", "n"))
        self.assertFalse(self.g.register("srv-ci-1", "https://alt.example:0/o.bin", "https://github.com/", "r", "n"))
        self.assertFalse(self.g.register("srv-ci-1", "https://alt.example:99999/o.bin", "https://github.com/", "r", "n"))
        for args, granted in ((("https", 8443), True), (("http", 80), False), (("https", 443), False), (("http", 8443), False)):
            self.assertEqual(self.g.check("srv-ci-1", "alt.example", "/o.bin", "GET", *args) is not None, granted, args)
        self.assertIsNotNone(self.g.check("srv-ci-1", "alt.example", "/", "CONNECT", "https", 8443))
        self.assertIsNone(self.g.check("srv-ci-1", "alt.example", "/", "CONNECT", "https", 443))
        for args, granted in ((("http", 80), True), (("http", 0), True), (("https", 443), False), (("ftp", 80), False)):
            self.assertEqual(self.g.check("srv-ci-1", "plain.example", "/p.bin", "GET", *args) is not None, granted, args)
        self.assertIsNone(self.g.check("srv-ci-1", "plain.example", "/", "CONNECT", "https", 443))
        self.assertIsNotNone(self.g.check("srv-ci-1", "plain.example", "/", "CONNECT", "http", 80))
        evp = lambda port, url: p.evaluate("10.1.0.5", "", "GET", "plain.example", port, "/p.bin", url, self.t, self.g).verdict
        self.assertEqual(evp(80, "http://plain.example/p.bin"), VERDICT_REDIRECT)
        self.assertEqual(evp(443, "https://plain.example/p.bin"), VERDICT_BLOCKED)
        self.assertEqual(request_origin("", 80), ("http", 80))
        self.assertEqual(request_origin("", 0), ("https", 443))
        self.assertEqual(request_origin("https://h.example:8443/x", 8443), ("https", 8443))
        self.assertEqual(request_origin("http://[bad/x", 443), ("https", 443))  # unparseable URL: from the port
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
        # IPv4 indicators also cover their NAT64 / 6to4 encodings (review round 3), like Snapshot.MatchIP
        self.assertEqual(t.match_host("[64:ff9b::c633:6409]").category, "hijacked_network")
        self.assertIsNotNone(t.match_host("[2002:c000:207::1]"))  # 6to4 of 192.0.2.7 (CIDR)
        self.assertIsNone(t.match_host("[64:ff9b::808:808]"))
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
             '<script type="application/json" id="aegis-data">%%AEGIS:data_json%%</script>')

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
        self.assertIn('id="aegis-data">{"endpoint": "https://aegis.example/api/public/requests", "block_token": "v1.a.b"}</script>', body)

    def test_raw_values_only_in_their_context(self):
        # R3-5: a raw placeholder smuggled into another spot of a shell (template text) is escaped like any value:
        # the JSON's quotes must not break out of an attribute.
        from aegis_dp.blockpage import fill
        values = {"nonce": "n0", "logo": "data:image/png;base64,AA==", "data_json": '{"a": "x\\u003c"}'}
        out = fill('<a title="%%AEGIS:data_json%%" href="%%AEGIS:logo%%">%%AEGIS:nonce%%</a>'
                   '<i nonce="%%AEGIS:data_json%%"></i><img src="%%AEGIS:logo%%">'
                   '<script type="application/json" id="aegis-data">%%AEGIS:data_json%%</script>', values, True)
        self.assertEqual(out, '<a title="{&quot;a&quot;: &quot;x\\u003c&quot;}" href="data:image/png;base64,AA==">n0</a>'
                              '<i nonce="{&quot;a&quot;: &quot;x\\u003c&quot;}"></i><img src="data:image/png;base64,AA==">'
                              '<script type="application/json" id="aegis-data">{"a": "x\\u003c"}</script>')


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

    def test_write_and_rotation_failures_are_counted(self):
        import tempfile
        from aegis_dp.accesslog import AccessLog

        class Broken:
            def write(self, _data):
                raise OSError("No space left on device")

            def flush(self):
                pass

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "access.log")
            al = AccessLog(path, "json")
            handler = al.logger.handlers[0]
            real, handler.stream = handler.stream, Broken()
            with self.assertLogs("aegis.dataplane", "WARNING") as warned:
                al.write(self.REC)
                al.flush()
            self.assertEqual(al.dropped, 1, "a failed write is a dropped line, not a silent stderr traceback")
            self.assertIn("No space left on device", warned.output[0])
            handler.stream = real
            al.close()

            def refuse(_src, _dst):
                raise PermissionError("the file is in use by another process")
            al = AccessLog(path, "json", rotate_bytes=200, keep=2)
            al.logger.handlers[0].rotator = refuse
            with self.assertLogs("aegis.dataplane", "WARNING"):
                for i in range(5):
                    al.write(dict(self.REC, id=f"r-{i}"))
                al.flush()
            for h in al.logger.handlers:
                h.flush()
            self.assertEqual((al.rotation_failures, al.dropped), (1, 0), "retried after a minute, lines keep going to the file")
            with open(path, encoding="utf-8") as f:
                ids = [json.loads(line)["id"] for line in f.read().splitlines() if line.startswith("{")]
            self.assertEqual(ids[-5:], [f"r-{i}" for i in range(5)])
            al.close()

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
        with self.assertLogs("aegis.dataplane", "WARNING"):
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


class BufferingTest(unittest.TestCase):
    def test_budget_and_guard(self):
        from aegis_dp.buffering import BLOCK, BodyGuard, BufferBudget, parse_size
        self.assertEqual([parse_size(v) for v in ("1g", "512m", "64k", "1048576", "")], [1 << 30, 512 << 20, 64 << 10, 1 << 20, None])
        for bad in ("1.5g", "lots", "-1m", "10mb"):
            with self.assertRaises(ValueError):
                parse_size(bad)
        budget = BufferBudget(1000)
        seen = []
        a = BodyGuard(budget, 800, lambda reason, size: seen.append((reason, size)) or BLOCK)
        b = BodyGuard(budget, 800, lambda reason, size: seen.append((reason, size)) or BLOCK)
        self.assertIsNone(a.admit(600))
        self.assertEqual(a.admit(801), "oversize")
        self.assertEqual(b.admit(500), "busy", "600 + 500 exceed the worker budget")
        self.assertEqual(b.exceed("busy", 500), BLOCK)
        self.assertEqual(seen, [("busy", 500)])
        self.assertTrue(a.hold(300))  # decoded copy beyond the cap, still within the budget
        self.assertFalse(b.hold(200))
        self.assertEqual((budget.used, budget.peak), (900, 900))
        a.release()
        a.release()
        self.assertEqual(budget.used, 0)

    def test_declared_size_reserves_nothing_and_clients_get_a_share(self):
        from aegis_dp.buffering import BodyGuard, BufferBudget
        budget = BufferBudget(1000, client_share=0.25)
        self.assertEqual(budget.client_limit(100), 250, "a quarter of the budget ...")
        self.assertEqual(budget.client_limit(400), 800, "... but at least one scan (body + decoded copy)")
        self.assertEqual(budget.client_limit(4000), 1000, "never more than the budget")
        noop = lambda reason, size: "stream"  # noqa: E731
        # An announced Content-Length decides "too large" up front but holds nothing: idle connections that announce
        # large bodies cannot exhaust the budget (round-2 review F1).
        idle = [BodyGuard(budget, 100, noop, client="attacker") for _ in range(64)]
        self.assertEqual([g.declared(100) for g in idle], [None] * 64)
        self.assertEqual((budget.used, budget.clients), (0, {}))
        self.assertEqual(idle[0].declared(101), "oversize")
        self.assertEqual(BodyGuard(BufferBudget(50), 100, noop).declared(80), "busy", "can never fit the budget")
        # Bytes that arrive count against the client's share: one client cannot take more than 250 of 1000 ...
        for g in idle[:2]:
            self.assertIsNone(g.admit(100))
        self.assertEqual(idle[2].admit(100), "busy", "client share (250) exhausted")
        self.assertIsNone(idle[2].admit(50))
        self.assertEqual((budget.used, budget.clients), (250, {"attacker": 250}))
        # ... while another client still gets its own share of the rest.
        other = [BodyGuard(budget, 100, noop, client=f"srv-{i}") for i in range(3)]
        for g in other:
            self.assertIsNone(g.admit(100))
        self.assertEqual(budget.top_client(), 250)
        for g in idle + other:
            g.release()
        self.assertEqual((budget.used, budget.clients), (0, {}))

    def test_buffer_budget_config(self):
        from aegis_dp.config import Config, ConfigError
        old = dict(os.environ)
        try:
            os.environ["AEGIS_DATAPLANE_KEY"] = "k" * 40
            os.environ.pop("AEGIS_BUFFER_BUDGET", None)
            self.assertEqual(Config.from_env().buffer_budget, 0, "default: derived from body_size_limit")
            os.environ["AEGIS_BUFFER_BUDGET"] = "768m"
            self.assertEqual(Config.from_env().buffer_budget, 768 << 20)
            for bad in ("lots", "512k"):
                os.environ["AEGIS_BUFFER_BUDGET"] = bad
                with self.assertRaises(ConfigError):
                    Config.from_env()
            os.environ.pop("AEGIS_BUFFER_BUDGET", None)
            self.assertEqual(Config.from_env().buffer_client_share, 25)
            for value, want in (("10%", 10), ("100", 100), (" 50 % ", 50)):
                os.environ["AEGIS_BUFFER_CLIENT_SHARE"] = value
                self.assertEqual(Config.from_env().buffer_client_share, want, value)
            for bad in ("0", "101", "0.25", "a quarter"):
                os.environ["AEGIS_BUFFER_CLIENT_SHARE"] = bad
                with self.assertRaises(ConfigError):
                    Config.from_env()
        finally:
            os.environ.clear()
            os.environ.update(old)


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
        # an unknown token is an authentication failure, never attributed to the source address
        self.assertEqual(f.response.status_code, 407)
        self.assertEqual((self.records(a)[-1]["verdict"], self.records(a)[-1]["block_reason"]), ("AUTH_FAILED", "invalid_proxy_token"))
        c = self.flow("10.0.1.158", "", method="CONNECT", headers=[("Proxy-Authorization", "Bearer \udcff")], port=443)
        self.call(a, "http_connect", c)
        self.assertEqual(c.response.status_code, 407)

    def test_invalid_proxy_token_is_refused_with_407(self):
        from aegis_dp.addon import parse_proxy_auth
        from aegis_dp.policy import MALFORMED_PROXY_AUTH
        basic = lambda s: "Basic " + base64.b64encode(s.encode()).decode()  # noqa: E731
        self.assertEqual(parse_proxy_auth(None), "")
        self.assertEqual(parse_proxy_auth(basic("svc:tok")), "svc:tok")
        self.assertEqual(parse_proxy_auth(basic("svc:")), "svc")
        self.assertEqual(parse_proxy_auth("Bearer tok"), "tok")
        for bad in ("", "Basic", "Basic !!!", basic(":"), "Negotiate abc", "Bearer  "):
            self.assertEqual(parse_proxy_auth(bad), MALFORMED_PROXY_AUTH, bad)
        a = self.addon()
        # srv-1 is registered for 10.1.0.5: a wrong token from that address must not fall back to the address
        for header in (basic("svc:wrong"), "Basic !!!"):
            c = self.flow("dl.example", "", method="CONNECT", headers=[("Proxy-Authorization", header)], port=443)
            self.call(a, "http_connect", c)
            self.assertEqual(c.response.status_code, 407, header)
            self.assertEqual(c.response.headers.get("Proxy-Authenticate"), 'Basic realm="AegisProxy"')
            self.assertEqual(c.response.headers.get("X-Aegis-Verdict"), "AUTH_FAILED")
            self.assertIn(b"Proxy authentication failed", c.response.raw_content)
            self.assertEqual(self.records(a)[-1]["server_id"], "srv-unregistered-10.1.0.5")
        f = self.flow("dl.example", "/x", headers=[("Host", "dl.example")])  # no credentials: the address identifies srv-1
        self.call(a, "requestheaders", f)
        self.assertIsNone(f.response)

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

    # -- bounded buffering (memory) --------------------------------------------
    def layer(self, f, request=False):
        """A mitmproxy HttpStream that is buffering f's request or response body: its check_body_size is the one
        buffering.install() wrapped, exactly as in the proxy."""
        from mitmproxy.addons.proxyserver import Proxyserver
        from mitmproxy.proxy.layers import http as lhttp
        opts = moptions.Options()
        Proxyserver().load(opts)  # body_size_limit, stream_large_bodies, ... with mitmproxy's defaults
        cx = mcontext.Context(f.client_conn, opts)
        cx.server = f.server_conn
        st = lhttp.HttpStream(cx, 1)
        st.flow = f
        if request:
            st.client_state = st.state_consume_request_body
        else:
            st.client_state, st.server_state = st.state_done, st.state_consume_response_body
        return st

    @staticmethod
    def feed(st, chunks, request=False):
        from mitmproxy.proxy.layers import http as lhttp
        cmds = []
        for c in chunks:
            cmds.extend(st.handle_event((lhttp.RequestData if request else lhttp.ResponseData)(1, c)))
        return cmds

    @staticmethod
    def sent(cmds, kind):
        from mitmproxy.proxy.layers import http as lhttp
        return [c.event for c in cmds if isinstance(c, lhttp.SendHttp) and type(c.event).__name__ == kind]

    def buffered_response(self, a, headers=()):
        f = self.flow("dl.example", headers=[("Host", "dl.example")])
        for hook in ("requestheaders", "request"):
            self.call(a, hook, f)
        f.response = tutils.tresp(headers=mhttp.Headers([(k.encode(), v.encode()) for k, v in headers]), content=b"")
        self.call(a, "responseheaders", f)
        return f

    def test_unknown_length_bodies_are_bounded(self):
        from aegis_dp import buffering
        self.assertTrue(buffering.install())
        # without inspection a response of unknown length is relayed, never accumulated
        n = self.addon(blocked_file_types=[], threat_intel_mode="off")
        f = self.buffered_response(n)
        self.assertTrue(f.response.stream)
        f = self.buffered_response(n, [("Content-Length", "100")])
        self.assertFalse(f.response.stream, "small bodies of known size may still be buffered")
        self.assertEqual(n.budget.used, 0, "a declared Content-Length reserves nothing")
        self.feed(self.layer(f), [b"x" * 100])
        self.assertEqual(n.budget.used, 100, "bytes that arrived are accounted")
        self.call(n, "response", f)
        self.assertEqual(n.budget.used, 0)
        # inspected, no Content-Length: buffered up to av_max_scan_bytes (1 MiB here), then av_oversize_action=allow
        a = self.addon()
        f = self.buffered_response(a)
        self.assertFalse(f.response.stream)
        st = self.layer(f)
        self.assertEqual(self.sent(self.feed(st, [b"a" * (512 << 10)]), "ResponseHeaders"), [])
        self.assertEqual(a.budget.used, 512 << 10)
        cmds = self.feed(st, [b"b" * (600 << 10)])
        self.assertTrue(f.response.stream, "switched to streaming at the scan limit")
        self.assertEqual(len(self.sent(cmds, "ResponseHeaders")), 1)
        self.assertEqual(sum(len(e.data) for e in self.sent(cmds, "ResponseData")), 1112 << 10, "buffered prefix flushed")
        self.assertEqual(len(st.response_body_buf), 0)
        self.assertEqual(a.budget.used, 0)
        self.assertIn("AV_UNSCANNED:oversize", f.metadata["aegis"]["res"].security_flags)
        self.assertEqual(sum(len(e.data) for e in self.sent(self.feed(st, [b"c" * 1000]), "ResponseData")), 1000)
        # av_oversize_action=block: the client gets the block message, the rest of the upstream body is discarded
        b = self.addon(av_oversize_action="block")
        f = self.buffered_response(b)
        st = self.layer(f)
        cmds = self.feed(st, [b"EVIL" * (300 << 10)])
        self.assertEqual(f.response.status_code, 403)
        self.assertEqual([e.response.status_code for e in self.sent(cmds, "ResponseHeaders")], [403])
        self.assertIn(b"antivirus scan limit", b"".join(e.data for e in self.sent(cmds, "ResponseData")))
        self.assertNotIn(b"EVIL", b"".join(e.data for e in self.sent(self.feed(st, [b"EVIL" * 10]), "ResponseData")))
        self.assertEqual(self.records(b)[-1]["block_reason"], "av_oversize")
        self.call(b, "response", f)
        self.assertEqual(b.budget.used, 0)

    def test_oversize_downloads_keep_file_type_control(self):
        # av_oversize_action=allow relays downloads beyond av_max_scan_bytes (1 MiB here) unscanned, but their file
        # type is still read from the head of the body: padding an executable past the scan limit does not get it through.
        from aegis_dp import buffering
        self.assertTrue(buffering.install())
        mib = 1 << 20
        zipped = b"PK\x03\x04" + b"\0" * 26 + b"payload.bin"
        cases = (([("Content-Length", str(3 * mib))], PE, b""),                 # declared oversize: the head is peeked
                 ([], PE, b""),                                                 # unknown length: buffered up to the limit
                 ([("Content-Length", str(3 * mib))], zipped, b""),
                 ([("Content-Length", str(3 * mib)), ("Content-Encoding", "gzip")], PE, b"gzip"))
        for headers, magic, coding in cases:
            a = self.addon(blocked_file_types=["pe", "zip"])
            f = self.buffered_response(a, headers)
            self.assertFalse(f.response.stream, headers)
            body = magic + os.urandom(3 * mib)
            if coding:
                body = gzip.compress(body, compresslevel=1)
            st = self.layer(f)
            cmds = self.feed(st, [body[i:i + (256 << 10)] for i in range(0, len(body), 256 << 10)])
            self.assertEqual([e.response.status_code for e in self.sent(cmds, "ResponseHeaders")], [403], headers)
            self.assertNotIn(magic[:8], b"".join(e.data for e in self.sent(cmds, "ResponseData")))
            rec = self.records(a)[-1]
            self.assertEqual((rec["verdict"], rec["block_reason"], rec["file_type"]),
                             ("FILETYPE_BLOCKED", "file_type", "zip" if magic is zipped else "pe"), headers)
            self.call(a, "response", f)
            self.assertEqual(a.budget.used, 0)
        # a clean oversize download passes (flagged unscanned); the head is held only until its type is known
        for headers in ([("Content-Length", str(3 * mib))], []):
            a = self.addon(blocked_file_types=["pe", "zip"])
            f = self.buffered_response(a, headers)
            st = self.layer(f)
            self.assertEqual(self.sent(self.feed(st, [b"a" * (512 << 10)]), "ResponseHeaders"), [])
            self.assertEqual(a.budget.used, 512 << 10, "the head counts against the buffer budget")
            cmds = self.feed(st, [b"b" * (600 << 10)])
            self.assertTrue(f.response.stream)
            self.assertEqual([e.response.status_code for e in self.sent(cmds, "ResponseHeaders")], [200])
            self.assertEqual(sum(len(e.data) for e in self.sent(cmds, "ResponseData")), 1112 << 10)
            self.assertEqual(a.budget.used, 0)
            self.call(a, "response", f)
            rec = self.records(a)[-1]
            self.assertEqual(rec["verdict"], "ALLOWED")
            self.assertIn("AV_UNSCANNED:oversize", rec["security_flags"])
        # the head needs room in the budget like any inspected body: without it the download fails closed
        a = self.addon(blocked_file_types=["pe"])
        a.budget.total = 300 << 10
        f = self.buffered_response(a, [("Content-Length", str(3 * mib))])
        cmds = self.feed(self.layer(f), [b"y" * (400 << 10)])
        self.assertEqual([e.response.status_code for e in self.sent(cmds, "ResponseHeaders")], [503])
        self.assertEqual(self.records(a)[-1]["block_reason"], "inspection_busy")
        # nothing to check on the head: relayed at once, as before
        n = self.addon(blocked_file_types=[], threat_intel_mode="block")
        n.cp.threat.hashes = {"0" * 64: 0}
        f = self.buffered_response(n, [("Content-Length", str(3 * mib))])
        self.assertTrue(f.response.stream)
        self.assertIn("AV_UNSCANNED:oversize", f.metadata["aegis"]["res"].security_flags)

    def test_worker_budget(self):
        # Concurrent downloads share the budget. Exhausted, an enforcing inspection fails closed (503 with
        # Retry-After) whatever av_oversize_action says: a capacity shortage must not deliver unscanned content.
        a = self.addon()
        a.budget.total = 300 << 10
        f1, f2 = self.buffered_response(a), self.buffered_response(a)
        s1, s2 = self.layer(f1), self.layer(f2)
        self.feed(s1, [b"x" * (200 << 10)])
        cmds = self.feed(s2, [b"y" * (200 << 10)])
        self.assertEqual([e.response.status_code for e in self.sent(cmds, "ResponseHeaders")], [503])
        self.assertEqual(f2.response.headers.get("Retry-After"), "5")
        self.assertNotIn(b"yyyy", b"".join(e.data for e in self.sent(cmds, "ResponseData")))
        self.assertEqual(self.records(a)[-1]["block_reason"], "inspection_busy")
        self.assertFalse(f1.response.stream)
        self.assertEqual(a.budget.used, 200 << 10)
        self.call(a, "error", f1)  # aborted flows return their share
        self.assertEqual((a.budget.used, a.budget.clients), (0, {}))
        # monitor-only inspection (ICAP RESPMOD in monitor mode): skipped and flagged, never blocked
        m = self.addon(blocked_file_types=[], icap_respmod_url="icap://icap.example/av", icap_mode="monitor")
        m.budget.total = 300 << 10
        f1, f2 = self.buffered_response(m), self.buffered_response(m)
        self.feed(self.layer(f1), [b"x" * (200 << 10)])
        cmds = self.feed(self.layer(f2), [b"y" * (200 << 10)])
        self.assertTrue(f2.response.stream)
        self.assertIn("AV_UNSCANNED:busy", f2.metadata["aegis"]["res"].security_flags)
        self.call(m, "error", f1)
        b = self.addon(av_oversize_action="block")
        b.budget.total = 1000
        f = self.flow("dl.example", headers=[("Host", "dl.example")])
        resp, body = self.exchange(b, f, [("Content-Length", "5000"), ("Content-Type", "application/octet-stream")], b"y" * 5000)
        self.assertEqual((resp.status_code, self.records(b)[-1]["block_reason"]), (503, "inspection_busy"))
        self.assertNotIn(b"yyyy", body)
        # a decoded copy that does not fit the budget: scan engines are skipped, the file type check still runs
        c = self.addon()
        c.budget.total = 4096
        f = self.flow("dl.example", headers=[("Host", "dl.example")])
        resp, body = self.exchange(c, f, [("Content-Encoding", "gzip")], gzip.compress(PE + b"\0" * 20000))
        self.assertEqual((resp.status_code, self.records(c)[-1]["verdict"]), (403, "FILETYPE_BLOCKED"))
        self.assertIn("AV_UNSCANNED:busy", self.records(c)[-1]["security_flags"])
        self.assertEqual(c.budget.used, 0)

    def two_servers(self, **security):
        """An addon whose policy knows a second server (10.1.0.6, group g1) next to srv-1 (10.1.0.5)."""
        a = self.addon(**security)
        bundle = json.loads(json.dumps(ADDON_BUNDLE))
        bundle["security_policy"].update(security)
        bundle["servers"].append({"id": "srv-2", "hostname": "victim", "ip": "10.1.0.6", "group_ids": ["g1"]})
        a.cp.policy = Policy(bundle)
        return a

    @staticmethod
    def from_ip(f, ip):
        f.client_conn.peername = (ip, 40001)
        return f

    def test_budget_exhaustion_does_not_disable_inspection(self):
        """Round-2 review F1: a client that announces large uploads (or holds buffered bytes) must neither exhaust
        the budget for others nor make the worker skip inspection."""
        for oversize_action in ("allow", "block"):
            a = self.two_servers(dlp_oversize_action=oversize_action, av_oversize_action=oversize_action)
            a.budget.total = 128 << 20  # 25 % share: 32 MiB per client (upload cap 8 MiB, so 2 x cap = 16 MiB)
            # 64 idle uploads announcing 8 MiB each (no body sent): nothing is reserved
            idle = []
            for _ in range(64):
                f = self.flow("dl.example", "/up", method="POST", headers=[("Host", "dl.example"), ("Content-Length", str(8 << 20))])
                self.call(a, "requestheaders", f)
                self.assertIsNone(f.response)
                idle.append(f)
            self.assertEqual(a.budget.used, 0, oversize_action)
            # the attacker actually sends bytes: at most its share (32 MiB) is held, then its own uploads get 503
            held = []
            for _ in range(9):
                f = self.flow("dl.example", "/up", method="POST", headers=[("Host", "dl.example")])
                self.call(a, "requestheaders", f)
                self.feed(self.layer(f, request=True), [b"z" * (4 << 20)], request=True)
                held.append(f)
            self.assertEqual(a.budget.clients.get("srv-1", 0), 32 << 20)
            self.assertEqual([f.response is None for f in held], [True] * 8 + [False])
            self.assertEqual(held[-1].response.status_code, 503, oversize_action)
            self.assertEqual(held[-1].response.headers.get("Retry-After"), "5")
            # the other server is still inspected: its secret upload is blocked ...
            f = self.from_ip(self.flow("dl.example", "/up", method="POST", headers=[("Host", "dl.example")],
                                       body=b"x" * 1000 + b"\nAKIAIOSFODNN7EXAMPLE"), "10.1.0.6")
            self.call(a, "requestheaders", f)
            self.feed(self.layer(f, request=True), [f.request.raw_content], request=True)
            self.assertIsNone(f.response)
            self.call(a, "request", f)
            self.assertEqual((f.response.status_code, self.records(a)[-1]["verdict"]), (403, "DLP_BLOCKED"), oversize_action)
            self.call(a, "response", f)  # mitmproxy runs the response hook for the local block page too
            # ... and so is its PE download
            f = self.from_ip(self.flow("dl.example", headers=[("Host", "dl.example")]), "10.1.0.6")
            for hook in ("requestheaders", "request"):
                self.call(a, hook, f)
            f.response = tutils.tresp(headers=mhttp.Headers([(b"Content-Length", str(len(PE)).encode())]), content=PE)
            self.call(a, "responseheaders", f)
            self.assertFalse(f.response.stream)
            self.feed(self.layer(f), [PE])
            self.call(a, "response", f)
            self.assertEqual((f.response.status_code, self.records(a)[-1]["verdict"]), (403, "FILETYPE_BLOCKED"), oversize_action)
            # every flow returns its share when it ends or is aborted
            for f in idle + held:
                self.call(a, "error", f)
            self.assertEqual((a.budget.used, a.budget.clients), (0, {}), oversize_action)

    def test_busy_upload_fails_closed_only_when_enforcing(self):
        for security, status in (({}, 503), ({"dlp_oversize_action": "block"}, 503), ({"dlp_mode": "monitor"}, None)):
            a = self.addon(**security)
            a.budget.total = 1 << 20
            f1 = self.flow("dl.example", "/up", method="POST", headers=[("Host", "dl.example")])
            f2 = self.flow("dl.example", "/up", method="POST", headers=[("Host", "dl.example")])
            for f in (f1, f2):
                self.call(a, "requestheaders", f)
            self.feed(self.layer(f1, request=True), [b"a" * (700 << 10)], request=True)
            self.feed(self.layer(f2, request=True), [b"b" * (700 << 10)], request=True)
            if status is None:  # monitor mode never blocks: the upload is streamed and flagged
                self.assertIsNone(f2.response, security)
                self.assertTrue(f2.request.stream)
                self.assertIn("DLP_UNSCANNED:busy", f2.metadata["aegis"]["res"].security_flags)
            else:
                self.assertEqual((f2.response.status_code, self.records(a)[-1]["block_reason"]), (status, "inspection_busy"), security)

    def test_upload_buffering(self):
        # nothing needs the body: streamed
        n = self.addon(dlp_mode="off")
        f = self.flow("dl.example", method="POST", headers=[("Host", "dl.example"), ("Content-Length", "10")], body=b"0123456789")
        self.call(n, "requestheaders", f)
        self.assertTrue(f.request.stream)
        # DLP on, chunked upload beyond the buffer cap (8 MiB): streamed and flagged (allow) ...
        a = self.addon()
        f = self.flow("dl.example", method="POST", headers=[("Host", "dl.example")])
        self.call(a, "requestheaders", f)
        self.assertFalse(f.request.stream)
        st = self.layer(f, request=True)
        cmds = self.feed(st, [b"z" * (4 << 20), b"z" * (5 << 20)], request=True)
        self.assertTrue(f.request.stream)
        self.assertTrue(any(type(c).__name__ == "GetHttpConnection" for c in cmds), "connects upstream to stream the rest")
        self.assertIn("DLP_UNSCANNED:oversize", f.metadata["aegis"]["res"].security_flags)
        self.assertEqual(a.budget.used, 0)
        # ... or blocked with dlp_oversize_action=block: the client gets the block page, nothing is kept
        b = self.addon(dlp_oversize_action="block")
        f = self.flow("dl.example", method="POST", headers=[("Host", "dl.example")])
        self.call(b, "requestheaders", f)
        st = self.layer(f, request=True)
        self.feed(st, [b"z" * (9 << 20), b"z" * (1 << 20)], request=True)
        self.assertEqual((f.response.status_code, self.records(b)[-1]["block_reason"]), (413, "dlp_oversize"))
        self.assertEqual(len(st.request_body_buf), 0)
        # known Content-Length beyond the cap: decided before the body arrives
        f = self.flow("dl.example", method="POST", headers=[("Host", "dl.example"), ("Content-Length", str(64 << 20))])
        self.call(b, "requestheaders", f)
        self.assertEqual(f.response.status_code, 413)
        f = self.flow("dl.example", "/up?k=AKIAIOSFODNN7EXAMPLE", method="POST", headers=[("Host", "dl.example"), ("Content-Length", str(64 << 20))])
        self.call(a, "requestheaders", f)
        self.assertEqual((f.response.status_code, self.records(a)[-1]["verdict"]), (403, "DLP_BLOCKED"), "query scanned before streaming")
        # max_upload_bytes with a chunked upload: buffered up to the limit, then 413
        m = self.addon(dlp_mode="off", max_upload_bytes=10 << 20)
        f = self.flow("dl.example", method="POST", headers=[("Host", "dl.example")])
        self.call(m, "requestheaders", f)
        self.assertFalse(f.request.stream)
        self.feed(self.layer(f, request=True), [b"u" * (6 << 20), b"u" * (6 << 20)], request=True)
        self.assertEqual((f.response.status_code, self.records(m)[-1]["block_reason"]), (413, "upload_too_large"))
        # uploads of blocked requests are discarded as they arrive
        f = self.flow("blocked.example", method="POST", headers=[("Host", "blocked.example")])
        self.call(a, "requestheaders", f)
        self.assertEqual(f.response.status_code, 403)
        st = self.layer(f, request=True)
        self.feed(st, [b"q" * (1 << 20)] * 3, request=True)
        self.assertEqual(len(st.request_body_buf), 0)

    def test_dlp_scans_whole_body_and_flags_oversize(self):
        secret = b"\nAKIAIOSFODNN7EXAMPLE"
        cases = [  # (policy, body, headers, expected status, verdict or flag)
            ({"dlp_max_scan_bytes": 8192}, b"x" * 5000 + secret, [], 403, "DLP_BLOCKED"),
            ({"dlp_max_scan_bytes": 4096}, b"x" * 5000 + secret, [], None, "DLP_UNSCANNED:oversize"),
            ({"dlp_max_scan_bytes": 4096, "dlp_oversize_action": "block"}, b"x" * 5000, [], 413, "dlp_oversize"),
            ({"dlp_max_scan_bytes": 4096, "dlp_oversize_action": "block"}, gzip.compress(b"a" * 100000),
             [("Content-Encoding", "gzip")], 413, "dlp_oversize"),
            ({"dlp_max_scan_bytes": 4096, "dlp_mode": "off", "icap_reqmod_url": "icap://icap.example/dlp", "icap_max_bytes": 1 << 20,
              "dlp_oversize_action": "block"}, gzip.compress(b"a" * (2 << 20)), [("Content-Encoding", "gzip")], 413, "dlp_oversize"),
        ]
        for security, body, headers, status, expect in cases:
            a = self.addon(**security)
            f = self.flow("dl.example", method="POST", headers=[("Host", "dl.example")] + headers, body=body)
            self.call(a, "requestheaders", f)
            self.call(a, "request", f)
            if status is None:
                self.assertIsNone(f.response, security)
                self.assertIn(expect, f.metadata["aegis"]["res"].security_flags, security)
                continue
            self.assertEqual(f.response.status_code, status, security)
            rec = self.records(a)[-1]
            self.assertIn(expect, (rec["verdict"], rec["block_reason"]), security)

    # -- HTTP/2, WebSocket, redirect targets --------------------------------------
    def test_http2_host_header_must_match_authority(self):
        a = self.addon()
        for host_hdr, blocked in (("evil.example", True), ("dl.example:443", False), (None, False), ("dl.example, evil.example", True)):
            f = self.flow("dl.example", headers=[("Host", host_hdr)] if host_hdr else [])
            f.request.http_version = "HTTP/2.0"
            f.request.authority = "dl.example"
            self.call(a, "requestheaders", f)
            self.assertEqual(f.response is not None, blocked, host_hdr)
            if blocked:
                self.assertIn(self.records(a)[-1]["block_reason"], ("host_mismatch", "malformed_host"))

    def test_websocket_upgrade_follows_policy(self):
        a = self.addon()
        ws = [("Upgrade", "websocket"), ("Connection", "Upgrade"), ("Sec-WebSocket-Version", "13"), ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")]
        f = self.flow("blocked.example", "/ws", headers=[("Host", "blocked.example")] + ws)
        self.call(a, "requestheaders", f)
        self.assertEqual((f.response.status_code, self.records(a)[-1]["block_reason"]), (403, "default_deny"))
        f = self.flow("dl.example", "/ws", headers=[("Host", "evil.example")] + ws)
        self.call(a, "requestheaders", f)
        self.assertEqual(self.records(a)[-1]["block_reason"], "host_mismatch")
        f = self.flow("dl.example", "/ws", headers=[("Host", "dl.example")] + ws)
        resp, _ = self.exchange(a, f, [("Upgrade", "websocket"), ("Connection", "Upgrade")], b"", status=101)
        self.assertEqual((resp.status_code, self.records(a)[-1]["verdict"]), (101, "ALLOWED"))

    def test_redirect_grants_follow_rule_redirect_hosts(self):
        a = self.addon()
        bundle = json.loads(json.dumps(ADDON_BUNDLE))
        bundle["rules"][0].update(follow_redirects=True, redirect_hosts=["objects.example"])
        a.cp.policy = Policy(bundle)
        for loc, granted in (("https://other.example/a.bin", False), ("https://objects.example/a.bin", True)):
            f = self.flow("dl.example", headers=[("Host", "dl.example")])
            self.exchange(a, f, [("Location", loc)], b"", status=302)
            host = loc.split("/")[2]
            self.assertEqual(a.grants.check("srv-1", host, "/a.bin", "GET") is not None, granted, loc)
            self.assertIsNone(a.grants.check("10.1.0.5", host, "/a.bin", "GET"))  # keyed by server identity

    def test_bounded_connection_state(self):
        from aegis_dp import addon as addon_mod
        a = self.addon()
        for i in range(addon_mod.MAX_TRACKED_CONNECTIONS + 10):
            addon_mod._bounded_put(a.conn_auth, f"c{i}", "u:t")
        self.assertEqual(len(a.conn_auth), addon_mod.MAX_TRACKED_CONNECTIONS)
        self.assertNotIn("c0", a.conn_auth)


# -- Review round 2: long-lived connections, telemetry delivery, policy max age, query redaction ----------------------

def _bundle(**changes):
    b = json.loads(json.dumps(ADDON_BUNDLE))
    for k, v in changes.items():
        b[k] = v
    return b


class RedactionTest(unittest.TestCase):
    def test_vectors_shared_with_control_plane(self):
        from aegis_dp.redact import redact_url
        with open(os.path.join(os.path.dirname(VECTORS), "redaction_vectors.json"), encoding="utf-8") as fh:
            vectors = json.load(fh)["vectors"]
        self.assertGreater(len(vectors), 20)
        for v in vectors:
            self.assertEqual(redact_url(v["in"], v["mode"]), v["out"], (v["mode"], v["in"]))

    def test_record_flow_redacts_per_policy(self):
        from aegis_dp.controlplane import ControlPlaneClient
        written = []
        cp = ControlPlaneClient(Config(control_plane_url="http://127.0.0.1:1", dataplane_key="k" * 40, worker_id="w1", ops_addr=""),
                                on_flow=written.append)
        url = "https://h.example/cb?code=abc&state=1"
        for setting, want in ((None, "https://h.example/cb?code=REDACTED&state=1"), ("sensitive", "https://h.example/cb?code=REDACTED&state=1"),
                              ("all", "https://h.example/cb"), ("none", url)):
            bundle = _bundle()
            if setting is not None:
                bundle["security_policy"]["telemetry_query_redaction"] = setting
            cp.policy = Policy(bundle)
            cp.record_flow({"id": "flw-1", "full_url": url, "redirect_location": url, "redirect_parent_url": url})
            rec = written[-1]
            self.assertEqual((rec["full_url"], rec["redirect_location"], rec["redirect_parent_url"]), (want, want, want), setting)
            self.assertTrue(rec["timestamp"].endswith("Z"), "records carry the time they happened (replay after outages)")
        cp.policy = None
        cp.record_flow({"id": "flw-2", "full_url": url})
        self.assertIn("REDACTED", written[-1]["full_url"], "no policy loaded yet: the default (sensitive) applies")


class _FakeControlPlane:
    """POST /api/dataplane/flows/batch: mode ok | 503 | 429 | 400; records every accepted flow ID."""

    def __init__(self):
        import http.server
        import threading
        fake = self
        self.mode, self.retry_after, self.received, self.attempts = "ok", "2", [], 0

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fake.attempts += 1
                fake.headers = dict(self.headers)
                if fake.mode == "ok":
                    fake.received.extend(f["id"] for f in body["flows"])
                    code, payload = 201, b'{"recorded_count": 1}'
                else:
                    code, payload = int(fake.mode), b'{"error": "storage unavailable"}'
                self.send_response(code)
                if code in (429, 503):
                    self.send_header("Retry-After", fake.retry_after)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class TelemetryDeliveryTest(unittest.TestCase):
    def setUp(self):
        import logging
        import tempfile
        self._level = logging.getLogger("aegis").level
        logging.getLogger("aegis").setLevel(logging.CRITICAL)
        self.cp_server = _FakeControlPlane()
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        import logging
        self.cp_server.close()
        self.tmp.cleanup()
        logging.getLogger("aegis").setLevel(self._level)

    def client(self, url=None, **cfg):
        from aegis_dp.controlplane import ControlPlaneClient
        return ControlPlaneClient(Config(control_plane_url=url or self.cp_server.url, dataplane_key="k" * 40, worker_id="w1",
                                         ops_addr="", **cfg))

    @staticmethod
    def record(cp, n, start=0):
        for i in range(start, start + n):
            cp.record_flow({"id": f"flw-{i:06d}", "verdict": "BLOCKED", "full_url": "https://x.example/"})

    def test_overflow_is_counted_and_reported(self):
        cp = self.client(url="http://127.0.0.1:1", flow_queue_max=5)
        self.record(cp, 8)
        self.assertEqual((cp.queue_len(), cp.dropped["overflow"], cp.drop_summary()), (5, 3, "overflow=3"))
        cp._flush()  # control-plane down: nothing is lost beyond the overflow
        self.assertEqual((cp.queue_len(), cp.dropped_total()), (5, 3))
        self.assertGreater(cp._retry_at, time.time(), "backoff after a network error")

    def test_backpressure_keeps_the_batch_and_honours_retry_after(self):
        cp = self.client()
        self.record(cp, 3)
        self.cp_server.mode = "503"
        cp._flush()
        self.assertEqual((cp.queue_len(), cp.backpressure, self.cp_server.received), (3, 1, []))
        self.assertAlmostEqual(cp._retry_at - time.time(), 2, delta=0.5)
        cp._flush()
        self.assertEqual(self.cp_server.attempts, 1, "no retry before Retry-After elapsed")
        self.cp_server.mode, cp._retry_at = "429", 0
        cp._flush()
        self.assertEqual((cp.queue_len(), cp.backpressure), (3, 2))
        self.cp_server.mode, cp._retry_at = "ok", 0
        self.record(cp, 2, start=3)
        cp._flush()
        self.assertEqual((cp.queue_len(), sorted(self.cp_server.received)), (0, [f"flw-{i:06d}" for i in range(5)]))
        self.assertEqual(cp.dropped_total(), 0)
        self.assertIn("X-Aegis-Dataplane-Key", self.cp_server.headers)

    def test_rejected_batch_is_dropped_and_counted(self):
        cp = self.client()
        self.record(cp, 2)
        self.cp_server.mode = "400"
        cp._flush()
        self.assertEqual((cp.queue_len(), cp.dropped["rejected"]), (0, 2))

    def test_control_plane_outage_and_worker_restart_with_spool(self):
        spool = os.path.join(self.tmp.name, "spool")
        cp = self.client(url="http://127.0.0.1:1", flow_spool_dir=spool)
        self.record(cp, 1200)
        cp._flush()
        segments = sorted(os.listdir(spool))
        self.assertEqual(len(segments), 3, segments)  # batches of 500 + 500 + 200, fsync'd before any upload
        self.assertEqual(cp.queue_len(), 1200)
        with open(os.path.join(spool, "seg-000000000099-1.jsonl.tmp"), "wb") as fh:
            fh.write(b'{"id": "torn')  # a write interrupted by a crash is never delivered
        # The worker restarts while the control-plane is still down: a new client finds the spool.
        cp2 = self.client(flow_spool_dir=spool)
        self.assertEqual((cp2.queue_len(), len(cp2.spool)), (1200, 3))
        self.assertFalse(any(n.endswith(".tmp") for n in os.listdir(spool)))
        self.record(cp2, 10, start=1200)
        self.cp_server.mode = "503"
        cp2._flush()
        self.assertEqual((cp2.queue_len(), self.cp_server.received), (1210, []))
        self.cp_server.mode, cp2._retry_at = "ok", 0
        cp2._flush()
        self.assertEqual(sorted(self.cp_server.received), [f"flw-{i:06d}" for i in range(1210)])
        self.assertEqual((cp2.queue_len(), os.listdir(spool), cp2.dropped_total()), (0, [], 0))

    def test_spool_size_limit_discards_oldest(self):
        from aegis_dp.spool import FlowSpool
        sp = FlowSpool(os.path.join(self.tmp.name, "small"), 4096)
        dropped = sum(sp.append([{"id": f"flw-{j}-{i}", "pad": "x" * 100} for i in range(10)]) for j in range(5))
        self.assertGreater(dropped, 0)
        self.assertLessEqual(sp.bytes, 4096)
        name, flows, bad = sp.oldest()
        self.assertEqual((bad, flows[0]["id"].split("-")[1] != "0"), (0, True), "the oldest batches went first")
        self.assertEqual(sp.flows + dropped, 50)

    def test_shutdown_spools_pending_records(self):
        spool = os.path.join(self.tmp.name, "spool")
        cp = self.client(url="http://127.0.0.1:1", flow_spool_dir=spool)
        self.record(cp, 7)
        cp.stop()
        self.assertEqual(self.client(flow_spool_dir=spool).queue_len(), 7)

    def test_policy_staleness(self):
        cp = self.client(policy_max_age=60)
        self.assertFalse(cp.policy_stale(), "no policy yet: answered as unavailable, not stale")
        cp.policy = Policy(_bundle())
        cp.last_sync_ok = time.time() - 59
        self.assertFalse(cp.policy_stale())
        cp.last_sync_ok = time.time() - 61
        self.assertTrue(cp.policy_stale())
        unlimited = self.client()
        unlimited.policy, unlimited.last_sync_ok = cp.policy, time.time() - 10 ** 6
        self.assertFalse(unlimited.policy_stale(), "AEGIS_POLICY_MAX_AGE unset (0): never stale")

    def test_config(self):
        import unittest.mock
        from aegis_dp.config import ConfigError, parse_duration
        self.assertEqual([parse_duration(v) for v in ("", "0", "900", "90s", "15m", "2h", "1d", "1h30m")],
                         [0, 0, 900, 90, 900, 7200, 86400, 5400])
        for bad in ("15x", "m", "-5", "1.5h"):
            with self.assertRaises(ValueError, msg=bad):
                parse_duration(bad)
        env = {"AEGIS_DATAPLANE_KEY": "k" * 40}
        for value, want in (("", 0.0), ("15m", 900.0)):
            with unittest.mock.patch.dict(os.environ, dict(env, AEGIS_POLICY_MAX_AGE=value), clear=True):
                self.assertEqual(Config.from_env().policy_max_age, want)
        for value in ("10s", "soon"):
            with unittest.mock.patch.dict(os.environ, dict(env, AEGIS_POLICY_MAX_AGE=value), clear=True):
                with self.assertRaises(ConfigError):
                    Config.from_env()
        with unittest.mock.patch.dict(os.environ, dict(env, AEGIS_FLOW_SPOOL_DIR="/var/spool/aegis", AEGIS_FLOW_SPOOL_MAX="64m"), clear=True):
            c = Config.from_env()
            self.assertEqual((c.flow_spool_dir, c.flow_spool_max), ("/var/spool/aegis", 64 << 20))
        with unittest.mock.patch.dict(os.environ, dict(env, AEGIS_FLOW_SPOOL_MAX="10k"), clear=True):
            with self.assertRaises(ConfigError):
                Config.from_env()

    def test_readyz_reports_the_reason(self):
        import urllib.error
        import urllib.request
        from aegis_dp.ops import Metrics, start_ops_server
        state = {"reason": "policy stale (last successful sync 20m ago, maximum 15m)"}
        srv = start_ops_server("127.0.0.1:0", Metrics(), dict, lambda: state["reason"])
        try:
            url = f"http://127.0.0.1:{srv.server_address[1]}/readyz"
            with self.assertRaises(urllib.error.HTTPError) as err:
                urllib.request.urlopen(url, timeout=5)
            self.assertEqual((err.exception.code, err.exception.read()), (503, b"policy stale (last successful sync 20m ago, maximum 15m)\n"))
            err.exception.close()
            state["reason"] = ""
            with urllib.request.urlopen(url, timeout=5) as resp:
                self.assertEqual(resp.status, 200)
        finally:
            srv.shutdown()
            srv.server_close()


class LiveConnectionDecisionTest(unittest.TestCase):
    """liveconns.decide: when a connection admitted earlier must be closed."""

    def setUp(self):
        self.t = ThreatSnapshot(THREATS)
        self.g = RedirectGrants()

    def conn(self, kind="websocket", host="dl.example", res=None, **kw):
        from aegis_dp.liveconns import LiveConn
        res = res or Policy(_bundle()).evaluate("10.1.0.5", "", "GET", host, 443, "/ws", f"https://{host}/ws", self.t, self.g)
        return LiveConn(key="k", kind=kind, client_id="c1", peer="10.1.0.5", auth="", method="CONNECT" if kind in ("connect", "passthrough") else "GET",
                        host=host, port=443, path="/ws", url=f"https://{host}/ws", verdict=res.verdict, allowed=res.allowed,
                        server_id=res.server_id, group_ids=list(res.group_ids), **kw)

    def decide(self, conn, bundle):
        from aegis_dp.liveconns import decide
        return decide(conn, Policy(bundle), self.t, self.g)[0]

    def test_reasons(self):
        c = self.conn()
        self.assertEqual(c.verdict, VERDICT_ALLOWED)
        self.assertEqual(self.decide(c, _bundle()), "")
        quarantined = _bundle()
        quarantined["servers"][0]["quarantined"] = True
        self.assertEqual(self.decide(c, quarantined), "quarantined")
        self.assertEqual(self.decide(c, _bundle(rules=ADDON_BUNDLE["rules"][1:])), "rule_revoked")
        disabled = _bundle()
        disabled["rules"][0]["enabled"] = False
        self.assertEqual(self.decide(c, disabled), "rule_revoked")
        expired = _bundle()
        expired["rules"][0]["expires_at"] = "2001-01-01T00:00:00Z"
        self.assertEqual(self.decide(c, expired), "rule_revoked")
        moved = _bundle(groups=[{"id": "g1"}, {"id": "g2"}])
        moved["servers"][0]["group_ids"] = ["g2"]
        self.assertEqual(self.decide(c, moved), "group_changed")
        guard = _bundle()
        guard["rules"].append({"id": "b1", "name": "no ws", "action": "BLOCK", "host_pattern": "dl.example", "path_pattern": "/ws",
                               "group_ids": ["*"], "enabled": True})
        self.assertEqual(self.decide(c, guard), "block_rule")
        threat = ThreatSnapshot(dict(THREATS, domains={"dl.example": 0}))
        from aegis_dp.liveconns import decide
        self.assertEqual(decide(c, Policy(_bundle()), threat, self.g)[0], "threat_intel")

    def test_learning_session_and_redirect_grant(self):
        session = {"id": "s1", "name": "learn", "server_id": "srv-1", "mode": "record_and_allow", "status": "active", "expires_at": FUTURE}
        learning = Policy(_bundle(sessions=[session])).evaluate("10.1.0.5", "", "GET", "new.example", 443, "/x", "https://new.example/x", self.t, self.g)
        self.assertEqual(learning.verdict, VERDICT_LEARNING)
        c = self.conn(host="new.example", res=learning)
        self.assertEqual(self.decide(c, _bundle(sessions=[session])), "")
        self.assertEqual(self.decide(c, _bundle()), "learning_session_ended")
        # A download admitted by a redirect grant keeps it for the whole transfer...
        self.g.register("srv-1", "https://objects.example/ws", "https://dl.example/a", "r1", "downloads")
        granted = Policy(_bundle()).evaluate("10.1.0.5", "", "GET", "objects.example", 443, "/ws", "https://objects.example/ws", self.t, self.g)
        self.assertEqual(granted.verdict, VERDICT_REDIRECT)
        c = self.conn(host="objects.example", res=granted, grant=(granted.redirect_parent_url, "r1", "downloads", time.time() + 120))
        self.g = RedirectGrants()  # ...after the 2-minute grant expired
        self.assertEqual(self.decide(c, _bundle()), "")
        quarantined = _bundle()
        quarantined["servers"][0]["quarantined"] = True
        self.assertEqual(self.decide(c, quarantined), "quarantined", "a pinned grant never outlives a quarantine")

    def test_tunnels_and_raw_relays(self):
        p = Policy(_bundle())
        connect = self.conn("connect", res=p.evaluate("10.1.0.5", "", "CONNECT", "dl.example", 443, "/", "", self.t, self.g))
        self.assertEqual(self.decide(connect, _bundle()), "")
        self.assertEqual(self.decide(connect, _bundle(rules=[])), "rule_revoked")
        bypass = self.conn("passthrough", host="update.example",
                           res=p.evaluate("10.1.0.5", "", "CONNECT", "update.example", 443, "/", "", self.t, self.g))
        self.assertEqual(bypass.verdict, VERDICT_TLS_BYPASS)
        self.assertEqual(self.decide(bypass, _bundle()), "")
        self.assertEqual(self.decide(bypass, _bundle(tls_bypass=[])), "tls_bypass_revoked")
        raw = self.conn("tcp")
        relays_on = _bundle()
        relays_on["security_policy"]["block_raw_tcp"] = False
        self.assertEqual(self.decide(raw, relays_on), "")
        self.assertEqual(self.decide(raw, _bundle()), "raw_tcp_disabled")
        relays_on["servers"][0]["quarantined"] = True
        self.assertEqual(self.decide(raw, relays_on), "quarantined")

    def test_next_expiry_and_registry(self):
        from aegis_dp.liveconns import Registry, next_expiry
        now = time.time()
        b = _bundle()
        b["rules"][0]["expires_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 30))
        b["rules"][1]["expires_at"] = "2001-01-01T00:00:00Z"
        self.assertAlmostEqual(next_expiry(Policy(b), now), int(now + 30), delta=1)
        self.assertEqual(next_expiry(Policy(_bundle()), now), float("inf"))
        reg = Registry()
        a, b2, c = self.conn("connect"), self.conn(), self.conn("passthrough")
        a.key, b2.key, c.key = ("connect", "c1"), "flow-1", ("passthrough", "c1")
        for x in (a, b2, c):
            reg.add(x)
        self.assertEqual([x.kind for x in reg.snapshot()], ["websocket", "passthrough", "connect"])
        self.assertEqual(reg.kinds()["connect"], 1)
        reg.drop_client("c1")
        self.assertEqual((len(reg), reg.kinds()["websocket"]), (0, 0))


@unittest.skipUnless(HAVE_MITMPROXY, "mitmproxy not installed (runs in the data-plane image)")
class LongLivedConnectionTest(unittest.TestCase):
    """Hook-level: quarantine/revocation closes WebSockets, tunnels and relays; stale policies fail closed."""

    setUpClass = AddonSecurityTest.setUpClass
    tearDownClass = AddonSecurityTest.tearDownClass
    addon = AddonSecurityTest.addon
    flow = AddonSecurityTest.flow
    exchange = AddonSecurityTest.exchange
    records = AddonSecurityTest.records
    call = staticmethod(AddonSecurityTest.call)

    def websocket(self, a, host="dl.example"):
        from mitmproxy import websocket as mws
        hdrs = [("Host", host), ("Upgrade", "websocket"), ("Connection", "Upgrade"), ("Sec-WebSocket-Version", "13"),
                ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")]
        f = self.flow(host, "/ws?token=s3cr3t", headers=hdrs)
        resp, _ = self.exchange(a, f, [("Upgrade", "websocket"), ("Connection", "Upgrade")], b"", status=101)
        self.assertEqual(resp.status_code, 101)
        f.websocket = mws.WebSocketData()
        self.call(a, "websocket_start", f)
        self.assertIsNotNone(a.live.get(f.id))
        return f

    def send(self, a, f, text):
        from mitmproxy import websocket as mws
        from wsproto.frame_protocol import Opcode
        f.websocket.messages.append(mws.WebSocketMessage(Opcode.TEXT, True, text.encode()))
        self.call(a, "websocket_message", f)
        return f.websocket.messages[-1]

    @staticmethod
    def quarantined():
        b = _bundle(revision=4)
        b["servers"][0]["quarantined"] = True
        return Policy(b)

    def test_quarantine_closes_open_websocket(self):
        a = self.addon()
        f = self.websocket(a)
        self.assertFalse(self.send(a, f, "BEFORE").dropped)
        a.cp.policy = self.quarantined()
        self.assertEqual(a.revalidate_now(), 1)
        self.assertEqual(f.metadata["aegis_terminated"], "quarantined")
        self.assertIsNone(a.live.get(f.id))
        self.assertFalse(f.killable, "the flow was killed")
        rec = self.records(a)[-1]
        self.assertEqual((rec["verdict"], rec["block_reason"], rec["security_flags"]),
                         ("QUARANTINED", "connection_terminated", ["CONNECTION_TERMINATED:quarantined"]))
        self.assertEqual(rec["full_url"], "http://dl.example/ws?token=REDACTED")
        self.assertTrue(self.send(a, f, "AFTER-QUARANTINE").dropped, "nothing reaches the destination afterwards")
        self.assertIn('aegis_dp_connections_terminated_total{kind="websocket",reason="quarantined"} 1', a.metrics.render({}))

    def test_message_after_policy_change_is_checked_before_revalidation_runs(self):
        a = self.addon()
        f = self.websocket(a)
        a.cp.policy = self.quarantined()  # the loop has not processed the update yet
        self.assertTrue(self.send(a, f, "AFTER-QUARANTINE").dropped)
        self.assertEqual(self.records(a)[-1]["security_flags"], ["CONNECTION_TERMINATED:quarantined"])
        a.cp.policy = Policy(_bundle(rules=[]))
        self.assertTrue(self.send(a, f, "still closed").dropped)

    def test_revoked_rule_closes_connect_tunnel_and_passthrough(self):
        a = self.addon()
        c = self.flow("dl.example", "", method="CONNECT", port=443)
        self.call(a, "http_connect", c)
        self.assertIsNone(c.response)
        client = tflow.tclient_conn()
        client.peername, client.sni = ("10.1.0.5", 40001), "update.example"
        cx = mcontext.Context(client, moptions.Options())
        cx.server = mconn.Server(address=("update.example", 443))
        hello = mtls.ClientHelloData(cx, None)
        self.call(a, "tls_clienthello", hello)
        self.assertTrue(hello.ignore_connection)
        self.assertEqual(a.live.kinds()["connect"] + a.live.kinds()["passthrough"], 2)
        self.assertEqual(a.revalidate_now(), 0)
        a.cp.policy = Policy(_bundle(rules=ADDON_BUNDLE["rules"][1:], tls_bypass=[]))
        self.assertEqual(a.revalidate_now(), 2)
        flags = sorted(r["security_flags"][0] for r in self.records(a)[-2:])
        self.assertEqual(flags, ["CONNECTION_TERMINATED:rule_revoked", "CONNECTION_TERMINATED:tls_bypass_revoked"])
        a.client_disconnected(c.client_conn)
        self.assertEqual(len(a.live), 0)

    def test_streamed_response_and_raw_relay(self):
        a = self.addon()
        f = self.flow("dl.example", "/events", headers=[("Host", "dl.example")])
        self.call(a, "requestheaders", f)
        f.response = tutils.tresp(headers=mhttp.Headers([(b"Content-Type", b"text/event-stream")]))
        self.call(a, "responseheaders", f)
        self.assertIsNotNone(a.live.get(f.id), "tracked until the response completed")
        a.cp.policy = self.quarantined()
        self.assertEqual(a.revalidate_now(), 1)
        self.assertEqual(f.metadata["aegis_terminated"], "quarantined")
        self.call(a, "response", f)
        self.assertEqual(len(a.live), 0)
        relays = _bundle()
        relays["security_policy"]["block_raw_tcp"] = False
        a.cp.policy = Policy(relays)
        t = tflow.ttcpflow()
        t.client_conn.peername = ("10.1.0.5", 40002)
        self.call(a, "tcp_start", t)
        self.assertIsNotNone(a.live.get(t.id))
        a.cp.policy = Policy(_bundle())
        self.call(a, "tcp_message", t)
        self.assertEqual(t.messages[-1].content, b"")
        self.assertEqual(self.records(a)[-1]["security_flags"], ["CONNECTION_TERMINATED:raw_tcp_disabled"])

    def test_stale_policy_fails_closed(self):
        a = self.addon()
        a.cfg.policy_max_age = 60
        f = self.websocket(a)
        a.cp.last_sync_ok = time.time() - 30
        self.assertEqual(a._not_ready(), "")
        self.assertEqual(a.revalidate_now(), 0)
        a.cp.last_sync_ok = time.time() - 600
        self.assertTrue(a._not_ready().startswith("policy stale"))
        for ua, marker in (("curl/8", b"POLICY STALE"), ("Mozilla/5.0", b"<!DOCTYPE html>")):
            r = self.flow("dl.example", "/x?token=abc", headers=[("Host", "dl.example"), ("User-Agent", ua), ("Accept", "text/html")])
            self.call(a, "requestheaders", r)
            self.assertEqual((r.response.status_code, r.response.headers["X-Aegis-Block-Reason"]), (503, "policy_stale"))
            self.assertIn(marker, r.response.raw_content)
            self.assertNotIn(b"abc", r.response.raw_content)
            self.assertEqual(self.records(a)[-1]["block_reason"], "policy_stale")
        c = self.flow("dl.example", "", method="CONNECT", port=443)
        self.call(a, "http_connect", c)
        self.assertEqual(c.response.status_code, 503)
        self.assertEqual(a.revalidate_now(), 1)
        self.assertEqual(f.metadata["aegis_terminated"], "policy_stale")
        hdrs = a._engine_status()
        self.assertEqual(hdrs["X-Aegis-Policy-Max-Age"], "60")
        self.assertGreaterEqual(int(hdrs["X-Aegis-Policy-Age"]), 600)
        self.assertEqual(a._gauges()["aegis_dp_policy_stale"], 1.0)

    def test_block_page_and_records_redact_queries(self):
        a = self.addon()
        f = self.flow("blocked.example", "/cb?code=s3cr3t&state=1", headers=[("Host", "blocked.example"), ("User-Agent", "curl/8")])
        self.call(a, "requestheaders", f)
        self.assertEqual(f.response.status_code, 403)
        self.assertNotIn(b"s3cr3t", f.response.raw_content)
        self.assertIn(b"code=REDACTED&state=1", f.response.raw_content)
        self.assertEqual(self.records(a)[-1]["full_url"], "http://blocked.example/cb?code=REDACTED&state=1")
        a.cp.policy.security["telemetry_query_redaction"] = "none"
        f = self.flow("blocked.example", "/cb?code=s3cr3t", headers=[("Host", "blocked.example"), ("User-Agent", "curl/8")])
        self.call(a, "requestheaders", f)
        self.assertIn(b"s3cr3t", f.response.raw_content)

    def test_heartbeat_reports_telemetry_loss(self):
        a = self.addon()
        a.cfg.flow_queue_max = 2
        for i in range(5):
            a.cp.record_flow({"id": f"flw-{i}", "verdict": "BLOCKED"})
        hdrs = a._engine_status()
        self.assertEqual((hdrs["X-Aegis-Flows-Dropped"], hdrs["X-Aegis-Flow-Backlog"]), ("overflow=3", "2"))
        g = a._gauges()
        self.assertEqual((g['aegis_dp_flows_dropped_total{reason="overflow"}'], g['aegis_dp_flows_dropped_total{reason="rejected"}']), (3.0, 0.0))


# ---------------------------------------------------------------------------
# Package firewall (3.0): classify, normalize, decide, filter, verify
# ---------------------------------------------------------------------------

import xml.etree.ElementTree as ET  # noqa: E402

from aegis_dp import packages as pk  # noqa: E402


def _pkg_bundle(**eco_modes):
    """A packages bundle covering all four ecosystems. ``eco_modes`` overrides individual modes."""
    modes = {"npm": "enforce", "pypi": "enforce", "nuget": "monitor", "psgallery": "enforce"}
    modes.update(eco_modes)
    return {
        "enabled": True, "console_url": "https://aegis.example", "max_metadata_bytes": 1 << 20, "max_verify_bytes": 1 << 20,
        "ecosystems": {
            "npm": {"mode": modes["npm"], "hosts": ["registry.npmjs.org", "registry.yarnpkg.com"], "group_ids": ["*"]},
            "pypi": {"mode": modes["pypi"], "hosts": ["pypi.org"], "file_hosts": ["files.pythonhosted.org"], "group_ids": ["*"]},
            "nuget": {"mode": modes["nuget"], "hosts": ["api.nuget.org"], "group_ids": ["grp-ci"]},
            "psgallery": {"mode": modes["psgallery"], "hosts": ["www.powershellgallery.com"],
                          "file_hosts": ["psg-prod-eastus.azureedge.net"], "group_ids": ["*"]},
        },
        "approved": {
            "npm": {"lodash": {"4.17.21": {"g": ["*"], "files": {"lodash-4.17.21.tgz": {"sha512": "npmPIN"}}},
                               "4.17.20": {"g": ["*"], "files": {"lodash-4.17.20.tgz": {"sha512": "npmPIN20"}}}},
                    "@babel/core": {"7.0.0": {"g": ["*"], "files": {"core-7.0.0.tgz": {"sha512": "babelPIN"}}}},
                    "event-stream": {"3.3.6": {"g": ["*"], "files": {"event-stream-3.3.6.tgz": {"sha512": "x"}}}}},
            "pypi": {"requests": {"2.32.3": {"g": ["*"], "files": {
                "requests-2.32.3-py3-none-any.whl": {"sha256": "whlhex"},
                "requests-2.32.3.tar.gz": {"sha256": "sdisthex"}}}}},
            "nuget": {"newtonsoft.json": {"13.0.3": {"g": ["grp-ci"], "files": {
                "newtonsoft.json.13.0.3.nupkg": {"sha512": "nugetPIN"}}}}},
            "psgallery": {"psreadline": {"2.3.5": {"g": ["*"], "files": {"psreadline.2.3.5.nupkg": {"sha512": "psgPIN"}}}}},
        },
        "blocked": {"npm": {"event-stream": {"3.3.6": "Known malicious (MAL-2018-1)"}}},
    }


class PackageNormalizeTest(unittest.TestCase):
    def test_pypi_name_pep503(self):
        for raw, out in [("Flask", "flask"), ("Flask_Cors", "flask-cors"), ("zope.interface", "zope-interface"),
                         ("a--_.b", "a-b"), ("Django", "django")]:
            self.assertEqual(pk.normalize_pypi_name(raw), out, raw)

    def test_pypi_version_subset(self):
        for raw, out in [("V1.0.0", "1.0.0"), ("2.32.3", "2.32.3"), ("1.0.0+ubuntu1", "1.0.0"), (" 1.0 ", "1.0")]:
            self.assertEqual(pk.normalize_pypi_version(raw), out, raw)

    def test_nuget_version_normalization(self):
        for raw, out in [("1.0", "1.0.0"), ("1.0.0.0", "1.0.0"), ("1.00.0", "1.0.0"), ("1.2.3.4", "1.2.3.4"),
                         ("1.0.0+githash", "1.0.0"), ("1.0.0-Alpha", "1.0.0-alpha"), ("13.0.3", "13.0.3")]:
            self.assertEqual(pk.normalize_nuget_version(raw), out, raw)

    def test_dispatch(self):
        self.assertEqual(pk.normalize_name("npm", "@Scope/Name"), "@Scope/Name")  # npm verbatim
        self.assertEqual(pk.normalize_name("nuget", "Newtonsoft.Json"), "newtonsoft.json")
        self.assertEqual(pk.normalize_name("psgallery", "PSReadLine"), "psreadline")
        self.assertEqual(pk.normalize_version("npm", "4.17.21-beta.1"), "4.17.21-beta.1")

    def test_filename_version_extractors(self):
        self.assertEqual(pk.pypi_file_version("requests-2.32.3-py3-none-any.whl"), "2.32.3")
        self.assertEqual(pk.pypi_file_version("requests-2.32.3.tar.gz"), "2.32.3")
        self.assertEqual(pk.pypi_file_version("google-cloud-storage-2.0.0.tar.gz"), "2.0.0")
        self.assertEqual(pk.npm_tarball_version("lodash", "lodash-4.17.21.tgz"), "4.17.21")
        self.assertEqual(pk.npm_tarball_version("@babel/core", "core-7.0.0.tgz"), "7.0.0")
        self.assertEqual(pk.npm_tarball_version("pre", "pre-1.0.0-beta.1.tgz"), "1.0.0-beta.1")


class PackageClassifyTest(unittest.TestCase):
    def setUp(self):
        self.g = pk.PackageGate(_pkg_bundle())

    def c(self, host, path, method="GET"):
        r = self.g.classify(host, path, method)
        return None if r is None else (r.eco, r.kind, r.name, r.version, r.filename)

    def test_npm(self):
        self.assertEqual(self.c("registry.npmjs.org", "/lodash"), ("npm", "metadata", "lodash", "", ""))
        self.assertEqual(self.c("registry.npmjs.org", "/lodash/4.17.21")[3], "4.17.21")
        self.assertEqual(self.c("registry.npmjs.org", "/@babel%2fcore"), ("npm", "metadata", "@babel/core", "", ""))
        self.assertEqual(self.c("registry.npmjs.org", "/@babel/core"), ("npm", "metadata", "@babel/core", "", ""))
        self.assertEqual(self.c("registry.npmjs.org", "/lodash/-/lodash-4.17.21.tgz"),
                         ("npm", "artifact", "lodash", "4.17.21", "lodash-4.17.21.tgz"))
        self.assertEqual(self.c("registry.npmjs.org", "/@babel/core/-/core-7.0.0.tgz"),
                         ("npm", "artifact", "@babel/core", "7.0.0", "core-7.0.0.tgz"))
        for svc in ("/-/v1/search", "/-/ping", "/-/whoami", "/-/npm/v1/keys", "/-/npm/v1/attestations/x", "/-/user/me"):
            self.assertEqual(self.c("registry.npmjs.org", svc)[1], "service", svc)
        self.assertEqual(self.c("registry.yarnpkg.com", "/lodash")[0], "npm")  # second metadata host

    def test_pypi(self):
        self.assertEqual(self.c("pypi.org", "/simple/requests/"), ("pypi", "metadata", "requests", "", ""))
        self.assertEqual(self.c("pypi.org", "/simple/Flask_Cors/")[2], "flask-cors")  # PEP 503 name
        self.assertEqual(self.c("pypi.org", "/simple/")[1], "service")               # index root
        self.assertEqual(self.c("pypi.org", "/pypi/requests/json")[1], "metadata")
        self.assertEqual(self.c("pypi.org", "/pypi/requests/2.32.3/json")[3], "2.32.3")
        self.assertEqual(self.c("files.pythonhosted.org", "/packages/ab/cd/requests-2.32.3-py3-none-any.whl"),
                         ("pypi", "artifact", "requests", "2.32.3", "requests-2.32.3-py3-none-any.whl"))
        self.assertEqual(self.c("files.pythonhosted.org", "/packages/ab/requests-2.32.3-py3-none-any.whl.metadata")[1], "service")
        self.assertEqual(self.c("files.pythonhosted.org", "/integrity/abc")[1], "service")

    def test_nuget(self):
        self.assertEqual(self.c("api.nuget.org", "/v3-flatcontainer/newtonsoft.json/index.json"),
                         ("nuget", "metadata", "newtonsoft.json", "", ""))
        self.assertEqual(self.c("api.nuget.org", "/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"),
                         ("nuget", "artifact", "newtonsoft.json", "13.0.3", "newtonsoft.json.13.0.3.nupkg"))
        self.assertEqual(self.c("api.nuget.org", "/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.nuspec")[1], "service")
        self.assertEqual(self.c("api.nuget.org", "/v3/registration5-gz-semver2/newtonsoft.json/index.json"),
                         ("nuget", "metadata", "newtonsoft.json", "", ""))
        self.assertEqual(self.c("api.nuget.org", "/v3/registration5-semver1/newtonsoft.json/13.0.3.json")[3], "13.0.3")
        self.assertEqual(self.c("api.nuget.org", "/v3/index.json")[1], "service")
        self.assertEqual(self.c("api.nuget.org", "/v3/vulnerabilities/index.json")[1], "service")
        self.assertEqual(self.c("api.nuget.org", "/v3/catalog0/page1.json")[1], "service")

    def test_psgallery(self):
        self.assertEqual(self.c("www.powershellgallery.com", "/api/v2/FindPackagesById()?id='PSReadLine'"),
                         ("psgallery", "metadata", "psreadline", "", ""))
        self.assertEqual(self.c("www.powershellgallery.com", "/api/v2/Packages(Id='PSReadLine',Version='2.3.5')"),
                         ("psgallery", "metadata", "psreadline", "2.3.5", ""))
        self.assertEqual(self.c("www.powershellgallery.com", "/api/v2/package/PSReadLine/2.3.5"),
                         ("psgallery", "artifact", "psreadline", "2.3.5", "psreadline.2.3.5.nupkg"))
        self.assertEqual(self.c("psg-prod-eastus.azureedge.net", "/packages/psreadline.2.3.5.nupkg"),
                         ("psgallery", "artifact", "psreadline", "2.3.5", "psreadline.2.3.5.nupkg"))
        self.assertEqual(self.c("www.powershellgallery.com", "/api/v2")[1], "service")
        self.assertEqual(self.c("www.powershellgallery.com", "/api/v2/$metadata")[1], "service")
        self.assertEqual(self.c("www.powershellgallery.com", "/api/v2/Search()?q=x")[1], "service")

    def test_non_registry_and_other(self):
        self.assertIsNone(self.c("example.com", "/lodash"))          # not a registry host
        self.assertIsNone(self.c("registry.npmjs.org", "/"))         # registry root ("other") -> None
        self.assertIsNone(self.c("registry.npmjs.org", "/lodash", "PUT"))  # publish/write -> ordinary egress
        # an "off" ecosystem host is invisible to the gate
        g2 = pk.PackageGate(_pkg_bundle(npm="off"))
        self.assertIsNone(g2.classify("registry.npmjs.org", "/lodash", "GET"))

    def test_bounded_path(self):
        self.assertIsNone(self.g.classify("registry.npmjs.org", "/" + "a" * 9000, "GET"))


class PackageDecideTest(unittest.TestCase):
    def setUp(self):
        self.g = pk.PackageGate(_pkg_bundle())

    def d(self, host, path, groups=("*",), sid="srv-1", method="GET"):
        req = self.g.classify(host, path, method)
        return None if req is None else self.g.decide(req, list(groups), sid)

    def test_enforce_metadata_filter_and_block(self):
        d = self.d("registry.npmjs.org", "/lodash")
        self.assertEqual((d.action, d.decision), (pk.ACT_FILTER, pk.D_FILTERED))
        self.assertEqual(d.approved_versions & {"4.17.21", "4.17.20"}, {"4.17.21", "4.17.20"})
        d = self.d("registry.npmjs.org", "/left-pad")  # no approval
        self.assertEqual((d.action, d.decision, d.status), (pk.ACT_BLOCK, pk.D_NOT_APPROVED, 403))
        self.assertIn("packages/request?", d.request_link())

    def test_enforce_metadata_concrete_version(self):
        self.assertEqual(self.d("registry.npmjs.org", "/lodash/4.17.21").action, pk.ACT_FILTER)
        d = self.d("registry.npmjs.org", "/lodash/9.9.9")  # concrete, not approved
        self.assertEqual((d.action, d.decision), (pk.ACT_BLOCK, pk.D_NOT_APPROVED))

    def test_enforce_artifact(self):
        d = self.d("registry.npmjs.org", "/lodash/-/lodash-4.17.21.tgz")
        self.assertEqual((d.action, d.decision, d.sha512), (pk.ACT_VERIFY, pk.D_APPROVED, "npmPIN"))
        d = self.d("registry.npmjs.org", "/lodash/-/lodash-9.9.9.tgz")  # version not approved
        self.assertEqual((d.action, d.decision), (pk.ACT_BLOCK, pk.D_NOT_APPROVED))
        d = self.d("files.pythonhosted.org", "/packages/x/requests-2.32.3-py3-none-any.whl")
        self.assertEqual((d.action, d.decision, d.sha256), (pk.ACT_VERIFY, pk.D_APPROVED, "whlhex"))

    def test_blocked_wins_over_approval(self):
        # event-stream 3.3.6 is approved AND blocked -> block wins, for both metadata and artifact.
        d = self.d("registry.npmjs.org", "/event-stream/-/event-stream-3.3.6.tgz")
        self.assertEqual((d.action, d.decision), (pk.ACT_BLOCK, pk.D_BLOCKED))
        d = self.d("registry.npmjs.org", "/event-stream")  # its only version is blocked -> no visible version
        self.assertEqual((d.action, d.decision), (pk.ACT_BLOCK, pk.D_BLOCKED))

    def test_service_passthrough(self):
        d = self.d("registry.npmjs.org", "/-/ping")
        self.assertEqual((d.action, d.decision), (pk.ACT_PASSTHROUGH, pk.D_SERVICE))

    def test_monitor_never_acts(self):
        # nuget is monitor in the fixture.
        d = self.d("api.nuget.org", "/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg", groups=["grp-ci"])
        self.assertEqual((d.action, d.decision, d.monitor), (pk.ACT_PASSTHROUGH, pk.D_MONITOR, True))
        self.assertEqual(d.reason, pk.D_APPROVED)  # the would-be outcome is preserved
        d = self.d("api.nuget.org", "/v3-flatcontainer/unknown/index.json", groups=["grp-ci"])
        self.assertEqual((d.action, d.decision, d.reason), (pk.ACT_PASSTHROUGH, pk.D_MONITOR, pk.D_NOT_APPROVED))

    def test_group_scoping(self):
        # nuget ecosystem is scoped to grp-ci: a client not in grp-ci is not covered -> ordinary egress (None).
        self.assertIsNone(self.d("api.nuget.org", "/v3-flatcontainer/newtonsoft.json/index.json", groups=["other"]))
        self.assertIsNotNone(self.d("api.nuget.org", "/v3-flatcontainer/newtonsoft.json/index.json", groups=["grp-ci"]))
        # npm ecosystem group_ids=["*"] covers unregistered clients (no groups, unregistered id).
        d = self.d("registry.npmjs.org", "/lodash", groups=[], sid="srv-unregistered-10.0.0.1")
        self.assertEqual(d.action, pk.ACT_FILTER)

    def test_version_group_scope(self):
        # Approve lodash 4.17.21 only for grp-ci; a client outside it sees no approved version.
        b = _pkg_bundle()
        b["approved"]["npm"]["lodash"]["4.17.21"]["g"] = ["grp-ci"]
        del b["approved"]["npm"]["lodash"]["4.17.20"]
        g = pk.PackageGate(b)
        req = g.classify("registry.npmjs.org", "/lodash", "GET")
        self.assertEqual(g.decide(req, ["grp-ci"], "s").action, pk.ACT_FILTER)
        self.assertEqual(g.decide(req, ["other"], "s").decision, pk.D_NOT_APPROVED)


class PackageFilterTest(unittest.TestCase):
    def test_npm_packument_full_and_abbrev(self):
        doc = {"name": "lodash", "dist-tags": {"latest": "4.17.21", "next": "5.0.0", "old": "3.0.0"},
               "versions": {"3.0.0": {"version": "3.0.0"}, "4.17.20": {"version": "4.17.20"},
                            "4.17.21": {"version": "4.17.21"}, "5.0.0": {"version": "5.0.0"}},
               "time": {"created": "a", "modified": "b", "3.0.0": "c", "4.17.21": "d", "5.0.0": "e"}}
        for ctype in ("application/json", "application/vnd.npm.install-v1+json"):
            r = pk.filter_metadata("npm", "lodash", frozenset(["4.17.21", "4.17.20"]), json.dumps(doc).encode(), ctype)
            out = json.loads(r.body)
            self.assertEqual(set(out["versions"]), {"4.17.21", "4.17.20"})
            self.assertEqual((r.hidden, r.visible), (2, 2))
            self.assertEqual(out["dist-tags"]["latest"], "4.17.21")  # approved, kept
            self.assertEqual(out["dist-tags"]["next"], "4.17.21")    # 5.0.0 -> highest approved <= 5.0.0
            self.assertEqual(out["dist-tags"]["old"], "4.17.21")     # 3.0.0 -> nothing <=, highest overall
            self.assertNotIn("5.0.0", out["time"])
            self.assertIn("created", out["time"])

    def test_npm_zero_approved(self):
        doc = {"versions": {"1.0.0": {}}, "dist-tags": {"latest": "1.0.0"}}
        r = pk.filter_metadata("npm", "x", frozenset(), json.dumps(doc).encode(), "application/json")
        self.assertEqual(json.loads(r.body)["versions"], {})
        self.assertEqual(json.loads(r.body)["dist-tags"], {})

    def test_pypi_html(self):
        html = (b'<html><body>\n'
                b'<a href="https://f/requests-2.32.3-py3-none-any.whl#sha256=aa" data-requires-python="&gt;=3.8"'
                b' data-core-metadata="sha256=bb" data-provenance="p">requests-2.32.3-py3-none-any.whl</a><br/>\n'
                b'<a href="https://f/requests-2.0.0.tar.gz#sha256=cc">requests-2.0.0.tar.gz</a><br/>\n'
                b'</body></html>')
        r = pk.filter_metadata("pypi", "requests", frozenset(["2.32.3"]), html, "text/html")
        self.assertEqual((r.hidden, r.visible), (1, 1))
        self.assertNotIn(b"2.0.0", r.body)
        self.assertIn(b"requests-2.32.3-py3-none-any.whl", r.body)
        self.assertIn(b"data-requires-python", r.body)
        self.assertIn(b"#sha256=aa", r.body)
        self.assertIn(b"data-provenance", r.body)

    def test_pypi_simple_json(self):
        doc = {"meta": {"api-version": "1.1"}, "name": "requests",
               "files": [{"filename": "requests-2.32.3-py3-none-any.whl", "url": "u", "hashes": {"sha256": "a"}},
                         {"filename": "requests-2.0.0.tar.gz", "url": "v", "hashes": {"sha256": "b"}}],
               "versions": ["2.0.0", "2.32.3"]}
        r = pk.filter_metadata("pypi", "requests", frozenset(["2.32.3"]), json.dumps(doc).encode(),
                               "application/vnd.pypi.simple.v1+json")
        out = json.loads(r.body)
        self.assertEqual([f["filename"] for f in out["files"]], ["requests-2.32.3-py3-none-any.whl"])
        self.assertEqual(out["versions"], ["2.32.3"])
        self.assertEqual(r.hidden, 1)

    def test_pypi_project_json(self):
        doc = {"info": {"version": "2.0.0"}, "releases": {"2.0.0": [{"filename": "x"}], "2.32.3": [{"filename": "y"}]},
               "urls": [{"filename": "latest-is-2.0.0"}]}
        r = pk.filter_metadata("pypi", "requests", frozenset(["2.32.3"]), json.dumps(doc).encode(), "application/json")
        out = json.loads(r.body)
        self.assertEqual(set(out["releases"]), {"2.32.3"})
        self.assertEqual(out["urls"], [])  # latest 2.0.0 not approved -> files withdrawn

    def test_nuget_flatcontainer(self):
        doc = {"versions": ["12.0.0", "13.0.1", "13.0.3"]}
        r = pk.filter_metadata("nuget", "newtonsoft.json", frozenset(["13.0.3"]), json.dumps(doc).encode(), "application/json")
        self.assertEqual(json.loads(r.body)["versions"], ["13.0.3"])
        self.assertEqual((r.hidden, r.visible), (2, 1))

    def test_nuget_registration_inline(self):
        doc = {"@id": "i", "@type": ["catalog:CatalogRoot"], "count": 1,
               "items": [{"@id": "p", "@type": "catalog:CatalogPage", "count": 3, "lower": "12.0.0", "upper": "13.0.3",
                          "items": [{"@id": "l1", "catalogEntry": {"version": "12.0.0"}},
                                    {"@id": "l2", "catalogEntry": {"version": "13.0.1"}},
                                    {"@id": "l3", "catalogEntry": {"version": "13.0.3"}}]}]}
        r = pk.filter_metadata("nuget", "newtonsoft.json", frozenset(["13.0.3"]), json.dumps(doc).encode(), "application/json")
        out = json.loads(r.body)
        self.assertEqual([l["catalogEntry"]["version"] for l in out["items"][0]["items"]], ["13.0.3"])
        self.assertEqual(out["items"][0]["count"], 1)
        self.assertEqual(out["@type"], ["catalog:CatalogRoot"])  # structural fields kept
        self.assertEqual((r.hidden, r.visible), (2, 1))

    def test_nuget_registration_paged_dropped(self):
        doc = {"@id": "i", "count": 1, "items": [{"@id": "page-url", "count": 99, "lower": "1.0.0", "upper": "9.0.0"}]}
        r = pk.filter_metadata("nuget", "newtonsoft.json", frozenset(["13.0.3"]), json.dumps(doc).encode(), "application/json")
        out = json.loads(r.body)
        self.assertEqual(out["items"], [])  # paged (not inline) -> dropped (fail closed)
        self.assertEqual(out["count"], 0)

    def test_psgallery_odata_atom(self):
        xml = (b'<?xml version="1.0" encoding="utf-8"?>\n'
               b'<feed xmlns="http://www.w3.org/2005/Atom"'
               b' xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices"'
               b' xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">'
               b'<title>Packages</title>'
               b'<link rel="next" href="https://p/x?$skiptoken=a"/>'
               b'<entry><m:properties><d:Version>2.0.0</d:Version><d:NormalizedVersion>2.0.0</d:NormalizedVersion></m:properties></entry>'
               b'<entry><m:properties><d:Version>2.3.5</d:Version><d:NormalizedVersion>2.3.5</d:NormalizedVersion></m:properties></entry>'
               b'</feed>')
        r = pk.filter_metadata("psgallery", "psreadline", frozenset(["2.3.5"]), xml, "application/atom+xml")
        self.assertEqual((r.hidden, r.visible), (1, 1))
        self.assertNotIn(b">2.0.0</d:NormalizedVersion>", r.body)
        self.assertIn(b">2.3.5</d:NormalizedVersion>", r.body)
        self.assertIn(b'rel="next"', r.body)       # feed-level link preserved
        root = ET.fromstring(r.body)                # still well-formed XML
        self.assertTrue(root.tag.endswith("feed"))

    def test_malformed_body_fails_closed(self):
        with self.assertRaises(pk.FilterError):
            pk.filter_metadata("npm", "x", frozenset(["1.0.0"]), b"not json", "application/json")
        with self.assertRaises(pk.FilterError):
            pk.filter_metadata("psgallery", "x", frozenset(["1.0.0"]), b"<feed><broken", "application/atom+xml")


class PackageVerifierTest(unittest.TestCase):
    DATA = b"artifact-payload-" * 9000  # ~153 KiB, larger than the tail window

    def _run(self, verifier, data, chunk=5000):
        out = bytearray()
        for i in range(0, len(data), chunk):
            out += verifier(data[i:i + chunk])
        out += verifier(b"")
        return bytes(out)

    def test_match_sha256_and_sha512(self):
        h256 = hashlib.sha256(self.DATA).hexdigest()
        h512 = base64.b64encode(hashlib.sha512(self.DATA).digest()).decode()
        v = pk.ArtifactVerifier(expected_sha256=h256, expected_sha512=h512)
        self.assertEqual(self._run(v, self.DATA), self.DATA)  # complete file delivered
        self.assertTrue(v.matched)
        self.assertEqual(v.sha256, h256)
        self.assertEqual(v.sha512.rstrip("="), h512.rstrip("="))

    def test_mismatch_truncates_and_calls_on_fail(self):
        failed = []
        v = pk.ArtifactVerifier(expected_sha256="0" * 64, on_fail=lambda vf: failed.append(vf))
        out = self._run(v, self.DATA)
        self.assertLess(len(out), len(self.DATA))  # tail withheld: the client never gets a complete file
        self.assertTrue(v.mismatch)
        self.assertEqual(len(failed), 1)

    def test_no_content_length_single_chunk(self):
        h256 = hashlib.sha256(self.DATA).hexdigest()
        v = pk.ArtifactVerifier(expected_sha256=h256)
        self.assertEqual(v(self.DATA) + v(b""), self.DATA)
        self.assertTrue(v.matched)

    def test_npm_integrity_prefix_and_no_pin(self):
        h512 = base64.b64encode(hashlib.sha512(self.DATA).digest()).decode()
        v = pk.ArtifactVerifier(expected_sha512="sha512-" + h512)  # npm integrity spelling
        self.assertEqual(self._run(v, self.DATA), self.DATA)
        self.assertTrue(v.matched)
        v = pk.ArtifactVerifier()  # no pin at all -> fail closed
        self._run(v, self.DATA)
        self.assertTrue(v.mismatch)

    def test_memory_is_bounded(self):
        v = pk.ArtifactVerifier(expected_sha256=hashlib.sha256(self.DATA).hexdigest())
        for i in range(0, len(self.DATA), 5000):
            v(self.DATA[i:i + 5000])
            self.assertLessEqual(len(v._pending), v.tail)  # never buffers the whole artifact


class PackagePolicyWiringTest(unittest.TestCase):
    def test_policy_builds_gate_from_bundle(self):
        p = Policy({**BUNDLE, "packages": _pkg_bundle()})
        self.assertTrue(p.packages.enabled)
        self.assertEqual(p.packages.status_summary(), "npm=enforce,pypi=enforce,nuget=monitor,psgallery=enforce")

    def test_absent_packages_disables_gate(self):
        p = Policy(BUNDLE)
        self.assertFalse(p.packages.enabled)
        self.assertIsNone(p.packages.classify("registry.npmjs.org", "/lodash", "GET"))


@unittest.skipUnless(HAVE_MITMPROXY, "mitmproxy not installed (runs in the data-plane image)")
class PackageGateAddonTest(unittest.TestCase):
    """Hook-level integration: the package gate through requestheaders/responseheaders/response."""

    def addon(self, **eco_modes):
        from aegis_dp.addon import AegisAddon
        a = AegisAddon(Config(control_plane_url="http://127.0.0.1:1", dataplane_key="k" * 40, worker_id="test", ops_addr=""))
        bundle = json.loads(json.dumps(ADDON_BUNDLE))
        bundle["rules"] = [{"id": "reg", "name": "registries", "action": "ALLOW", "host_pattern": "*",
                            "path_pattern": "/**", "group_ids": ["g1"], "enabled": True}]
        bundle["packages"] = _pkg_bundle(**eco_modes)
        a.cp.policy = Policy(bundle)
        return a

    def flow(self, host, path, method="GET", headers=()):
        client = tflow.tclient_conn()
        client.peername = ("10.1.0.5", 40000)
        client.proxy_mode = mode_specs.ProxyMode.parse("regular")
        hdrs = mhttp.Headers([(k.encode(), v.encode()) for k, v in (list(headers) + [("Host", host)])])
        req = tutils.treq(host=host, port=443, scheme=b"https", method=method.encode(), path=path.encode(), headers=hdrs)
        return tflow.tflow(client_conn=client, req=req)

    @staticmethod
    def call(a, hook, data):
        r = getattr(a, hook)(data)
        if inspect.isawaitable(r):
            asyncio.run(r)

    def records(self, a):
        return list(a.cp._queue)

    def test_metadata_not_approved_blocked_locally(self):
        a = self.addon()
        f = self.flow("registry.npmjs.org", "/left-pad")
        self.call(a, "requestheaders", f)
        self.assertIsNotNone(f.response)
        self.assertEqual(f.response.status_code, 403)
        self.assertEqual(f.response.headers["X-Aegis-Verdict"], "PACKAGE_BLOCKED")
        body = json.loads(f.response.raw_content)  # npm gets JSON {"error": ...}
        self.assertIn("packages/request?", body["error"])
        rec = self.records(a)[-1]
        self.assertEqual(rec["verdict"], "PACKAGE_BLOCKED")
        self.assertEqual(rec["package"]["decision"], "not_approved")
        self.assertEqual(rec["package"]["ecosystem"], "npm")

    def test_metadata_filtered(self):
        a = self.addon()
        doc = {"name": "lodash", "dist-tags": {"latest": "5.0.0"},
               "versions": {"4.17.21": {"version": "4.17.21"}, "5.0.0": {"version": "5.0.0"}}}
        f = self.flow("registry.npmjs.org", "/lodash", headers=[("If-None-Match", '"abc"')])
        self.call(a, "requestheaders", f)
        self.assertIsNone(f.response)
        self.assertNotIn("If-None-Match", f.request.headers)  # conditional header stripped
        f.response = tutils.tresp(content=json.dumps(doc).encode(),
                                  headers=mhttp.Headers([(b"Content-Type", b"application/json"), (b"ETag", b'"up"')]))
        self.call(a, "responseheaders", f)
        self.call(a, "response", f)
        out = json.loads(f.response.raw_content)
        self.assertEqual(set(out["versions"]), {"4.17.21"})  # 5.0.0 hidden
        self.assertEqual(out["dist-tags"]["latest"], "4.17.21")  # repointed
        self.assertEqual(f.response.headers["Cache-Control"], "no-store")
        self.assertTrue(f.response.headers["ETag"].startswith('W/"aegis-'))
        rec = self.records(a)[-1]
        self.assertEqual((rec["verdict"], rec["matched_rule_id"]), ("ALLOWED", "package-firewall"))
        self.assertEqual((rec["package"]["decision"], rec["package"]["hidden_versions"]), ("filtered", 1))

    def test_artifact_hash_match_and_mismatch(self):
        body = b"TARBALL-BYTES-" * 5000
        h512 = base64.b64encode(hashlib.sha512(body).digest()).decode()
        a = self.addon()
        a.cp.policy.packages._approved["npm"]["lodash"]["4.17.21"]["files"]["lodash-4.17.21.tgz"]["sha512"] = h512
        # match: the full body is delivered and recorded approved
        f = self.flow("registry.npmjs.org", "/lodash/-/lodash-4.17.21.tgz")
        self.call(a, "requestheaders", f)
        f.response = tutils.tresp(content=b"", headers=mhttp.Headers([(b"Content-Length", str(len(body)).encode())]))
        self.call(a, "responseheaders", f)
        self.assertTrue(callable(f.response.stream))
        delivered = f.response.stream(body) + f.response.stream(b"")
        self.call(a, "response", f)
        self.assertEqual(delivered, body)
        rec = self.records(a)[-1]
        self.assertEqual((rec["verdict"], rec["package"]["decision"]), ("ALLOWED", "approved"))
        self.assertEqual(rec["package"]["sha512"].rstrip("="), h512.rstrip("="))
        # mismatch: the registry serves different bytes -> truncated + hash_mismatch
        a.cp.policy.packages._approved["npm"]["lodash"]["4.17.21"]["files"]["lodash-4.17.21.tgz"]["sha512"] = "WRONGPIN"
        f = self.flow("registry.npmjs.org", "/lodash/-/lodash-4.17.21.tgz")
        self.call(a, "requestheaders", f)
        f.response = tutils.tresp(content=b"", headers=mhttp.Headers([(b"Content-Length", str(len(body)).encode())]))
        self.call(a, "responseheaders", f)
        delivered = f.response.stream(body) + f.response.stream(b"")
        self.call(a, "response", f)
        self.assertLess(len(delivered), len(body))  # tail withheld
        rec = self.records(a)[-1]
        self.assertEqual((rec["verdict"], rec["package"]["decision"]), ("PACKAGE_BLOCKED", "hash_mismatch"))
        self.assertIn("PACKAGE_HASH_MISMATCH", rec["security_flags"])

    def test_monitor_records_but_does_not_block(self):
        a = self.addon()
        # nuget is scoped to grp-ci in the fixture; the test client is in g1, so widen the scope to every client.
        a.cp.policy.packages.ecosystems["nuget"]["group_ids"] = ["*"]
        f = self.flow("api.nuget.org", "/v3-flatcontainer/unknown/index.json")
        self.call(a, "requestheaders", f)
        self.assertIsNone(f.response)  # monitor never blocks
        f.response = tutils.tresp(content=b'{"versions":[]}', headers=mhttp.Headers([(b"Content-Type", b"application/json")]))
        self.call(a, "responseheaders", f)
        self.call(a, "response", f)
        rec = self.records(a)[-1]
        self.assertEqual(rec["package"]["decision"], "monitor")
        self.assertEqual(rec["package"]["reason"], "not_approved")

    def test_heartbeat_header(self):
        a = self.addon()
        self.assertEqual(a._engine_status()["X-Aegis-Packages"], "npm=enforce,pypi=enforce,nuget=monitor,psgallery=enforce")


if __name__ == "__main__":
    unittest.main()
