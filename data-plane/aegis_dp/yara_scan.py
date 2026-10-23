"""YARA scanning of downloads and uploads with rule sets managed in the console.

Rule sets arrive with the policy bundle; they are compiled once per content hash. Every set is checked
on its own: a set that fails to compile falls back to its last working version (or is skipped), the
other sets stay active, and the error is reported to the control-plane (heartbeat header).
Engine: YARA-X (VirusTotal's Rust implementation, the official successor of YARA; installed in the
data-plane image), falling back to yara-python. Without either the engine reports "unavailable".
"""

from __future__ import annotations

import hashlib
import logging
import threading
from typing import Any, Dict, List, Optional

log = logging.getLogger("aegis.yara")

try:  # pragma: no cover - depends on the installation
    import yara_x  # type: ignore
except Exception:  # noqa: BLE001
    yara_x = None
try:  # pragma: no cover
    import yara  # type: ignore
except Exception:  # noqa: BLE001
    yara = None

ENGINE = "yara-x" if yara_x is not None else ("yara" if yara is not None else "")


class YaraEngine:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rules: Any = None
        self._hash = ""
        self.status = "idle" if ENGINE else "unavailable"
        self.error = ""
        self.rule_count = 0
        self._last_good: Dict[str, str] = {}

    @property
    def available(self) -> bool:
        return bool(ENGINE)

    def configure(self, rule_sets: List[Dict[str, Any]]) -> None:
        enabled = [rs for rs in (rule_sets or []) if rs.get("enabled", True)]
        digest = hashlib.sha256(repr([(rs.get("id"), rs.get("source")) for rs in enabled]).encode()).hexdigest()
        with self._lock:
            if digest == self._hash:
                return
            if not enabled:
                self._rules, self._hash, self.status, self.error, self.rule_count = None, digest, ("idle" if ENGINE else "unavailable"), "", 0
                return
            if not ENGINE:
                self.status, self.error = "unavailable", "no YARA engine (yara-x) in this data-plane installation"
                return
            sources: Dict[str, str] = {}
            failed: List[str] = []
            for i, rs in enumerate(enabled):
                rid = rs.get("id") or f"set{i}"
                ns = f"rs_{i}_{rid[:24]}".replace("-", "_")
                src = rs.get("source", "")
                err = self._compile_error({ns: src})
                if err is None:
                    sources[ns] = src
                    self._last_good[rid] = src
                    continue
                name = rs.get("name") or rid
                fallback = self._last_good.get(rid)
                if fallback is not None and self._compile_error({ns: fallback}) is None:
                    sources[ns] = fallback
                    failed.append(f"{name}: {err} (previous version stays active)")
                else:
                    failed.append(f"{name}: {err} (rule set skipped)")
                log.error("YARA rule set %r failed to compile: %s", name, err)
            self._last_good = {k: v for k, v in self._last_good.items() if k in {rs.get("id") for rs in enabled}}
            compiled = self._build(sources) if sources else None
            self._rules, self._hash, self.rule_count = compiled, digest, len(sources)
            if failed:
                self.status, self.error = "error", f"{len(failed)} of {len(enabled)} rule sets failed: " + "; ".join(failed)
            else:
                self.status, self.error = "ok", ""
            log.info("YARA rules compiled with %s (%d of %d rule sets active)", ENGINE, len(sources), len(enabled))

    @staticmethod
    def _build(sources: Dict[str, str]) -> Any:
        if ENGINE == "yara-x":
            comp = yara_x.Compiler()
            for ns, src in sources.items():
                comp.new_namespace(ns)
                comp.add_source(src)
            return comp.build()
        return yara.compile(sources=sources)

    def _compile_error(self, sources: Dict[str, str]) -> Optional[str]:
        try:
            self._build(sources)
            return None
        except Exception as exc:  # noqa: BLE001 - syntax errors in admin-provided rules
            return " ".join(str(exc).split())[:200]

    def scan(self, data: bytes, timeout: int = 10) -> Optional[List[str]]:
        """Returns matching rule names ([] = clean) or None when no rules are loaded."""
        rules = self._rules
        if rules is None or not data:
            return None
        try:
            if ENGINE == "yara-x":
                scanner = yara_x.Scanner(rules)
                scanner.set_timeout(timeout)
                return [m.identifier for m in scanner.scan(data).matching_rules]
            return [m.rule for m in rules.match(data=data, timeout=timeout)]
        except Exception as exc:  # noqa: BLE001 - timeouts and engine errors
            log.warning("YARA scan failed: %s", exc)
            return ["__error__:" + str(exc)[:80]]

    def heartbeat(self) -> str:
        if self.status == "error":
            return "error:" + self.error[:300].replace("\n", " ")
        return self.status
