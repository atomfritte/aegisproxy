"""Data-plane package gate (package firewall 3.0).

The gate classifies registry requests (npm, PyPI, NuGet, PowerShell Gallery), decides what the addon should
do with each one (forward, filter the metadata, verify the artifact, or block locally), filters registry
metadata down to the versions an approval covers, and verifies artifact bytes against the pinned hash as they
stream through. It is pure Python (stdlib only) so it unit-tests without mitmproxy; ``addon.py`` wires the
decisions into the mitmproxy hooks.

Binding spec: docs/package-firewall.md ("Data-plane bundle" and "Gate decisions in the data-plane") and the
telemetry shape control-plane/internal/models/packages.go (``FlowPackage``).

Everything here treats registry URLs and bodies as attacker-influenced: every parse is bounded, malformed
metadata is treated as "no approved version" (fail closed in enforce), and a filter that raises never results in
an unfiltered body being delivered (the addon blocks 503 instead).

Artifact verification (``ArtifactVerifier``)
--------------------------------------------
Artifacts can be hundreds of MiB, so the body is never buffered whole. The verifier is a callable installed as
``flow.response.stream``; mitmproxy hands it each body chunk and finally an empty chunk (EOF). For every chunk the
verifier updates an incremental SHA-256 and SHA-512 (``hashlib`` objects, constant memory) and appends the chunk to
a small rolling tail buffer. It emits everything in the buffer except the last ``TAIL_WINDOW`` bytes, which it
holds back. Because the trailing window is always withheld, the client never receives the complete file before the
digest is known. On EOF the whole body has been hashed:

  * digest matches the pin  -> the held-back tail is emitted (the client gets the complete, verified file);
  * digest mismatches       -> the tail is dropped (the client is left with a truncated body whose own integrity
                               check fails) and ``on_fail`` is invoked so the addon kills the flow / records a
                               ``hash_mismatch`` security event.

Memory bound: O(TAIL_WINDOW + one mitmproxy stream chunk) per in-flight artifact, independent of artifact size.
Content-Length is not required: the rolling tail window makes the end-detection unnecessary (we always withhold a
tail until EOF), which also covers chunked / unknown-length responses.

Name / version normalization (reconcile with the Go ``pkgver`` package when it lands)
-------------------------------------------------------------------------------------
The control-plane writes the ``approved`` / ``blocked`` maps with already-normalized keys. The gate normalizes the
*request* the same way and, to tolerate any divergence, matches leniently: a candidate matches when its raw form,
its lower-cased form, or its normalized form is present in the (equally expanded) approved set.

  * npm       - name verbatim, version verbatim (registry is authoritative).
  * pypi      - name PEP 503 (``[-_.]+`` -> ``-``, lower-case); version a PEP 440 *subset* (strip a leading ``v``,
                lower-case, trim whitespace, drop a ``+local`` segment). Full PEP 440 spelling normalization
                (``1.0alpha1`` -> ``1.0a1`` etc.) is NOT implemented; such versions fall back to raw string
                equality against the (normalized) approved map. DIVERGENCE RISK: reconcile with pkgver.
  * nuget     - id lower-case; version NuGet-normalized (strip leading zeros per numeric field, pad to >=3 fields,
                drop a 4th field equal to 0, drop ``+build`` metadata, lower-case the prerelease).
  * psgallery - same as nuget.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple

from .policy import normalize_host, printable

# Ecosystem identifiers (mirror control-plane/internal/models.Ecosystem*).
NPM = "npm"
PYPI = "pypi"
NUGET = "nuget"
PSGALLERY = "psgallery"
ECOSYSTEMS = (NPM, PYPI, NUGET, PSGALLERY)

# Enforcement modes.
MODE_OFF = "off"
MODE_MONITOR = "monitor"
MODE_ENFORCE = "enforce"

# Request kinds (FlowPackage.Kind).
KIND_METADATA = "metadata"
KIND_ARTIFACT = "artifact"
KIND_SERVICE = "service"
KIND_OTHER = "other"

# Decisions (FlowPackage.Decision; mirror models.PackageDecision*).
D_APPROVED = "approved"
D_FILTERED = "filtered"
D_NOT_APPROVED = "not_approved"
D_BLOCKED = "blocked"
D_HASH_MISMATCH = "hash_mismatch"
D_MONITOR = "monitor"
D_SERVICE = "service"

# Gate actions the addon carries out.
ACT_IGNORE = "ignore"            # not our concern: ordinary egress rules apply (classify/decide returned nothing)
ACT_PASSTHROUGH = "passthrough"  # service endpoint (or monitor): forward unchanged, record
ACT_FILTER = "filter_metadata"   # forward, then filter the response body to the approved versions
ACT_VERIFY = "verify_artifact"   # forward, hash the body and compare with the pin before the last byte is released
ACT_BLOCK = "block"              # answer locally with a readable 4xx/5xx and never contact upstream

DEFAULT_MAX_METADATA_BYTES = 64 << 20   # 67108864
DEFAULT_MAX_VERIFY_BYTES = 256 << 20    # 268435456
MAX_PATH = 8192                          # registry paths longer than this are never classified
TAIL_WINDOW = 64 << 10                    # bytes of an artifact's tail withheld until the hash is verified


class FilterError(Exception):
    """A metadata body could not be filtered safely (too large, malformed, unsupported). In enforce mode the
    addon turns this into a local 503 rather than delivering an unfiltered body."""


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

_PYPI_SEP = re.compile(r"[-_.]+")
_NUGET_FIELD = re.compile(r"^\d+$")


def normalize_pypi_name(name: str) -> str:
    """PEP 503: runs of ``-_.`` collapse to a single ``-`` and the result is lower-cased."""
    return _PYPI_SEP.sub("-", (name or "").strip()).lower()


def normalize_pypi_version(version: str) -> str:
    """PEP 440 *subset* (see the module docstring): strip a leading ``v``, lower-case, trim, drop ``+local``."""
    v = (version or "").strip().lower()
    if v.startswith("v"):
        v = v[1:]
    v = v.split("+", 1)[0]  # local version segment is never part of the approval key
    return v.strip()


def normalize_nuget_version(version: str) -> str:
    """NuGet version normalization: numeric fields lose leading zeros and are padded to at least three, a fourth
    field equal to zero is dropped, build metadata (``+...``) is dropped and the prerelease label is lower-cased."""
    v = (version or "").strip()
    if v.lower().startswith("v") and v[1:2].isdigit():
        v = v[1:]
    v = v.split("+", 1)[0]              # drop build metadata
    core, _, pre = v.partition("-")     # split off the prerelease label
    fields = core.split(".")
    nums: List[str] = []
    for f in fields:
        if _NUGET_FIELD.match(f):
            nums.append(str(int(f)))    # strip leading zeros
        else:
            nums.append(f)              # leave anything unexpected untouched (lenient)
    while len(nums) < 3:
        nums.append("0")
    if len(nums) == 4 and nums[3] == "0":
        nums = nums[:3]
    out = ".".join(nums)
    if pre:
        out += "-" + pre.lower()
    return out


def normalize_name(eco: str, name: str) -> str:
    if eco == PYPI:
        return normalize_pypi_name(name)
    if eco in (NUGET, PSGALLERY):
        return (name or "").strip().lower()
    return (name or "").strip()  # npm: verbatim


def normalize_version(eco: str, version: str) -> str:
    if eco == PYPI:
        return normalize_pypi_version(version)
    if eco in (NUGET, PSGALLERY):
        return normalize_nuget_version(version)
    return (version or "").strip()  # npm: verbatim


def _candidates_name(eco: str, name: str) -> Tuple[str, ...]:
    raw = (name or "").strip()
    return tuple(dict.fromkeys((raw, raw.lower(), normalize_name(eco, raw))))


def _candidates_version(eco: str, version: str) -> Tuple[str, ...]:
    raw = (version or "").strip()
    return tuple(dict.fromkeys((raw, raw.lower(), normalize_version(eco, version))))


_CONCRETE_VERSION = re.compile(r"^[0-9]")


def _is_concrete_version(eco: str, version: str) -> bool:
    """A path segment that looks like a concrete version (starts with a digit), not a dist-tag/branch."""
    return bool(version) and bool(_CONCRETE_VERSION.match(version.strip()))


# ---------------------------------------------------------------------------
# Classification: URL shape -> PackageRequest
# ---------------------------------------------------------------------------

@dataclass
class PackageRequest:
    eco: str
    kind: str
    name: str = ""          # normalized
    version: str = ""       # normalized ("" when not identified)
    filename: str = ""      # normalized (lower-cased for nuget/psgallery)
    raw_version: str = ""   # as seen in the URL (for lenient matching / concrete-version detection)

    def __bool__(self) -> bool:  # a request we care about is anything other than KIND_OTHER
        return self.kind != KIND_OTHER


def _split_path(path: str) -> Tuple[str, List[str]]:
    """(clean_path, non-empty percent-decoded segments). Query and fragment are dropped; ``%2f`` inside a segment
    (npm scoped names) is decoded to a separator so ``/@scope%2fname`` and ``/@scope/name`` parse identically."""
    p = (path or "/").split("#", 1)[0].split("?", 1)[0]
    try:
        p = urllib.parse.unquote(p, errors="strict")
    except (UnicodeDecodeError, ValueError):
        return p, []
    segs = [s for s in p.split("/") if s]
    return p, segs


def npm_tarball_version(name: str, filename: str) -> str:
    """Version embedded in an npm tarball name: ``lodash-4.17.21.tgz`` -> ``4.17.21`` (the base name is the package
    name without its scope, e.g. ``@babel/core`` -> ``core-7.0.0.tgz``). The base prefix is used because npm
    versions may contain hyphens (prereleases)."""
    base = (name or "").split("/")[-1]
    fn = (filename or "")
    stem = fn[:-4] if fn.lower().endswith(".tgz") else (fn[:-7] if fn.lower().endswith(".tar.gz") else fn)
    if base and stem.lower().startswith(base.lower() + "-"):
        return stem[len(base) + 1:]
    return stem.rsplit("-", 1)[1] if "-" in stem else ""


def _npm_artifact(name: str, filename: str) -> PackageRequest:
    ver = npm_tarball_version(name, filename)
    return PackageRequest(NPM, KIND_ARTIFACT, normalize_name(NPM, name),
                          version=normalize_version(NPM, ver), raw_version=ver, filename=filename)


def _classify_npm(segs: List[str]) -> PackageRequest:
    if not segs:
        return PackageRequest(NPM, KIND_OTHER)
    if segs[0] == "-":
        return PackageRequest(NPM, KIND_SERVICE)  # /-/ping, /-/whoami, /-/v1/search, /-/npm/v1/keys|attestations, /-/user/..
    if segs[0].startswith("@"):
        if len(segs) < 2:
            return PackageRequest(NPM, KIND_OTHER)
        name = segs[0] + "/" + segs[1]
        if len(segs) >= 4 and segs[2] == "-":               # /@scope/name/-/file.tgz
            return _npm_artifact(name, segs[-1])
        ver = segs[2] if len(segs) >= 3 else ""             # /@scope/name[/<version|tag>]
        return PackageRequest(NPM, KIND_METADATA, normalize_name(NPM, name),
                              version=normalize_version(NPM, ver), raw_version=ver)
    name = segs[0]
    if len(segs) >= 3 and segs[1] == "-":                   # /name/-/file.tgz
        return _npm_artifact(name, segs[-1])
    ver = segs[1] if len(segs) >= 2 else ""                 # /name[/<version|tag>]
    return PackageRequest(NPM, KIND_METADATA, normalize_name(NPM, name),
                          version=normalize_version(NPM, ver), raw_version=ver)


_PYPI_ARTIFACT_EXT = (".whl", ".egg", ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip")


def pypi_file_name(filename: str) -> str:
    """Best-effort normalized (PEP 503) project name from a PyPI artifact filename. Wheels escape the name with
    ``_`` (``flask_cors-...whl``), which PEP 503 normalization collapses back to ``-``."""
    fn = (filename or "").strip()
    low = fn.lower()
    if low.endswith(".whl") or low.endswith(".egg"):
        parts = fn.rsplit(".", 1)[0].split("-")
        return normalize_pypi_name(parts[0]) if parts else ""
    for ext in (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip"):
        if low.endswith(ext):
            stem = fn[: -len(ext)]
            return normalize_pypi_name(stem.rsplit("-", 1)[0]) if "-" in stem else ""
    return ""


def pypi_file_version(filename: str) -> str:
    """Best-effort version from a PyPI artifact filename (``requests-2.32.3-py3-none-any.whl`` -> ``2.32.3``,
    ``requests-2.32.3.tar.gz`` -> ``2.32.3``). Returns "" when it cannot be parsed."""
    fn = (filename or "").strip()
    low = fn.lower()
    if low.endswith(".whl") or low.endswith(".egg"):
        parts = fn.rsplit(".", 1)[0].split("-")
        return parts[1] if len(parts) >= 2 else ""
    for ext in (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip"):
        if low.endswith(ext):
            stem = fn[: -len(ext)]
            return stem.rsplit("-", 1)[1] if "-" in stem else ""
    return ""


def _classify_pypi(segs: List[str], file_host: bool) -> PackageRequest:
    if file_host:
        # files.pythonhosted.org: /packages/**/<file>, plus .metadata sidecar and /integrity/.. (service).
        if segs and segs[0] == "integrity":
            return PackageRequest(PYPI, KIND_SERVICE)
        last = segs[-1] if segs else ""
        if last.endswith(".metadata"):
            return PackageRequest(PYPI, KIND_SERVICE)
        if last.lower().endswith(_PYPI_ARTIFACT_EXT):
            ver = pypi_file_version(last)
            return PackageRequest(PYPI, KIND_ARTIFACT, name=pypi_file_name(last),
                                  version=normalize_version(PYPI, ver), raw_version=ver, filename=last)
        return PackageRequest(PYPI, KIND_OTHER)
    if not segs:
        return PackageRequest(PYPI, KIND_OTHER)
    if segs[0] == "simple":
        if len(segs) == 1:
            return PackageRequest(PYPI, KIND_SERVICE)        # /simple/ index root
        return PackageRequest(PYPI, KIND_METADATA, normalize_name(PYPI, segs[1]))
    if segs[0] == "pypi" and len(segs) >= 3 and segs[-1] == "json":
        name = normalize_name(PYPI, segs[1])
        if len(segs) == 4:                                   # /pypi/<project>/<version>/json
            return PackageRequest(PYPI, KIND_METADATA, name, version=normalize_version(PYPI, segs[2]), raw_version=segs[2])
        return PackageRequest(PYPI, KIND_METADATA, name)     # /pypi/<project>/json
    return PackageRequest(PYPI, KIND_OTHER)


def _classify_nuget(segs: List[str]) -> PackageRequest:
    if not segs:
        return PackageRequest(NUGET, KIND_OTHER)
    head = segs[0]
    if head == "v3-flatcontainer":
        if len(segs) == 3 and segs[2] == "index.json":       # /v3-flatcontainer/<id>/index.json
            return PackageRequest(NUGET, KIND_METADATA, normalize_name(NUGET, segs[1]))
        if len(segs) == 4:                                    # /v3-flatcontainer/<id>/<ver>/<file>
            last = segs[3].lower()
            if last.endswith(".nupkg"):
                return PackageRequest(NUGET, KIND_ARTIFACT, normalize_name(NUGET, segs[1]),
                                      version=normalize_version(NUGET, segs[2]), raw_version=segs[2], filename=last)
            return PackageRequest(NUGET, KIND_SERVICE)        # .nuspec / readme / icon
        return PackageRequest(NUGET, KIND_OTHER)
    if head == "v3":
        if len(segs) >= 2 and segs[1].startswith("registration"):
            if len(segs) < 3:
                return PackageRequest(NUGET, KIND_OTHER)
            name = normalize_name(NUGET, segs[2])
            if len(segs) >= 4 and segs[3].endswith(".json") and segs[3] not in ("index.json",) and "page" not in segs[3:]:
                if len(segs) == 4:                             # /v3/registration*/<id>/<version>.json
                    ver = segs[3][:-5]
                    return PackageRequest(NUGET, KIND_METADATA, name, version=normalize_version(NUGET, ver), raw_version=ver)
            return PackageRequest(NUGET, KIND_METADATA, name)  # registration index or a page
        if segs[1:2] == ["index.json"] or (len(segs) >= 2 and segs[1] in ("catalog0", "vulnerabilities")):
            return PackageRequest(NUGET, KIND_SERVICE)
    if any("query" in s or "autocomplete" in s for s in segs):
        return PackageRequest(NUGET, KIND_SERVICE)
    return PackageRequest(NUGET, KIND_OTHER)


_PSG_NUPKG = re.compile(r"^(?P<id>.+?)\.(?P<ver>\d+(?:\.\d+)*(?:-[0-9a-zA-Z.-]+)?)\.nupkg$")
_PSG_ODATA_ID = re.compile(r"id=(?:'|%27)([^'%]+)", re.IGNORECASE)
_PSG_ODATA_IDVER = re.compile(r"Id=(?:'|%27)([^'%]+)(?:'|%27).*?Version=(?:'|%27)([^'%]+)", re.IGNORECASE)


def _classify_psgallery(path: str, segs: List[str], file_host: bool, query: str) -> PackageRequest:
    if file_host:
        last = segs[-1] if segs else ""
        m = _PSG_NUPKG.match(last)
        if m:
            name = normalize_name(PSGALLERY, m.group("id"))
            return PackageRequest(PSGALLERY, KIND_ARTIFACT, name, version=normalize_version(PSGALLERY, m.group("ver")),
                                  raw_version=m.group("ver"), filename=last.lower())
        return PackageRequest(PSGALLERY, KIND_OTHER)
    if not segs or segs[0] != "api" or len(segs) < 2 or segs[1] != "v2":
        return PackageRequest(PSGALLERY, KIND_OTHER)
    if len(segs) == 2:
        return PackageRequest(PSGALLERY, KIND_SERVICE)        # /api/v2 service document
    tail = segs[2]
    low = tail.lower()
    if tail == "$metadata":
        return PackageRequest(PSGALLERY, KIND_SERVICE)
    if low.startswith("package") and len(segs) >= 5:          # /api/v2/package/<id>/<ver>
        name = normalize_name(PSGALLERY, segs[3])
        ver = normalize_version(PSGALLERY, segs[4])
        fn = f"{name}.{ver}.nupkg"
        return PackageRequest(PSGALLERY, KIND_ARTIFACT, name, version=ver, raw_version=segs[4], filename=fn)
    if low.startswith("findpackagesbyid"):
        m = _PSG_ODATA_ID.search(query)
        if m:
            return PackageRequest(PSGALLERY, KIND_METADATA, normalize_name(PSGALLERY, m.group(1)))
        return PackageRequest(PSGALLERY, KIND_METADATA)
    if low.startswith("packages("):                           # /api/v2/Packages(Id='..',Version='..')
        m = _PSG_ODATA_IDVER.search(path)
        if m:
            return PackageRequest(PSGALLERY, KIND_METADATA, normalize_name(PSGALLERY, m.group(1)),
                                  version=normalize_version(PSGALLERY, m.group(2)), raw_version=m.group(2))
        return PackageRequest(PSGALLERY, KIND_METADATA)
    if low.startswith("search") or low.startswith("getupdates"):
        # Multi-package discovery feeds cannot be filtered to one name's approvals; installs are backstopped by
        # the per-version FindPackagesById metadata filter and the hash-pinned artifact gate.
        return PackageRequest(PSGALLERY, KIND_SERVICE)
    return PackageRequest(PSGALLERY, KIND_OTHER)


# ---------------------------------------------------------------------------
# Gate decision
# ---------------------------------------------------------------------------

@dataclass
class GateDecision:
    action: str
    eco: str
    kind: str
    name: str = ""
    version: str = ""
    filename: str = ""
    decision: str = ""              # FlowPackage.decision
    status: int = 403
    message: str = ""               # readable body text for a local block
    reason: str = ""                # FlowPackage.reason / would-be outcome in monitor mode
    console_url: str = ""
    approved_versions: FrozenSet[str] = field(default_factory=frozenset)
    sha256: str = ""                # pin (hex) for ACT_VERIFY; delivered digest in telemetry
    sha512: str = ""                # pin (base64) for ACT_VERIFY; delivered digest in telemetry
    hidden_versions: int = 0
    visible_versions: int = 0
    monitor: bool = False

    def request_link(self) -> str:
        base = (self.console_url or "").rstrip("/")
        if not base:
            return ""
        q = urllib.parse.urlencode({"ecosystem": self.eco, "name": self.name, "version": self.version})
        return f"{base}/packages/request?{q}"

    def telemetry(self, **override: Any) -> Dict[str, Any]:
        """The ``package`` dict added to a flow record (models.FlowPackage). Empty fields are omitted."""
        d = {
            "ecosystem": self.eco, "name": printable(self.name, 255), "version": printable(self.version, 128),
            "kind": self.kind, "decision": self.decision, "filename": printable(self.filename, 255),
            "sha256": self.sha256, "sha512": self.sha512, "hidden_versions": self.hidden_versions,
            "visible_versions": self.visible_versions, "reason": printable(self.reason, 255),
        }
        d.update(override)
        return {k: v for k, v in d.items() if v not in ("", 0, None)}


def _group_ok(scope: Any, groups: List[str], server_id: str) -> bool:
    """``["*"]`` covers every client (registered or not); otherwise any of the client's groups must be listed."""
    if not scope:
        return False
    if "*" in scope:
        return True
    return any(g in scope for g in (groups or []))


class PackageGate:
    """Compiled, immutable view of the bundle's ``packages`` object. Built once per policy bundle."""

    def __init__(self, raw: Optional[Dict[str, Any]]) -> None:
        raw = raw or {}
        self.enabled: bool = bool(raw.get("enabled"))
        self.console_url: str = (raw.get("console_url") or "").rstrip("/")
        self.max_metadata_bytes: int = int(raw.get("max_metadata_bytes") or DEFAULT_MAX_METADATA_BYTES)
        self.max_verify_bytes: int = int(raw.get("max_verify_bytes") or DEFAULT_MAX_VERIFY_BYTES)
        self.ecosystems: Dict[str, Dict[str, Any]] = {}
        self._meta_hosts: Dict[str, str] = {}   # host -> eco (serves metadata + artifacts + service)
        self._file_hosts: Dict[str, str] = {}   # host -> eco (artifacts only)
        for eco, spec in (raw.get("ecosystems") or {}).items():
            if eco not in ECOSYSTEMS or not isinstance(spec, dict):
                continue
            mode = str(spec.get("mode") or MODE_OFF).lower()
            if mode not in (MODE_MONITOR, MODE_ENFORCE):
                continue  # "off" (or unknown): the gate is invisible, ordinary egress rules apply
            self.ecosystems[eco] = {"mode": mode, "group_ids": list(spec.get("group_ids") or [])}
            for h in spec.get("hosts") or []:
                self._meta_hosts[normalize_host(h)] = eco
            for h in spec.get("file_hosts") or []:
                self._file_hosts[normalize_host(h)] = eco
        # approved[eco][name_candidate] -> {normalized_version: version_spec}; blocked[eco][name_candidate] -> {ver|"*": reason}
        self._approved: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self._blocked: Dict[str, Dict[str, Dict[str, str]]] = {}
        for eco, pkgs in (raw.get("approved") or {}).items():
            if eco not in ECOSYSTEMS or not isinstance(pkgs, dict):
                continue
            bucket = self._approved.setdefault(eco, {})
            for name, versions in pkgs.items():
                if not isinstance(versions, dict):
                    continue
                vmap = {normalize_version(eco, v): spec for v, spec in versions.items() if isinstance(spec, dict)}
                for key in _candidates_name(eco, name):
                    bucket.setdefault(key, vmap)
        for eco, pkgs in (raw.get("blocked") or {}).items():
            if eco not in ECOSYSTEMS or not isinstance(pkgs, dict):
                continue
            bucket = self._blocked.setdefault(eco, {})
            for name, versions in pkgs.items():
                if not isinstance(versions, dict):
                    continue
                bmap = {}
                for v, reason in versions.items():
                    bmap[v] = str(reason)
                    if v != "*":
                        bmap[normalize_version(eco, v)] = str(reason)
                for key in _candidates_name(eco, name):
                    bucket.setdefault(key, bmap)

    # -- status ------------------------------------------------------------
    def status_summary(self) -> str:
        """One-line heartbeat value: ``npm=enforce,pypi=enforce,nuget=monitor``."""
        return ",".join(f"{e}={self.ecosystems[e]['mode']}" for e in ECOSYSTEMS if e in self.ecosystems)

    # -- classification ----------------------------------------------------
    def classify(self, host: str, path: str, method: str) -> Optional[PackageRequest]:
        """Identify the ecosystem/kind/name/version of a request, or None when no non-off ecosystem owns the host
        or the path is not a package URL. Group scoping is applied later in :meth:`decide`."""
        if not self.enabled:
            return None
        if len(path or "") > MAX_PATH:
            return None
        h = normalize_host(host)
        eco = self._meta_hosts.get(h)
        file_host = False
        if eco is None:
            eco = self._file_hosts.get(h)
            file_host = eco is not None
        if eco is None:
            return None
        query = (path or "").split("?", 1)[1] if "?" in (path or "") else ""
        clean, segs = _split_path(path)
        if eco == NPM:
            req = _classify_npm(segs)
        elif eco == PYPI:
            req = _classify_pypi(segs, file_host)
        elif eco == NUGET:
            req = _classify_nuget(segs)
        elif eco == PSGALLERY:
            req = _classify_psgallery(clean, segs, file_host, query)
        else:  # pragma: no cover - ECOSYSTEMS is closed
            return None
        if req.kind == KIND_OTHER:
            return None
        if req.kind in (KIND_METADATA, KIND_ARTIFACT) and (method or "GET").upper() not in ("GET", "HEAD"):
            return None  # a write to a package path (publish, yank) is ordinary egress, not a gate concern
        return req

    def applies(self, eco: str, groups: List[str], server_id: str) -> bool:
        spec = self.ecosystems.get(eco)
        return bool(spec) and _group_ok(spec["group_ids"], groups, server_id)

    def mode(self, eco: str) -> str:
        spec = self.ecosystems.get(eco)
        return spec["mode"] if spec else MODE_OFF

    # -- approvals ---------------------------------------------------------
    def _block_reason(self, eco: str, name: str, version: str) -> Optional[str]:
        bmap = self._blocked.get(eco, {}).get(name)
        if not bmap:
            return None
        if "*" in bmap:
            return bmap["*"]
        for cand in _candidates_version(eco, version):
            if cand in bmap:
                return bmap[cand]
        return None

    def _versions_for(self, eco: str, name: str, groups: List[str], server_id: str) -> Dict[str, Any]:
        """Normalized-version -> spec, limited to versions whose ``g`` covers the client and that are not blocked."""
        vmap = self._approved.get(eco, {}).get(name)
        if not vmap:
            return {}
        out: Dict[str, Any] = {}
        for ver, spec in vmap.items():
            if not _group_ok(spec.get("g"), groups, server_id):
                continue
            if self._block_reason(eco, name, ver) is not None:
                continue
            out[ver] = spec
        return out

    @staticmethod
    def _approved_set(eco: str, versions: Dict[str, Any]) -> FrozenSet[str]:
        s: set = set()
        for v in versions:
            s.add(v)
            s.add(v.lower())
            s.add(normalize_version(eco, v))
        return frozenset(s)

    def decide(self, req: PackageRequest, groups: List[str], server_id: str) -> Optional[GateDecision]:
        """Translate a classified request into what the addon should do, or None to apply ordinary egress rules."""
        eco = req.eco
        if not self.applies(eco, groups, server_id):
            return None  # ecosystem does not cover this client: ordinary egress rules
        mode = self.mode(eco)
        base = dict(eco=eco, kind=req.kind, name=req.name, version=req.version, filename=req.filename,
                    console_url=self.console_url)

        if req.kind == KIND_SERVICE:
            return self._finish(GateDecision(ACT_PASSTHROUGH, decision=D_SERVICE, **base), mode)

        if req.kind == KIND_METADATA:
            versions = self._versions_for(eco, req.name, groups, server_id)
            concrete = _is_concrete_version(eco, req.raw_version)
            if concrete:
                nv = normalize_version(eco, req.raw_version)
                blocked = self._block_reason(eco, req.name, nv)
                if blocked is not None:
                    return self._block(base, D_BLOCKED, blocked, mode)
                if nv not in self._approved_set(eco, versions):
                    return self._block(base, D_NOT_APPROVED, "no approved version for this client", mode)
            elif not versions:
                # Distinguish "nothing approved for this client" from "every approved version is blocked" (block wins).
                blocked = self._block_reason(eco, req.name, "")  # a "*" block
                if blocked is None:
                    for v in (self._approved.get(eco, {}).get(req.name) or {}):
                        blocked = self._block_reason(eco, req.name, v)
                        if blocked is not None:
                            break
                reason = blocked or "no approved version for this client"
                return self._block(base, D_BLOCKED if blocked else D_NOT_APPROVED, reason, mode)
            dec = GateDecision(ACT_FILTER, decision=D_FILTERED,
                               approved_versions=self._approved_set(eco, versions), **base)
            return self._finish(dec, mode)

        if req.kind == KIND_ARTIFACT:
            blocked = self._block_reason(eco, req.name, req.version)
            if blocked is not None:
                return self._block(base, D_BLOCKED, blocked, mode)
            versions = self._versions_for(eco, req.name, groups, server_id)
            spec = None
            for cand in _candidates_version(eco, req.version):
                if cand in versions:
                    spec = versions[cand]
                    break
            if spec is None:
                return self._block(base, D_NOT_APPROVED, "no approved version for this client", mode)
            pin = self._pin(spec, req.filename)
            if pin is None:
                return self._block(base, D_NOT_APPROVED, "this file is not covered by the approval", mode)
            dec = GateDecision(ACT_VERIFY, decision=D_APPROVED, sha256=pin[0], sha512=pin[1], **base)
            return self._finish(dec, mode)

        return None

    @staticmethod
    def _pin(spec: Dict[str, Any], filename: str) -> Optional[Tuple[str, str]]:
        files = spec.get("files") or {}
        entry = files.get(filename) or files.get(filename.lower())
        if entry is None:
            return None
        return str(entry.get("sha256") or ""), str(entry.get("sha512") or "")

    @staticmethod
    def _finish(dec: GateDecision, mode: str) -> GateDecision:
        """Monitor mode never acts: the computed decision moves to ``reason`` and the action becomes record-only."""
        if mode == MODE_MONITOR:
            dec.reason = dec.decision
            dec.decision = D_MONITOR
            dec.monitor = True
            dec.action = ACT_PASSTHROUGH
        return dec

    @staticmethod
    def _block(base: Dict[str, Any], decision: str, reason: str, mode: str) -> GateDecision:
        dec = GateDecision(ACT_BLOCK, decision=decision, reason=reason, status=403, message=reason, **base)
        return PackageGate._finish(dec, mode)


# ---------------------------------------------------------------------------
# Metadata filtering
# ---------------------------------------------------------------------------

def _version_approved(eco: str, version: str, approved: FrozenSet[str]) -> bool:
    if not version:
        return False
    return (version in approved or version.lower() in approved or normalize_version(eco, version) in approved)


@dataclass
class FilterResult:
    body: bytes
    content_type: str
    hidden: int = 0
    visible: int = 0


def filter_metadata(eco: str, name: str, approved: FrozenSet[str], body: bytes, content_type: str) -> FilterResult:
    """Rewrite a metadata response body so the client's resolver only sees approved versions. Raises
    :class:`FilterError` when the body cannot be parsed/filtered (the addon then blocks 503 in enforce mode)."""
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    try:
        if eco == NPM:
            return _filter_npm(approved, body, content_type)
        if eco == PYPI:
            if ctype == "text/html" or (not ctype and body.lstrip()[:1] == b"<"):
                return _filter_pypi_html(approved, body)
            return _filter_pypi_json(approved, body, content_type)
        if eco == NUGET:
            return _filter_nuget(approved, body, content_type)
        if eco == PSGALLERY:
            return _filter_psgallery(approved, body, content_type)
    except FilterError:
        raise
    except Exception as exc:  # noqa: BLE001 - any parse failure fails closed
        raise FilterError(f"{eco} metadata filtering failed: {type(exc).__name__}: {exc}") from exc
    raise FilterError(f"no metadata filter for ecosystem {eco!r}")


# --- npm --------------------------------------------------------------------

def _semver_key(v: str) -> Tuple:
    """Coarse semver ordering key: (major, minor, patch, has_no_prerelease, prerelease-parts)."""
    core = (v or "").strip().split("+", 1)[0]
    main, _, pre = core.partition("-")
    nums: List[int] = []
    for part in main.split(".")[:3]:
        nums.append(int(part) if part.isdigit() else 0)
    while len(nums) < 3:
        nums.append(0)
    pre_parts: List[Tuple[int, Any]] = []
    if pre:
        for p in pre.split("."):
            pre_parts.append((0, int(p)) if p.isdigit() else (1, p))
    return (nums[0], nums[1], nums[2], 1 if not pre else 0, pre_parts)


def _repoint_tag(target: str, approved_list: List[str]) -> Optional[str]:
    """Highest approved version <= target (semver), else the highest approved overall, else None."""
    if not approved_list:
        return None
    if target in approved_list:
        return target
    tkey = _semver_key(target)
    below = [v for v in approved_list if _semver_key(v) <= tkey]
    pool = below or approved_list
    return max(pool, key=_semver_key)


def _filter_npm(approved: FrozenSet[str], body: bytes, content_type: str) -> FilterResult:
    doc = json.loads(body.decode("utf-8", "strict"))
    if not isinstance(doc, dict):
        raise FilterError("npm packument is not an object")
    versions = doc.get("versions")
    if not isinstance(versions, dict):
        # Single-version manifest (/<name>/<version|tag>): no version map to filter; left as-is (the artifact
        # download is still hash-pinned and gated, which backstops a non-approved dist-tag).
        v = doc.get("version")
        visible = 1 if (isinstance(v, str) and _version_approved(NPM, v, approved)) else 0
        return FilterResult(body, content_type, hidden=0, visible=visible)
    kept = {v: m for v, m in versions.items() if _version_approved(NPM, v, approved)}
    hidden = len(versions) - len(kept)
    doc["versions"] = kept
    approved_list = list(kept)
    time_map = doc.get("time")
    if isinstance(time_map, dict):
        doc["time"] = {k: t for k, t in time_map.items() if k in kept or k in ("created", "modified")}
    tags = doc.get("dist-tags")
    if isinstance(tags, dict):
        new_tags: Dict[str, str] = {}
        for tag, ver in tags.items():
            if not isinstance(ver, str):
                continue
            repointed = _repoint_tag(ver, approved_list)
            if repointed is not None:
                new_tags[tag] = repointed
        doc["dist-tags"] = new_tags
    out = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return FilterResult(out, content_type, hidden=hidden, visible=len(kept))


# --- pypi -------------------------------------------------------------------

def _filter_pypi_json(approved: FrozenSet[str], body: bytes, content_type: str) -> FilterResult:
    doc = json.loads(body.decode("utf-8", "strict"))
    if not isinstance(doc, dict):
        raise FilterError("pypi JSON is not an object")
    if "releases" in doc or "info" in doc:  # legacy project JSON (/pypi/<project>/json)
        releases = doc.get("releases")
        hidden = visible = 0
        if isinstance(releases, dict):
            kept = {v: f for v, f in releases.items() if _version_approved(PYPI, v, approved)}
            hidden = len(releases) - len(kept)
            visible = len(kept)
            doc["releases"] = kept
        info = doc.get("info")
        latest = info.get("version") if isinstance(info, dict) else None
        if not (isinstance(latest, str) and _version_approved(PYPI, latest, approved)):
            doc["urls"] = []  # the "latest" files point at a non-approved version
        out = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return FilterResult(out, content_type, hidden=hidden, visible=visible)
    # PEP 691 Simple JSON
    files = doc.get("files")
    hidden = 0
    if isinstance(files, list):
        kept_files = [f for f in files if isinstance(f, dict)
                      and _version_approved(PYPI, pypi_file_version(str(f.get("filename", ""))), approved)]
        hidden = len(files) - len(kept_files)
        doc["files"] = kept_files
    vers = doc.get("versions")
    visible = 0
    if isinstance(vers, list):
        kept_v = [v for v in vers if isinstance(v, str) and _version_approved(PYPI, v, approved)]
        doc["versions"] = kept_v
        visible = len(kept_v)
    else:
        visible = len({pypi_file_version(str(f.get("filename", ""))) for f in doc.get("files", [])})
    out = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return FilterResult(out, content_type, hidden=hidden, visible=visible)


_HTML_ANCHOR = re.compile(rb"(?is)<a\b[^>]*>.*?</a>")
_HTML_HREF = re.compile(rb'(?is)href\s*=\s*"([^"]*)"')
_HTML_TEXT = re.compile(rb"(?is)>([^<]*)</a>")


def _anchor_filename(anchor: bytes) -> str:
    text = _HTML_TEXT.search(anchor)
    if text and text.group(1).strip():
        return text.group(1).strip().decode("utf-8", "replace")
    href = _HTML_HREF.search(anchor)
    if href:
        path = href.group(1).split(b"#", 1)[0]
        return path.rsplit(b"/", 1)[-1].decode("utf-8", "replace")
    return ""


def _filter_pypi_html(approved: FrozenSet[str], body: bytes) -> FilterResult:
    counts = {"hidden": 0, "visible": 0}

    def repl(m: "re.Match") -> bytes:
        fn = _anchor_filename(m.group(0))
        if _version_approved(PYPI, pypi_file_version(fn), approved):
            counts["visible"] += 1
            return m.group(0)
        counts["hidden"] += 1
        return b""

    out = _HTML_ANCHOR.sub(repl, body)
    return FilterResult(out, "text/html", hidden=counts["hidden"], visible=counts["visible"])


# --- nuget ------------------------------------------------------------------

def _filter_nuget(approved: FrozenSet[str], body: bytes, content_type: str) -> FilterResult:
    doc = json.loads(body.decode("utf-8", "strict"))
    if not isinstance(doc, dict):
        raise FilterError("nuget metadata is not an object")
    if isinstance(doc.get("versions"), list) and "items" not in doc:
        # flat-container /<id>/index.json
        vers = doc["versions"]
        kept = [v for v in vers if isinstance(v, str) and _version_approved(NUGET, v, approved)]
        doc["versions"] = kept
        out = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return FilterResult(out, content_type, hidden=len(vers) - len(kept), visible=len(kept))
    hidden, visible = _filter_nuget_registration(doc, approved)
    out = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return FilterResult(out, content_type, hidden=hidden, visible=visible)


def _leaf_version(leaf: Any) -> str:
    if isinstance(leaf, dict):
        entry = leaf.get("catalogEntry")
        if isinstance(entry, dict) and isinstance(entry.get("version"), str):
            return entry["version"]
        if isinstance(leaf.get("version"), str):
            return leaf["version"]
    return ""


def _filter_nuget_registration(doc: Dict[str, Any], approved: FrozenSet[str]) -> Tuple[int, int]:
    """Filter a registration index or a registration page in place. Inline leaves are kept iff their version is
    approved; a page we cannot see inline (``items`` absent) is dropped whole (fail closed), see the module docs."""
    items = doc.get("items")
    hidden = visible = 0
    if not isinstance(items, list):
        return 0, 0
    # A registration *page* has leaves directly in ``items``; a registration *index* has pages in ``items``.
    if items and isinstance(items[0], dict) and "catalogEntry" in items[0]:
        kept = []
        for leaf in items:
            if _version_approved(NUGET, _leaf_version(leaf), approved):
                kept.append(leaf)
                visible += 1
            else:
                hidden += 1
        doc["items"] = kept
        doc["count"] = len(kept)
        return hidden, visible
    kept_pages = []
    for page in items:
        if not isinstance(page, dict):
            continue
        if isinstance(page.get("items"), list):
            h, v = _filter_nuget_registration(page, approved)
            hidden += h
            visible += v
            if page.get("items"):
                kept_pages.append(page)
        # else: paged (not inline) -> the page's versions cannot be verified here, so it is dropped (fail closed).
    doc["items"] = kept_pages
    doc["count"] = len(kept_pages)
    return hidden, visible


# --- psgallery --------------------------------------------------------------

_ATOM_NS = "http://www.w3.org/2005/Atom"
_DS_NS = "http://schemas.microsoft.com/ado/2007/08/dataservices"
_DSM_NS = "http://schemas.microsoft.com/ado/2007/08/dataservices/metadata"


def _filter_psgallery(approved: FrozenSet[str], body: bytes, content_type: str) -> FilterResult:
    for prefix, uri in (("", _ATOM_NS), ("d", _DS_NS), ("m", _DSM_NS)):
        ET.register_namespace(prefix, uri)
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise FilterError(f"psgallery OData XML parse error: {exc}") from exc
    entry_tag = f"{{{_ATOM_NS}}}entry"
    hidden = visible = 0
    for entry in list(root):
        if entry.tag != entry_tag:
            continue
        ver = _psg_entry_version(entry)
        if _version_approved(PSGALLERY, ver, approved):
            visible += 1
        else:
            root.remove(entry)
            hidden += 1
    out = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    return FilterResult(out, content_type or "application/atom+xml", hidden=hidden, visible=visible)


def _psg_entry_version(entry: "ET.Element") -> str:
    props = entry.find(f"{{{_DSM_NS}}}properties")
    if props is None:
        for child in entry:
            if child.tag.endswith("properties"):
                props = child
                break
    if props is None:
        return ""
    for tag in ("NormalizedVersion", "Version"):
        el = props.find(f"{{{_DS_NS}}}{tag}")
        if el is None:
            for child in props:
                if child.tag.endswith(tag):
                    el = child
                    break
        if el is not None and (el.text or "").strip():
            return el.text.strip()
    return ""


# ---------------------------------------------------------------------------
# Artifact verification (streaming)
# ---------------------------------------------------------------------------

class ArtifactVerifier:
    """Callable installed as ``flow.response.stream``. See the module docstring for the mechanism and memory bound.

    ``expected_sha256`` is a hex digest, ``expected_sha512`` a base64 digest (either may be ""). A pin with neither
    digest cannot be verified and is treated as a mismatch (fail closed). ``on_fail`` is invoked once, at EOF, when
    the digest does not match (so the addon can kill the flow and record the event)."""

    def __init__(self, expected_sha256: str = "", expected_sha512: str = "",
                 on_fail: Optional[Callable[["ArtifactVerifier"], None]] = None, tail: int = TAIL_WINDOW) -> None:
        self.expected_sha256 = (expected_sha256 or "").strip().lower()
        self.expected_sha512 = _strip_b64(expected_sha512)
        self.on_fail = on_fail
        self.tail = max(1, int(tail))
        self._h256 = hashlib.sha256()
        self._h512 = hashlib.sha512()
        self._pending = bytearray()
        self.total = 0
        self.finished = False
        self.matched: Optional[bool] = None
        self.sha256 = ""   # computed hex digest (available once finished)
        self.sha512 = ""   # computed base64 digest

    @property
    def mismatch(self) -> bool:
        return self.finished and self.matched is False

    def __call__(self, chunk: bytes) -> bytes:
        if chunk:
            self._h256.update(chunk)
            self._h512.update(chunk)
            self.total += len(chunk)
            self._pending += chunk
            if len(self._pending) > self.tail:
                emit = bytes(self._pending[: len(self._pending) - self.tail])
                del self._pending[: len(emit)]
                return emit
            return b""
        # EOF: the whole body has been hashed.
        if self.finished:
            return b""
        self.finished = True
        self.sha256 = self._h256.hexdigest()
        self.sha512 = base64.b64encode(self._h512.digest()).decode("ascii")
        self.matched = self._compare()
        if self.matched:
            tail = bytes(self._pending)
            self._pending.clear()
            return tail
        self._pending.clear()  # drop the tail: the client is left with a truncated, unusable file
        if self.on_fail is not None:
            try:
                self.on_fail(self)
            except Exception:  # noqa: BLE001 - failure handling must not raise inside the stream callback
                pass
        return b""

    def _compare(self) -> bool:
        ok = False
        if self.expected_sha256:
            if not _consteq(self.sha256, self.expected_sha256):
                return False
            ok = True
        if self.expected_sha512:
            if not _consteq(_strip_b64(self.sha512), self.expected_sha512):
                return False
            ok = True
        return ok  # no pin at all -> False (fail closed)


def _strip_b64(value: str) -> str:
    v = (value or "").strip()
    if v.lower().startswith("sha512-"):
        v = v[7:]
    return v.rstrip("=")


def _consteq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
