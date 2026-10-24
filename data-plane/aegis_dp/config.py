"""Environment configuration for the data-plane worker."""

from __future__ import annotations

import os
import re
import socket
from dataclasses import dataclass, field
from typing import List

from .buffering import parse_size

KNOWN_LEAKED_KEYS = {"aegis-dp-internal-key-2026-v1"}
DEFAULT_FLOW_SPOOL_MAX = 256 << 20
MIN_POLICY_MAX_AGE = 30.0


class ConfigError(RuntimeError):
    pass


def _read_secret(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if value:
        return value
    path = os.environ.get(name + "_FILE", "").strip()
    if path:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError as exc:
            raise ConfigError(f"{name}_FILE: {exc}") from exc
    return ""


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc


_DURATION_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(raw: str) -> float:
    """Seconds of "90", "90s", "15m", "2h", "1d" (or a combination such as "1h30m"); "" and "0" are 0."""
    s = (raw or "").strip().lower()
    if not s:
        return 0.0
    if not re.fullmatch(r"\d+|(?:\d+[smhd])+", s):
        raise ValueError(f"invalid duration {raw!r}")
    return float(sum(int(n) * _DURATION_UNITS[u] for n, u in re.findall(r"(\d+)([smhd]?)", s)))


@dataclass
class Config:
    control_plane_url: str
    dataplane_key: str
    worker_id: str
    public_url: str = ""
    dashboard_url: str = ""
    control_plane_ca_file: str = ""
    fail_mode: str = "closed"  # closed | open (when no policy bundle could ever be loaded)
    proxy_mode: str = "regular"
    clamd_address: str = ""  # tcp://host:3310 or unix:///path/clamd.sock ("" = disabled)
    clamd_timeout: float = 60.0
    magic_hosts: List[str] = field(default_factory=lambda: ["aegis.ca", "mitm.it"])
    ops_addr: str = "0.0.0.0:9091"
    sync_interval: float = 2.0
    threat_sync_interval: float = 30.0
    flush_interval: float = 0.5
    access_log: str = ""  # off | stdout | stderr | /path | syslog://host:514 | syslog+tcp://host:514 | syslog:///dev/log
    access_log_format: str = "squid"  # squid | combined | json
    access_log_rotate_mb: int = 0  # > 0: the worker rotates a file destination itself (default on Windows)
    access_log_keep: int = 10
    buffer_budget: int = 0  # bytes of bodies buffered for inspection at once; 0 = min(512 MiB, body_size_limit)
    buffer_client_share: int = 25  # percent of the budget one client (server identity, else address) may hold
    policy_max_age: float = 0.0  # seconds; > 0: fail closed when the last successful policy sync is older
    flow_spool_dir: str = ""  # durable telemetry spool ("" = memory queue only)
    flow_spool_max: int = DEFAULT_FLOW_SPOOL_MAX
    flow_queue_max: int = 20_000  # flow records held in memory before they are uploaded or spooled

    @classmethod
    def from_env(cls) -> "Config":
        key = _read_secret("AEGIS_DATAPLANE_KEY")
        if not key:
            raise ConfigError(
                "AEGIS_DATAPLANE_KEY (or AEGIS_DATAPLANE_KEY_FILE) is required: it authenticates this worker "
                "to the control-plane and signs block tokens. Use the same value as the control-plane."
            )
        if key in KNOWN_LEAKED_KEYS or len(key) < 32:
            raise ConfigError("AEGIS_DATAPLANE_KEY must be a random secret of at least 32 characters (openssl rand -hex 32)")
        fail_mode = os.environ.get("AEGIS_FAIL_MODE", "closed").strip().lower()
        if fail_mode not in ("closed", "open"):
            raise ConfigError("AEGIS_FAIL_MODE must be 'closed' or 'open'")
        proxy_mode = os.environ.get("AEGIS_PROXY_MODE", "regular").strip().lower()
        if proxy_mode not in ("regular", "transparent"):
            raise ConfigError("AEGIS_PROXY_MODE must be 'regular' or 'transparent'")
        access_format = os.environ.get("AEGIS_ACCESS_LOG_FORMAT", "squid").strip().lower()
        if access_format not in ("squid", "combined", "json"):
            raise ConfigError("AEGIS_ACCESS_LOG_FORMAT must be squid, combined or json")
        rotate_mb = _env_int("AEGIS_ACCESS_LOG_ROTATE_MB", 100 if os.name == "nt" else 0)
        keep = _env_int("AEGIS_ACCESS_LOG_KEEP", 10)
        if not 0 <= rotate_mb <= 1_048_576 or not 1 <= keep <= 1000:
            raise ConfigError("AEGIS_ACCESS_LOG_ROTATE_MB must be 0-1048576 and AEGIS_ACCESS_LOG_KEEP 1-1000")
        magic = [h.strip().lower() for h in os.environ.get("AEGIS_MAGIC_HOSTS", "aegis.ca,mitm.it").split(",") if h.strip()]
        try:
            budget = parse_size(os.environ.get("AEGIS_BUFFER_BUDGET", "")) or 0
        except ValueError as exc:
            raise ConfigError("AEGIS_BUFFER_BUDGET must be a size such as 512m or 1g") from exc
        if budget and budget < 1 << 20:
            raise ConfigError("AEGIS_BUFFER_BUDGET must be at least 1m")
        share_raw = os.environ.get("AEGIS_BUFFER_CLIENT_SHARE", "25").strip().removesuffix("%").strip()
        if not share_raw.isdigit() or not 1 <= int(share_raw) <= 100:
            raise ConfigError("AEGIS_BUFFER_CLIENT_SHARE must be a percentage from 1 to 100 (e.g. 25%)")
        sync_interval = float(_env_int("AEGIS_SYNC_INTERVAL_SECONDS", 2))
        try:
            max_age = parse_duration(os.environ.get("AEGIS_POLICY_MAX_AGE", ""))
        except ValueError as exc:
            raise ConfigError("AEGIS_POLICY_MAX_AGE must be a duration such as 15m, 1h or 900s (0 = unlimited)") from exc
        if max_age and max_age < max(MIN_POLICY_MAX_AGE, 5 * sync_interval):
            raise ConfigError(f"AEGIS_POLICY_MAX_AGE must be at least {int(max(MIN_POLICY_MAX_AGE, 5 * sync_interval))}s "
                              "(30s and five policy sync intervals), or 0 for unlimited")
        try:
            spool_max = parse_size(os.environ.get("AEGIS_FLOW_SPOOL_MAX", "")) or DEFAULT_FLOW_SPOOL_MAX
        except ValueError as exc:
            raise ConfigError("AEGIS_FLOW_SPOOL_MAX must be a size such as 256m or 1g") from exc
        if spool_max < 1 << 20:
            raise ConfigError("AEGIS_FLOW_SPOOL_MAX must be at least 1m")
        return cls(
            control_plane_url=os.environ.get("CONTROL_PLANE_URL", "http://localhost:8081").rstrip("/"),
            dataplane_key=key,
            worker_id=os.environ.get("AEGIS_WORKER_ID", "").strip() or socket.gethostname(),
            public_url=os.environ.get("AEGIS_PUBLIC_URL", "").rstrip("/"),
            dashboard_url=os.environ.get("DASHBOARD_URL", "").rstrip("/"),
            control_plane_ca_file=os.environ.get("AEGIS_CONTROL_PLANE_CA_FILE", "").strip(),
            fail_mode=fail_mode,
            proxy_mode=proxy_mode,
            clamd_address=os.environ.get("AEGIS_CLAMD_ADDRESS", "").strip(),
            clamd_timeout=float(_env_int("AEGIS_CLAMD_TIMEOUT_SECONDS", 60)),
            magic_hosts=magic,
            ops_addr=os.environ.get("AEGIS_OPS_ADDR", "0.0.0.0:9091").strip(),
            sync_interval=sync_interval,
            threat_sync_interval=float(_env_int("AEGIS_THREAT_SYNC_INTERVAL_SECONDS", 30)),
            access_log=os.environ.get("AEGIS_ACCESS_LOG", "").strip(),
            access_log_format=access_format,
            access_log_rotate_mb=rotate_mb,
            access_log_keep=keep,
            buffer_budget=budget,
            buffer_client_share=int(share_raw),
            policy_max_age=max_age,
            flow_spool_dir=os.environ.get("AEGIS_FLOW_SPOOL_DIR", "").strip(),
            flow_spool_max=spool_max,
        )
