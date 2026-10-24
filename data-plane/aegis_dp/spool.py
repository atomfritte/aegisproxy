"""Durable telemetry spool (AEGIS_FLOW_SPOOL_DIR): flow records survive control-plane outages and worker restarts.

Every upload batch becomes one segment file (seg-<sequence>-<flows>.jsonl), written under a temporary name, fsync'd
and renamed, so a crash never leaves a torn segment. Segments are uploaded oldest first and deleted only after the
control-plane acknowledged them; the control-plane acknowledges after durable storage and de-duplicates by flow ID,
so delivery is at-least-once without duplicates in the console. When the spool would grow beyond
AEGIS_FLOW_SPOOL_MAX the oldest segments are discarded and counted (aegis_dp_flows_dropped_total{reason="spool_full"}).
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("aegis.controlplane")

_SEGMENT = re.compile(r"seg-(\d{12})-(\d+)\.jsonl")


class FlowSpool:
    def __init__(self, directory: str, max_bytes: int) -> None:
        self.dir = directory
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        os.makedirs(directory, mode=0o700, exist_ok=True)
        self._segments: List[Tuple[int, int, int, str]] = []  # (sequence, flows, bytes, file name), oldest first
        for name in os.listdir(directory):
            path = os.path.join(directory, name)
            if name.endswith(".tmp"):
                try:
                    os.remove(path)  # interrupted write: the flows were never acknowledged by the spool
                except OSError:
                    pass
                continue
            m = _SEGMENT.fullmatch(name)
            if m:
                try:
                    size = os.path.getsize(path)
                except OSError:
                    continue
                self._segments.append((int(m.group(1)), int(m.group(2)), size, name))
        self._segments.sort()
        self._seq = (self._segments[-1][0] + 1) if self._segments else 1
        if self._segments:
            log.info("flow spool %s: %d flows in %d segments from an earlier run will be delivered", directory,
                     self.flows, len(self._segments))

    @property
    def flows(self) -> int:
        with self._lock:
            return sum(s[1] for s in self._segments)

    @property
    def bytes(self) -> int:
        with self._lock:
            return sum(s[2] for s in self._segments)

    def __len__(self) -> int:
        with self._lock:
            return len(self._segments)

    def append(self, flows: List[Dict[str, Any]]) -> int:
        """Persists one batch (raises OSError when it cannot); returns the number of older flows discarded to stay
        within the size limit."""
        if not flows:
            return 0
        data = b"".join(json.dumps(f, separators=(",", ":"), default=str).encode("utf-8", "backslashreplace") + b"\n"
                        for f in flows)
        with self._lock:
            seq = self._seq
            self._seq += 1
        name = f"seg-{seq:012d}-{len(flows)}.jsonl"
        path = os.path.join(self.dir, name)
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        except OSError:
            os.close(fd)
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
        os.close(fd)
        os.replace(tmp, path)
        self._sync_dir()
        with self._lock:
            self._segments.append((seq, len(flows), len(data), name))
            return self._trim_locked()

    def _trim_locked(self) -> int:
        dropped = 0
        total = sum(s[2] for s in self._segments)
        while total > self.max_bytes and len(self._segments) > 1:
            _, count, size, name = self._segments.pop(0)
            total -= size
            dropped += count
            self._unlink(name)
        return dropped

    def oldest(self) -> Optional[Tuple[str, List[Dict[str, Any]], int]]:
        """(segment name, flows, unreadable lines) of the oldest segment."""
        with self._lock:
            if not self._segments:
                return None
            name = self._segments[0][3]
        flows: List[Dict[str, Any]] = []
        bad = 0
        try:
            with open(os.path.join(self.dir, name), "rb") as fh:
                for line in fh:
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        bad += 1
                        continue
                    if isinstance(rec, dict):
                        flows.append(rec)
                    else:
                        bad += 1
        except OSError as exc:
            log.error("flow spool: cannot read %s (%s); discarding it", name, exc)
            with self._lock:
                bad += next((s[1] for s in self._segments if s[3] == name), 0)
            self.remove(name)
            return name, [], bad
        return name, flows, bad

    def remove(self, name: str) -> None:
        with self._lock:
            self._segments = [s for s in self._segments if s[3] != name]
        self._unlink(name)

    def _unlink(self, name: str) -> None:
        try:
            os.remove(os.path.join(self.dir, name))
        except FileNotFoundError:
            pass
        except OSError as exc:
            log.warning("flow spool: cannot delete %s: %s", name, exc)

    def _sync_dir(self) -> None:
        if os.name == "nt":
            return
        try:
            fd = os.open(self.dir, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        except OSError:
            pass
        finally:
            os.close(fd)
