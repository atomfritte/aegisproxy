#!/usr/bin/env python3
"""Container health probe for the data-plane worker (stdlib only).

Usage: healthcheck.py [readyz|healthz]   (default: readyz)
"""
import os
import sys
import urllib.request

endpoint = sys.argv[1] if len(sys.argv) > 1 else "readyz"
addr = os.environ.get("AEGIS_OPS_ADDR", "0.0.0.0:9091").replace("0.0.0.0", "127.0.0.1")
try:
    with urllib.request.urlopen(f"http://{addr}/{endpoint}", timeout=3) as resp:
        sys.exit(0 if resp.status == 200 else 1)
except Exception:
    sys.exit(1)
