#!/usr/bin/env python3
"""
AegisProxy Enterprise — mitmproxy data-plane entry point
=======================================================

    mitmdump -s aegis_addon.py --set confdir=/certs --set connection_strategy=lazy ...

All logic lives in the ``aegis_dp`` package next to this file. Import errors are deliberately NOT
caught: a proxy that silently runs without its policy addon would be an open proxy.

Environment (see docs/configuration.md):
  CONTROL_PLANE_URL            control-plane base URL (https recommended)
  AEGIS_DATAPLANE_KEY[_FILE]   shared secret with the control-plane (required)
  AEGIS_CLAMD_ADDRESS          tcp://clamav:3310 or unix:///run/clamav/clamd.ctl (enables antivirus)
  AEGIS_FAIL_MODE              closed (default) | open — behaviour before the first policy sync
  AEGIS_PROXY_MODE             regular (default) | transparent
"""

import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aegis_dp.addon import AegisAddon  # noqa: E402

logging.getLogger("aegis").setLevel(os.environ.get("AEGIS_LOG_LEVEL", "INFO").upper())

addons = [AegisAddon()]
