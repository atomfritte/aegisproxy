"""AegisProxy data-plane: mitmproxy addon enforcing the control-plane policy.

The package is dependency-free apart from mitmproxy itself (only the ``addon`` module imports it),
so policy, threat-intel, DLP, file-type and ClamAV logic can be unit-tested without mitmproxy.
"""

__version__ = "2.1.0"
