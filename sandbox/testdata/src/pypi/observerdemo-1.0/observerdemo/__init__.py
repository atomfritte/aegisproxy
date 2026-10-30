"""Harmless AegisProxy sandbox fixture package. Importing it (the ``load`` scenario) performs a small set of
observable actions: a DNS lookup + HTTP request to a made-up host and a ``sh -c id`` spawn."""
import os

try:
    import urllib.request

    urllib.request.urlopen("http://telemetry.evil.example/load", timeout=3)
except Exception:
    pass

try:
    os.system("sh -c id")
except Exception:
    pass


def ok():
    return True
