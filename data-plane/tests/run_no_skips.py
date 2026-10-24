"""Runs every data-plane test module and fails when a test is skipped.

CI runs the suite in the hash-locked data-plane environment (requirements-lock.txt: mitmproxy, YARA-X), where the
mitmproxy hook tests and the YARA tests must run; a missing dependency then fails the job instead of silently
skipping them. Local runs without mitmproxy keep using test_dataplane.py directly, where those tests are skipped.

    python -I data-plane/tests/run_no_skips.py
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

suite = unittest.defaultTestLoader.discover(HERE, pattern="test_*.py", top_level_dir=HERE)
result = unittest.TextTestRunner(verbosity=1).run(suite)
for test, reason in result.skipped:
    print(f"SKIPPED (not allowed here): {test.id()}: {reason}", file=sys.stderr)
print(f"{result.testsRun} tests, {len(result.failures)} failures, {len(result.errors)} errors, {len(result.skipped)} skipped")
sys.exit(0 if result.wasSuccessful() and not result.skipped else 1)
