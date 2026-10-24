"""Shared helpers of the console regression suite: configuration from the environment (set by run.sh), step
bookkeeping with failure screenshots, browser launch, sign-in and locator helpers."""
import os
import re
import sys
import time
import traceback

from playwright.sync_api import expect

# Origin of the control plane under test; it serves the console build (AEGIS_UI_DIR).
BASE = os.environ["AEGIS_E2E_BASE"].rstrip("/")
# Logs, screenshots and downloads of this run.
OUT = os.environ.get("AEGIS_E2E_OUT") or os.path.join(os.getcwd(), "e2e-out")
os.makedirs(OUT, exist_ok=True)
# Demo-mode accounts (AEGIS_DEMO_MODE=true).
PW = {"admin": "admin123", "infosec": "infosec123", "teamlead": "teamlead123", "auditor": "auditor123"}
XRW = {"X-Requested-With": "aegis-ui"}

results = []


def step(name):
    """Runs a step, records PASS/FAIL and keeps a full-page screenshot of a failure; the first argument is the page."""
    def deco(fn):
        def run(*a):
            page = a[0]
            t = time.time()
            try:
                fn(*a)
                results.append((name, "PASS", f"{time.time() - t:.1f}s"))
                print(f"PASS  {name}", flush=True)
            except Exception as e:  # noqa: BLE001
                fname = re.sub(r"[^a-z0-9]+", "-", name.lower())
                try:
                    page.screenshot(path=os.path.join(OUT, f"FAIL-{fname}.png"), full_page=True)
                except Exception:  # noqa: BLE001
                    pass
                results.append((name, "FAIL", str(e).splitlines()[0][:240]))
                print(f"FAIL  {name}: {e}", flush=True)
                traceback.print_exc(limit=3)

        return run

    return deco


def check(name, cond, detail: object = ""):
    """Records a single assertion that is not tied to a page step."""
    results.append((name, "PASS" if cond else "FAIL", "" if cond else str(detail)[:400]))
    print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else f" -> {str(detail)[:400]}"), flush=True)


def launch(pw):
    """Headless Chromium: Playwright's own build, or the executable in AEGIS_E2E_CHROME (e.g. a local Chrome)."""
    return pw.chromium.launch(executable_path=os.environ.get("AEGIS_E2E_CHROME") or None, headless=True)


def new_page(browser, user=None, viewport=(1440, 900)):
    """A page in a fresh browser context, signed in as a demo account when user is given; collects page errors."""
    ctx = browser.new_context(viewport={"width": viewport[0], "height": viewport[1]}, accept_downloads=True)
    page = ctx.new_page()
    page.on("dialog", lambda d: d.accept())  # navigation blockers (window.confirm)
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.errors = errors
    if user:
        r = page.request.post(f"{BASE}/api/auth/login", data={"username": user, "password": PW[user]}, headers=XRW)
        assert r.ok, r.text()
    return page


def goto(page, path):
    page.goto(f"{BASE}{path}")
    page.wait_for_load_state("networkidle")


def dialog(page):
    return page.locator('[role="dialog"]').last


def toast(page, text):
    expect(page.locator('[role="status"], [role="alert"]').filter(has_text=text).first).to_be_visible(timeout=10000)


def api_json(page, path):
    r = page.request.get(f"{BASE}{path}", headers=XRW)
    assert r.ok, f"{path}: {r.status} {r.text()[:200]}"
    return r.json()


def finish(errors=()):
    """Prints the summary and exits non-zero on a failed step or an uncaught page error."""
    if errors:
        print("Page errors:", *list(errors)[:10], sep="\n  ")
        results.append(("No uncaught page errors", "FAIL", str(list(errors)[0])[:200]))
    else:
        results.append(("No uncaught page errors", "PASS", ""))
    passed = sum(1 for r in results if r[1] == "PASS")
    print(f"\n{passed}/{len(results)} passed")
    for n, st, info in results:
        print(f"  {st}  {n}  {info}")
    sys.exit(0 if passed == len(results) else 1)
