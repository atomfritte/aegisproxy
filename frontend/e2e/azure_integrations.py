"""Console regression suite: Microsoft Sentinel authentication choices in the log export drawer and the Defender
cloud presets / permission texts. Runs against a fresh control plane without demo data (bootstrap admin
password in AEGIS_E2E_ADMIN_PASSWORD) that serves the console build; started by run.sh."""
import json
import os
import urllib.error
import urllib.request

from playwright.sync_api import sync_playwright

from common import BASE as CP, OUT, check, finish, launch

PW = os.environ["AEGIS_E2E_ADMIN_PASSWORD"]
cookie = {}


def call(m, p, b=None):
    data = json.dumps(b).encode() if b is not None else None
    r = urllib.request.Request(CP + p, data=data, method=m, headers={"X-Requested-With": "aegis-ui", "Content-Type": "application/json",
                                                                       "Cookie": "; ".join(f"{k}={v}" for k, v in cookie.items())})
    try:
        with urllib.request.urlopen(r, timeout=30) as x:
            for c in x.headers.get_all("Set-Cookie") or []:
                k, v = c.split(";")[0].split("=", 1)
                cookie[k] = v
            raw = x.read()
            return x.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def main():
    st, _ = call("POST", "/api/auth/login", {"username": "admin", "password": PW})
    check("API: bootstrap admin signs in", st == 200, st)
    st, mi = call("POST", "/api/integrations/exports", {"name": "Sentinel MI", "type": "sentinel", "enabled": False, "streams": ["audit"],
                                                        "endpoint": "https://dce-1.westeurope-1.ingest.monitor.azure.com", "dcr_immutable_id": "dcr-1",
                                                        "azure_auth": "managed_identity"})
    check("API: managed identity destination without tenant, client or secret accepted", st == 200 and mi.get("azure_auth") == "managed_identity", mi)
    st, bad = call("POST", "/api/integrations/exports", {"name": "Sentinel CS", "type": "sentinel", "enabled": False, "streams": ["audit"],
                                                         "endpoint": "https://dce-1.westeurope-1.ingest.monitor.azure.com", "dcr_immutable_id": "dcr-1", "secret": "x"})
    check("API: client secret still requires tenant and client ID", st == 400, (st, bad))

    with sync_playwright() as pw:
        browser = launch(pw)
        ctx = browser.new_context(viewport={"width": 1400, "height": 1000})
        ctx.add_cookies([{"name": k, "value": v, "url": CP} for k, v in cookie.items()])
        page = ctx.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(CP + "/settings/log-export")
        page.get_by_role("button", name="Sentinel MI", exact=True).click()
        drawer = page.get_by_role("dialog")
        drawer.get_by_text("Authentication", exact=True).wait_for()
        sel = drawer.locator("select").filter(has=page.locator("option[value=managed_identity]"))
        check("drawer: authentication shows the stored choice (managed identity)", sel.input_value() == "managed_identity", sel.input_value())
        check("drawer: no secret input for managed identity", drawer.locator("input[type=password]").count() == 0, drawer.locator("input[type=password]").count())
        check("drawer: client ID explained as user-assigned identity", drawer.get_by_text("User-assigned identity; empty uses the system-assigned identity.").count() == 1)
        page.screenshot(path=os.path.join(OUT, "sentinel-managed-identity.png"), full_page=True)
        sel.select_option("client_secret")
        drawer.get_by_role("button", name="Save destination").click()
        page.wait_for_timeout(500)
        check("drawer: switching to client secret requires tenant, client and secret",
              drawer.get_by_text("Required.").count() >= 2 and drawer.get_by_text("is required for this destination", exact=False).count() == 1)
        sel.select_option("workload_identity")
        check("drawer: workload identity explains the pod environment", drawer.get_by_text("Empty: AZURE_TENANT_ID injected into the pod.").count() == 1)
        drawer.get_by_role("button", name="Save destination").click()
        page.wait_for_timeout(800)
        st, lst = call("GET", "/api/integrations/exports")
        sinks = lst.get("sinks", lst) if isinstance(lst, dict) else lst
        saved = next((s for s in sinks if s.get("id") == mi.get("id")), {})
        check("saved from the console: azure_auth = workload_identity, no secret", saved.get("azure_auth") == "workload_identity" and not saved.get("has_secret"), saved)

        page.goto(CP + "/settings/defender")
        page.get_by_text("Required API permissions").wait_for()
        body = page.inner_text("body")
        check("Defender: documented permissions (Ti.ReadWrite.All, Machine.Read.All, Machine.ReadWrite.All only for isolation)",
              "Ti.ReadWrite.All" in body and "Machine.Read.All" in body and "Machine.ReadWrite.All (only for quarantine on isolation" in body and "Ti.Read.All" not in body, body[:300])
        ids = page.get_by_placeholder("00000000-0000-0000-0000-000000000000")
        ids.nth(0).fill("11111111-2222-3333-4444-555555555555")
        ids.nth(1).fill("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        page.get_by_placeholder("Paste the secret").fill("ui-secret-value")
        page.get_by_role("button", name="Save", exact=False).last.click()
        page.wait_for_timeout(800)
        st, d = call("GET", "/api/integrations/defender")
        cfg = (d or {}).get("config", {})
        check("Defender: commercial preset saves api.security.microsoft.com", cfg.get("api_base_url") == "https://api.security.microsoft.com"
              and cfg.get("authority_url") == "https://login.microsoftonline.com", cfg)
        page.screenshot(path=os.path.join(OUT, "defender.png"), full_page=True)
        browser.close()
    finish(errors)


if __name__ == "__main__":
    main()
