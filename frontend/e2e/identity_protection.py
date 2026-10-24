"""Console regression suite: single sign-on (against the mock IdP), break-glass sign-in, service accounts, the
Defender integration, YARA rule sets, ICAP/YARA protection policy, TAXII feeds, posture, policy as code, command
palette, audit export, public portal and the read-only states of these pages. Runs against a fresh demo control
plane that serves the console build; started by run.sh, which sets AEGIS_E2E_BASE and AEGIS_E2E_IDP."""
import json
import os
import re

from playwright.sync_api import expect, sync_playwright

import common
from common import BASE, OUT, api_json, dialog, finish, launch, new_page, step, toast

IDP = os.environ["AEGIS_E2E_IDP"].rstrip("/")


def goto(page, path):
    common.goto(page, path)
    page.wait_for_selector("#root h1, #root h2", timeout=20000)


def switch(page, name):
    return page.get_by_role("switch", name=re.compile("^" + re.escape(name)))


def fill_secret(scope, label, value):
    """SecretField: click Replace when a value is stored, then type the new one."""
    replace = scope.get_by_role("button", name="Replace")
    if replace.count() > 0 and replace.first.is_visible():
        replace.first.click()
    scope.get_by_label(label).fill(value)


def menu_action(page, row_label, item):
    page.get_by_role("button", name=f"Actions for {row_label}").first.click()
    page.get_by_role("menuitem", name=re.compile("^" + re.escape(item))).click()


# ---------------------------------------------------------------------------
# Single sign-on
# ---------------------------------------------------------------------------


@step("SSO: connection test failure is shown with the error")
def sso_test_failure(page):
    goto(page, "/settings/sso")
    page.get_by_role("radio", name=re.compile("^Generic OpenID Connect")).click()
    page.get_by_label("Issuer URL").first.fill(f"{IDP}/realms/missing")
    page.get_by_label("Application (client) ID").fill("aegis-console")
    page.get_by_role("button", name="Test connection").click()
    box = page.locator('[role="alert"]').filter(has_text="The connection test failed")
    expect(box).to_be_visible(timeout=20000)
    expect(page.get_by_test_id("sso-test-error")).not_to_be_empty()


@step("SSO: save with write-only client secret, test against the mock IdP")
def sso_save(page):
    goto(page, "/settings/sso")
    page.get_by_role("radio", name=re.compile("^Generic OpenID Connect")).click()
    page.get_by_label("Issuer URL").first.fill(IDP)
    page.get_by_label("Application (client) ID").fill("aegis-console")
    fill_secret(page, "Client secret", "smoke-client-secret-123")
    page.get_by_label("Button label").fill("Corporate SSO")
    page.get_by_label("Client authentication").select_option("client_secret_basic")
    page.get_by_role("button", name="Test connection").click()
    expect(page.locator("text=The identity provider is reachable")).to_be_visible(timeout=20000)
    switch(page, "Enable single sign-on").click()
    page.get_by_role("button", name="Save changes").click()
    toast(page, "Single sign-on saved")
    cfg = api_json(page, "/api/state?exclude_flows=1")["entra_config"]
    assert cfg["enabled"] and cfg["provider"] == "oidc" and cfg.get("has_client_secret"), cfg
    assert "client_secret" not in cfg or not cfg["client_secret"], "secret returned by the API"
    assert cfg.get("token_auth_method") == "client_secret_basic", cfg
    goto(page, "/settings/sso")
    secret_box = page.locator("text=Stored").first
    expect(secret_box).to_be_visible()
    assert "smoke-client-secret-123" not in page.content(), "secret rendered in the page"
    expect(page.get_by_test_id("sso-redirect-uri")).to_have_text(re.compile(r"/api/auth/sso/callback$"))


@step("Login page: SSO button and sso_error round trip through the IdP")
def login_sso(page):
    goto(page, "/")
    btn = page.get_by_test_id("sso-login")
    expect(btn).to_be_visible()
    expect(btn).to_have_text(re.compile("Sign in with Corporate SSO"))
    assert "/api/auth/sso/login" in (btn.get_attribute("href") or "")
    expect(page.get_by_label("Username")).to_be_visible()  # local login still allowed
    btn.click()
    page.wait_for_url(re.compile(r"/login\?sso_error=idp_access_denied"), timeout=20000)
    expect(page.get_by_test_id("sso-error")).to_contain_text("denied or cancelled")
    goto(page, "/login?sso_error=not_authorized")
    expect(page.locator("text=Your account has no AegisProxy role")).to_be_visible()
    expect(page.locator("text=not_authorized")).to_be_visible()
    goto(page, "/login?sso_error=account_disabled")
    expect(page.get_by_test_id("sso-error")).to_have_text("Your account was disabled by an administrator. Contact your AegisProxy administrator.")


@step("Break-glass: badge, drawer toggle rules, password form collapsed when local login is off")
def break_glass(page, browser):
    goto(page, "/settings/identity")
    admin_row = page.locator("tr", has_text="@admin")
    expect(admin_row.get_by_text("Break-glass")).to_be_visible()
    page.locator("tr", has_text="@infosec").click()
    d = dialog(page)
    expect(d.get_by_role("switch", name=re.compile("Break-glass account"))).to_be_disabled()
    d.get_by_role("button", name="Cancel").click()
    # disable password sign-in (admin is an active break-glass Super Admin)
    goto(page, "/settings/sso")
    switch(page, "Allow password sign-in").click()
    expect(page.locator("text=Password sign-in limited to break-glass accounts")).to_be_visible()
    page.get_by_role("button", name="Save changes").click()
    toast(page, "Single sign-on saved")
    anon = new_page(browser)
    try:
        goto(anon, "/")
        expect(anon.get_by_test_id("sso-login")).to_be_visible()
        expect(anon.get_by_label("Username")).to_have_count(0)
        anon.get_by_role("button", name=re.compile("Use a local account")).click()
        expect(anon.locator("text=Emergency access only")).to_be_visible()
        expect(anon.get_by_role("button", name="Sign in with break-glass account")).to_be_visible()
        anon.screenshot(path=os.path.join(OUT, "login-break-glass.png"))
        # a non-break-glass account is refused with the server's explanation and a pointer to SSO
        anon.get_by_label("Username").fill("infosec")
        anon.get_by_label("Password").fill("infosec123")
        anon.get_by_role("button", name="Sign in with break-glass account").click()
        expect(anon.locator("text=password sign-in is limited to break-glass accounts")).to_be_visible()
        expect(anon.locator("text=Use “Sign in with Corporate SSO” above")).to_be_visible()
    finally:
        anon.context.close()
    # restore password sign-in for the remaining steps
    goto(page, "/settings/sso")
    switch(page, "Allow password sign-in").click()
    page.get_by_role("button", name="Save changes").click()
    toast(page, "Single sign-on saved")
    assert api_json(page, "/api/public/meta")["local_login_enabled"] is True


# ---------------------------------------------------------------------------
# Service accounts
# ---------------------------------------------------------------------------


def bearer_status(page, key):
    r = page.request.get(f"{BASE}/api/auth/me", headers={"Authorization": f"Bearer {key}"})
    return r.status


@step("Service accounts: create shows the key once, rotate, disable, delete")
def service_accounts(page):
    goto(page, "/settings/service-accounts")
    page.get_by_role("button", name="New service account").first.click()
    d = dialog(page)
    d.get_by_label("Name").fill("smoke-ci")
    d.get_by_label("Description").fill("Smoke test automation")
    d.get_by_role("radio", name=re.compile("^Auditor")).click()
    cidr = d.get_by_label("Allowed source networks")
    cidr.fill("127.0.0.1/32")
    cidr.press("Enter")
    d.get_by_role("button", name="Create and show key").click()
    m = dialog(page)
    expect(m.locator("text=You won’t see this API key again")).to_be_visible()
    key = page.get_by_test_id("one-time-secret").inner_text().strip()
    assert key.startswith("aegis_sa_"), key
    close = m.get_by_role("button", name=re.compile("^Close — I have stored the key"))
    expect(close).to_be_disabled()
    m.get_by_label("I have copied the key to a secure place").check()
    close.click()
    expect(page.get_by_test_id("one-time-secret")).to_have_count(0)
    row = page.locator("tr", has_text="smoke-ci")
    expect(row).to_be_visible()
    assert key not in page.content(), "API key still rendered after closing"
    assert bearer_status(page, key) == 200, "new key does not work"
    # rotate
    menu_action(page, "smoke-ci", "Rotate key")
    dialog(page).get_by_role("button", name="Rotate key").click()
    expect(page.get_by_test_id("one-time-secret")).to_be_visible()
    key2 = page.get_by_test_id("one-time-secret").inner_text().strip()
    assert key2.startswith("aegis_sa_") and key2 != key
    dialog(page).get_by_label("I have copied the key to a secure place").check()
    dialog(page).get_by_role("button", name="Close — I have stored the key").click()
    assert bearer_status(page, key) == 401, "old key still valid after rotation"
    assert bearer_status(page, key2) == 200, "rotated key does not work"
    # disable
    menu_action(page, "smoke-ci", "Disable")
    dialog(page).get_by_role("button", name="Disable account").click()
    toast(page, "Disabled smoke-ci")
    expect(page.locator("tr", has_text="smoke-ci").get_by_text("Disabled")).to_be_visible()
    assert bearer_status(page, key2) == 401, "disabled key still valid"
    # delete (typed confirmation)
    menu_action(page, "smoke-ci", "Delete")
    d = dialog(page)
    confirm_btn = d.get_by_role("button", name="Delete service account")
    expect(confirm_btn).to_be_disabled()
    d.locator("input").last.fill("smoke-ci")
    confirm_btn.click()
    toast(page, "Deleted smoke-ci")
    expect(page.locator("tr", has_text="smoke-ci")).to_have_count(0)


# ---------------------------------------------------------------------------
# Defender
# ---------------------------------------------------------------------------


@step("Defender: Super Admin saves (secret write-only), InfoSec sees it read-only")
def defender(page, browser):
    goto(page, "/settings/defender")
    switch(page, "Enable the integration").click()
    page.get_by_label("Directory (tenant) ID").fill("72f988bf-86f1-41af-91ab-2d7cd011db47")
    page.get_by_label("Application (client) ID").fill("11111111-2222-3333-4444-555555555555")
    fill_secret(page, "Client secret", "defender-secret-xyz")
    switch(page, "Import Defender indicators").click()
    switch(page, "Synchronize devices").click()
    page.get_by_role("radio", name="High", exact=True).click()
    switch(page, "Quarantine servers isolated in Defender").click()
    page.get_by_role("button", name="Save changes").click()
    toast(page, "Defender integration saved")
    cfg = api_json(page, "/api/integrations/defender")["config"]
    assert cfg["enabled"] and cfg["import_indicators"] and cfg["device_sync"] and cfg["quarantine_on_risk"] == "high", cfg
    assert cfg.get("has_client_secret") and not cfg.get("client_secret"), cfg
    goto(page, "/settings/defender")
    expect(page.locator("text=Stored").first).to_be_visible()
    assert "defender-secret-xyz" not in page.content()
    feeds = api_json(page, "/api/state?exclude_flows=1")["security"]["feeds"]
    assert any(f["format"] == "mde" and f["enabled"] for f in feeds), "Defender feed not created"
    infosec = new_page(browser, "infosec")
    try:
        goto(infosec, "/settings/defender")
        expect(infosec.locator("text=Only Super Admins can change this integration")).to_be_visible()
        expect(infosec.get_by_label("Directory (tenant) ID")).to_be_disabled()
        expect(infosec.get_by_role("button", name="Save changes")).to_have_count(0)
    finally:
        infosec.context.close()
    # the managed feed renders as Defender-managed in Threat protection → Feeds
    goto(page, "/threats/feeds")
    row = page.locator("tr", has_text="Microsoft Defender for Endpoint indicators")
    expect(row.get_by_text("Defender", exact=True)).to_be_visible()
    expect(row.get_by_role("switch")).to_be_disabled()
    # turn the integration off again (no outbound calls to Microsoft from the test)
    goto(page, "/settings/defender")
    switch(page, "Enable the integration").click()
    page.get_by_role("button", name="Save changes").click()
    toast(page, "Defender integration saved")


# ---------------------------------------------------------------------------
# YARA, protection policy, feeds
# ---------------------------------------------------------------------------


@step("YARA: create a valid rule set, invalid rules show the server error inline")
def yara(page):
    goto(page, "/threats/yara")
    page.get_by_role("link", name="New rule set").first.click()
    page.wait_for_url(re.compile(r"/threats/yara/new$"))
    page.get_by_label("Name").fill("Smoke detections")
    page.get_by_role("button", name="Insert example").click()
    page.get_by_role("button", name="Create rule set").click()
    toast(page, "Created rule set")
    page.wait_for_url(re.compile(r"/threats/yara/yara-"))
    sets = api_json(page, "/api/security/yara")["rule_sets"]
    assert any(s["name"] == "Smoke detections" and s["enabled"] for s in sets), sets
    # invalid rules: server lint error inline
    goto(page, "/threats/yara/new")
    page.get_by_label("Name").fill("Broken detections")
    page.get_by_label("YARA rules source").fill('rule Broken\n{\n  condition:\n    true\n}\n}\n')
    page.get_by_role("button", name="Create rule set").click()
    err = page.get_by_test_id("yara-lint-error")
    expect(err).to_be_visible()
    expect(err).to_contain_text("invalid YARA rules")
    # duplicate names are rejected by the server as well
    page.get_by_label("Name").fill("Smoke detections")
    page.get_by_label("YARA rules source").fill('rule Dup { condition: true }\n')
    page.get_by_role("button", name="Create rule set").click()
    expect(page.get_by_test_id("yara-server-error")).to_contain_text("already exists")
    goto(page, "/threats/yara")
    expect(page.locator("tr", has_text="Smoke detections")).to_be_visible()


@step("Protection policy: ICAP and YARA fields save")
def icap_yara_policy(page):
    goto(page, "/threats/policy")
    page.get_by_label("RESPMOD service (downloads)").fill("icap://av.corp.example:1344/respmod")
    page.get_by_label("REQMOD service (uploads)").fill("icaps://dlp.corp.example:11344/reqmod")
    t = page.get_by_label("Timeout")
    t.fill("45")
    page.get_by_role("radiogroup", name="YARA mode").get_by_role("radio", name=re.compile("^Monitor")).click()
    page.get_by_label("Largest file to scan").last.fill("50")
    page.get_by_role("button", name="Save policy").click()
    toast(page, "Protection policy saved")
    p = api_json(page, "/api/state?exclude_flows=1")["security"]["policy"]
    assert p["icap_respmod_url"] == "icap://av.corp.example:1344/respmod", p
    assert p["icap_reqmod_url"] == "icaps://dlp.corp.example:11344/reqmod", p
    assert p["icap_timeout_seconds"] == 45 and p["yara_mode"] == "monitor" and p["yara_max_bytes"] == 50 * 1024 * 1024, p
    # an invalid URL is caught before saving
    page.get_by_label("RESPMOD service (downloads)").fill("http://not-icap")
    expect(page.locator("text=Use icap://host:1344/service").first).to_be_visible()
    page.get_by_role("button", name="Reset").click()


@step("Threat feeds: add a TAXII 2.1 collection")
def taxii_feed(page):
    goto(page, "/threats/feeds")
    page.get_by_role("button", name="Add feed").click()
    d = dialog(page)
    d.get_by_label("Type").select_option("taxii21")
    d.get_by_label(re.compile(r"^Name")).fill("Smoke TAXII")
    d.get_by_label("Collection URL").fill("https://taxii.example.org/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/")
    d.get_by_label("Indicator age").fill("30")
    expect(d.get_by_label("Header name")).to_have_attribute("placeholder", "Authorization")
    d.get_by_role("button", name="Add feed").click()
    toast(page, "Added feed")
    feeds = api_json(page, "/api/state?exclude_flows=1")["security"]["feeds"]
    f = next(x for x in feeds if x["name"] == "Smoke TAXII")
    assert f["format"] == "taxii21" and f.get("lookback_days") == 30, f
    expect(page.locator("tr", has_text="Smoke TAXII").get_by_text("TAXII", exact=True)).to_be_visible()


# ---------------------------------------------------------------------------
# Posture, policy as code, palette, audit
# ---------------------------------------------------------------------------


@step("Posture page and overview card")
def posture(page):
    goto(page, "/posture")
    expect(page.get_by_role("img", name=re.compile(r"Security posture score \d+ of 100"))).to_be_visible()
    expect(page.locator("text=Identity and access").first).to_be_visible()
    page.get_by_role("radio", name=re.compile("^Failing")).click()
    expect(page).to_have_url(re.compile(r"status=fail"))
    expect(page.get_by_test_id("posture-check-demo")).to_be_visible()
    goto(page, "/")
    card = page.get_by_test_id("overview-posture")
    expect(card).to_be_visible()
    card.get_by_role("link", name="View posture").click()
    page.wait_for_url(re.compile(r"/posture$"))


@step("Policy as code: export download, import dry-run preview, apply as drafts")
def policy_io(page):
    goto(page, "/policies")
    with page.expect_download() as dl:
        page.get_by_test_id("export-policy-sets").click()
    path = dl.value.path()
    bundle = json.load(open(path))
    assert bundle["format"] == "aegisproxy.policy-sets/v1" and bundle["policy_sets"], bundle.keys()
    std = next(s for s in bundle["policy_sets"] if s["kind"] == "standard" and not (s.get("draft")))
    std["description"] = (std.get("description") or "") + " (changed by import)"
    new = dict(std)
    new["id"] = ""
    new["name"] = "Imported smoke set"
    new["rules"] = [dict(r, id="") for r in (std.get("rules") or [])][:1]
    bundle["policy_sets"] = [std, new]
    src = os.path.join(OUT, "import-bundle.json")
    json.dump(bundle, open(src, "w"))
    page.get_by_role("button", name="Import", exact=True).click()
    d = dialog(page)
    d.get_by_test_id("import-file").set_input_files(src)
    preview = d.get_by_test_id("import-preview")
    expect(preview).to_be_visible(timeout=15000)
    expect(preview.get_by_text("Update draft", exact=True)).to_be_visible()
    expect(preview.get_by_text("New set", exact=True)).to_be_visible()
    d.get_by_role("button", name="Import 2 sets as drafts").click()
    toast(page, "Imported 2 policy sets as drafts")
    sets = api_json(page, "/api/policy-sets")
    assert any(s["name"] == "Imported smoke set" for s in sets), "imported set missing"
    changed = next(s for s in sets if s["id"] == std["id"])
    assert changed.get("draft"), "update did not create a draft"
    dialog(page).get_by_role("button", name="Done").click()


@step("Command palette finds a settings section and a block page")
def palette(page):
    goto(page, "/")
    page.keyboard.press("Control+k")
    page.get_by_label("Search commands").fill("service accounts")
    opt = page.get_by_role("option", name=re.compile("Service accounts"))
    expect(opt.first).to_be_visible()
    page.keyboard.press("Enter")
    page.wait_for_url(re.compile(r"/settings/service-accounts"))
    bp = api_json(page, "/api/state?exclude_flows=1")["block_pages"][0]
    page.keyboard.press("Control+k")
    page.get_by_label("Search commands").fill(bp["name"])
    expect(page.get_by_role("option", name=re.compile(re.escape(bp["name"]))).first).to_be_visible()
    page.keyboard.press("Enter")
    page.wait_for_url(re.compile(r"/block-pages/" + re.escape(bp["id"])))
    page.keyboard.press("Control+k")
    page.get_by_label("Search commands").fill("defender")
    expect(page.get_by_role("option", name=re.compile("Microsoft Defender")).first).to_be_visible()
    page.keyboard.press("Escape")


@step("Audit trail: full export as JSON Lines")
def audit_export(page):
    goto(page, "/audit")
    btn = page.get_by_test_id("audit-export")
    expect(btn).to_have_text(re.compile("Export full audit trail \\(JSONL\\)"))
    with page.expect_download() as dl:
        btn.click()
    lines = [ln for ln in open(dl.value.path()).read().splitlines() if ln.strip()]
    assert len(lines) > 5, len(lines)
    ev = json.loads(lines[-1])
    assert "event_hash" in ev and "action" in ev, ev.keys()


@step("Public portal reads the request options")
def portal_options(page):
    seen = []
    page.on("request", lambda r: seen.append(r.url) if "/api/public/request-options" in r.url else None)
    goto(page, "/?portal=block")
    expect(page.get_by_role("button", name=re.compile("Submit access request"))).to_be_visible()
    assert seen, "request-options not requested"


@step("Auditor: new pages are read-only or restricted")
def auditor(page):
    goto(page, "/settings/sso")
    expect(page.locator("text=Only Super Admins can change single sign-on")).to_be_visible()
    expect(page.get_by_label("Application (client) ID")).to_be_disabled()
    goto(page, "/settings/service-accounts")
    expect(page.locator("text=Restricted")).to_be_visible()
    goto(page, "/settings/defender")
    expect(page.locator("text=Restricted")).to_be_visible()
    goto(page, "/threats/yara")
    expect(page.get_by_role("link", name="New rule set")).to_have_count(0)
    expect(page.locator("text=Only InfoSec Approvers and Super Admins can change YARA rules")).to_be_visible()
    page.get_by_role("link", name="Smoke detections").click()
    expect(page.get_by_label("YARA rules source")).to_have_attribute("readonly", "")
    expect(page.get_by_role("button", name="Save changes")).to_have_count(0)
    goto(page, "/threats/policy")
    expect(page.get_by_label("RESPMOD service (downloads)")).to_be_disabled()
    goto(page, "/posture")
    expect(page.locator("text=Restricted")).to_be_visible()
    goto(page, "/policies")
    expect(page.get_by_test_id("export-policy-sets")).to_be_visible()
    expect(page.get_by_role("button", name="Import", exact=True)).to_have_count(0)
    goto(page, "/")
    expect(page.get_by_test_id("overview-posture")).to_have_count(0)
    expect(page.get_by_role("link", name="Security posture")).to_have_count(0)
    goto(page, "/threats/feeds")
    expect(page.get_by_role("button", name="Add feed")).to_have_count(0)


def main():
    with sync_playwright() as p:
        browser = launch(p)
        admin = new_page(browser, "admin")
        sso_test_failure(admin)
        sso_save(admin)
        anon = new_page(browser)
        login_sso(anon)
        anon.context.close()
        break_glass(admin, browser)
        service_accounts(admin)
        defender(admin, browser)
        yara(admin)
        icap_yara_policy(admin)
        taxii_feed(admin)
        posture(admin)
        policy_io(admin)
        palette(admin)
        audit_export(admin)
        anon = new_page(browser)
        portal_options(anon)
        anon.context.close()
        aud = new_page(browser, "auditor")
        auditor(aud)
        errors = admin.errors + aud.errors
        browser.close()
    finish(errors)


if __name__ == "__main__":
    main()
