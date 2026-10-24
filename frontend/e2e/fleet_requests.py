"""Console regression suite: fleet, server groups, access requests and learning sessions, plus the Team Lead and
Auditor views of them. Runs against a fresh demo control plane (AEGIS_DEMO_MODE=true) that serves the console
build; started by run.sh, which sets AEGIS_E2E_BASE and AEGIS_E2E_DATAPLANE_KEY."""
import json
import os
import re
import time

from playwright.sync_api import expect, sync_playwright

from common import BASE, OUT, dialog, finish, goto, launch, new_page, step, toast

DP_KEY = os.environ["AEGIS_E2E_DATAPLANE_KEY"]


# ---------------------------------------------------------------------------
# Setup through the API
# ---------------------------------------------------------------------------


def setup(api):
    # three pending requests from 127.0.0.1 (= srv-ci-runner-01, group grp-ci-runners)
    for i, (path, dur) in enumerate([("/smoke-bulk/a.tgz", "24h"), ("/smoke-bulk/b.tgz", "24h"), ("/smoke-tl/c.tgz", "permanent")]):
        r = api.post(
            f"{BASE}/api/public/requests",
            data={"requester": f"smoke{i}@corp.example", "reason": "Smoke test request", "requested_scope": "prefix_with_objects", "duration": dur, "requested_url": f"https://downloads.example.org{path}", "method": "GET"},
        )
        assert r.status in (200, 201), r.text()
    # one flow from an unregistered source -> Discovered tab
    r = api.post(
        f"{BASE}/api/dataplane/flows/batch",
        headers={"X-Aegis-DataPlane-Key": DP_KEY},
        data={"flows": [{"server_ip": "10.99.1.5", "method": "GET", "scheme": "https", "host": "pypi.org", "path": "/simple/requests/", "full_url": "https://pypi.org/simple/requests/", "user_agent": "pip/24.2", "verdict": "BLOCKED", "status_code": 403, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}]},
    )
    assert r.status == 201, r.text()


# ---------------------------------------------------------------------------
# Admin flows
# ---------------------------------------------------------------------------


@step("Servers: register with labels, dynamic preview, onboarding token + snippets")
def register_server(page):
    goto(page, "/servers")
    page.get_by_role("button", name="Register server").first.click()
    d = dialog(page)
    d.get_by_label("Host name").fill("smoke-app-01.internal.corp")
    d.get_by_label("Server id").fill("srv-smoke-01")
    d.get_by_label("IP address").fill("10.30.99.10")
    d.get_by_role("button", name="Add label").click()
    d.get_by_label("Label key 1").fill("compliance")
    d.get_by_label("Label value 1").fill("pci")
    expect(d.get_by_text("PCI DSS scope")).to_be_visible()
    d.get_by_role("button", name="Register server").click()
    expect(d.get_by_text("is in the inventory")).to_be_visible()
    d.get_by_role("button", name="Issue token and onboard").click()
    d = dialog(page)
    expect(d).to_contain_text("Onboard smoke-app-01.internal.corp")
    d.get_by_role("button", name="Issue token").click()
    tok = d.get_by_test_id("proxy-token")
    expect(tok).to_contain_text("aegis_")
    expect(d.locator("pre")).to_contain_text("install-linux.sh")
    d.get_by_role("tab", name="Windows").click()
    expect(d.locator("pre")).to_contain_text("PowerShell")
    d.get_by_role("tab", name="Environment").click()
    expect(d.locator("pre")).to_contain_text("HTTPS_PROXY")
    page.screenshot(path=os.path.join(OUT, "onboarding.png"))
    d.get_by_role("button", name="Done").click()
    expect(page.get_by_role("link", name="smoke-app-01.internal.corp").first).to_be_visible()


@step("Servers: URL-synced label filter + dynamic group chip")
def filter_servers(page):
    goto(page, "/servers?label=compliance%3Dpci")
    rows = page.locator("tbody tr")
    expect(rows).to_have_count(3)
    expect(page.locator("tbody")).to_contain_text("smoke-app-01.internal.corp")
    goto(page, "/servers?quarantined=1")
    expect(page).to_have_url(re.compile(r"status=quarantined"))


@step("Server detail: effective policy, quarantine and release")
def server_detail(page):
    goto(page, "/servers/srv-smoke-01/policy")
    expect(page.get_by_text("Applied policy sets")).to_be_visible()
    expect(page.get_by_role("link", name="Global guardrails")).to_be_visible()
    goto(page, "/servers/srv-smoke-01")
    expect(page.get_by_text(re.compile(r"^matched")).first).to_be_visible()
    page.get_by_role("button", name="Quarantine").click()
    d = dialog(page)
    d.get_by_label("Reason").fill("SMOKE-1 beaconing test")
    d.get_by_role("button", name="Quarantine").click()
    expect(page.get_by_text("Quarantined — all egress is blocked")).to_be_visible()
    expect(page.get_by_text("SMOKE-1 beaconing test")).to_be_visible()
    page.get_by_role("button", name="Release").first.click()
    d = dialog(page)
    d.get_by_role("button", name="Release").click()
    expect(page.get_by_text("Quarantined — all egress is blocked")).to_have_count(0)
    page.get_by_role("tab", name="Audit").click()
    expect(page.get_by_text("Server quarantined")).to_be_visible()


@step("Servers: CSV import dry run (row error) then apply")
def import_servers(page):
    goto(page, "/servers")
    page.get_by_role("button", name="Import").click()
    d = dialog(page)
    bad = "id,hostname,ip,group_ids,labels\nsrv-imp-01,imp-01.corp,10.30.98.1,grp-linux-core,env=prod\nsrv-imp-02,imp-02.corp,999.1.1.1,grp-linux-core,env=prod\n"
    d.locator("textarea").fill(bad)
    d.get_by_role("button", name="Run dry run").click()
    expect(d.get_by_text("invalid IP address")).to_be_visible()
    expect(d.get_by_role("button", name=re.compile("Apply import"))).to_be_disabled()
    d.locator("textarea").fill(bad.replace("999.1.1.1", "10.30.98.2"))
    d.get_by_role("button", name="Run dry run").click()
    expect(d.get_by_text("Ready to import")).to_be_visible()
    d.get_by_role("button", name="Apply import (2)").click()
    toast(page, "Imported 2 servers")
    expect(page.get_by_role("link", name="imp-02.corp")).to_be_visible()


@step("Servers: export CSV/JSON (authenticated download) + selection export")
def export_servers(page):
    goto(page, "/servers")
    with page.expect_download() as dl:
        page.get_by_role("button", name="Export").click()
        page.get_by_role("menuitem", name=re.compile("Export CSV")).click()
    assert dl.value.suggested_filename.endswith(".csv"), dl.value.suggested_filename
    text = open(dl.value.path()).read()
    assert text.startswith("id,hostname,ip,"), text[:80]
    with page.expect_download() as dl2:
        page.get_by_role("button", name="Export").click()
        page.get_by_role("menuitem", name=re.compile("Export JSON")).click()
    data = json.load(open(dl2.value.path()))
    assert any(s["id"] == "srv-smoke-01" for s in data)
    page.locator("tbody tr").first.get_by_role("checkbox").check()
    page.locator("tbody tr").nth(1).get_by_role("checkbox").check()
    expect(page.get_by_text("2 selected")).to_be_visible()
    with page.expect_download() as dl3:
        page.get_by_role("button", name="Export CSV").click()
    lines = open(dl3.value.path()).read().strip().splitlines()
    assert len(lines) == 3, lines


@step("Servers: bulk set label")
def bulk_label(page):
    goto(page, "/servers?q=imp-0")
    page.get_by_role("checkbox", name="Select all rows").check()
    page.get_by_role("button", name="Set label").click()
    d = dialog(page)
    d.get_by_label("Key").fill("batch")
    d.get_by_label("Value").fill("smoke")
    d.get_by_role("button", name="Set label").click()
    toast(page, "Labeled 2 servers")
    goto(page, "/servers?label=batch%3Dsmoke")
    expect(page.locator("tbody tr")).to_have_count(2)


@step("Servers: discovered source -> register prefilled")
def discovered(page):
    goto(page, "/servers?view=discovered")
    expect(page.get_by_text("10.99.1.5").first).to_be_visible()
    page.get_by_role("button", name="Register", exact=True).first.click()
    d = dialog(page)
    expect(d.get_by_label("IP address")).to_have_value("10.99.1.5")
    expect(d.get_by_label("Server id")).to_have_value("srv-10-99-1-5")
    d.get_by_role("button", name="Cancel").click()


@step("Groups: create with label selector + live preview, members, delete")
def groups(page):
    goto(page, "/groups")
    page.get_by_role("button", name="New group").click()
    d = dialog(page)
    d.get_by_label(re.compile(r"^Name")).fill("Smoke staging")
    expect(d.get_by_label("Group id")).to_have_value("grp-smoke-staging")
    d.get_by_label("CIDR ranges").fill("10.77.0.0/16")
    d.get_by_label("CIDR ranges").press("Enter")
    d.get_by_role("button", name="Add condition").click()
    d.get_by_label("Selector key 1").fill("env")
    d.get_by_label("Selector value 1").fill("staging")
    expect(d.get_by_text(re.compile(r"1 of \d+ registered servers match"))).to_be_visible()
    expect(d.get_by_text("gpu-h100-node04.internal.corp")).to_be_visible()
    d.get_by_role("radio", name="#7C3AED").click()
    d.get_by_role("button", name="Create group").click()
    expect(page).to_have_url(re.compile(r"/groups/grp-smoke-staging$"))
    expect(page.locator("tbody")).to_contain_text("gpu-h100-node04.internal.corp")
    expect(page.locator("tbody")).to_contain_text("Label selector")
    page.get_by_role("tab", name="Policy sets").click()
    expect(page.get_by_text("No policy set is assigned to this group")).to_be_visible()
    page.get_by_role("button", name="More actions").click()
    page.get_by_role("menuitem", name="Delete group").click()
    d = dialog(page)
    d.locator("input").last.fill("grp-smoke-staging")
    d.get_by_role("button", name="Delete group").click()
    expect(page).to_have_url(re.compile(r"/groups$"))
    toast(page, "Deleted Smoke staging")


@step("Groups: delete refused while referenced (server error shown)")
def group_delete_refused(page):
    goto(page, "/groups/grp-ci-runners")
    page.get_by_role("button", name="More actions").click()
    page.get_by_role("menuitem", name="Delete group").click()
    d = dialog(page)
    d.locator("input").last.fill("grp-ci-runners")
    d.get_by_role("button", name="Delete group").click()
    toast(page, "still assigned")
    d.get_by_role("button", name="Cancel").click()


@step("Request: approve with 7 days, created rule + approvals set link")
def approve_request(page):
    goto(page, "/requests/req-1001")
    page.get_by_role("radio", name=re.compile("^7 d")).click()
    expect(page.get_by_text("What will be allowed")).to_be_visible()
    expect(page.get_by_text(re.compile("for 7 days"))).to_be_visible()
    page.get_by_role("button", name=re.compile("^Approve")).click()
    toast(page, "Approved")
    expect(page.get_by_text("Rules created")).to_be_visible()
    expect(page.get_by_role("link", name=re.compile("Approved requests"))).to_be_visible()


@step("Request: extend and revoke")
def extend_revoke(page):
    goto(page, "/requests/req-1001")
    page.get_by_role("button", name="Extend").first.click()
    d = dialog(page)
    d.get_by_role("radio", name=re.compile("^30 d")).click()
    d.get_by_role("button", name="Extend").click()
    toast(page, "Access extended")
    expect(page.get_by_text("extended access")).to_be_visible()
    page.get_by_role("button", name="Revoke").first.click()
    d = dialog(page)
    d.get_by_label("Reason").fill("Smoke test revocation")
    d.get_by_role("button", name="Revoke access").click()
    toast(page, "Access revoked")
    expect(page.get_by_text("revoked access")).to_be_visible()


@step("Request: comment and assign to me")
def comment_assign(page):
    goto(page, "/requests/req-1002")
    page.get_by_label("Add a comment").fill("Smoke comment from admin")
    page.get_by_role("button", name="Comment", exact=True).click()
    toast(page, "Comment added")
    expect(page.get_by_text("Smoke comment from admin")).to_be_visible()
    page.get_by_role("button", name="Assign to me").click()
    toast(page, "Assigned to you")
    goto(page, "/requests?status=mine")
    expect(page.locator("tbody")).to_contain_text("pkgs.k8s.io")


@step("Requests inbox: bulk reject with per-id results")
def bulk_reject(page):
    goto(page, "/requests?q=smoke-bulk")
    expect(page.locator("tbody tr")).to_have_count(2)
    page.get_by_role("checkbox", name="Select all rows").check()
    page.get_by_role("button", name="Reject").click()
    d = dialog(page)
    d.get_by_label("Comment").fill("Not needed, use the internal mirror")
    d.get_by_role("button", name="Reject 2").click()
    expect(d.get_by_role("list", name="Review results").locator("li")).to_have_count(2)
    d.get_by_role("button", name="Done").click()
    goto(page, "/requests?status=closed&q=smoke-bulk")
    expect(page.locator("tbody tr")).to_have_count(2)


@step("Learning: start session, simulate traffic, publish into new set")
def learning(page):
    goto(page, "/learning")
    page.get_by_role("button", name="Start session").first.click()
    d = dialog(page)
    d.get_by_label("Name").fill("Smoke session")
    d.get_by_label("Reference server").click()
    page.get_by_role("option", name=re.compile("ci-runner-fra01")).click()
    d.get_by_role("button", name="Start recording").click()
    toast(page, "Recording ci-runner-fra01")
    expect(page.get_by_role("heading", name="Smoke session")).to_be_visible()
    page.get_by_role("button", name="Simulate traffic").click()
    page.get_by_role("menuitem", name=re.compile("GitHub release download")).click()
    toast(page, "Recorded")
    expect(page.get_by_role("checkbox", name=re.compile("Select github.com"))).to_be_visible(timeout=15000)
    page.get_by_role("button", name="Stop").click()
    dialog(page).get_by_role("button", name="Stop session").click()
    toast(page, "Session stopped")
    expect(page.get_by_text("Ready for review").first).to_be_visible()
    page.get_by_role("button", name=re.compile(r"^Publish \d+ rule")).click()
    d = dialog(page)
    d.get_by_role("radio", name=re.compile("New policy set")).click()
    d.get_by_label("Set name").fill("Smoke learned set")
    d.get_by_role("button", name="Publish now").click()
    toast(page, "Smoke learned set")
    expect(page.get_by_text("Rules from this session are in policy sets")).to_be_visible()
    expect(page.get_by_text("Published").first).to_be_visible()
    page.get_by_role("link", name="Smoke learned set").click()
    expect(page).to_have_url(re.compile(r"/policies/"))
    expect(page.get_by_text("Smoke session").first).to_be_visible()


@step("Command palette: jump to a server")
def palette(page):
    goto(page, "/")
    page.keyboard.press("Control+k")
    page.get_by_label("Search commands").fill("smoke-app")
    page.keyboard.press("Enter")
    expect(page).to_have_url(re.compile(r"/servers/srv-smoke-01$"))


@step("Server: decommission with typed confirmation")
def decommission(page):
    goto(page, "/servers/srv-smoke-01")
    page.get_by_role("button", name="More actions").click()
    page.get_by_role("menuitem", name="Decommission").click()
    d = dialog(page)
    d.locator("input").last.fill("srv-smoke-01")
    d.get_by_role("button", name="Decommission").click()
    expect(page).to_have_url(re.compile(r"/servers$"))
    toast(page, "Decommissioned")


# ---------------------------------------------------------------------------
# Role checks
# ---------------------------------------------------------------------------


@step("Team Lead: no fleet admin, scoped review, duration cap")
def teamlead(page):
    goto(page, "/servers")
    expect(page.get_by_role("button", name="Register server")).to_have_count(0)
    expect(page.get_by_role("button", name="Import")).to_have_count(0)
    # need-to-know: requests of other groups are not delivered to Team Leads at all
    goto(page, "/requests/req-1002")
    expect(page.get_by_text("belongs to server groups outside your scope")).to_be_visible()
    goto(page, "/requests?q=smoke-tl")
    page.get_by_role("link", name=re.compile("downloads.example.org")).first.click()
    expect(page.get_by_role("radio", name=re.compile("^Permanent"))).to_be_disabled()
    expect(page.get_by_role("radio", name=re.compile("^90 d"))).to_be_disabled()
    expect(page.get_by_role("radio", name=re.compile("^30 d"))).to_be_enabled()
    expect(page.get_by_text("Team Leads grant temporary access only")).to_be_visible()
    page.get_by_role("button", name=re.compile("^Approve")).click()
    toast(page, "Approved")
    goto(page, "/groups")
    expect(page.get_by_role("button", name="New group")).to_have_count(0)


@step("Auditor: read-only everywhere")
def auditor(page):
    goto(page, "/servers")
    expect(page.get_by_role("button", name="Register server")).to_have_count(0)
    expect(page.get_by_role("checkbox", name="Select all rows")).to_have_count(1)  # export selection only
    goto(page, "/requests/req-1002")
    expect(page.get_by_text("Read-only access").first).to_be_visible()
    expect(page.get_by_label("Add a comment")).to_have_count(0)
    goto(page, "/learning")
    expect(page.get_by_role("button", name="Start session")).to_have_count(0)


def main():
    with sync_playwright() as p:
        browser = launch(p)
        api = p.request.new_context()
        setup(api)
        page = new_page(browser, "admin")
        errors = page.errors
        for fn in (register_server, filter_servers, server_detail, import_servers, export_servers, bulk_label, discovered, groups, group_delete_refused,
                   approve_request, extend_revoke, comment_assign, bulk_reject, learning, palette, decommission):
            fn(page)
        page.context.close()
        for user, fn in (("teamlead", teamlead), ("auditor", auditor)):
            pg = new_page(browser, user)
            fn(pg)
            errors += pg.errors
            pg.context.close()
        browser.close()
    finish(errors)


if __name__ == "__main__":
    main()
