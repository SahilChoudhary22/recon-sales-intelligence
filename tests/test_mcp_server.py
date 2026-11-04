"""The MCP server over the real protocol: start it on stdio, speak JSON-RPC, call tools.

Needs the serving store (data/serve/current); skipped where the export hasn't been run."""
import json
import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(not os.path.exists("data/serve/current/meta.json"), reason="export not run")


class Client:
    def __init__(self, env):
        self.p = subprocess.Popen([sys.executable, "-m", "mcp_server.server"], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=env)
        self.n = 0

    def send(self, method, params=None, notify=False):
        msg = {"jsonrpc": "2.0", "method": method, **({"params": params} if params is not None else {})}
        if not notify:
            self.n += 1
            msg["id"] = self.n
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()
        if notify:
            return None
        while True:
            reply = json.loads(self.p.stdout.readline())
            if reply.get("id") == self.n:
                return reply

    def call(self, tool, **args):
        r = self.send("tools/call", {"name": tool, "arguments": args})["result"]
        assert not r.get("isError"), r
        return r.get("structuredContent") or json.loads(r["content"][0]["text"])

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    from api.workspace import hash_password
    db = tmp_path_factory.mktemp("app") / "recon.db"
    env = {**os.environ, "RECON_DB": str(db), "RECON_USERS": f"seller:{hash_password('x')}", "RECON_USER": "seller"}
    c = Client(env)
    c.db = db
    init = c.send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "recon-test", "version": "0"}})
    assert init["result"]["serverInfo"]["name"] == "Recon"
    c.send("notifications/initialized", notify=True)
    yield c
    c.close()


def test_lists_the_tools(client):
    names = {t["name"] for t in client.send("tools/list")["result"]["tools"]}
    assert names == {"dataset_overview", "list_signal_templates", "search_accounts", "get_account", "cve_exposure",
                     "make_list", "my_lists", "save_search", "whats_new", "update_accounts", "export_crm_tasks"}


def test_search_matches_the_app_filters(client):
    r = client.call("search_accounts", template="exchange", sector="commercial", limit=5)
    assert r["total"] == 719 and r["view_in_app"].endswith("play=exchange&sector=commercial")
    assert all(a["sector"] == "Commercial" for a in r["accounts"])


def test_cve_in_the_news_falls_back_to_product(client):
    r = client.call("cve_exposure", cve_or_name="Citrix Bleed", limit=3)
    assert r["total_in_app"] == 0 and "Citrix NetScaler" in r["fallback"]["reason"]


def test_lists_are_the_sellers_own(client):
    r = client.call("make_list", account_ids=["chevron.com", "nope.invalid"])
    assert r["list"] == "My list" and r["added"] == 1 and r["skipped_unknown"] == 1 and "play=list:" in r["open_in_app"]
    r = client.call("make_list", list_name="UK edge", template="edge", country="GB", limit=10)
    assert r["added"] == 10
    lists = {li["name"]: li["accounts"] for li in client.call("my_lists")["lists"]}
    assert lists == {"My list": 1, "UK edge": 10}


def test_saved_search_reports_whats_new(client):
    client.call("save_search", name="GB firewalls", template="edge", country="GB")
    r = client.call("whats_new", saved_search="GB firewalls")
    assert r["new"] == 0  # nothing is first ranked after the build it was saved on


def test_dataset_overview_states_the_funnel(client):
    r = client.call("dataset_overview")
    assert r["funnel"]["raw_records"] > r["funnel"]["clean"] > r["funnel"]["companies_with_material_signal"]


def test_several_values_in_one_filter_mean_any_of_them(client):
    gb = client.call("search_accounts", template="kev", country="GB", limit=1)["total"]
    ie = client.call("search_accounts", template="kev", country="IE", limit=1)["total"]
    both = client.call("search_accounts", template="kev", country=["GB", "IE"], limit=1)
    assert both["total"] == gb + ie and "country=GB,IE" in both["view_in_app"]
    assert client.call("search_accounts", template="kev", country="gb, ie", limit=1)["total"] == gb + ie


def test_estate_size(client):
    r = client.call("search_accounts", template="kev", size="small", limit=50)
    assert r["total"] > 0 and all(1 <= a["ips"] <= 5 for a in r["accounts"])


def test_not_in_my_lists(client):
    everything = client.call("search_accounts", template="edge", country="GB", limit=1)["total"]
    fresh = client.call("search_accounts", template="edge", country="GB", not_in_my_lists=True, limit=100)
    assert fresh["total"] == everything - 10  # the 10 saved to "UK edge" above
    assert not any("your_lists" in a for a in fresh["accounts"])


def test_account_has_the_opening_line_and_the_sellers_status(client):
    r = client.call("get_account", account_id="chevron.com")
    assert r["opening_line"].startswith("Hi, while mapping chevron.com's external attack surface")
    assert r["your_lists"] == ["My list"] and r["status"] == "to_contact"


def test_update_accounts(client):
    r = client.call("update_accounts", account_ids=["chevron.com"], status="contacted")
    assert r["status"] == "contacted" and "added_to_my_list" not in r
    assert client.call("get_account", account_id="chevron.com")["status"] == "contacted"
    r = client.call("update_accounts", account_ids=["toyota.com"], status="meeting")
    assert r["added_to_my_list"] == 1  # a status needs a list, as in the app
    r = client.call("update_accounts", account_ids=["chevron.com", "toyota.com"], remove_from_list="My list")
    assert r["removed_from"] == {"list": "My list", "removed": 2}
    assert {li["name"]: li["accounts"] for li in client.call("my_lists")["lists"]}["My list"] == 0


def test_the_sellers_profile_applies_unless_turned_off(client):
    from api.workspace import Workspace
    w = Workspace(str(client.db))
    ws = w.user_by_name("seller")["workspace_id"]
    w.save_profile(ws, {"active": True, "countries": ["GB"], "sectors": [], "industries": [], "sizes": [],
                        "product": "", "personas": []})
    gb = client.call("search_accounts", template="kev", country="GB", use_my_profile=False, limit=1)["total"]
    r = client.call("search_accounts", template="kev", limit=1)
    assert r["total"] == gb and r["profile_applied"] == "GB"
    whole = client.call("search_accounts", template="kev", use_my_profile=False, limit=1)
    assert whole["total"] > gb and whole["profile_applied"] is None
    w.save_profile(ws, {"active": False, "countries": ["GB"], "sectors": [], "industries": [], "sizes": [],
                        "product": "", "personas": []})
