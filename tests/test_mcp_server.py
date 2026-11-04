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
    init = c.send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "recon-test", "version": "0"}})
    assert init["result"]["serverInfo"]["name"] == "Recon"
    c.send("notifications/initialized", notify=True)
    yield c
    c.close()


def test_lists_the_tools(client):
    names = {t["name"] for t in client.send("tools/list")["result"]["tools"]}
    assert names == {"dataset_overview", "list_signal_templates", "search_accounts", "get_account", "cve_exposure",
                     "make_list", "my_lists", "save_search", "whats_new", "export_crm_tasks"}


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
