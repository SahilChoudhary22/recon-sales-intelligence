"""The MCP server over HTTP: refused without the bearer token, the same tools with it."""
import os

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.skipif(not os.path.exists("data/serve/current/meta.json"), reason="export not run")


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    # one client for the module: the MCP session manager starts once per process, as in production
    import api.workspace as wsmod
    from api.workspace import Workspace, hash_password
    w = Workspace(str(tmp_path_factory.mktemp("app") / "app.db"))
    w.sync_users(f"seller:{hash_password('x')}")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(wsmod, "_ws", w)
        mp.setenv("RECON_USER", "seller")
        import mcp_server.http as h
        mp.setattr(h, "TOKEN", "test-token")
        import api.app
        with TestClient(api.app.application, base_url="http://localhost:8787") as c:
            yield c


HEAD = {"accept": "application/json, text/event-stream", "content-type": "application/json"}
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}}


def test_needs_the_token(client):
    assert client.post("/mcp", json=INIT, headers=HEAD).status_code == 401
    assert client.post("/mcp", json=INIT, headers={**HEAD, "authorization": "Bearer wrong"}).status_code == 401


def test_lists_and_calls_tools(client):
    h = {**HEAD, "authorization": "Bearer test-token"}
    assert client.post("/mcp", json=INIT, headers=h).json()["result"]["serverInfo"]["name"] == "Recon"
    tools = client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=h).json()
    assert len(tools["result"]["tools"]) == 10
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                  "params": {"name": "make_list", "arguments": {"account_ids": ["chevron.com"]}}}, headers=h).json()
    assert not r["result"].get("isError") and "My list" in r["result"]["content"][0]["text"]
