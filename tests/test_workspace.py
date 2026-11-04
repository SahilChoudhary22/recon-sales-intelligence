"""Users, sessions and each user's lists and saved searches, through the HTTP API.

The scan-data routes need the serving store (data/serve/current); skipped where the export hasn't run."""
import os

import pytest
from fastapi.testclient import TestClient

import api.workspace as wsmod
from api.workspace import LimitError, Workspace, check_password, hash_password

HAS_STORE = os.path.exists("data/serve/current/meta.json")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    w = Workspace(str(tmp_path / "app.db"))
    w.sync_users(f"ana:{hash_password('ana-pass')},ben:{hash_password('ben-pass')}")
    monkeypatch.setattr(wsmod, "_ws", w)
    import api.app
    monkeypatch.setattr(api.app, "SECURE_COOKIE", False)  # the test client speaks plain http
    return TestClient(api.app.app)


def sign_in(c, user):
    r = c.post("/api/login", json={"username": user, "password": f"{user}-pass"})
    assert r.status_code == 200
    return c


def test_passwords_are_salted_and_checked():
    a, b = hash_password("x"), hash_password("x")
    assert a != b and check_password("x", a) and not check_password("y", a)


def test_everything_but_login_needs_a_session(client):
    assert client.get("/api/me").status_code == 401
    assert client.post("/api/search", json={}).status_code == 401
    assert client.post("/api/login", json={"username": "ana", "password": "nope"}).status_code == 401
    assert sign_in(client, "ana").get("/api/me").json() == {"username": "ana"}


def test_each_user_has_their_own_workspace(client):
    sign_in(client, "ana")
    client.post("/api/lists", json={"name": "Ana's banks", "id": "lanabanks"})
    assert [li["name"] for li in client.get("/api/workspace").json()["lists"]] == ["My list", "Ana's banks"]
    client.post("/api/logout")
    sign_in(client, "ben")
    assert [li["name"] for li in client.get("/api/workspace").json()["lists"]] == ["My list"]
    # ben can't add to, rename or delete ana's list
    assert client.post("/api/lists/lanabanks/items", json={"ids": []}).status_code == 404


def test_caps_keep_a_workspace_bounded(tmp_path):
    w = Workspace(str(tmp_path / "caps.db"))
    w.sync_users(f"ana:{hash_password('p')}")
    ws = w.user_by_name("ana")["workspace_id"]
    with pytest.raises(LimitError):
        for i in range(wsmod.MAX_LISTS + 1):
            w.create_list(ws, f"list {i}")


def test_status_follows_membership(tmp_path):
    w = Workspace(str(tmp_path / "s.db"))
    w.sync_users(f"ana:{hash_password('p')}")
    ws = w.user_by_name("ana")["workspace_id"]
    mine = w.lists(ws)[0]["id"]
    other = w.create_list(ws, "Other")["id"]
    w.add_items(ws, mine, ["a.com", "b.com"])
    w.add_items(ws, other, ["a.com"])
    w.set_status(ws, "a.com", "meeting")
    snap = w.snapshot(ws)
    assert snap["entries"]["a.com"] == {**snap["entries"]["a.com"], "status": "meeting", "lists": [mine, other]}
    w.remove_items(ws, mine, ["a.com", "b.com"])
    assert set(w.snapshot(ws)["entries"]) == {"a.com"}  # b.com is in no list now, so its status is gone
    assert w.listed_ids(ws) == ["a.com"]


@pytest.mark.skipif(not HAS_STORE, reason="export not run")
def test_search_to_list_to_not_in_my_lists(client):
    sign_in(client, "ana")
    mine = client.get("/api/workspace").json()["lists"][0]["id"]
    search = {"template": "edge", "country": ["GB"]}
    total = client.post("/api/search", json={**search, "limit": 1}).json()["total"]
    r = client.post(f"/api/lists/{mine}/items", json={"search": search}).json()
    assert r["added"] == total
    # the list view and "not in my lists" are resolved on the server from the workspace
    assert client.post("/api/search", json={"template": "list", "list_id": mine, "limit": 1}).json()["total"] == total
    assert client.post("/api/search", json={**search, "exclude_listed": True, "limit": 1}).json()["total"] == 0
    r = client.post(f"/api/lists/{mine}/items", json={"ids": ["chevron.com", "nope.invalid"]}).json()
    assert r["added"] == 1 and r["skipped_unknown"] == 1


@pytest.mark.skipif(not HAS_STORE, reason="export not run")
def test_saved_search_remembers_its_build(client):
    sign_in(client, "ana")
    s = client.post("/api/searches", json={"name": "UK edge", "filters": {"play": "edge", "country": ["GB"]}}).json()
    build = client.get("/api/meta").json()["build_id"]
    assert s["lastRun"] == build
    fresh = client.post("/api/search", json={"template": "edge", "country": ["GB"], "since_build": build, "limit": 1}).json()
    assert fresh["total"] == 0  # nothing is first ranked after the build it was saved on
