"""Recon's API: ranked accounts, counts, facets, evidence and CVE search over the serving store, plus
each user's lists, statuses, saved searches and profile.

run:   uv run uvicorn api.app:app --port 8787
docs:  http://localhost:8787/api/docs  (OpenAPI, after signing in)

Two stores behind one API. Scan data is read-only: the build writes the serving store and the API only
queries it (api/store.py, DuckDB over Parquet). A user's work is the only thing the API writes
(api/workspace.py, SQLite here, Postgres in production). Every route except health and login needs a
session: the account list names companies with exploitable exposure, so it isn't public.

Queries are POST with a JSON body, so a full profile never runs into URL length limits. "This list" and
"not in my lists" are resolved here from the signed-in user's workspace, so the browser never sends a
list of ids.
"""
import csv
import io
import os

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from api.rules import CATALOG
from api.store import FACETS, Query, get_store
from api.workspace import STATUSES, LimitError, get_workspace

app = FastAPI(title="Recon API", version="1.0", docs_url="/api/docs", openapi_url="/api/openapi.json",
              description="Ranked cybersecurity-need accounts from internet scan data (IPs masked to /24), and each "
                          "user's lists and saved searches. Sign in with POST /api/login.")

COOKIE = "recon_session"
SECURE_COOKIE = os.environ.get("RECON_SECURE_COOKIE", "1") != "0"  # off only for http://localhost
PUBLIC = {"/api/health", "/api/login"}


@app.middleware("http")
async def require_session(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.url.path not in PUBLIC:
        user = get_workspace().session_user(request.cookies.get(COOKIE))
        if not user:
            return JSONResponse({"detail": "sign in first"}, status_code=401)
        request.state.user = user
    return await call_next(request)


def ws(request: Request) -> str:
    return request.state.user["workspace_id"]


# --- filters ------------------------------------------------------------------------------------
class Filters(BaseModel):
    template: str = Field("market", description="signal template id, 'market' for every account, 'list' with list_id")
    list_id: str | None = Field(None, description="with template 'list': one of your lists")
    exclude_listed: bool = Field(False, description="leave out accounts already in any of your lists")
    q: str = Field("", max_length=200, description="part of a company or organisation name")
    country: list[str] = Field([], description="any of these ISO-2 codes")
    industry: list[str] = []
    sector: list[str] = Field([], description="commercial, public, infra")
    software: list[str] = Field([], description="runs any of these product families")
    size: list[str] = Field([], description="estate size: small (1-5 IPs), mid (6-50), large (over 50)")
    since_build: str = Field("", max_length=32, description="only accounts first ranked after this build id")
    strong: bool = False
    tier: str = ""
    icp_country: list[str] = []
    icp_sector: list[str] = []
    icp_industry: list[str] = []
    icp_size: list[str] = []

    def query(self, request: Request):
        w = get_workspace()
        f = self.model_dump(exclude={"list_id", "exclude_listed"})
        if self.template == "list":
            if not self.list_id or not w.find_list(ws(request), self.list_id):
                raise HTTPException(404, "no such list")
            f["ids"] = w.list_ids(ws(request), self.list_id)
        if self.exclude_listed:
            f["exclude_ids"] = w.listed_ids(ws(request))
        try:
            return Query.make(**f)
        except ValueError as e:
            raise HTTPException(422, str(e)) from e


class SearchBody(Filters):
    offset: int = Field(0, ge=0, le=1_000_000)
    limit: int = Field(100, ge=1, le=500)


class IdsBody(Filters):
    limit: int = Field(5000, ge=1, le=5000)


class FacetBody(Filters):
    dims: list[str] = list(FACETS)


class CveBody(Filters):
    cve: str = Field(..., max_length=200, description="CVE id(s) or a known name such as 'Citrix Bleed'")
    limit: int = Field(300, ge=1, le=1000)


# --- session ------------------------------------------------------------------------------------
class Login(BaseModel):
    username: str = Field(..., max_length=64)
    password: str = Field(..., max_length=256)


@app.post("/api/login")
def login(b: Login, response: Response):
    token = get_workspace().login(b.username, b.password)
    if not token:
        raise HTTPException(401, "wrong username or password")
    response.set_cookie(COOKIE, token, max_age=14 * 86400, httponly=True, samesite="lax", secure=SECURE_COOKIE, path="/")
    return {"username": b.username}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    get_workspace().logout(request.cookies.get(COOKIE))
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.get("/api/me")
def me(request: Request):
    return {"username": request.state.user["username"]}


# --- scan data (read-only) ----------------------------------------------------------------------
@app.get("/api/health")
def health():
    s = get_store()
    return {"ok": True, "build": s.meta["build_id"], "accounts": s.meta["rows"]["accounts"]}


@app.get("/api/meta")
def meta():
    """Funnel, signal and maturity labels, the catalogue, and which build is being served."""
    return {**get_store().meta, "catalog": CATALOG}


@app.post("/api/search")
def search(b: SearchBody, request: Request):
    """Accounts matching the filters, ranked by priority, one page at a time."""
    return get_store().search(b.query(request), b.offset, b.limit)


@app.post("/api/ids")
def ids(b: IdsBody, request: Request):
    """The ids of the top matches (up to 5,000), ranked."""
    return get_store().ids(b.query(request), b.limit)


@app.post("/api/counts")
def counts(b: Filters, request: Request):
    """Accounts per signal template for these filters (usually just the profile)."""
    return get_store().counts(b.query(request))


@app.post("/api/facets")
def facets(b: FacetBody, request: Request):
    """For each dimension, how many accounts each value would give with every other filter applied."""
    return get_store().facets(b.query(request), tuple(d for d in b.dims if d in FACETS))


@app.get("/api/accounts/{account_id:path}/evidence")
def evidence(account_id: str):
    return get_store().evidence(account_id)


@app.get("/api/accounts/{account_id:path}")
def account(account_id: str):
    a = get_store().account(account_id)
    if not a:
        raise HTTPException(404, "no such account")
    return a


@app.post("/api/cve")
def cve(b: CveBody, request: Request):
    """Which accounts run software affected by a CVE in the news, inside the filters."""
    s = get_store()
    return s.cve(s.resolve_cves(b.cve), b.query(request), b.limit)


@app.post("/api/export.csv")
def export_csv(b: Filters, request: Request):
    """The filtered list as CSV for a CRM import, streamed (up to 100,000 rows), with list status."""
    s, w = get_store(), get_workspace()
    q = b.query(request)
    labels = {k: v["label"] for k, v in s.meta["signals"].items()}
    snap = w.snapshot(ws(request))
    names = {li["id"]: li["name"] for li in snap["lists"]}

    def rows():
        buf = io.StringIO()
        out = csv.writer(buf)
        out.writerow(["score", "tier", "company", "organisation", "country", "industry", "identified_by", "signals",
                      "ips", "services", "status", "lists"])
        for a in s.iter_rows(q):
            e = snap["entries"].get(a["id"])
            out.writerow([round(a["score"]), a["tier"], a["name"], a["org"], a["country"], a["industry"], a["ident"],
                          "; ".join(labels.get(x, x) for x in a["signals"]), a["ips"], a["assets"],
                          e["status"] if e else "", "; ".join(names[li] for li in e["lists"]) if e else ""])
            if buf.tell() > 64_000:
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate()
        yield buf.getvalue()

    return StreamingResponse(rows(), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="accounts.csv"'})


# --- your work: lists, statuses, saved searches, profile ------------------------------------------
def _limits(fn):
    try:
        return fn()
    except LimitError as e:
        raise HTTPException(409, str(e)) from e
    except ValueError as e:
        raise HTTPException(422, str(e)) from e


@app.get("/api/workspace")
def workspace(request: Request):
    """Everything the app starts from: lists, which list each account is in and its status, saved
    searches and the profile."""
    return get_workspace().snapshot(ws(request))


class NewList(BaseModel):
    name: str = Field(..., min_length=1, max_length=60)
    id: str | None = Field(None, description="optional client-chosen id, [a-z][a-z0-9]{5,31}")


@app.post("/api/lists")
def create_list(b: NewList, request: Request):
    return _limits(lambda: get_workspace().create_list(ws(request), b.name, b.id))


class Rename(BaseModel):
    name: str = Field(..., min_length=1, max_length=60)


@app.patch("/api/lists/{list_id}")
def rename_list(list_id: str, b: Rename, request: Request):
    get_workspace().rename_list(ws(request), list_id, b.name)
    return {"ok": True}


@app.delete("/api/lists/{list_id}")
def delete_list(list_id: str, request: Request):
    get_workspace().delete_list(ws(request), list_id)
    return {"ok": True}


class AddItems(BaseModel):
    ids: list[str] | None = Field(None, max_length=5000, description="these accounts")
    search: Filters | None = Field(None, description="or the top results of this search")
    limit: int = Field(5000, ge=1, le=5000)


@app.post("/api/lists/{list_id}/items")
def add_items(list_id: str, b: AddItems, request: Request):
    """Add accounts to a list: given ids (unknown ones are skipped), or the top results of a search."""
    s, w = get_store(), get_workspace()
    if b.search is not None:
        ids_ = s.ids(b.search.query(request), b.limit)["ids"]
    else:
        ids_ = s.ids(Query.make(template="list", ids=b.ids or []), 5000)["ids"]  # only accounts that exist
    try:
        r = _limits(lambda: w.add_items(ws(request), list_id, ids_))
    except KeyError as e:
        raise HTTPException(404, "no such list") from e
    return {**r, "skipped_unknown": len(set(b.ids or [])) - len(ids_) if b.search is None else 0}


class RemoveItems(BaseModel):
    ids: list[str] = Field(..., max_length=5000)


@app.post("/api/lists/{list_id}/items/remove")
def remove_items(list_id: str, b: RemoveItems, request: Request):
    get_workspace().remove_items(ws(request), list_id, b.ids)
    return {"ok": True}


class SetStatus(BaseModel):
    account_id: str
    status: str = Field(..., description=", ".join(STATUSES))


@app.put("/api/status")
def set_status(b: SetStatus, request: Request):
    _limits(lambda: get_workspace().set_status(ws(request), b.account_id, b.status))
    return {"ok": True}


class NewSearch(BaseModel):
    name: str = Field(..., min_length=1, max_length=60)
    filters: dict
    profile: dict = {}
    id: str | None = None


@app.post("/api/searches")
def save_search(b: NewSearch, request: Request):
    """Save a search; it remembers the build it was saved on, so its next run can say what's new."""
    return _limits(lambda: get_workspace().save_search(ws(request), b.name, b.filters, b.profile,
                                                       get_store().meta["build_id"], b.id))


class SearchUpdate(BaseModel):
    reviewed: bool = Field(False, description="mark it run on the current build")
    schedule: str | None = Field(None, description="daily or manual")


@app.patch("/api/searches/{search_id}")
def update_search(search_id: str, b: SearchUpdate, request: Request):
    w = get_workspace()
    if b.reviewed:
        w.mark_run(ws(request), search_id, get_store().meta["build_id"])
    if b.schedule:
        _limits(lambda: w.set_schedule(ws(request), search_id, b.schedule))
    return {"ok": True}


@app.delete("/api/searches/{search_id}")
def delete_search(search_id: str, request: Request):
    get_workspace().delete_search(ws(request), search_id)
    return {"ok": True}


@app.put("/api/profile")
def save_profile(data: dict, request: Request):
    get_workspace().save_profile(ws(request), data)
    return {"ok": True}
