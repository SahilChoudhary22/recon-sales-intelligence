"""Recon's read API: ranked accounts, counts, facets, evidence and CVE search over the serving store.

run:   uv run uvicorn api.app:app --port 8787
docs:  http://localhost:8787/api/docs  (OpenAPI)

Read-only by design: the build writes the store, the API only queries it. Queries are POST with a JSON
body, so a long list of account ids or a full profile never runs into URL length limits.
"""
import csv
import io

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from api.rules import CATALOG
from api.store import FACETS, Query, get_store

app = FastAPI(title="Recon API", version="1.0", docs_url="/api/docs", openapi_url="/api/openapi.json",
              description="Ranked cybersecurity-need accounts from internet scan data. IP addresses are masked to /24.")


class Filters(BaseModel):
    template: str = Field("market", description="signal template id, 'market' for every account, 'list' with ids")
    ids: list[str] | None = Field(None, max_length=5000, description="restrict to these account ids (a list)")
    exclude_ids: list[str] = Field([], max_length=20000, description="leave these out (accounts already in your lists)")
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

    def query(self):
        try:
            return Query.make(**self.model_dump())
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


@app.get("/api/health")
def health():
    s = get_store()
    return {"ok": True, "build": s.meta["build_id"], "accounts": s.meta["rows"]["accounts"]}


@app.get("/api/meta")
def meta():
    """Funnel, signal and maturity labels, the catalogue, and which build is being served."""
    m = get_store().meta
    return {**m, "catalog": CATALOG}


@app.post("/api/search")
def search(b: SearchBody):
    """Accounts matching the filters, ranked by priority, one page at a time."""
    return get_store().search(b.query(), b.offset, b.limit)


@app.post("/api/ids")
def ids(b: IdsBody):
    """The ids of the top matches (up to 5,000), ranked: what "add all to a list" adds."""
    return get_store().ids(b.query(), b.limit)


@app.post("/api/counts")
def counts(b: Filters):
    """Accounts per signal template for these filters (usually just the profile)."""
    return get_store().counts(b.query())


@app.post("/api/facets")
def facets(b: FacetBody):
    """For each dimension, how many accounts each value would give with every other filter applied."""
    dims = tuple(d for d in b.dims if d in FACETS)
    return get_store().facets(b.query(), dims)


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
def cve(b: CveBody):
    """Which accounts run software affected by a CVE in the news, inside the filters."""
    s = get_store()
    return s.cve(s.resolve_cves(b.cve), b.query(), b.limit)


@app.post("/api/export.csv")
def export_csv(b: Filters):
    """The filtered list as CSV for a CRM import, streamed (up to 100,000 rows)."""
    s = get_store()
    labels = {k: v["label"] for k, v in s.meta["signals"].items()}

    def rows():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["score", "tier", "company", "organisation", "country", "industry", "identified_by", "signals", "ips", "services"])
        for a in s.iter_rows(b.query()):
            w.writerow([round(a["score"]), a["tier"], a["name"], a["org"], a["country"], a["industry"], a["ident"],
                        "; ".join(labels.get(x, x) for x in a["signals"]), a["ips"], a["assets"]])
            if buf.tell() > 64_000:
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate()
        yield buf.getvalue()

    return StreamingResponse(rows(), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="accounts.csv"'})
