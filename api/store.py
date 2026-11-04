"""Read-only queries over the serving store (data/serve/current), shared by the HTTP API and the MCP server.

DuckDB reads the Parquet files in place: only the columns a query touches, and only the row groups its
filters can match. Nothing is loaded into memory up front, so the same code runs over a laptop folder
or, with httpfs, over object storage.

Two query paths:
  * the count cube (cube.parquet) answers anything that filters only on template, country, sector,
    industry and estate size: template counts and the ICP panel's badges. Its size depends on how many
    combinations of those exist, not on how many accounts there are.
  * everything else (name search, software, identity strength, a list of ids) scans accounts.parquet,
    which is sorted by priority so the first page of a ranked list comes from the first row groups.
"""
import json
import os
import threading
from dataclasses import dataclass, field, fields
from functools import lru_cache

import duckdb

from api.rules import CATALOG, MARKET, TEMPLATES, template_sql

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVE = os.environ.get("RECON_SERVE", os.path.join(ROOT, "data", "serve", "current"))
FACETS = ("country", "industry", "sector", "size", "software")
CUBE_DIMS = {"country", "sector", "industry", "size"}

ACCOUNT_COLS = ("id, name, org, country, score, tier, play, ips, assets, ident, signals, kev, eol, maturity, "
                "products, need, urgency, fit, priority, industry, new, software, sector, size, peer, first_ranked")


MULTI = ("country", "industry", "sector", "software", "size")


@dataclass(frozen=True)
class Query:
    """One filter set. Each filter takes several values, ORed (GB or IE); different filters are ANDed.
    The toolbar filters and the ideal customer profile are separate layers, both applied, so a seller
    can switch the profile off without losing their filters."""
    template: str = MARKET
    ids: tuple[str, ...] | None = None
    exclude_ids: tuple[str, ...] = ()
    q: str = ""
    country: tuple[str, ...] = ()
    industry: tuple[str, ...] = ()
    sector: tuple[str, ...] = ()
    software: tuple[str, ...] = ()
    size: tuple[str, ...] = ()
    since_build: str = ""  # only accounts first ranked after this build: "new since you last ran it"
    strong: bool = False
    tier: str = ""
    icp_country: tuple[str, ...] = ()
    icp_sector: tuple[str, ...] = ()
    icp_industry: tuple[str, ...] = ()
    icp_size: tuple[str, ...] = ()

    @classmethod
    def make(cls, **kw):
        """From loose input (lists, None): normalised and hashable, so results can be cached."""
        names = {f.name for f in fields(cls)}
        clean = {}
        for k, v in kw.items():
            if k not in names or v is None:
                continue
            if k in ("ids", "exclude_ids") or k in MULTI or k.startswith("icp_"):
                v = (v,) if isinstance(v, str) else v
                v = tuple(sorted({str(x) for x in v if x}))
            clean[k] = v
        q = cls(**clean)
        if q.template not in ("", MARKET, "list") and q.template not in TEMPLATES:
            raise ValueError(f"unknown template {q.template!r}")
        return q

    def uses_only(self, dims):
        """True when every active filter is one of dims (or the template), so the cube can answer it."""
        active = {f.name for f in fields(self) if f.name != "template" and getattr(self, f.name) not in ("", False, (), None)}
        active = {a.removeprefix("icp_") for a in active}
        return active <= dims and self.template != "list"


def where(q: Query, skip: str = ""):
    """SQL predicate and parameters for a query. skip leaves one dimension out, for its own facet:
    the country badges show how many accounts each country would give with everything else applied."""
    conds, params = [], []

    def add(sql, *p):
        conds.append(sql)
        params.extend(p)

    if q.template not in ("", MARKET, "list"):
        conds.append(template_sql(q.template))
    if q.ids is not None:
        add("list_contains(?, id)", list(q.ids))
    if q.exclude_ids:
        add("not list_contains(?, id)", list(q.exclude_ids))
    if q.q.strip():
        add("contains(search, ?)", q.q.strip().lower())
    if q.since_build:
        add("first_ranked > ?", q.since_build)
    _dims(q, skip, add)
    if q.software and skip != "software":
        add("list_has_any(software, ?)", list(q.software))
    if q.strong:
        conds.append("strong")
    if q.tier:
        add("tier = ?", q.tier.upper())
    return (" and ".join(conds) or "true"), params


def _dims(q: Query, skip, add):
    """country, industry, sector and size, from the toolbar and the profile (case-insensitive)."""
    for dim in ("country", "industry", "sector", "size"):
        if dim == skip:
            continue
        for vals in (getattr(q, dim), getattr(q, f"icp_{dim}")):
            if vals:
                add(f"list_contains(?, lower({dim}))", [v.lower() for v in vals])


def _cube_where(q: Query, skip: str = ""):
    conds, params = [], []

    def add(sql, *p):
        conds.append(sql)
        params.extend(p)

    _dims(q, skip, add)
    return (" and ".join(conds) or "true"), params


class Store:
    def __init__(self, root=SERVE):
        self.root = os.path.realpath(root)
        self.meta = json.load(open(f"{self.root}/meta.json"))
        self.cve_index = json.load(open(f"{self.root}/cve_index.json"))
        cfg = {"threads": os.cpu_count() or 4}
        if os.environ.get("DUCKDB_MEMORY_LIMIT"):
            cfg["memory_limit"] = os.environ["DUCKDB_MEMORY_LIMIT"]  # bounded on a shared host
        self._con = duckdb.connect(config=cfg)
        for name in ("accounts", "evidence", "cube", "cve_hits"):
            self._con.execute(f"create view {name} as select * from read_parquet('{self.root}/{name}.parquet')")
        by_id = f"{self.root}/accounts_by_id.parquet"
        self._con.execute(f"create view accounts_by_id as select * from read_parquet('{by_id if os.path.exists(by_id) else self.root + '/accounts.parquet'}')")
        self._local = threading.local()
        # results are cached per store; a new build is a new Store, so nothing stale is ever served
        self.search = lru_cache(maxsize=2048)(self._search)
        self.counts = lru_cache(maxsize=1024)(self._counts)
        self.facets = lru_cache(maxsize=2048)(self._facets)

    def _cur(self):
        """One cursor per thread: DuckDB connections aren't shared across threads, cursors are cheap."""
        cur = getattr(self._local, "cur", None)
        if cur is None:
            cur = self._local.cur = self._con.cursor()
        return cur

    def _rows(self, sql, params=()):
        cur = self._cur().execute(sql, list(params))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    # ranked accounts --------------------------------------------------------------------------------
    def _search(self, q: Query, offset=0, limit=100):
        w, p = where(q)
        total = self._cur().execute(f"select count(*) from accounts where {w}", p).fetchone()[0]
        # DuckDB's top-N keeps only offset + limit rows while scanning; measured, relying on the
        # file's priority order instead was no faster (api/bench.py), so the order is explicit
        rows = self._rows(f"select {ACCOUNT_COLS} from accounts where {w} order by priority desc, id "
                          f"limit {int(limit)} offset {int(offset)}", p)
        return {"total": total, "offset": offset, "accounts": rows}

    def account(self, account_id):
        # a copy sorted by id: the lookup reads only the row group whose id range can hold it
        rows = self._rows(f"select {ACCOUNT_COLS} from accounts_by_id where id = ?", [account_id])
        return rows[0] if rows else None

    def evidence(self, account_id):
        return self._rows("select s, ip, port, p, e, t, cn from evidence where company_id = ?", [account_id])

    def iter_rows(self, q: Query, cap=100_000, batch=5000):
        """Streams a filtered list for CSV export, without holding it all in memory."""
        w, p = where(q)
        cur = self._con.cursor().execute(f"select {ACCOUNT_COLS} from accounts where {w} order by priority desc, id limit {int(cap)}", p)
        cols = [d[0] for d in cur.description]
        while chunk := cur.fetchmany(batch):
            yield from (dict(zip(cols, r)) for r in chunk)

    # counts -----------------------------------------------------------------------------------------
    def _counts(self, q: Query):
        """Accounts per template (and the whole market) for a profile. From the cube when it can."""
        ids = [MARKET] + list(TEMPLATES)
        if q.uses_only(CUBE_DIMS):
            w, p = _cube_where(q)
            got = dict(self._cur().execute(f"select template, sum(n)::bigint from cube where {w} group by template", p).fetchall())
        else:  # one scan, every template counted in the same pass
            w, p = where(Query.make(**{**q.__dict__, "template": MARKET}))
            sel = ", ".join(f"count_if({template_sql(t)})" for t in ids)
            got = dict(zip(ids, self._cur().execute(f"select {sel} from accounts where {w}", p).fetchone()))
        return {t: int(got.get(t, 0)) for t in ids}

    def _facets(self, q: Query, dims=FACETS):
        """Value -> count for each dimension, that dimension's own filter left out (Apollo-style badges)."""
        out = {}
        cube_ok = q.uses_only(CUBE_DIMS)
        for dim in dims:
            if dim in CUBE_DIMS and cube_ok:
                w, p = _cube_where(q, skip=dim)
                t = q.template or MARKET
                sql = f"select {dim} v, sum(n)::bigint c from cube where template = ? and {w} and {dim} is not null group by v order by c desc"
                rows = self._cur().execute(sql, [t, *p]).fetchall()
            else:
                w, p = where(q, skip=dim)
                col = "unnest(software)" if dim == "software" else dim
                sql = f"select v, count(*) c from (select {col} v from accounts where {w}) where v is not null group by v order by c desc"
                rows = self._cur().execute(sql, p).fetchall()
            out[dim] = [[v, int(c)] for v, c in rows]
        return out

    # CVE in the news --------------------------------------------------------------------------------
    def resolve_cves(self, text):
        import re
        ids = {f"CVE-{a}-{b}" for a, b in re.findall(r"\bcve-(\d{4})-(\d{4,7})\b", text, re.I)}
        bare = re.fullmatch(r"\s*(\d{4})-(\d{4,7})\s*", text)
        if bare:
            ids.add(f"CVE-{bare[1]}-{bare[2]}")
        if not ids:
            ids.update(self.cve_index["nicknames"].get(text.strip().lower(), []))
        return sorted(ids)

    def cve(self, ids, q: Query, limit=300, outside_limit=300):
        facts = {i: self.cve_index["cves"].get(i) for i in ids}
        if not ids:
            return {"ids": [], "facts": {}, "total": 0, "accounts": [], "outside": {"total": 0, "top": []}}
        w, p = where(q)
        cols = ", ".join(f"a.{c.strip()}" for c in ACCOUNT_COLS.split(","))
        # the account filters run inside the subquery, so their column names can't clash with cve_hits
        base = f"""from cve_hits h join (select * from accounts where {w}) a on a.id = h.company_id
                   where list_contains(?, h.cve)"""
        hits = self._rows(f"""
            select {cols}, max(h.n) affected, any_value(h.product) affected_product, bool_or(h.new) affected_new,
                   list_distinct(flatten(list(h.services)))[1:3] example_services, list(distinct h.cve) cves
            {base} group by all order by a.priority desc limit {int(limit)}""", [*p, list(ids)])
        total = self._cur().execute(f"select count(distinct h.company_id) {base}", [*p, list(ids)]).fetchone()[0]
        outside = self._cur().execute("""
            select count(distinct company_id) from cve_hits where list_contains(?, cve) and not served""", [list(ids)]).fetchone()[0]
        top = self._rows(f"""select name, country, max(score) score, max(n) n, any_value(product) product
            from cve_hits where list_contains(?, cve) and not served group by company_id, name, country
            order by score desc limit {int(outside_limit)}""", [list(ids)])
        return {"ids": ids, "facts": facts, "scanDate": self.cve_index["scanDate"], "kev": self.cve_index["kev"],
                "total": total, "accounts": hits, "outside": {"total": outside, "top": top}}


_store = None
_store_root = None
_lock = threading.Lock()


def get_store():
    """The store for the current build; picks up a new build when the 'current' pointer moves."""
    global _store, _store_root
    root = os.path.realpath(SERVE)
    if _store is None or root != _store_root:
        with _lock:
            if _store is None or root != _store_root:
                _store, _store_root = Store(root), root
    return _store
