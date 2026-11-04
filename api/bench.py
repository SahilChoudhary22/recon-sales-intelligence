"""How the read API's queries scale: time every query the app makes over the real store and over
synthetic stores 10x and 100x its size.

A synthetic store copies every account N times (ids suffixed, priority jittered so the ranking mixes
the copies), with its evidence and CVE rows, then rebuilds the count cube. Country, sector, industry
and size keep their real distribution, which is the honest case for the cube: more accounts, same
combinations.

usage: uv run python -m api.bench [--scales 1,10,100] [--runs 15]
"""
import argparse
import json
import os
import statistics
import time

import duckdb

from api.store import Query, Store
from pipeline.export import write_cube

SRC = "data/serve/current"
OUT = "data/bench"


def synth(n):
    out = f"{OUT}/x{n}"
    if os.path.exists(f"{out}/meta.json"):
        return out
    os.makedirs(out, exist_ok=True)
    con = duckdb.connect()
    sfx = "case when k = 0 then '' else '~' || k end"
    con.execute(f"""copy (select * replace (id || {sfx} as id, priority * (0.85 + 0.3 * random()) as priority)
        from '{SRC}/accounts.parquet', range({n}) t(k) order by priority desc)
        to '{out}/accounts.parquet' (format parquet, row_group_size 16384)""")
    con.execute(f"copy (select * from '{out}/accounts.parquet' order by id) to '{out}/accounts_by_id.parquet' "
                "(format parquet, row_group_size 16384)")
    con.execute(f"""copy (select * replace (company_id || {sfx} as company_id)
        from '{SRC}/evidence.parquet', range({n}) t(k) order by company_id)
        to '{out}/evidence.parquet' (format parquet, row_group_size 16384)""")
    if n <= 10:  # 100x of the CVE table is 88M rows; CVE search is measured up to 10x
        con.execute(f"""copy (select * replace (company_id || {sfx} as company_id)
            from '{SRC}/cve_hits.parquet', range({n}) t(k) order by cve)
            to '{out}/cve_hits.parquet' (format parquet, row_group_size 16384)""")
    else:
        con.execute(f"copy (select * from '{SRC}/cve_hits.parquet' limit 0) to '{out}/cve_hits.parquet' (format parquet)")
    write_cube(con, out)
    meta = json.load(open(f"{SRC}/meta.json"))
    meta["rows"]["accounts"] = con.execute(f"select count(*) from '{out}/accounts.parquet'").fetchone()[0]
    json.dump(meta, open(f"{out}/meta.json", "w"))
    os.system(f"cp {SRC}/cve_index.json {out}/")
    return out


def timed(f, runs):
    f()  # warm the OS file cache once, as a running server would be
    ts = []
    for _ in range(runs):
        t0 = time.perf_counter()
        f()
        ts.append((time.perf_counter() - t0) * 1000)
    ts.sort()
    return statistics.median(ts), ts[int(len(ts) * 0.95) - 1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scales", default="1,10,100")
    ap.add_argument("--runs", type=int, default=15)
    a = ap.parse_args()
    profile = dict(icp_country=["GB", "IE"], icp_sector=["commercial"])
    results = {}
    for n in [int(x) for x in a.scales.split(",")]:
        root = SRC if n == 1 else synth(n)
        s = Store(root)
        acc = s.meta["rows"]["accounts"]
        cube_rows = s._cur().execute("select count(*) from cube").fetchone()[0]
        size_mb = sum(os.path.getsize(f"{root}/{f}") for f in os.listdir(root)) / 1e6
        some_id = s._search(Query.make(), 5000, 1)["accounts"][0]["id"]
        cases = {
            "first page, whole market": lambda: s._search(Query.make(), 0, 100),
            "first page, template + profile": lambda: s._search(Query.make(template="edge", **profile), 0, 100),
            "page 50 (offset 5,000)": lambda: s._search(Query.make(), 5000, 100),
            "name search": lambda: s._search(Query.make(q="bank"), 0, 100),
            "template counts (cube)": lambda: s._counts(Query.make(**profile)),
            "template counts (live, strong identity)": lambda: s._counts(Query.make(strong=True, **profile)),
            "profile badges (cube)": lambda: s._facets(Query.make(**profile), ("country", "sector", "industry", "size")),
            "toolbar facets (live)": lambda: s._facets(Query.make(template="edge", **profile), ("country", "industry", "software")),
            "account by id": lambda: s.account(some_id),
            "evidence by id": lambda: s.evidence(some_id),
        }
        if n <= 10:
            cases["CVE search (OpenSSH CVE)"] = lambda: s.cve(["CVE-2023-38408"], Query.make(**profile))
        results[n] = {"accounts": acc, "cube_rows": cube_rows, "store_mb": round(size_mb),
                      "ms": {k: timed(f, a.runs) for k, f in cases.items()}}
        print(json.dumps({n: {**results[n], "ms": {k: [round(x, 1) for x in v] for k, v in results[n]["ms"].items()}}}), flush=True)
    json.dump(results, open(f"{OUT}/results.json", "w"), indent=1)


if __name__ == "__main__":
    main()
