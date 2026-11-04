"""The read API's query layer over the real serving store (data/serve/current; not in git, skipped
where the export hasn't been run).

The count cube is an optimisation, so the main test is that it can never disagree with a live count."""
import os
import random
import re

import pytest

from api.rules import TEMPLATES
from api.store import Query, Store, where

pytestmark = pytest.mark.skipif(not os.path.exists("data/serve/current/meta.json"), reason="export not run")


@pytest.fixture(scope="module")
def s():
    return Store("data/serve/current")


def live_count(s, q):
    w, p = where(q)
    return s._cur().execute(f"select count(*) from accounts where {w}", p).fetchone()[0]


def test_cube_agrees_with_live_counts(s):
    rnd = random.Random(7)
    countries = [c for c, _ in s.facets(Query.make(), ("country",))["country"][:25]]
    industries = [i for i, _ in s.facets(Query.make(), ("industry",))["industry"]]
    for _ in range(25):
        q = Query.make(icp_country=rnd.sample(countries, rnd.randint(0, 3)),
                       icp_sector=rnd.sample(["commercial", "public", "infra"], rnd.randint(0, 2)),
                       icp_industry=rnd.sample(industries, rnd.randint(0, 2)),
                       icp_size=rnd.sample(["small", "mid", "large"], rnd.randint(0, 1)))
        assert q.uses_only({"country", "sector", "industry", "size"})
        counts = s._counts(q)
        for t in ["market", *TEMPLATES]:
            assert counts[t] == live_count(s, Query.make(**{**q.__dict__, "template": t})), (t, q)


def test_facet_leaves_its_own_filter_out(s):
    q = Query.make(icp_country=["GB"], icp_sector=["commercial"])
    f = s.facets(q, ("country", "sector"))
    # the GB badge is "GB, given commercial": the same as the count with both applied
    assert dict(f["country"])["GB"] == s.counts(q)["market"]
    # other countries still have counts, so a second country can be added
    assert dict(f["country"])["US"] > 0
    assert dict(f["sector"])["commercial"] == s.counts(q)["market"]


def test_search_is_ranked_and_paged(s):
    q = Query.make(template="kev", strong=True)
    p1, p2 = s.search(q, 0, 50), s.search(q, 50, 50)
    rows = p1["accounts"] + p2["accounts"]
    assert p1["total"] == live_count(s, q) and len({a["id"] for a in rows}) == 100
    assert [a["priority"] for a in rows] == sorted((a["priority"] for a in rows), reverse=True)
    # paging is stable: two pages are the first 100 of one sort
    w, p = where(q)
    top = [r[0] for r in s._cur().execute(f"select id from accounts where {w} order by priority desc, id limit 100", p).fetchall()]
    assert [a["id"] for a in rows] == top


def test_my_list_ignores_unknown_ids(s):
    r = s.search(Query.make(template="list", ids=["chevron.com", "nope.invalid"]), 0, 10)
    assert [a["id"] for a in r["accounts"]] == ["chevron.com"]


def test_unknown_template_is_rejected():
    with pytest.raises(ValueError):
        Query.make(template="nope")


def test_cve_respects_the_profile(s):
    ids = s.resolve_cves("CVE-2023-38408")
    everyone = s.cve(ids, Query.make())["total"]
    gb = s.cve(ids, Query.make(icp_country=["GB"]))
    assert 0 < gb["total"] < everyone and all(a["country"] == "GB" for a in gb["accounts"])


def test_nothing_served_carries_a_full_ip(s):
    full_ip = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    for e in s.evidence("chevron.com"):
        assert not any(full_ip.search(str(v or "")) for v in e.values())
    assert s.meta["ips_masked"]


def test_template_flags_match_the_rules(s):
    """The export precomputes each template's membership; it must equal the catalogue rule."""
    from api.rules import flag, rule_sql
    for t in TEMPLATES:
        bad = s._cur().execute(f"select count(*) from accounts where {flag(t)} is distinct from {rule_sql(t)}").fetchone()[0]
        assert bad == 0, t


def test_first_ranked_carries_over_by_id(tmp_path):
    """An account keeps the build it was first ranked in; an account new to this build gets this build."""
    import duckdb

    from pipeline.export import first_ranked_join, first_ranked_sql
    prev = tmp_path / "prev"
    prev.mkdir()
    con = duckdb.connect()
    con.execute(f"copy (select * from (values ('a.com', '20261101T000000'), ('b.com', '20261102T000000')) t(id, first_ranked)) "
                f"to '{prev}/accounts.parquet' (format parquet)")
    con.execute(f"copy (select * from (values ('a.com'), ('c.com')) t(id)) to '{tmp_path}/raw.parquet' (format parquet)")
    got = dict(con.execute(f"""select r.id, {first_ranked_sql(str(prev), '20261103T000000')} from '{tmp_path}/raw.parquet' r
                               {first_ranked_join(str(prev))}""").fetchall())
    assert got == {"a.com": "20261101T000000", "c.com": "20261103T000000"}
    # no previous build (or --rebaseline): everything starts now
    assert first_ranked_sql("", "20261103T000000") == "'20261103T000000'" and first_ranked_join("") == ""
