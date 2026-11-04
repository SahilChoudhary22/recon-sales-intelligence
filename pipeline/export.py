"""Scored build -> the serving store the API, the MCP server and the app read.

  data/serve/<build-id>/accounts.parquet   every company with a material signal, IP-masked, sorted by priority
  data/serve/<build-id>/evidence.parquet   evidence rows, masked, sorted by company (lookups prune row groups)
  data/serve/<build-id>/cube.parquet       account counts per template x country x sector x industry x size
  data/serve/<build-id>/cve_hits.parquet   CVE -> affected companies (pipeline/cve_index.py)
  data/serve/<build-id>/cve_index.json     CVE facts, CISA KEV status, nicknames
  data/serve/<build-id>/meta.json          funnel, signal and maturity labels, row counts, masked flag
  data/serve/current                       symlink to the newest complete build, swapped atomically

The whole store is written to <build-id>.partial and renamed only once every file and check passed,
so the API never reads a half-written build.

usage: python -m pipeline.export <build_dir> [--out data/serve] [--limit N]
"""
import argparse
import csv
import json
import os
import re
import shutil
import time

import duckdb

from pipeline.signals import MATURITY, SIGNALS

IPV4 = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b")
IPV4_SQL = r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b"
OUT = os.environ.get("RECON_SERVE_ROOT", "data/serve")
RETAIN_BUILDS = 3
BASELINE = "00000000T000000"  # first_ranked for accounts present when tracking (re)started
DOMAIN_LABELS = "data/labels/domain_labels.csv"

# cheap, transparent industry guess; LLM labels (when present) take precedence
INDUSTRY_RULES = [
    ("Government", r"(\.gov(\.[a-z]{2})?$|\.gob\.|\.go\.[a-z]{2}$|\.gouv\.|\.mil$|ministry|municipal|city of|county|council|government)"),
    ("Education", r"(\.edu(\.[a-z]{2})?$|\.ac\.[a-z]{2}$|universi|college|school|academy|institute of technology|vutbr|utoronto)"),
    ("Healthcare", r"(hospital|clinic|health|medical|pharma|acibadem|dental|care\b|labs?\b.*diagnos)"),
    ("Financial services", r"(bank|banco|credit|insurance|assurance|capital|finance|financial|invest|securities|payment)"),
    ("Energy & utilities", r"(energ|power|electric|utility|utilities|gas\b|oil\b|petro|solar|water)"),
    ("Manufacturing", r"(manufactur|industri|steel|motor|automotive|chemical|plastics|factory|siemens)"),
    ("Retail & e-commerce", r"(shop|store|retail|market|mall|commerce|fashion)"),
    ("Logistics & transport", r"(logistic|transport|shipping|freight|cargo|airline|aero|rail|port\b)"),
    ("Media", r"(media|news|tv\b|radio|broadcast|press|bbc)"),
]


# raw product strings -> the families a seller filters by ("Fortinet FortiGate-60F" -> "Fortinet FortiGate"),
# like a technographics filter; first match wins, order is display order
SOFTWARE_FAMILIES = [
    ("Fortinet FortiGate", r"forti"), ("Citrix NetScaler", r"netscaler|citrix"), ("F5 BIG-IP", r"big-?ip"),
    ("SonicWall", r"sonicwall"), ("Check Point", r"check ?point|connectra"), ("Cisco", r"cisco"),
    ("Palo Alto", r"palo alto|globalprotect|pan-os"), ("Ivanti / Pulse Secure", r"pulse secure|ivanti"),
    ("MikroTik", r"mikrotik"), ("DrayTek", r"draytek"), ("Ubiquiti", r"ubiquiti"),
    ("Microsoft Exchange", r"exchange|outlook web app"), ("Microsoft IIS", r"\biis\b"),
    ("Microsoft SQL Server", r"ms-sql|sql server"), ("Windows remote access (RDP, WinRM)", r"winrm|remote desktop|\brdp\b"),
    ("VNC", r"\bvnc\b"), ("OpenSSH", r"openssh"), ("Apache httpd", r"apache httpd"),
    ("Apache Tomcat", r"tomcat|coyote"), ("nginx", r"nginx|openresty"), ("LiteSpeed", r"litespeed"),
    ("cPanel / WHM", r"cpanel|\bwhm\b"), ("MySQL / MariaDB", r"mysql|mariadb"), ("PostgreSQL", r"postgres"),
    ("MongoDB", r"mongo"), ("Redis", r"redis"), ("Elasticsearch", r"elastic"), ("MinIO", r"minio"),
    ("Kubernetes", r"kubernetes"), ("Jenkins", r"jenkins"), ("Grafana", r"grafana"), ("n8n", r"\bn8n\b"),
    ("Nextcloud", r"nextcloud"), ("Mail server (Exim, Postfix)", r"exim|postfix"),
    ("IP cameras (Hikvision, Dahua)", r"hikvision|dahua"),
]
_FAMILY_RE = [(name, re.compile(rx, re.I)) for name, rx in SOFTWARE_FAMILIES]


def software(products, signals):
    seen = {name for p in products or [] for name, rx in _FAMILY_RE if rx.search(p)}
    if "exchange_onprem" in (signals or []):
        seen.add("Microsoft Exchange")
    return [name for name, _ in SOFTWARE_FAMILIES if name in seen]


def industry(*texts):
    blob = " ".join(t for t in texts if t).lower()
    for name, rx in INDUSTRY_RULES:
        if re.search(rx, blob):
            return name
    return None


def mask(v, on):
    """203.0.113.7 -> 203.0.113.x: the public demo must not be a target list of vulnerable hosts."""
    return IPV4.sub(r"\1.x", v) if on and isinstance(v, str) else v


CATALOG = json.load(open(os.path.join(os.path.dirname(__file__), "..", "web", "src", "catalog.json")))
PUBLIC_NAME = re.compile(r"(universi|college|ministry|municipal|\.edu|\.ac\.|\.gov|\.gob\.|\.mil\b)", re.I)


def sector(ind, name, org):
    """ICP sector, stored on each served account so every reader filters it the same way."""
    if ind == "Telecom & hosting":
        return "infra"
    if ind in ("Education", "Government") or PUBLIC_NAME.search(f"{name} {org or ''}"):
        return "public"
    return "commercial"


PEER_MIN = 30
COUNTRY_NAMES = {"US": "the US", "GB": "the UK", "DE": "Germany", "FR": "France", "JP": "Japan", "CN": "China", "IN": "India",
                 "NL": "the Netherlands", "BR": "Brazil", "SG": "Singapore", "AU": "Australia", "IT": "Italy", "CA": "Canada",
                 "KR": "South Korea", "IE": "Ireland", "HK": "Hong Kong", "ID": "Indonesia", "TW": "Taiwan", "ES": "Spain",
                 "PL": "Poland", "TH": "Thailand", "FI": "Finland", "VN": "Vietnam", "SE": "Sweden", "RU": "Russia",
                 "AR": "Argentina", "CZ": "Czechia", "MX": "Mexico", "CH": "Switzerland", "TR": "Turkey"}


def add_peer_benchmarks(con, build_dir, accounts):
    """Peer benchmark: an account's risk (need x urgency, fit left out) ranked among companies like it,
    over every scored company in the scan, not just the exported top. Peer industries use the keyword
    rules, applied the same way to every company, so the pool is not skewed towards top accounts that
    got LLM labels; an industry group is used only when that rule agrees with the industry the app shows.
    Most specific group with at least PEER_MIN peers wins: industry + country, then industry, then country."""
    import bisect
    pool = con.execute(f"""select company_id, display_name, business_org, domain, country, need * urgency
                           from '{build_dir}/accounts.parquet'""").fetchall()
    groups, rule_ind, risk_of = {}, {}, {}
    for cid, name, borg, dom, cc, risk in pool:
        ind = industry(dom, borg, name)
        rule_ind[cid], risk_of[cid] = ind, risk
        keys = [(None, cc)] + ([(ind, cc), (ind, None)] if ind else [])
        for key in keys:
            groups.setdefault(key, []).append(risk)
    for v in groups.values():
        v.sort()
    for acc in accounts:
        ind = acc["industry"] if rule_ind.get(acc["id"]) == acc["industry"] else None
        cc, r = acc["country"], risk_of[acc["id"]]
        acc["peer"] = None
        for key in ([(ind, cc), (ind, None)] if ind else []) + [(None, cc)]:
            risks = groups.get(key, [])
            n = len(risks)
            if n - 1 < PEER_MIN:
                continue
            rank = n - bisect.bisect_right(risks, r) + 1  # 1 = most exposed in the group
            noun = f"{key[0].lower()} organisations" if key[0] else "companies"
            where = f" in {COUNTRY_NAMES.get(key[1], key[1])}" if key[1] else " in this scan"
            acc["peer"] = {"rank": rank, "n": n, "pct": round(100 * bisect.bisect_left(risks, r) / (n - 1)),
                           "group": f"{noun}{where}"}
            break


def size_bucket(n_ips):
    """Estate size, as the ICP panel offers it: small 1-5 IPs, mid 6-50, large above 50."""
    return "small" if n_ips <= 5 else "mid" if n_ips <= 50 else "large"


def _schema():
    import pyarrow as pa
    s, d, b, i = pa.string(), pa.float64(), pa.bool_(), pa.int64()
    return pa.schema([
        ("id", s), ("name", s), ("org", s), ("country", s), ("score", d), ("tier", s), ("play", s),
        ("ips", i), ("assets", i), ("ident", s), ("strong", b), ("signals", pa.list_(s)), ("kev", b), ("eol", b),
        ("maturity", pa.list_(s)), ("products", pa.list_(s)), ("need", d), ("urgency", d), ("fit", d),
        ("priority", d), ("industry", s), ("new", b), ("software", pa.list_(s)), ("sector", s), ("size", s),
        ("peer", pa.struct([("rank", i), ("n", i), ("pct", i), ("group", s)])), ("search", s),
    ])


STRONG = {"cert", "ntlm", "http_host", "same_ip"}


def build_accounts(con, build_dir, limit=None):
    rows = con.execute(f"""
        select company_id, display_name, business_org, top_org, country, score::double, tier, play,
               n_ips, n_assets, identity_source, signals, has_kev, has_eol, maturity, products,
               round(need, 2)::double, round(urgency, 2)::double, round(fit, 2)::double, round(priority, 4)::double,
               org_industry, domain, has_new, products_all
        from '{build_dir}/accounts.parquet'
        where has_material order by priority desc {f'limit {int(limit)}' if limit else ''}""").fetchall()
    dom_ind = {}
    if os.path.exists(DOMAIN_LABELS):
        for r in csv.DictReader(open(DOMAIN_LABELS)):
            if r["industry"] not in ("Unknown", "Other") and r["confidence"] != "low":
                dom_ind[r["domain"]] = r["industry"]
    accounts = []
    for (cid, name, borg, torg, cc, score, tier, play, n_ips, n_assets, ident, sigs, kev, eol, mat,
         prods, need, urg, fit, prio, llm_ind, domain, new, prods_all) in rows:
        ind = dom_ind.get(domain) or llm_ind or industry(domain, borg, name)
        org = borg or torg
        accounts.append({
            "id": cid, "name": name, "org": org, "country": cc, "score": score, "tier": tier,
            "play": play, "ips": n_ips, "assets": n_assets, "ident": ident, "strong": ident in STRONG,
            "signals": sigs, "kev": kev, "eol": eol, "maturity": mat, "products": [p for p in (prods or []) if p][:6],
            "need": need, "urgency": urg, "fit": fit, "priority": prio, "industry": ind, "new": bool(new),
            "software": software(prods_all, sigs), "sector": sector(ind, name, org), "size": size_bucket(n_ips),
            "search": f"{name} {org or ''}".lower(),
        })
    add_peer_benchmarks(con, build_dir, accounts)
    return accounts


def _prev_accounts(prev_dir):
    path = os.path.join(prev_dir, "accounts.parquet")
    return path if os.path.exists(path) else None


def first_ranked_sql(prev_dir, build_id):
    """The build an account first became a ranked account in, carried over from the previous build,
    so "new since this saved search last ran" is one filter (first_ranked > last run), with no
    per-user snapshot of results to store. It is carried by account id, so a change to the identity
    rules (which renames companies) must re-baseline it; a company registry with aliases is what lets
    it survive renames."""
    prev = _prev_accounts(prev_dir)
    has_col = prev and "first_ranked" in duckdb.connect().execute(f"select * from '{prev}' limit 0").fetchdf().columns
    return f"coalesce(p.first_ranked, '{build_id}')" if has_col else f"'{build_id}'"


def first_ranked_join(prev_dir):
    prev = _prev_accounts(prev_dir)
    has_col = prev and "first_ranked" in duckdb.connect().execute(f"select * from '{prev}' limit 0").fetchdf().columns
    return f"left join (select id, first_ranked from '{prev}') p on p.id = r.id" if has_col else ""


def write_cube(con, out):
    """Pre-aggregated counts over the low-cardinality ICP dimensions. Its size depends on how many
    (template, country, sector, industry, size) combinations exist, not on how many accounts there are,
    so template counts and the ICP panel's badges stay instant however large the market grows."""
    from api.rules import CATALOG, template_sql
    ids = [CATALOG["market"]["id"]] + [t["id"] for t in CATALOG["templates"]]
    union = " union all ".join(
        f"select '{t}' template, country, sector, industry, size, count(*) n from '{out}/accounts.parquet' "
        f"where {template_sql(t)} group by all" for t in ids)
    con.execute(f"copy ({union} order by template) to '{out}/cube.parquet' (format parquet)")


def check(con, out):
    """Refuse to publish a store that would leak a full IP address or is obviously broken."""
    leaks = con.execute(f"""select count(*) from '{out}/evidence.parquet'
        where regexp_matches(coalesce(ip,'') || ' ' || coalesce(e,'') || ' ' || coalesce(t,'') || ' ' || coalesce(cn,''),
                             '{IPV4_SQL}')""").fetchone()[0]
    assert leaks == 0, f"{leaks} evidence rows still carry a full IP address"
    n, ids = con.execute(f"select count(*), count(distinct id) from '{out}/accounts.parquet'").fetchone()
    assert n > 0 and n == ids, f"accounts: {n} rows, {ids} distinct ids"
    orphans = con.execute(f"""select count(*) from '{out}/evidence.parquet' e
        anti join '{out}/accounts.parquet' a on e.company_id = a.id""").fetchone()[0]
    assert orphans == 0, f"{orphans} evidence rows for unknown accounts"


def main():
    import pyarrow as pa
    import pyarrow.parquet as pq

    from pipeline import cve_index
    ap = argparse.ArgumentParser()
    ap.add_argument("build_dir")
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--limit", type=int, default=None, help="only the top N accounts (tests, small demos)")
    ap.add_argument("--rebaseline", action="store_true",
                    help="the identity or scoring rules changed: start first_ranked afresh, or renamed companies look new")
    a = ap.parse_args()
    t0 = time.time()
    build_id = time.strftime("%Y%m%dT%H%M%S")
    final = os.path.join(a.out, build_id)
    tmp = final + ".partial"
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    con = duckdb.connect()

    accounts = build_accounts(con, a.build_dir, a.limit)
    pq.write_table(pa.Table.from_pylist(accounts, schema=_schema()), f"{tmp}/accounts.raw.parquet")
    # one boolean column per signal template, computed from the catalogue rules once per build;
    # sorted by tier then priority (the order search shows), so "the top N for this filter" reads the first row groups only
    from api.rules import TEMPLATES, flag, rule_sql
    flags = ", ".join(f"{rule_sql(t)} as {flag(t)}" for t in TEMPLATES)
    prev = "" if a.rebaseline else os.path.join(a.out, "current")
    # re-baselining marks every account present now as already seen (a marker older than any build),
    # so neither renamed companies nor saved searches made before it see a flood of "new"
    first = f"'{BASELINE}'" if a.rebaseline else first_ranked_sql(prev, build_id)
    con.execute(f"""copy (select r.*, {first} as first_ranked, {flags} from '{tmp}/accounts.raw.parquet' r
        {first_ranked_join(prev)} order by tier, priority desc, id)
        to '{tmp}/accounts.parquet' (format parquet, row_group_size 16384)""")
    os.remove(f"{tmp}/accounts.raw.parquet")
    con.execute(f"""copy (select * from '{tmp}/accounts.parquet' order by id)
        to '{tmp}/accounts_by_id.parquet' (format parquet, row_group_size 16384)""")

    m = f"'{IPV4_SQL}', '\\1.x', 'g'"
    con.execute(f"""copy (
        select e.company_id, e.signal s, regexp_replace(e.ip, {m}) ip, e.port, e.product p,
               regexp_replace(e.evidence, {m}) e, regexp_replace(e.http_title, {m}) t, regexp_replace(e.cert_cn, {m}) cn
        from '{a.build_dir}/evidence.parquet' e semi join '{tmp}/accounts.parquet' a on e.company_id = a.id
        -- one row per service and finding: the crawl can observe a service twice (two host names on one
        -- IP:port), which would show as a repeated line; the latest observation stands for it
        qualify row_number() over (partition by e.company_id, e.signal, e.ip, e.port, e.evidence order by e.ts desc) = 1
        order by e.company_id) to '{tmp}/evidence.parquet' (format parquet, row_group_size 16384)""")
    write_cube(con, tmp)
    cve = cve_index.build(con, a.build_dir, tmp)
    check(con, tmp)

    funnel = json.load(open(f"{a.build_dir}/funnel.json"))
    n_ev, n_cube = (con.execute(f"select count(*) from '{tmp}/{f}.parquet'").fetchone()[0] for f in ("evidence", "cube"))
    meta = {
        "build_id": build_id, "generated_from": f"scan data observed {funnel.get('observed_from', '?')[:16]} to {funnel.get('observed_to', '?')[:16]} UTC ({funnel['raw_records']:,} banners)", "ips_masked": True,
        "funnel": funnel, "signals": {sid: {"label": label, "category": cat, "weight": w} for sid, cat, w, label, _, _ in SIGNALS},
        "maturity": {mid: label for mid, _, label in MATURITY},
        "rows": {"accounts": len(accounts), "evidence": n_ev, "cube": n_cube, **cve},
    }
    json.dump(meta, open(f"{tmp}/meta.json", "w"), indent=1)
    os.rename(tmp, final)
    link = os.path.join(a.out, "current")
    os.symlink(build_id, link + ".new")
    os.replace(link + ".new", link)  # atomic swap: readers see the old build or the new one, never a mix
    # keep the last few builds: a bad build is rolled back by moving the pointer, and builds can be diffed
    builds = sorted(d for d in os.listdir(a.out) if d[:1].isdigit() and not d.endswith(".partial"))
    for old in builds[:-RETAIN_BUILDS]:
        shutil.rmtree(os.path.join(a.out, old))
    print(json.dumps({"build": final, "seconds": round(time.time() - t0, 1), **meta["rows"]}))


if __name__ == "__main__":
    main()
