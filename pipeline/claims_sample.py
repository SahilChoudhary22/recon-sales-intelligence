"""Blind sample for checking claims: does the scan evidence support what Recon says about an account?

Draws N random P1/P2 accounts from each of two builds (the build before a change and after it),
skipping accounts used in earlier gold sets, and writes one shuffled file of cases under neutral ids,
so a reviewer can't tell which build a case came from. For each account: its identity (as in the
identity gold sets) and up to MAX_CLAIMS risk claims (hygiene left out), each with the raw scan
fields behind it. Every IP is masked to /24. The key (case -> build, account) is written separately
and never shown to reviewers.

usage: python -m pipeline.claims_sample <before_build_dir> <after_build_dir> "<scan glob>" <out_prefix>
       (before_build_dir "-" samples one build only: a fresh holdout)
"""
import argparse
import glob
import json
import random

import duckdb

from pipeline.export import mask

N, MAX_CLAIMS, SEED = 60, 4, 20261104
HYGIENE = "('cert_expired', 'cert_expiring', 'weak_tls', 'self_signed_web')"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("before")
    ap.add_argument("after")
    ap.add_argument("scan_glob")
    ap.add_argument("out_prefix")
    a = ap.parse_args()
    con = duckdb.connect()
    con.execute("set memory_limit='3GB'")
    used = set()
    for f in glob.glob("data/eval/identity_sample*.csv"):
        used |= {r[0] for r in con.execute(f"select company_id from read_csv('{f}', all_varchar=true)").fetchall()}
    for f in glob.glob("data/eval/claims_*_key.json"):  # and every account an earlier claims sample showed
        used |= {v["company_id"] for v in json.load(open(f)).values()}
    builds = [("after", a.after)] if a.before == "-" else [("before", a.before), ("after", a.after)]

    rng = random.Random(SEED)
    picks = []
    for build, d in builds:
        ids = [r[0] for r in con.execute(f"""select company_id from '{d}/accounts.parquet'
            where tier in ('P1', 'P2') order by company_id""").fetchall() if r[0] not in used]
        picks += [(build, d, cid) for cid in rng.sample(ids, N)]
    con.execute("create table pick (build varchar, dir varchar, company_id varchar)")
    con.executemany("insert into pick values (?, ?, ?)", picks)

    # the strongest evidence row per signal, for the sampled accounts of each build
    parts = []
    for build, d in builds:
        parts.append(f"""select '{build}' build, e.company_id, e.signal, e.label, e.evidence, e.ip, e.port, e.weight
            from '{d}/evidence.parquet' e join pick p on p.company_id = e.company_id and p.build = '{build}'
            where e.signal not in {HYGIENE}
            qualify row_number() over (partition by e.company_id, e.signal order by e.weight desc, e.ip, e.port) = 1""")
    con.execute("create table ev as " + " union all ".join(parts))
    # one read of the scan, limited to the services those rows name
    con.execute(f"""create table raw as
        select ip, port, any_value(module) module, any_value(product) product, any_value(version) version,
               any_value(http_server) http_server, any_value(http_title) http_title, any_value(os) os,
               any_value(tags) tags, any_value(left(banner, 300)) banner
        from read_parquet('{a.scan_glob}') where (ip, port) in (select ip, port from ev) group by ip, port""")

    cases = []
    for build, d, cid in picks:
        acc = con.execute(f"""select display_name, identity_source, top_org, country, n_ips, tier
            from '{d}/accounts.parquet' where company_id = ?""", [cid]).fetchone()
        hosts = con.execute(f"""select list(distinct cert_cn) filter (where cert_cn is not null)[1:5],
                list(distinct http_title) filter (where http_title is not null)[1:5]
            from '{d}/evidence.parquet' where company_id = ?""", [cid]).fetchone()
        claims = con.execute("""select e.label, e.evidence, e.ip, e.port, r.module, r.product, r.version,
                r.http_server, r.http_title, r.os, r.tags, r.banner
            from ev e left join raw r using (ip, port) where e.build = ? and e.company_id = ?
            order by e.weight desc, e.signal limit ?""", [build, cid, MAX_CLAIMS]).fetchall()
        cases.append(({"build": build, "company_id": cid, "tier": acc[5]}, {
            "name": acc[0], "identity_source": acc[1], "network_owner": acc[2], "country": acc[3], "ips": acc[4],
            "certificate_names": [mask(x, True) for x in hosts[0] or []],
            "page_titles": [mask(x, True) for x in hosts[1] or []],
            "claims": [{"claim": c[0], "evidence": mask(c[1], True), "service": mask(f"{c[2]}:{c[3]}", True),
                        "scan": {"module": c[4], "product": c[5], "version": c[6], "server_header": c[7],
                                 "page_title": mask(c[8], True), "os": c[9], "tags": c[10], "banner": mask(c[11], True)}}
                       for c in claims]}))
    rng.shuffle(cases)
    sample, key = [], {}
    for i, (k, case) in enumerate(cases):
        cid = f"c{i + 1:03d}"
        key[cid] = k
        sample.append({"case": cid, **case})
    json.dump(sample, open(f"{a.out_prefix}_sample.json", "w"), indent=1, default=str, ensure_ascii=False)
    json.dump(key, open(f"{a.out_prefix}_key.json", "w"), indent=1)
    print(len(sample), "cases,", sum(len(c["claims"]) for c in sample), "claims")


if __name__ == "__main__":
    main()
