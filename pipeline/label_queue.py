"""Queue the names of top-tier accounts that have no label yet, as TSV chunks for labeling
(by any batch labeler), plus the items.json that merge_labels reads.

Re-run after each rebuild: re-ranking promotes new names, and only unlabeled ones are queued.

usage: python -m pipeline.label_queue <build_dir> <queue_dir> [--chunks 4] [--tiers P1,P2]
"""
import argparse
import json
import os
import re

import duckdb

from pipeline.llm_label import load_cache

IPV4 = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("build_dir")
    ap.add_argument("queue_dir")
    ap.add_argument("--chunks", type=int, default=4)
    ap.add_argument("--tiers", default="P1,P2")
    a = ap.parse_args()
    tiers = ",".join(f"'{t}'" for t in a.tiers.split(","))
    con = duckdb.connect()
    acc, ev = f"'{a.build_dir}/accounts.parquet'", f"'{a.build_dir}/evidence.parquet'"
    rows = con.execute(f"""
        with top as (select * from {acc} where tier in ({tiers})),
        ctx as (select company_id, string_agg(distinct left(coalesce(cert_cn,''),40), '; ') certs,
                       string_agg(distinct left(coalesce(http_title,''),50), '; ') titles
                from {ev} where company_id in (select company_id from top) group by 1)
        select case when company_id like 'org:%' then 'org' else 'domain' end,
               case when company_id like 'org:%' then replace(company_id,'org:','') else domain end,
               country, top_org, n_ips, left(coalesce(certs,''),120), left(coalesce(titles,''),120)
        from top left join ctx using (company_id) order by priority desc""").fetchall()
    cache = load_cache()
    items = []
    for kind, key, cc, org, n, certs, titles in rows:
        if (kind, key) in cache:
            continue
        ctx = f"ips={n}; certs={certs}; titles={titles}" if kind == "org" else f"ip_owner={org}; ips={n}; titles={titles}"
        ctx = IPV4.sub(r"\1.x", ctx).replace("\t", " ").replace("\n", " ")
        items.append({"kind": kind, "key": key, "country": cc, "context": ctx})
    os.makedirs(a.queue_dir, exist_ok=True)
    for c in range(a.chunks):
        with open(f"{a.queue_dir}/chunk_{c}.tsv", "w") as f:
            f.write("id\tkind\tname\tcountry\tcontext\n")
            for i, it in enumerate(items):
                if i % a.chunks == c:
                    f.write(f"{i}\t{it['kind']}\t{it['key']}\t{it['country'] or '?'}\t{it['context']}\n")
    json.dump(items, open(f"{a.queue_dir}/items.json", "w"))
    print(f"queued {len(items)} unlabeled names in {a.chunks} chunks -> {a.queue_dir}")


if __name__ == "__main__":
    main()
