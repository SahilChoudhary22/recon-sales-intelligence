"""Measure the pipeline against blind gold labels (data/eval/identity_gold.csv).

  label accuracy : LLM org_type vs the gold entity_type, for gold accounts the labeler also saw
  precision      : share of gold-sampled accounts a build still puts in P1/P2 that are sellable,
                   and how many unsellable ones it removed from the top tiers

usage: python -m pipeline.evaluate <build_dir>
"""
import argparse
import json
import os

import duckdb

LABEL_CACHE = "data/labels/llm_cache.jsonl"
BUYER = {"business", "government", "education", "public_sector"}
INFRA = {"isp_telecom", "hosting_cloud"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("build_dir")
    a = ap.parse_args()
    con = duckdb.connect()
    con.execute("create view gold as select * from read_csv('data/eval/identity_gold.csv', all_varchar=true)")
    con.execute("create view sample as select * from read_csv('data/eval/identity_sample.csv', all_varchar=true)")
    con.execute(f"create view acc as select * from '{a.build_dir}/accounts.parquet'")
    out = {}

    # --- label accuracy: the gold set's display names that the labeler also labelled -----------
    if not os.path.exists(LABEL_CACHE):
        con.execute("create view labels as select ''::varchar key, ''::varchar org_type, ''::varchar confidence where false")
    else:
        con.execute(f"create view labels as select * from read_json_auto('{LABEL_CACHE}')")
    rows = con.execute("""
        select g.entity_type, l.org_type, l.confidence
        from gold g join sample s using (company_id)
        join labels l on l.key = case when s.company_id like 'org:%' then replace(s.company_id, 'org:', '')
                                      else s.company_id end""").fetchall()
    scored = [(gt, lt, c) for gt, lt, c in rows if gt != "unknown" and lt != "unknown"]
    agree = sum((gt in BUYER) == (lt in BUYER) for gt, lt, _ in scored)
    out["label_overlap"] = len(rows)
    out["label_buyer_vs_infra_accuracy"] = round(agree / len(scored), 3) if scored else None
    out["label_compared"] = len(scored)
    out["label_confusion"] = {f"gold={gt} / llm={lt}": n for (gt, lt), n in
                              sorted(_count((gt, lt) for gt, lt, _ in rows).items())}

    # --- precision of the top tiers on the gold sample ------------------------------------------
    res = con.execute("""
        select s.stratum, g.sellable, coalesce(a.tier, 'dropped') tier
        from gold g join sample s using (company_id) left join acc a using (company_id)""").fetchall()
    top = [r for r in res if r[2] in ("P1", "P2")]
    out["gold_accounts"] = len(res)
    out["gold_in_top_tiers"] = len(top)
    out["top_tier_precision"] = round(sum(r[1] == "yes" for r in top) / len(top), 3) if top else None
    out["unsellable_removed_from_top"] = sum(1 for r in res if r[0] == "top3000" and r[1] == "no"
                                             and r[2] not in ("P1", "P2"))
    out["sellable_lost_from_top"] = sum(1 for r in res if r[0] == "top3000" and r[1] == "yes"
                                        and r[2] not in ("P1", "P2"))
    print(json.dumps(out, indent=2))


def _count(it):
    d = {}
    for k in it:
        d[k] = d.get(k, 0) + 1
    return d


if __name__ == "__main__":
    main()
