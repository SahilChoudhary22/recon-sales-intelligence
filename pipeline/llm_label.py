"""LLM labels for the long tail the heuristics can't settle: is this WHOIS org an ISP/hoster or a
real business, and what industry is a company in?

Runs only on *distinct* names from top-ranked accounts (thousands, not millions of rows), batched,
cached on disk, and every call's token usage is logged so cost is reported, not estimated.

usage: python -m pipeline.llm_label <build_dir> [--orgs 3000] [--domains 2000] [--model claude-haiku-5-5]
writes data/labels/org_labels.csv, data/labels/domain_labels.csv, data/labels/llm_usage.json
"""
import argparse
import csv
import json
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Literal

import anthropic
import duckdb
from pydantic import BaseModel

LABEL_DIR = "data/labels"
CACHE = f"{LABEL_DIR}/llm_cache.jsonl"
BATCH = 40
# $ per 1M tokens, from the Claude API reference (cached 2026-10-06)
PRICES = {"claude-haiku-5-5": (0.10, 0.50), "claude-sonnet-5-5": (2.00, 10.00), "claude-opus-5-5": (4.00, 20.00)}

OrgType = Literal["isp_telecom", "hosting_cloud", "business", "government", "education", "unknown"]
Industry = Literal["Government", "Education", "Healthcare", "Financial services", "Energy & utilities",
                   "Manufacturing", "Retail & e-commerce", "Logistics & transport", "Media",
                   "Technology & software", "Telecom & hosting", "Professional services",
                   "Hospitality & travel", "Real estate & construction", "Non-profit", "Other", "Unknown"]


class Label(BaseModel):
    id: int
    org_type: OrgType
    industry: Industry
    confidence: Literal["high", "medium", "low"]


class Labels(BaseModel):
    labels: list[Label]


SYSTEM = """You label entities seen in internet scan data for a B2B cybersecurity sales team.
For each item decide:
- org_type: isp_telecom (sells connectivity: ISPs, carriers, mobile operators, cable), hosting_cloud
  (sells servers/hosting/CDN/VPS/colocation), business (any other company that would be a security
  software buyer), government, education, or unknown when the name gives no real clue.
- industry: the buyer's industry. Telecom & hosting for isp_telecom/hosting_cloud.
Judge from the name, country and the hostnames/page titles given. Do not guess from vague names:
use unknown/Unknown with low confidence instead. Return exactly one label per input id."""


def load_cache():
    out = {}
    if os.path.exists(CACHE):
        for line in open(CACHE):
            r = json.loads(line)
            out[(r["kind"], r["key"])] = r
    return out


def label_batch(client, model, kind, items):
    lines = [f'{i}. {it["key"]} | country={it.get("country") or "?"} | {it.get("context") or ""}'
             for i, it in enumerate(items)]
    noun = "WHOIS organisation names" if kind == "org" else "company web domains"
    resp = client.messages.parse(
        model=model,
        max_tokens=4000,
        system=SYSTEM,
        output_config={"effort": "low"},
        messages=[{"role": "user", "content": f"Label these {noun}:\n" + "\n".join(lines)}],
        output_format=Labels,
    )
    got = {lab.id: lab for lab in (resp.parsed_output.labels if resp.parsed_output else [])}
    rows = []
    for i, it in enumerate(items):
        lab = got.get(i)
        rows.append({"kind": kind, "key": it["key"], "org_type": lab.org_type if lab else "unknown",
                     "industry": lab.industry if lab else "Unknown",
                     "confidence": lab.confidence if lab else "low", "model": model})
    return rows, resp.usage.input_tokens, resp.usage.output_tokens


def candidates(build_dir, n_orgs, n_domains):
    con = duckdb.connect()
    acc = f"'{build_dir}/accounts.parquet'"
    ev = f"'{build_dir}/evidence.parquet'"
    # orgs that would be accounts on their own, plus the IP owners behind top domain accounts
    orgs = con.execute(f"""
        with top as (select * from {acc} where has_material order by priority desc)
        select org, any_value(country), any_value(ctx) from (
            select replace(company_id, 'org:', '') org, country, priority,
                   (select string_agg(distinct coalesce(e.cert_cn, e.http_title, ''), '; ')
                    from {ev} e where e.company_id = top.company_id) ctx
            from top where company_id like 'org:%' limit {n_orgs})
        group by org""").fetchall()
    doms = con.execute(f"""
        select domain, country, top_org, (select string_agg(distinct coalesce(e.http_title, ''), '; ')
            from {ev} e where e.company_id = a.company_id) from {acc} a
        where has_material and domain is not null order by priority desc limit {n_domains}""").fetchall()
    return ([{"key": o, "country": c, "context": (x or "")[:160]} for o, c, x in orgs],
            [{"key": d, "country": c, "context": f"ip_owner={o}; titles={(t or '')[:120]}"} for d, c, o, t in doms])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("build_dir")
    ap.add_argument("--orgs", type=int, default=3000)
    ap.add_argument("--domains", type=int, default=2000)
    ap.add_argument("--model", default="claude-haiku-5-5")
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    os.makedirs(LABEL_DIR, exist_ok=True)
    cache = load_cache()
    orgs, doms = candidates(a.build_dir, a.orgs, a.domains)
    todo = [("org", it) for it in orgs if ("org", it["key"]) not in cache] + \
           [("domain", it) for it in doms if ("domain", it["key"]) not in cache]
    print(f"{len(orgs)} orgs + {len(doms)} domains, {len(todo)} not cached")

    client = anthropic.Anthropic()
    jobs = []
    for kind in ("org", "domain"):
        items = [it for k, it in todo if k == kind]
        jobs += [(kind, items[i:i + BATCH]) for i in range(0, len(items), BATCH)]
    tin = tout = 0
    with ThreadPoolExecutor(a.workers) as ex, open(CACHE, "a") as fc:
        for rows, i_tok, o_tok in ex.map(lambda j: label_batch(client, a.model, *j), jobs):
            tin, tout = tin + i_tok, tout + o_tok
            for r in rows:
                cache[(r["kind"], r["key"])] = r
                fc.write(json.dumps(r) + "\n")
    pin, pout = PRICES.get(a.model, (0, 0))
    usage_path = f"{LABEL_DIR}/llm_usage.json"
    usage = json.load(open(usage_path)) if os.path.exists(usage_path) else {"runs": []}
    usage["runs"].append({"model": a.model, "requests": len(jobs), "items": len(todo),
                          "input_tokens": tin, "output_tokens": tout,
                          "cost_usd": round(tin / 1e6 * pin + tout / 1e6 * pout, 4)})
    usage["total_cost_usd"] = round(sum(r["cost_usd"] for r in usage["runs"]), 4)
    json.dump(usage, open(usage_path, "w"), indent=2)

    business = {"business", "government", "education"}
    with open(f"{LABEL_DIR}/org_labels.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["org", "org_type", "industry", "confidence"])
        for (kind, key), r in sorted(cache.items()):
            # only overrule the heuristic when the model is sure
            if kind == "org" and r["confidence"] != "low" and r["org_type"] != "unknown":
                w.writerow([key, "business" if r["org_type"] in business else "isp_or_hosting",
                            None if r["industry"] == "Unknown" else r["industry"], r["confidence"]])
    with open(f"{LABEL_DIR}/domain_labels.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["domain", "org_type", "industry", "confidence"])
        for (kind, key), r in sorted(cache.items()):
            if kind == "domain":
                w.writerow([key, r["org_type"], r["industry"], r["confidence"]])
    print(json.dumps(usage["runs"][-1]))


if __name__ == "__main__":
    main()
