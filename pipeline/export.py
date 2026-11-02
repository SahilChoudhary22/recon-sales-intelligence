"""Scored Parquet -> static JSON for the web app.

  web/public/data/accounts.json      summary rows for every exported account + funnel + signal catalogue
  web/public/data/evidence/NN.json   evidence rows, sharded by company so the UI loads them on demand

usage: python -m pipeline.export <build_dir> [--limit 15000]
"""
import argparse
import csv
import hashlib
import json
import os
import re

import duckdb

from pipeline.signals import MATURITY, SIGNALS

SHARDS = 64
OUT = "web/public/data"
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


def industry(*texts):
    blob = " ".join(t for t in texts if t).lower()
    for name, rx in INDUSTRY_RULES:
        if re.search(rx, blob):
            return name
    return None


def shard(company_id):
    return int(hashlib.md5(company_id.encode()).hexdigest(), 16) % SHARDS


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("build_dir")
    ap.add_argument("--limit", type=int, default=15000)
    a = ap.parse_args()
    con = duckdb.connect()
    rows = con.execute(f"""
        select company_id, display_name, business_org, top_org, country, score::double, tier, play,
               n_ips, n_assets, identity_source, signals, has_kev, has_eol, maturity, products,
               round(need, 2)::double, round(urgency, 2)::double, round(fit, 2)::double, round(priority, 2)::double, org_industry, domain
        from '{a.build_dir}/accounts.parquet'
        where has_material order by priority desc limit {a.limit}""").fetchall()
    dom_ind = {}
    if os.path.exists(DOMAIN_LABELS):
        for r in csv.DictReader(open(DOMAIN_LABELS)):
            if r["industry"] not in ("Unknown", "Other") and r["confidence"] != "low":
                dom_ind[r["domain"]] = r["industry"]
    accounts, keep = [], set()
    for (cid, name, borg, torg, cc, score, tier, play, n_ips, n_assets, ident, sigs, kev, eol, mat,
         prods, need, urg, fit, prio, llm_ind, domain) in rows:
        keep.add(cid)
        llm_ind = dom_ind.get(domain) or llm_ind
        accounts.append({
            "id": cid, "name": name, "org": borg or torg, "country": cc, "score": score, "tier": tier,
            "play": play, "ips": n_ips, "assets": n_assets, "ident": ident, "signals": sigs, "kev": kev,
            "eol": eol, "maturity": mat, "products": [p for p in (prods or []) if p][:6],
            "need": need, "urgency": urg, "fit": fit, "priority": prio,
            "industry": llm_ind or industry(domain, borg, name), "shard": shard(cid),
        })
    ev = con.execute(f"""select company_id, signal, ip, port, product, evidence, http_title, cert_cn
        from '{a.build_dir}/evidence.parquet'""").fetchall()
    shards = [dict() for _ in range(SHARDS)]
    for cid, sig, ip, port, prod, evid, title, cn in ev:
        if cid in keep:
            shards[shard(cid)].setdefault(cid, []).append(
                {"s": sig, "ip": ip, "port": port, "p": prod, "e": evid, "t": title, "cn": cn})
    os.makedirs(f"{OUT}/evidence", exist_ok=True)
    for i, s in enumerate(shards):
        with open(f"{OUT}/evidence/{i:02d}.json", "w") as f:
            json.dump(s, f, separators=(",", ":"))
    funnel = json.load(open(f"{a.build_dir}/funnel.json"))
    meta = {
        "generated_from": "scan 2026-11-01 (13.4M banners)",
        "funnel": funnel,
        "signals": {sid: {"label": label, "category": cat, "weight": w} for sid, cat, w, label, _, _ in SIGNALS},
        "maturity": {mid: label for mid, _, label in MATURITY},
        "accounts": accounts,
    }
    with open(f"{OUT}/accounts.json", "w") as f:
        json.dump(meta, f, separators=(",", ":"))
    print(f"exported {len(accounts)} accounts, {sum(len(s) for s in shards)} with evidence "
          f"-> {os.path.getsize(f'{OUT}/accounts.json') / 1e6:.1f} MB summary")


if __name__ == "__main__":
    main()
