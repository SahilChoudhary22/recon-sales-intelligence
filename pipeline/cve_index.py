"""CVE-in-the-news index: which companies does a given CVE affect?

Built from the notable CVEs per service (build.py writes asset_cves.parquet) and enriched with the
current CISA KEV catalogue (data/enrichment/cisa_kev.json), so a CVE added to KEV after the scan is
still recognised and mapped to the product it affects. Called by pipeline/export.py; writes into the
serving store:

  cve_hits.parquet   one row per (CVE, company): services affected, product, examples (masked),
                     and whether the company is a served account; sorted by CVE so a lookup reads
                     one row group
  cve_index.json     every known CVE: facts, KEV status today, companies affected, plus nicknames
                     ("Citrix Bleed") and product families for the fallback search
"""
import json
import os

import pyarrow as pa
import pyarrow.parquet as pq

from pipeline.export import _FAMILY_RE, mask
from pipeline.signals import NOISE_CVES

KEV_PATH = "data/enrichment/cisa_kev.json"
NOISE = set(eval(NOISE_CVES))  # the same list the scoring ignores
EXAMPLES_PER_COMPANY = 3

# names security sellers actually hear in the news -> CVE ids (kept small and checkable)
NICKNAMES = {
    "citrix bleed": ["CVE-2023-4966"],
    "citrix bleed 2": ["CVE-2025-5777"],
    "proxyshell": ["CVE-2021-34473", "CVE-2021-34523", "CVE-2021-31207"],
    "proxylogon": ["CVE-2021-26855", "CVE-2021-26857", "CVE-2021-26858", "CVE-2021-27065"],
    "log4shell": ["CVE-2021-44228"],
    "heartbleed": ["CVE-2014-0160"],
    "bluekeep": ["CVE-2019-0708"],
    "eternalblue": ["CVE-2017-0144"],
    "shellshock": ["CVE-2014-6271"],
    "moveit": ["CVE-2023-34362"],
    "fortijump": ["CVE-2024-47575"],
    "rapid reset": ["CVE-2023-44487"],
}


def family(text):
    return next((name for name, rx in _FAMILY_RE if rx.search(text or "")), None)


def build(con, build_dir, out, kev_path=KEV_PATH):
    funnel = json.load(open(f"{build_dir}/funnel.json"))
    scan_date = funnel.get("observed_to", "")[:10] or "unknown"
    served = {r[0] for r in con.execute(f"select id from '{out}/accounts.parquet'").fetchall()}

    kev = {}
    kev_meta = {}
    if os.path.exists(kev_path):
        doc = json.load(open(kev_path))
        kev_meta = {"version": doc.get("catalogVersion"), "released": doc.get("dateReleased", "")[:10]}
        for v in doc["vulnerabilities"]:
            kev[v["cveID"]] = {
                "added": v.get("dateAdded"), "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
                "vendor": v.get("vendorProject"), "product": v.get("product"), "name": v.get("vulnerabilityName"),
            }

    rows = con.execute(f"""
        with x as (
            select c.company_id, c.ip, c.port, c.product, c.is_new, unnest(c.cves) v
            from '{build_dir}/asset_cves.parquet' c)
        select v.cve, any_value(v.cvss), max(v.epss), bool_or(v.kev), x.company_id,
               count(*) n, list(distinct x.ip || ':' || x.port)[1:{EXAMPLES_PER_COMPANY}] svc,
               mode(x.product order by x.product) product, bool_or(x.is_new) is_new,
               any_value(ac.display_name), any_value(ac.country), any_value(ac.score)::double,
               any_value(ac.tier), any_value(ac.identity_source)
        from x join '{build_dir}/accounts.parquet' ac using (company_id)
        group by v.cve, x.company_id""").fetchall()

    by_cve = {}
    facts = {}
    for cve, cvss, epss, kev_flag, cid, n, svc, product, new, name, cc, score, tier, ident in rows:
        f = facts.setdefault(cve, {"cvss": cvss, "epss": epss, "kevInScan": bool(kev_flag), "companies": 0,
                                   "inScan": True, "noise": cve in NOISE, "products": {}})
        f["companies"] += 1
        if product:
            f["products"][product] = f["products"].get(product, 0) + 1
        by_cve.setdefault(cve, []).append({
            "id": cid, "name": name, "country": cc, "score": score, "tier": tier, "ident": ident,
            "served": cid in served, "n": n, "product": product, "new": bool(new),
            "services": [mask(s, True) for s in (svc or [])],
        })

    for cve, f in facts.items():
        k = kev.get(cve)
        f["kev"] = bool(k) or f["kevInScan"]
        if k:
            f.update({"kevAdded": k["added"], "ransomware": k["ransomware"], "vendor": k["vendor"],
                      "product": k["product"], "title": k["name"]})
        top = max(f.pop("products").items(), key=lambda kv: kv[1])[0] if f.get("products") else None
        f["family"] = family(f"{f.get('vendor', '')} {f.get('product', '')}") or family(top or "")
        f["seenProduct"] = top
    # CVEs on the KEV list today that this scan never matched: the "in the news" case
    for cve, k in kev.items():
        if cve not in facts:
            facts[cve] = {"inScan": False, "kev": True, "companies": 0, "inApp": 0, "kevAdded": k["added"], "ransomware": k["ransomware"],
                          "vendor": k["vendor"], "product": k["product"], "title": k["name"], "noise": cve in NOISE,
                          "family": family(f"{k['vendor']} {k['product']}")}

    hits = []
    for cve, companies in by_cve.items():
        companies.sort(key=lambda c: -(c["score"] or 0))
        facts[cve]["inApp"] = sum(c["served"] for c in companies)
        hits += [{"cve": cve, "company_id": c["id"], "n": c["n"], "product": c["product"], "new": c["new"],
                  "services": c["services"], "name": c["name"], "country": c["country"], "score": c["score"],
                  "served": c["served"]} for c in companies]
    pq.write_table(pa.Table.from_pylist(hits), f"{out}/cve_hits.parquet", row_group_size=16384)
    index = {"scanDate": scan_date, "kev": kev_meta, "cves": facts, "nicknames": NICKNAMES}
    with open(f"{out}/cve_index.json", "w") as fh:
        json.dump(index, fh, separators=(",", ":"))
    in_scan = sum(1 for f in facts.values() if f["inScan"])
    return {"cve_hits": len(hits), "cves_in_scan": in_scan, "kev_only": len(facts) - in_scan}
