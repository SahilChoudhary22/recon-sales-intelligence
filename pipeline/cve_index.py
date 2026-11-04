"""CVE-in-the-news index: which companies does a given CVE affect?

Built from the notable CVEs per service (build.py writes asset_cves.parquet) and enriched with the
current CISA KEV catalogue (data/enrichment/cisa_kev.json), so a CVE added to KEV after the scan is
still recognised and mapped to the product it affects.

  web/public/data/cve/index.json     every known CVE: facts, KEV status today, companies affected,
                                     plus nicknames ("Citrix Bleed") and product families for fallback
  web/public/data/cve/<CVE>.json     the affected companies, ranked, loaded only when searched:
                                     {"in": [[id, services, product, new, examples]],      accounts in the app
                                      "out": [[name, country, score, services, product]],  the rest, top 300
                                      "outTotal": n}

usage: python -m pipeline.cve_index <build_dir> [--kev data/enrichment/cisa_kev.json]
"""
import argparse
import json
import os
import shutil

import duckdb

from pipeline.export import OUT, _FAMILY_RE, mask
from pipeline.signals import NOISE_CVES

KEV_PATH = "data/enrichment/cisa_kev.json"
SCAN_DATE = "2026-11-01"
NOISE = set(eval(NOISE_CVES))  # the same list the scoring ignores
EXAMPLES_PER_COMPANY = 3
OUTSIDE_CAP = 300  # accounts not in the app's top 15,000 are summarised, not shipped in full

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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("build_dir")
    ap.add_argument("--kev", default=KEV_PATH)
    a = ap.parse_args()
    con = duckdb.connect()
    exported = {r["id"] for r in json.load(open(f"{OUT}/accounts.json"))["accounts"]}

    kev = {}
    kev_meta = {}
    if os.path.exists(a.kev):
        doc = json.load(open(a.kev))
        kev_meta = {"version": doc.get("catalogVersion"), "released": doc.get("dateReleased", "")[:10]}
        for v in doc["vulnerabilities"]:
            kev[v["cveID"]] = {
                "added": v.get("dateAdded"), "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
                "vendor": v.get("vendorProject"), "product": v.get("product"), "name": v.get("vulnerabilityName"),
            }

    rows = con.execute(f"""
        with x as (
            select c.company_id, c.ip, c.port, c.product, c.is_new, unnest(c.cves) v
            from '{a.build_dir}/asset_cves.parquet' c)
        select v.cve, any_value(v.cvss), max(v.epss), bool_or(v.kev), x.company_id,
               count(*) n, list(distinct x.ip || ':' || x.port)[1:{EXAMPLES_PER_COMPANY}] svc,
               mode(x.product) product, bool_or(x.is_new) is_new,
               any_value(ac.display_name), any_value(ac.country), any_value(ac.score)::double,
               any_value(ac.tier), any_value(ac.identity_source)
        from x join '{a.build_dir}/accounts.parquet' ac using (company_id)
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
            "exported": cid in exported, "n": n, "product": product, "new": bool(new),
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
            facts[cve] = {"inScan": False, "kev": True, "companies": 0, "kevAdded": k["added"], "ransomware": k["ransomware"],
                          "vendor": k["vendor"], "product": k["product"], "title": k["name"], "noise": cve in NOISE,
                          "family": family(f"{k['vendor']} {k['product']}")}

    out = f"{OUT}/cve"
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    for cve, companies in by_cve.items():
        companies.sort(key=lambda c: -(c["score"] or 0))
        inside = [[c["id"], c["n"], c["product"], int(c["new"]), c["services"]] for c in companies if c["exported"]]
        outside = [c for c in companies if not c["exported"]]
        doc = {"in": inside, "out": [[c["name"], c["country"], c["score"], c["n"], c["product"]] for c in outside[:OUTSIDE_CAP]],
               "outTotal": len(outside)}
        facts[cve]["inApp"] = len(inside)
        with open(f"{out}/{cve}.json", "w") as fh:
            json.dump(doc, fh, separators=(",", ":"))
    index = {"scanDate": SCAN_DATE, "kev": kev_meta, "cves": facts, "nicknames": NICKNAMES}
    with open(f"{out}/index.json", "w") as fh:
        json.dump(index, fh, separators=(",", ":"))
    in_scan = sum(1 for f in facts.values() if f["inScan"])
    print(json.dumps({"cves_in_scan": in_scan, "kev_only": len(facts) - in_scan, "company_files": len(by_cve),
                      "index_kb": round(os.path.getsize(f"{out}/index.json") / 1024)}))


if __name__ == "__main__":
    main()
