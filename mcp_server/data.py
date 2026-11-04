"""Read-only access to Recon's published data, for the MCP server.

Reads exactly what the web app reads (IP-masked): accounts.json, the evidence shards and the CVE
index, from a local folder or the hosted app. Signal templates, products and sectors come from the
same catalogue the app uses (web/src/catalog.json), so both always agree on what a template matches.

  RECON_DATA     folder or base URL of the published data (default: web/public/data in this repo)
  RECON_APP_URL  where links should point (default: http://localhost:5173)
"""
import csv
import io
import json
import os
import urllib.parse
import urllib.request
from functools import lru_cache

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.environ.get("RECON_DATA", os.path.join(ROOT, "web", "public", "data")).rstrip("/")
APP_URL = os.environ.get("RECON_APP_URL", "http://localhost:5173").rstrip("/")
CATALOG = json.load(open(os.path.join(ROOT, "web", "src", "catalog.json")))
STRONG_IDENTITY = {"cert", "ntlm", "http_host", "same_ip"}
TEMPLATES = {t["id"]: t for t in CATALOG["templates"]}
PRODUCTS = dict(CATALOG["products"])
SECTORS = dict(CATALOG["sectors"])


def _read(path):
    if DATA.startswith(("http://", "https://")):
        with urllib.request.urlopen(f"{DATA}/{path}", timeout=30) as r:  # noqa: S310 (our own published data)
            return json.loads(r.read())
    with open(f"{DATA}/{path}") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def dataset():
    return _read("accounts.json")


@lru_cache(maxsize=1)
def accounts_by_id():
    return {a["id"]: a for a in dataset()["accounts"]}


@lru_cache(maxsize=64)
def evidence_shard(n):
    return _read(f"evidence/{n:02d}.json")


@lru_cache(maxsize=1)
def cve_index():
    return _read("cve/index.json")


@lru_cache(maxsize=256)
def cve_file(cve):
    return _read(f"cve/{cve}.json")


def matches(a, rule):
    """Same semantics as web/src/plays.ts: an OR of clauses, each an AND of conditions."""
    for c in rule:
        if ((not c.get("signals") or any(s in a["signals"] for s in c["signals"]))
                and ("kev" not in c or a["kev"] == c["kev"])
                and (not c.get("tier") or a["tier"] == c["tier"])
                and ("maturity" not in c or bool(a["maturity"]) == c["maturity"])
                and ("new" not in c or a["new"] == c["new"])):
            return True
    return False


def in_template(a, template):
    return template in ("", "market") or matches(a, TEMPLATES[template]["rule"])


def icp(a, country="", industry="", sector="", software="", strong_identity=False):
    return ((not country or a["country"] == country.upper())
            and (not industry or (a["industry"] or "").lower() == industry.lower())
            and (not sector or a["sector"] == sector)
            and (not software or any(software.lower() in s.lower() for s in a["software"]))
            and (not strong_identity or a["ident"] in STRONG_IDENTITY))


def signal_label(sig):
    return dataset()["signals"].get(sig, {}).get("label", sig)


def summary(a):
    """The compact form tools return: enough to rank and pitch, small enough to keep context lean."""
    return {
        "id": a["id"], "name": a["name"], "organisation": a["org"], "country": a["country"],
        "industry": a["industry"], "sector": SECTORS.get(a["sector"], a["sector"]),
        "score": round(a["score"]), "tier": a["tier"], "identified_by": a["ident"],
        "why_now": [signal_label(s) for s in a["signals"][:4]],
        "software_seen": a["software"][:6], "ips": a["ips"], "services": a["assets"],
        "newly_exposed": a["new"], "app_link": account_link(a["id"]),
        "peer_benchmark": (f"#{a['peer']['rank']} of {a['peer']['n']} {a['peer']['group']} by external exposure"
                           if a.get("peer") else None),
        "exposure_brief": f"{APP_URL}/?brief={urllib.parse.quote(a['id'])}",
    }


def account_link(account_id):
    return f"{APP_URL}/?account={urllib.parse.quote(account_id)}"


def view_link(**params):
    q = {k: v for k, v in params.items() if v not in ("", None, False, "market")}
    if q.get("strong"):
        q["strong"] = "1"
    return f"{APP_URL}/?{urllib.parse.urlencode(q)}" if q else f"{APP_URL}/"


def import_link(account_ids):
    """Opening this link adds the accounts to the viewer's My list in the app."""
    return f"{APP_URL}/?{urllib.parse.urlencode({'import': ','.join(account_ids)})}"


def crm_tasks_csv(account_ids):
    """CRM-ready tasks built from variables (company, signal, summary), one row per account."""
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["company", "task_subject", "task_note", "priority", "recon_link"])
    for aid in account_ids:
        a = accounts_by_id().get(aid)
        if not a:
            continue
        top = signal_label(a["signals"][0]) if a["signals"] else "security exposure"
        note = (f"Recon score {round(a['score'])} ({a['tier']}). Why now: "
                + "; ".join(signal_label(s) for s in a["signals"][:3])
                + f". {a['assets']} internet-facing services across {a['ips']} IPs.")
        w.writerow([a["name"], f"Call {a['name']}: {top}", note,
                    {"P1": "High", "P2": "Normal"}.get(a["tier"], "Low"), account_link(aid)])
    return out.getvalue()
