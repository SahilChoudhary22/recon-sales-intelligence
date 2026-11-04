"""Read-only access to Recon's serving store, for the MCP server.

Uses the same query layer as the HTTP API (api/store.py): the same SQL, the same IP-masked data and
the same template rules (compiled from web/src/catalog.json), so the app, the API and an assistant
always give the same answer.

  RECON_SERVE    the serving store (default: data/serve/current in this repo)
  RECON_DB       the app database with users' lists and saved searches (default: data/app/recon.db)
  RECON_USER     whose lists and saved searches the tools work on (a user configured in RECON_USERS)
  RECON_APP_URL  where links should point (default: http://localhost:5173)
"""
import csv
import io
import os
import urllib.parse

from api.rules import CATALOG, TEMPLATES
from api.store import Query, get_store
from api.workspace import get_workspace
from pipeline.export import SOFTWARE_FAMILIES

APP_URL = os.environ.get("RECON_APP_URL", "http://localhost:5173").rstrip("/")
PRODUCTS = dict(CATALOG["products"])
SECTORS = dict(CATALOG["sectors"])
FAMILIES = [name for name, _ in SOFTWARE_FAMILIES]


def store():
    return get_store()


def meta():
    return store().meta


def software_family(text):
    """Loose input ("fortigate", "exchange") -> the family name the data uses, or the text unchanged."""
    t = text.strip().lower()
    return next((f for f in FAMILIES if t and t in f.lower()), text)


def query(template="market", query="", country="", industry="", sector="", software="", strong_identity=False,
          tier="", ids=None):
    return Query.make(template=template or "market", q=query, country=country.upper(), industry=industry,
                      sector=sector, software=software_family(software) if software else (), strong=strong_identity,
                      tier=tier, ids=ids)


def account(account_id):
    return store().account(account_id)


def known_ids(ids):
    found = store().search(Query.make(template="list", ids=ids), 0, 500)["accounts"]
    return {a["id"] for a in found}


def signal_label(sig):
    return meta()["signals"].get(sig, {}).get("label", sig)


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


def list_link(list_id):
    return f"{APP_URL}/?play=list:{urllib.parse.quote(list_id)}"


def search_link(search_id):
    return f"{APP_URL}/?search={urllib.parse.quote(search_id)}"


def saved_query(search, listed):
    """A saved search as a query for what is new since it was last reviewed and in none of the lists."""
    f = search["filters"]
    return Query.make(template=f.get("play", "market"), q=f.get("q", ""), country=f.get("country", []),
                      industry=f.get("industry", []), sector=f.get("sector", []), software=f.get("software", []),
                      size=f.get("size", []), strong=f.get("strong", False), since_build=search["lastRun"] or "",
                      exclude_ids=tuple(listed), **search["profile"])


def workspace_id():
    """The workspace of RECON_USER: the same lists and saved searches the user sees in the app."""
    name = os.environ.get("RECON_USER", "")
    user = get_workspace().user_by_name(name) if name else None
    if not user:
        raise LookupError("Set RECON_USER to a Recon user (one configured in RECON_USERS) to use lists and saved searches.")
    return user["workspace_id"]


def crm_tasks_csv(account_ids):
    """CRM-ready tasks built from variables (company, signal, summary), one row per account."""
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["company", "task_subject", "task_note", "priority", "recon_link"])
    for aid in account_ids:
        a = account(aid)
        if not a:
            continue
        top = signal_label(a["signals"][0]) if a["signals"] else "security exposure"
        note = (f"Recon score {round(a['score'])} ({a['tier']}). Why now: "
                + "; ".join(signal_label(s) for s in a["signals"][:3])
                + f". {a['assets']} internet-facing services across {a['ips']} IPs.")
        w.writerow([a["name"], f"Call {a['name']}: {top}", note,
                    {"P1": "High", "P2": "Normal"}.get(a["tier"], "Low"), account_link(aid)])
    return out.getvalue()
