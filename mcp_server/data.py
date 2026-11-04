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
import re
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


SIZES = {"small": "small", "mid": "mid", "mid-size": "mid", "midsize": "mid", "medium": "mid", "large": "large"}


def values(v):
    """A filter as the tools accept it (one value, a comma-separated string, a list, or nothing) -> a list."""
    if v is None:
        return []
    items = v if isinstance(v, (list, tuple)) else str(v).split(",")
    return [str(x).strip() for x in items if str(x).strip()]


def query(template="market", query="", country=None, industry=None, sector=None, software=None, size=None,
          strong_identity=False, tier="", ids=None, exclude_ids=(), icp=None):
    """The app's search, from tool arguments. Several values in one filter are ORed, as in the app."""
    return Query.make(template=template or "market", q=query, country=[c.upper() for c in values(country)],
                      industry=values(industry), sector=[x.lower() for x in values(sector)],
                      software=[software_family(x) for x in values(software)],
                      size=[SIZES.get(x.lower(), x.lower()) for x in values(size)], strong=strong_identity,
                      tier=tier, ids=ids, exclude_ids=tuple(exclude_ids), **(icp or {}))


def profile_filters(ws):
    """The seller's ideal customer profile as query filters, when it's set and switched on (as the app
    applies it to every view), and a plain description of it."""
    p = get_workspace().profile(ws) if ws else None
    if not p or not p.get("active"):
        return {}, None
    f = {"icp_country": p.get("countries", []), "icp_sector": p.get("sectors", []),
         "icp_industry": p.get("industries", []), "icp_size": p.get("sizes", [])}
    f = {k: v for k, v in f.items() if v}
    parts = [" or ".join(p[k]) for k in ("countries", "sectors", "industries", "sizes") if p.get(k)]
    return f, ("; ".join(parts) if parts else None)


def account(account_id):
    return store().account(account_id)


def known_ids(ids):
    found = store().search(Query.make(template="list", ids=ids), 0, 500)["accounts"]
    return {a["id"] for a in found}


def signal_label(sig):
    return meta()["signals"].get(sig, {}).get("label", sig)


def summary(a, mine=None):
    """The compact form tools return: enough to rank and pitch, small enough to keep context lean. With the
    seller's entries (mine), also the lists the account is in and its status, as every table in the app shows."""
    out = {
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
    if mine is not None and a["id"] in mine:
        out["your_lists"], out["status"] = mine[a["id"]]["lists"], mine[a["id"]]["status"]
    return out


def my_entries(ws):
    """account id -> the seller's lists (by name) and status, for the accounts in any of their lists."""
    if not ws:
        return None
    snap = get_workspace().snapshot(ws)
    names = {li["id"]: li["name"] for li in snap["lists"]}
    return {aid: {"lists": [names.get(x, x) for x in e["lists"]], "status": e["status"]}
            for aid, e in snap["entries"].items()}


# The opening line, built only from what the scan observed: the same rules as the app (web/src/talkTrack.ts)
# The evidence names each CVE under its product ("PHP 7.4.33 — CVE-…; Apache httpd 2.4.49 — CVE-…"): a
# line uses the first product and only its CVEs, so one product's CVE is never put on another.
_CONFIRMED = "Confirmed by the scanner's own test on "


def _first(e):
    parts = (e.get("e") or "").split("; ")[0].split(" — ")
    return (parts[0], parts[1]) if len(parts) > 1 else (None, e.get("e") or "")


def _cves(e):
    m = re.findall(r"CVE-\d{4}-\d+", _first(e)[1])
    return " / ".join(m[:2]) if m else "a known-exploited CVE"


def _seen(e):
    return _first(e)[0]


def _confirmed(e):
    s = _seen(e)
    return s[len(_CONFIRMED):] if s and s.startswith(_CONFIRMED) else None


def _or(v, default):
    return default if v is None else v


_LINES = {
    "breach_evidence": lambda e: f"{_or(e.get('e'), 'a service')} at {e['ip']} shows signs of an existing compromise, which usually means someone is already inside.",
    "ai_exposed": lambda e: f"a self-hosted AI service ({_or(e.get('e'), 'an AI app')}) at {e['ip']} answers on the public internet, where model gateways and agent servers can leak keys, data and tool access.",
    "edge_kev": lambda e: f"{_or(e.get('p'), 'Your edge appliance')} at {e['ip']}:{e['port']} is reachable from the internet and runs a version affected by {_cves(e)}, which CISA lists as actively exploited.",
    "edge_device": lambda e: f"{_or(e.get('p'), 'your firewall/VPN appliance')} ({e['ip']}:{e['port']}) answers on the public internet. These appliances are the most common ransomware entry point.",
    "exchange_onprem": lambda e: f"{_or(e.get('e'), 'an on-prem Exchange server')} is internet-facing at {e['ip']}.",
    "remote_access": lambda e: f"{e.get('e')} at {e['ip']} is open to anyone on the internet.",
    "database_exposed": lambda e: f"a database ({e.get('e')}) at {e['ip']} accepts connections from the internet.",
    "smb_exposed": lambda e: f"Windows file sharing is exposed at {e['ip']}:{e['port']}.",
    "ot_exposed": lambda e: f"an industrial/operational protocol ({e.get('e')}) is reachable at {e['ip']}.",
    "kev_cve": lambda e: (f"the scanner's own test confirmed {_cves(e)} on {_confirmed(e)} at {e['ip']}:{e['port']}, which is on CISA's known-exploited list."
                          if _confirmed(e) else
                          f"{_seen(e) or _or(e.get('p'), 'a public server')} at {e['ip']}:{e['port']} is a version affected by {_cves(e)}, which is on CISA's known-exploited list."),
    "eol_os": lambda e: (f"a server at {e['ip']} runs {e.get('e')}." if "support ended" in (e.get("e") or "")
                         else f"a server at {e['ip']} runs {e.get('e')}, past the end of its security support."),
    "ntlm_leak": lambda e: f"a Windows host at {e['ip']} reveals your internal domain ({e.get('e')}) to anyone who connects.",
    "mgmt_exposed": lambda e: f"an infrastructure management service ({e.get('e')}) is exposed at {e['ip']}.",
}


def opening_line(a, evidence):
    weight = {k: v["weight"] for k, v in meta()["signals"].items()}
    lines, used = [], set()
    for e in sorted(evidence, key=lambda x: -weight.get(x["s"], 0)):
        f = _LINES.get(e["s"])
        if not f or e["s"] in used:
            continue
        used.add(e["s"])
        lines.append(f(e))
        if len(lines) == 2:
            break
    if not lines:
        return ""
    who = a["org"] if a.get("org") and a.get("ident") == "org" else a["name"]
    extra = (f" We counted {a['assets']} internet-facing services across {a['ips']} IPs in the same scan."
             if a["assets"] > len(lines) else "")
    second = f" {lines[1][0].upper()}{lines[1][1:]}" if len(lines) > 1 else ""
    return (f"Hi, while mapping {who}'s external attack surface we noticed that {lines[0]}{second}{extra} "
            "Worth 15 minutes to walk through what an attacker sees?")


def account_link(account_id):
    return f"{APP_URL}/?account={urllib.parse.quote(account_id)}"


def view_link(**params):
    """A link to the same view in the app; several values in one filter are comma-separated, as the app reads them."""
    q = {k: (",".join(v) if isinstance(v, (list, tuple)) else v) for k, v in params.items()}
    q = {k: v for k, v in q.items() if v not in ("", None, False, "market")}
    if q.get("strong"):
        q["strong"] = "1"
    return f"{APP_URL}/?{urllib.parse.urlencode(q, safe=',')}" if q else f"{APP_URL}/"


def workspace_or_none():
    """The seller's workspace when RECON_USER is set; read-only tools work without one."""
    try:
        return workspace_id()
    except LookupError:
        return None


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
