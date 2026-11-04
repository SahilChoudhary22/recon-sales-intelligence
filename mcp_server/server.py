"""Recon as an MCP server: prospect from Claude, Cursor or any MCP client.

The assistant does the language; these tools are deterministic queries over Recon's IP-masked serving
store (the same query layer as the HTTP API), so there is no model on our side, no per-call cost and
nothing to hallucinate here.

run:  uv run python -m mcp_server.server        (stdio)
"""
from typing import Literal

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from mcp_server import data

mcp = MCPServer("Recon")

# v2 descriptions (after the first eval): name every template id and say what an account id is, so an
# assistant can make the right call first time instead of discovering ids with a lookup call
_TEMPLATE_IDS = ["market"] + [t["id"] for t in data.CATALOG["templates"]]
TemplateId = Literal[tuple(_TEMPLATE_IDS)]
_TEMPLATE_GUIDE = "\n".join(f"  {t['id']}: {t['name']}. {t['blurb']}" for t in data.CATALOG["templates"])
_ACCOUNT_ID = ("An account id is the company's own domain exactly as Recon shows it (e.g. chevron.com, toyota.com); "
               "pass it directly, no search needed. Accounts named only by the owner of their IP block use org:<name>.")
_SEARCH_DOC = f"""Find and rank companies that need security help now, from internet scan evidence.

template: the buying trigger to search for. Use one of these ids (or "market" for every account):
{_TEMPLATE_GUIDE}
query: part of a company or organisation name. country: ISO-2 code (US, GB, DE, JP...).
industry: e.g. "Financial services", "Healthcare", "Manufacturing", "Education", "Retail & e-commerce",
"Energy & utilities" (partial text matches). sector: commercial, public (public sector and education) or infra
(telecom and hosting). software: a product family seen on their services, e.g. "Fortinet FortiGate",
"Microsoft Exchange", "Citrix NetScaler", "Microsoft SQL Server". strong_identity: only accounts whose name comes
from their own TLS certificate or domain. tier: P1 (top 500 this week), P2 or P3. Ranked by priority, highest first."""


@mcp.tool()
def dataset_overview() -> dict:
    """Where Recon's accounts come from: the scan, how many records survived each step (noise removal,
    company identification, real risk), and the CISA KEV catalogue version used. Use it to explain or
    cite the data behind any answer."""
    m = data.meta()
    f = m["funnel"]
    keep = ["raw_records", "honeypot", "cdn", "phantom", "clean", "attributed_assets", "companies",
            "companies_with_material_signal", "scans"]
    return {"scan": m["generated_from"], "build": m["build_id"], "funnel": {k: f[k] for k in keep if k in f},
            "accounts_ranked_in_app": m["rows"]["accounts"], "kev_catalogue": data.store().cve_index["kev"],
            "ips_masked": m.get("ips_masked", True)}


@mcp.tool()
def list_signal_templates(product: str = "") -> list[dict]:
    """List Recon's signal templates: ready-to-run searches, each built around one buying trigger.

    product: optional product line the seller sells, one of firewall, email, endpoint, vuln, asm,
    mdr, ot. Templates built for that product are marked for_you. Use the template id with
    search_accounts.
    """
    counts = data.store().counts(data.query())
    out = []
    for t in data.CATALOG["templates"]:
        n = counts[t["id"]]
        if t["id"] == "new" and n == 0:
            continue  # needs a second scan
        built_for = [data.PRODUCTS[p] for p in t.get("forProducts", [])] or ["any security product"]
        out.append({"id": t["id"], "name": t["name"], "why_now": t["blurb"], "pitch": t["pitch"],
                    "built_for": built_for, "recommended_targeting": t.get("targeting", {}), "accounts": n,
                    "for_you": not product or not t.get("forProducts") or product in t["forProducts"]})
    return sorted(out, key=lambda t: not t["for_you"])


@mcp.tool(description=_SEARCH_DOC)
def search_accounts(template: TemplateId = "market", query: str = "", country: str = "", industry: str = "",
                    sector: str = "", software: str = "", strong_identity: bool = False, tier: str = "",
                    limit: int = 20) -> dict:
    if template not in ("market", "") and template not in data.TEMPLATES:
        raise ToolError(f"Unknown template {template!r}. Call list_signal_templates for valid ids.")
    q = data.query(template, query, country, industry, sector, software, strong_identity, tier)
    limit = max(1, min(limit, 100))
    page = data.store().search(q, 0, limit)
    return {"total": page["total"], "returned": len(page["accounts"]),
            "view_in_app": data.view_link(play=template, q=query, country=country.upper(), industry=industry,
                                          sector=sector, software=",".join(q.software), strong=strong_identity),
            "accounts": [data.summary(a) for a in page["accounts"]]}


@mcp.tool(description="Everything Recon knows about one account: score breakdown, why now, and the evidence by signal "
                       "(IP addresses masked to /24). " + _ACCOUNT_ID)
def get_account(account_id: str) -> dict:
    a = data.account(account_id)
    if not a:
        raise ToolError(f"No account {account_id!r} in Recon's ranked accounts.")
    ev = data.store().evidence(account_id)
    grouped = {}
    for e in ev:
        grouped.setdefault(data.signal_label(e["s"]), []).append(f"{e['ip']}:{e['port']} {e['e'] or e['p'] or ''}".strip())
    weight = {data.signal_label(k): v["weight"] for k, v in data.meta()["signals"].items()}
    ordered = sorted(grouped.items(), key=lambda kv: -weight.get(kv[0], 0))  # strongest evidence first
    return {**data.summary(a), "score_breakdown": {"need": a["need"], "urgency": a["urgency"], "fit": a["fit"]},
            "already_invests_in": [data.meta()["maturity"].get(m, m) for m in a["maturity"]],
            "evidence": {k: v[:6] for k, v in ordered},
            "contacts": "Not in this scan data. Named contacts come from an enrichment source joined on the domain."}


@mcp.tool()
def cve_exposure(cve_or_name: str, country: str = "", sector: str = "", limit: int = 20) -> dict:
    """Which companies run software affected by a vulnerability in the news.

    cve_or_name: a CVE id (CVE-2023-4966) or a well-known name (Citrix Bleed, ProxyShell, Log4Shell).
    Returns the CVE's facts (CVSS, EPSS, CISA KEV status and ransomware use) and the affected accounts
    ranked by priority. A CVE not matched in the scan falls back to companies running the affected product.
    """
    s = data.store()
    ids = s.resolve_cves(cve_or_name)
    if not ids:
        raise ToolError(f"{cve_or_name!r} is neither a CVE id nor a known name ({', '.join(sorted(s.cve_index['nicknames']))}).")
    r = s.cve(ids, data.query(country=country, sector=sector), limit=max(1, min(limit, 100)))
    facts = {c: f or "Not matched in this scan and not on CISA's known-exploited list." for c, f in r["facts"].items()}
    fallback = next((f["family"] for f in r["facts"].values() if f and not f.get("inScan") and f.get("family")), None)
    ranked = [{**data.summary(a), "affected_product": a["affected_product"], "affected_services": a["affected"],
               "example_services": a["example_services"], "cves": a["cves"]} for a in r["accounts"]]
    out = {"cves": facts, "scan_date": r["scanDate"], "kev_catalogue": r["kev"], "total_in_app": r["total"],
           "accounts": ranked, "view_in_app": data.view_link(q=" ".join(ids))}
    if not ranked and fallback:
        alt = search_accounts(software=fallback, country=country, sector=sector, limit=limit)
        out["fallback"] = {"reason": f"Not matched by version in the scan; these companies run {fallback}, version unknown.",
                           **alt}
    return out


def _ws():
    try:
        return data.workspace_id()
    except LookupError as e:
        raise ToolError(str(e)) from e


@mcp.tool(description="Save accounts to one of the seller's lists in Recon (the same lists they see in the app), "
                       "creating the list if it doesn't exist. Pass account ids, or a search (template and filters, as "
                       "for search_accounts) to add its top results. Returns the list and a link to it. " + _ACCOUNT_ID)
def make_list(account_ids: list[str] | None = None, list_name: str = "My list", template: TemplateId | None = None,
              country: str = "", industry: str = "", sector: str = "", software: str = "", strong_identity: bool = False,
              limit: int = 500) -> dict:
    ws, w, s = _ws(), data.get_workspace(), data.store()
    if not account_ids and template is None:
        raise ToolError("Pass account_ids, or a template (and filters) whose results to add.")
    if template is not None:
        ids = s.ids(data.query(template, "", country, industry, sector, software, strong_identity), max(1, min(limit, 5000)))["ids"]
    else:
        ids = s.ids(data.query("list", ids=account_ids), 5000)["ids"]
    if not ids:
        raise ToolError("None of those are Recon accounts." if account_ids else "That search has no results.")
    li = w.find_list(ws, list_name) or w.create_list(ws, list_name)
    r = w.add_items(ws, li["id"], ids)
    return {"list": li["name"], "added": r["added"], "now_in_list": r["in_list"],
            "skipped_unknown": len(set(account_ids or [])) - len(ids) if account_ids else 0,
            "open_in_app": data.list_link(li["id"])}


@mcp.tool()
def my_lists() -> dict:
    """The seller's lists (with how many accounts each holds) and saved searches (with how many accounts
    are new since each was last reviewed and in none of their lists)."""
    ws, w, s = _ws(), data.get_workspace(), data.store()
    listed = w.listed_ids(ws)
    searches = []
    for x in w.searches(ws):
        q = data.saved_query(x, listed)
        searches.append({"name": x["name"], "new_since_last_review": s.ids(q, 1)["total"],
                         "last_reviewed": x["lastRunAt"], "open_in_app": data.search_link(x["id"])})
    return {"lists": [{"name": li["name"], "accounts": li["n"], "open_in_app": data.list_link(li["id"])} for li in w.lists(ws)],
            "saved_searches": searches}


@mcp.tool(description="Save a search (a template and filters, as for search_accounts) so the seller can re-run it; "
                       "its next run reports the accounts that are new since today and in none of their lists.")
def save_search(name: str, template: TemplateId = "market", country: str = "", industry: str = "", sector: str = "",
                software: str = "", strong_identity: bool = False) -> dict:
    ws = _ws()
    filters = {"play": template, "q": "", "country": [country.upper()] if country else [], "industry": [industry] if industry else [],
               "sector": [sector] if sector else [], "software": [data.software_family(software)] if software else [],
               "size": [], "strong": strong_identity, "hideListed": False}
    s = data.get_workspace().save_search(ws, name, filters, {}, data.meta()["build_id"])
    return {"saved": s["name"], "open_in_app": data.search_link(s["id"])}


@mcp.tool(description="What a saved search finds that is new since it was last reviewed and not in any of the seller's "
                       "lists, ranked. With mark_reviewed, the search's last review moves to now.")
def whats_new(saved_search: str, limit: int = 20, mark_reviewed: bool = False) -> dict:
    ws, w, s = _ws(), data.get_workspace(), data.store()
    x = w.find_search(ws, saved_search)
    if not x:
        raise ToolError(f"No saved search {saved_search!r}. Call my_lists for their names.")
    page = s.search(data.saved_query(x, w.listed_ids(ws)), 0, max(1, min(limit, 100)))
    if mark_reviewed:
        w.mark_run(ws, x["id"], data.meta()["build_id"])
    return {"saved_search": x["name"], "last_reviewed": x["lastRunAt"], "new": page["total"],
            "accounts": [data.summary(a) for a in page["accounts"]], "open_in_app": data.search_link(x["id"])}


@mcp.tool(description="CRM-ready call tasks for accounts, one per row (company, subject, note, priority, link), as CSV "
                       "to import into HubSpot or Salesforce. Subjects and notes are filled from the evidence. " + _ACCOUNT_ID)
def export_crm_tasks(account_ids: list[str]) -> dict:
    csv_text = data.crm_tasks_csv(account_ids)
    return {"rows": csv_text.count("\n") - 1, "csv": csv_text}


if __name__ == "__main__":
    mcp.run()
