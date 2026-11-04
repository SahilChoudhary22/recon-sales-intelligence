# Recon MCP server

Prospect from Claude, Cursor or any MCP client. The assistant handles the language; these tools are
deterministic queries over Recon's IP-masked serving store, through the same query layer as the read
API (`api/store.py`), so there is no model on Recon's side, no per-call cost, nothing for Recon to
hallucinate, and the app and the assistant always agree.

## A seller's week, in plain requests

Everything below is something a seller types to their assistant. Each request becomes one or two
tool calls, and every list, status and saved search it touches is the same one the seller sees in the
app.

| The seller says | What happens |
|---|---|
| "I sell firewalls in the UK and Ireland. Where should I start?" | `list_signal_templates(product="firewall")`: the templates built for firewall sellers, with how many accounts each finds. The seller's ideal customer profile (set in the app) applies to every search from here on |
| "Find UK or Irish companies with an exploited firewall, mid-size estates, that I haven't listed yet." | `search_accounts(template="edge-kev", country=["GB","IE"], size="mid", not_in_my_lists=true)`: ranked accounts, why now, and a link to the same view in the app |
| "Tell me about turkishbank.co.uk and give me an opening line." | `get_account`: the score breakdown, peer rank, evidence (IPs masked), an opening line built only from that evidence, and a link to the printable exposure brief |
| "Put the top 20 into a list called UK edge Q4." | `make_list`: the list appears in the app, under the same login |
| "Save this search and tell me what's new each week." | `save_search` now; `whats_new("UK edge")` later, for accounts first ranked since the last review and in none of the seller's lists |
| "I called chevron.com. And I booked a meeting with bbc.com." | `update_accounts(status="contacted")`, then `status="meeting"`: the statuses every table in the app shows |
| "Take usp.br out of UK edge Q4, it's not a fit." | `update_accounts(remove_from_list="UK edge Q4", status="not_a_fit")` |
| "Citrix Bleed is in the news. Who's exposed in France or Belgium?" | `cve_exposure("Citrix Bleed", country=["FR","BE"])`: the CVE's facts (CVSS, EPSS, CISA KEV, ransomware use) and the accounts, or the companies running the product when no version matched |
| "Export my calls for HubSpot." | `export_crm_tasks`: one call task per account, as CSV |
| "Where does this data come from?" | `dataset_overview`: the scan and how many records survived each step |

## Tools

| Tool | What it does |
|---|---|
| `dataset_overview()` | The scan and how many records survived each step; the KEV catalogue version |
| `list_signal_templates(product)` | The signal templates, with templates for your product first |
| `search_accounts(template, query, tier, filters…)` | Ranked accounts, the profile applied, a link to the same view in the app, and each account's lists and status |
| `get_account(account_id)` | Score breakdown, why now, evidence by signal (IPs masked), the opening line, the seller's lists and status |
| `cve_exposure(cve_or_name, filters…)` | CVE facts and affected accounts, with the product fallback |
| `make_list(account_ids or template + filters, list_name)` | Adds accounts, or a search's top results, to one of the seller's lists, creating it if needed |
| `my_lists()` | The seller's lists with their sizes, and how many accounts are new in each saved search |
| `save_search(name, template, filters…)` | Saves a search, with the seller's profile, to re-run in the app or with `whats_new` |
| `whats_new(saved_search, limit, mark_reviewed)` | Accounts new since the search was last reviewed and in none of the seller's lists |
| `update_accounts(account_ids, status, remove_from_list)` | Sets a status (to contact, contacted, meeting, not a fit) and/or removes accounts from a list |
| `export_crm_tasks(account_ids)` | CRM call tasks as CSV, filled from the evidence |

**Filters**, the same as the app's: `country`, `industry`, `sector`, `software` and `size` (small, mid,
large estates) each take one value or several (`["GB", "IE"]` means either), plus `strong_identity`
and `not_in_my_lists`. `use_my_profile` (default on) applies the seller's ideal customer profile, as
the app does; every response says which profile was applied, and `false` searches the whole market.

Left to the app, on purpose: renaming or deleting lists and saved searches, schedules, and the
per-option counts on filters. They're rare, and safer done by the person who owns them.

Templates, products and sectors come from `web/src/catalog.json`, the same file the app reads.

## Connecting

```bash
# the hosted app: nothing to install (the host and token come with the submission)
claude mcp add --transport http recon https://<host>/mcp --header "Authorization: Bearer <token>"

# or locally, with the serving store built
uv run python -m mcp_server.server          # stdio
```

The hosted endpoint is the same server over MCP's streamable HTTP transport, served by the API
process at `/mcp` ([`http.py`](http.py)): stateless JSON calls, a bearer token checked in constant
time, an allow-list of host names, and its own rate limit at nginx. Its tools work on the same user's
lists as the app, so a list Claude builds shows up when that user signs in.

The repo ships a `.mcp.json` for MCP clients that read project config. `RECON_SERVE` points at a
serving store (default `data/serve/current`), `RECON_DB` at the app database, `RECON_USER` names whose
lists and saved searches the tools work on, and `RECON_APP_URL` is the app the links open.

## Evaluation

`mcp_server/eval/`: sales requests with accepted answers, written before each run. A model sees only
the tool schemas and the requests, writes the first call it would make, and `score.py` checks it.
On the eleven-tool server (`tools_v4.json`), 52 requests, including 12 written for the new
abilities: Claude Haiku 52/52, Claude Sonnet 51/52 (the miss: "Look up Toyota" answered with
`get_account("toyota.com")`, which works, against a rubric fixed before the first run). Every run is in
`results.md`.
Protocol tests cover every tool: `tests/test_mcp_server.py`.
