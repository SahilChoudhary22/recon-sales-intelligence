# Recon MCP server

Prospect from Claude, Cursor or any MCP client. The assistant handles the language; these tools are
deterministic queries over Recon's IP-masked serving store, through the same query layer as the read
API (`api/store.py`), so there is no model on Recon's side, no per-call cost, nothing for Recon to
hallucinate, and the app and the assistant always agree.

| Tool | What it does |
|---|---|
| `dataset_overview()` | The scan and how many records survived each step; the KEV catalogue version |
| `list_signal_templates(product)` | The signal templates, with templates for your product first |
| `search_accounts(template, query, country, industry, sector, software, strong_identity, tier, limit)` | Ranked accounts, plus a link to the same view in the app |
| `get_account(account_id)` | Score breakdown, why now, evidence by signal (IPs masked) |
| `cve_exposure(cve_or_name, country, sector, limit)` | CVE facts (CVSS, EPSS, KEV, ransomware use) and affected accounts, with the product fallback |
| `make_list(account_ids or template + filters, list_name)` | Adds accounts, or a search's top results, to one of the seller's lists, creating it if needed |
| `my_lists()` | The seller's lists with their sizes, and how many accounts are new in each saved search |
| `save_search(name, template, country, industry, sector, software, strong_identity)` | Saves a search the seller can re-run in the app |
| `whats_new(saved_search, limit, mark_reviewed)` | Accounts new since the search was last reviewed and in none of the seller's lists |
| `export_crm_tasks(account_ids)` | CRM call tasks as CSV, filled from the evidence |

Templates, products and sectors come from `web/src/catalog.json`, the same file the app reads.

```bash
uv run python -m mcp_server.server          # stdio
```

The repo ships a `.mcp.json` for MCP clients that read project config. `RECON_SERVE` points at a
serving store (default `data/serve/current`), `RECON_DB` at the app database, `RECON_USER` names whose
lists and saved searches the tools work on, and `RECON_APP_URL` is the app the links open.

**Evaluation** (`mcp_server/eval/`): 18 sales requests with accepted answers. A model sees only the
tool schemas (`tools.json`) and the requests (`prompts.json`), writes the first call it would make, and
`score.py` checks it. The evaluated tool set is the one in `tools.json`; `my_lists`, `save_search` and
`whats_new` aren't in it yet. Protocol tests cover all ten tools: `tests/test_mcp_server.py`.
