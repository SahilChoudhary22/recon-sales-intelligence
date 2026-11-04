# MCP tool-call evaluation

Does an assistant, given only Recon's tool schemas, turn a salesperson's request into the right
first tool call? Scored by `score.py` (tool must match an accepted answer, every argument that answer
names must match; extra arguments allowed). Models saw only the tool schemas and the request text.

## v3: the full ten-tool server

The current server (`tools_v3.json`, exported from a live `tools/list`) adds lists and saved searches
(`make_list` writing real lists, `my_lists`, `save_search`, `whats_new`). Ten new requests for those
tools (`lists.json`) were written with their accepted answers before the run, and the earlier 30 were
re-run to check that four more tools didn't confuse the calls that already worked.

| First call correct (v3 tools) | Original 18 | Held-out 12 | List and saved-search 10 |
|---|---|---|---|
| Claude Sonnet | 18/18 | 12/12 | 10/10 |
| Claude Haiku | 18/18 | 12/12 | 10/10 |

Runs: `run_v3_sonnet.json`, `run_v3_haiku.json`; requests and answers: `expected_v3.json`. Score one
with `python -m mcp_server.eval.score mcp_server/eval/run_v3_sonnet.json mcp_server/eval/expected_v3.json`.

## v1 to v2: fixing the descriptions

| First call correct | v1 descriptions (18) | v2, in-sample (same 18) | v2, held-out (12 new) |
|---|---|---|---|
| Claude Sonnet | 10/18 (56%) | 17/18 (94%) | 12/12 |
| Claude Haiku | 8/18 (44%) | 18/18 (100%) | 12/12 |

**What v1 got wrong:** models didn't know the template ids (Sonnet called `list_signal_templates`
first; Haiku dropped the trigger and searched by industry only), and didn't know an account id is
the domain, so "tell me about chevron.com" became a search.

**v2 change:** `search_accounts` lists every template id with its trigger and constrains `template`
to an enum; `get_account`, `make_list` and `export_crm_tasks` say the id is the company's domain.

**Held-out set:** `holdout.json` was written after the v1 run and before the v2 run, worded differently,
and never used to change a description.

**Caveats:** 12 held-out requests is small and the same person wrote the requests and the
descriptions; this measures the first call, not a whole conversation. The one in-sample miss
("Look up Toyota" -> `get_account("toyota.com")`) would work in practice but is counted wrong because
the rubric was fixed before the run.
