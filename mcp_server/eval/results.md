# MCP tool-call evaluation

Does an assistant, given only Recon's tool schemas, turn a salesperson's request into the right
first tool call? Scored by `score.py` (tool must match an accepted answer, every argument that answer
names must match; extra arguments allowed). Models saw only `tools.json` and the request text.

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
