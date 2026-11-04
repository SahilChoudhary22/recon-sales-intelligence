"""Signal-template rules from the catalogue (web/src/catalog.json), compiled to SQL.

A rule is an OR of clauses and each clause an AND of conditions, stored as data. The same rule is
evaluated in SQL here (API, MCP server, export's count cube), so a template means one thing everywhere.
"""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG = json.load(open(os.path.join(ROOT, "web", "src", "catalog.json")))
TEMPLATES = {t["id"]: t for t in CATALOG["templates"]}
MARKET = CATALOG["market"]["id"]


def _lit(s):
    return "'" + str(s).replace("'", "''") + "'"


def clause_sql(c):
    parts = []
    if c.get("signals"):
        parts.append(f"list_has_any(signals, [{', '.join(_lit(s) for s in c['signals'])}])")
    if "kev" in c:
        parts.append(f"kev = {str(bool(c['kev'])).lower()}")
    if c.get("tier"):
        parts.append(f"tier = {_lit(c['tier'])}")
    if "maturity" in c:
        parts.append(f"(len(maturity) > 0) = {str(bool(c['maturity'])).lower()}")
    if "new" in c:
        parts.append(f"new = {str(bool(c['new'])).lower()}")
    return "(" + (" and ".join(parts) or "true") + ")"


def flag(template_id):
    """The precomputed membership column the export writes for each template (t_edge_kev, ...)."""
    return "t_" + template_id.replace("-", "_")


def rule_sql(template_id):
    """The rule itself as a SQL predicate, used by the export to compute the flag columns."""
    if template_id in ("", MARKET):
        return "true"
    if template_id not in TEMPLATES:
        raise KeyError(template_id)
    return "(" + " or ".join(clause_sql(c) for c in TEMPLATES[template_id]["rule"]) + ")"


def template_sql(template_id):
    """Predicate over the served accounts table. Membership is computed once per build, so a query
    reads one boolean column instead of evaluating list rules on every row."""
    if template_id in ("", MARKET):
        return "true"
    if template_id not in TEMPLATES:
        raise KeyError(template_id)
    return flag(template_id)
