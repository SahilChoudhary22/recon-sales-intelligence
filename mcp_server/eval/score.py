"""Score an MCP tool-call run against the expected calls in requests.json.

A request counts as correct when the tool matches one of its accepted answers and every argument
that answer specifies matches (strings compared case-insensitively by containment, country codes
upper-cased, lists as sets, and a list or a comma-separated string of the same values treated alike, as
the server reads them). Extra arguments are allowed.

usage: python -m mcp_server.eval.score <run.json> [expected.json, default requests.json]
"""
import json
import sys

HERE = "mcp_server/eval"


def _items(v):
    """A filter value as the server reads it: a list, or a string of comma-separated values."""
    return [str(x).strip().lower() for x in (v if isinstance(v, list) else str(v).split(",")) if str(x).strip()]


def arg_ok(want, got):
    if isinstance(want, list):  # same set of values, whether passed as a list or "GB,IE"
        return isinstance(got, (list, str)) and set(_items(want)) == set(_items(got))
    if isinstance(want, bool) or isinstance(want, int):
        return got == want
    if isinstance(got, list):  # one value asked for, passed as a one-item list
        return len(got) == 1 and want.lower() in str(got[0]).lower()
    return isinstance(got, str) and want.lower() in got.lower()


def correct(expect, call):
    return any(call.get("tool") == e["tool"] and all(arg_ok(v, (call.get("arguments") or {}).get(k)) for k, v in e["args"].items())
               for e in expect)


def main():
    expected = sys.argv[2] if len(sys.argv) > 2 else f"{HERE}/requests.json"
    reqs = {r["id"]: r for r in json.load(open(expected))}
    run = {c["id"]: c for c in json.load(open(sys.argv[1]))}
    results = [(i, correct(r["expect"], run.get(i, {}))) for i, r in reqs.items()]
    ok = sum(1 for _, c in results if c)
    print(json.dumps({"correct": ok, "total": len(results), "accuracy": round(ok / len(results), 3),
                      "wrong": [{"id": i, "request": reqs[i]["request"], "got": run.get(i)} for i, c in results if not c]}, indent=2))


if __name__ == "__main__":
    main()
