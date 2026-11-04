"""Merge labels from a batch run (Claude Haiku, the same instructions as pipeline/llm_label.py)
into the shared label cache, validating every row.

usage: python -m pipeline.merge_labels [queue_dir]
reads <queue_dir>/items.json + out_*.jsonl, appends to data/labels/llm_cache.jsonl,
rewrites org_labels.csv / domain_labels.csv
"""
import argparse
import glob
import json
import typing

from pipeline.llm_label import CACHE, Industry, OrgType, load_cache, write_label_csvs

ORG_TYPES, INDUSTRIES = set(typing.get_args(OrgType)), set(typing.get_args(Industry))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("queue_dir", nargs="?", default="data/labels/queue")
    QUEUE = ap.parse_args().queue_dir
    items = json.load(open(f"{QUEUE}/items.json"))
    got, bad = {}, 0
    for path in sorted(glob.glob(f"{QUEUE}/out_*.jsonl")):
        for line in open(path):
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                ok = (isinstance(r.get("id"), int) and 0 <= r["id"] < len(items) and r.get("org_type") in ORG_TYPES
                      and r.get("industry") in INDUSTRIES and r.get("confidence") in ("high", "medium", "low"))
            except json.JSONDecodeError:
                ok = False
            if ok:
                got[r["id"]] = r
            else:
                bad += 1
    missing = [i for i in range(len(items)) if i not in got]
    cache = load_cache()
    with open(CACHE, "a") as f:
        for i, r in got.items():
            it = items[i]
            row = {"kind": it["kind"], "key": it["key"], "org_type": r["org_type"], "industry": r["industry"],
                   "confidence": r["confidence"], "model": "claude-haiku (batch)"}
            cache[(it["kind"], it["key"])] = row
            f.write(json.dumps(row) + "\n")
    write_label_csvs(cache)
    print(json.dumps({"items": len(items), "labelled": len(got), "invalid_rows": bad, "missing": len(missing)}))
    if missing:
        json.dump(missing, open(f"{QUEUE}/missing.json", "w"))


if __name__ == "__main__":
    main()
