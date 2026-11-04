"""Score the blind claims review (pipeline/claims_sample.py) per build.

  identity precision : share of sampled P1/P2 accounts the reviewer judged sellable (real, correctly named)
  claim support      : share of claims the reviewer judged supported by the scan fields shown
                       ("unclear" is reported, and counted as not supported)

usage: python -m pipeline.evaluate_claims <prefix> <review.json> [<review.json> ...]
"""
import argparse
import json
from collections import Counter, defaultdict


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("prefix")
    ap.add_argument("reviews", nargs="+")
    a = ap.parse_args()
    sample = {c["case"]: c for c in json.load(open(f"{a.prefix}_sample.json"))}
    key = json.load(open(f"{a.prefix}_key.json"))
    review = {r["case"]: r for f in a.reviews for r in json.load(open(f))}
    missing = set(sample) - set(review)
    assert not missing, f"no review for {sorted(missing)}"

    out = {}
    for build in [b for b in ("before", "after") if any(k["build"] == b for k in key.values())]:
        cases = [c for c in sample if key[c]["build"] == build]
        sellable = sum(review[c]["sellable"] == "yes" for c in cases)
        verdicts, by_signal = Counter(), defaultdict(Counter)
        accounts_all_supported = 0
        for c in cases:
            claims, labels = sample[c]["claims"], review[c]["claims"]
            assert len(claims) == len(labels), f"{c}: {len(claims)} claims, {len(labels)} verdicts"
            for cl, lb in zip(claims, labels):
                verdicts[lb["verdict"]] += 1
                by_signal[cl["claim"]][lb["verdict"]] += 1
            accounts_all_supported += bool(labels) and all(lb["verdict"] == "supported" for lb in labels)
        n = sum(verdicts.values())
        out[build] = {
            "accounts": len(cases),
            "sellable": f"{sellable}/{len(cases)} ({sellable / len(cases):.0%})",
            "claims": n,
            "claims_supported": f"{verdicts['supported']}/{n} ({verdicts['supported'] / n:.0%})",
            "claims_unsupported": verdicts["unsupported"], "claims_unclear": verdicts["unclear"],
            "accounts_with_every_claim_supported": f"{accounts_all_supported}/{len(cases)}",
            "by_claim": {k: dict(v) for k, v in sorted(by_signal.items(), key=lambda kv: -sum(kv[1].values()))},
            "entity_types": dict(Counter(review[c]["entity_type"] for c in cases)),
        }
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
