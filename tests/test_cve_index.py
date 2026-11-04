"""The CVE search shows exactly the companies a direct query over the build output finds.

Runs against the real build (data/build/full) and the exported web data; skipped where those
haven't been generated (they are not in git)."""
import json
import os

import duckdb
import pytest

BUILD = "data/build/full"
WEB = "web/public/data/cve"
pytestmark = pytest.mark.skipif(not os.path.exists(f"{WEB}/index.json"), reason="build + cve_index not run")

CASES = ["CVE-2021-34473", "CVE-2024-38475", "CVE-2023-44487", "CVE-2021-40438"]


def direct_count(cve):
    return duckdb.connect().execute(f"""
        select count(distinct c.company_id)
        from (select company_id, unnest(cves) v from '{BUILD}/asset_cves.parquet') c
        join '{BUILD}/accounts.parquet' a using (company_id)
        where c.v.cve = '{cve}'""").fetchone()[0]


@pytest.mark.parametrize("cve", CASES)
def test_index_matches_direct_query(cve):
    index = json.load(open(f"{WEB}/index.json"))["cves"]
    doc = json.load(open(f"{WEB}/{cve}.json"))
    expected = direct_count(cve)
    assert index[cve]["companies"] == expected
    assert len(doc["in"]) + doc["outTotal"] == expected
    assert len(doc["in"]) == index[cve]["inApp"]


def test_kev_only_cves_carry_product_for_fallback():
    index = json.load(open(f"{WEB}/index.json"))["cves"]
    bleed = index["CVE-2023-4966"]  # Citrix Bleed: on KEV, not matched in this scan
    assert not bleed["inScan"] and bleed["kev"] and bleed["family"] == "Citrix NetScaler"


def test_noise_cves_are_flagged():
    index = json.load(open(f"{WEB}/index.json"))["cves"]
    assert index["CVE-2023-44487"]["noise"]
