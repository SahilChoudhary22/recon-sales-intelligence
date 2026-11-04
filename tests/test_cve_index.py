"""The CVE search shows exactly the companies a direct query over the build output finds.

Runs against the real build (data/build/full) and the serving store (data/serve/current); skipped
where those haven't been generated (they are not in git)."""
import json
import os

import duckdb
import pytest

BUILD = "data/build/full"
SERVE = "data/serve/current"
pytestmark = pytest.mark.skipif(not os.path.exists(f"{SERVE}/cve_index.json"), reason="build + export not run")

CASES = ["CVE-2021-34473", "CVE-2024-38475", "CVE-2023-44487", "CVE-2021-40438"]


def direct_count(cve):
    return duckdb.connect().execute(f"""
        select count(distinct c.company_id)
        from (select company_id, unnest(cves) v from '{BUILD}/asset_cves.parquet') c
        join '{BUILD}/accounts.parquet' a using (company_id)
        where c.v.cve = '{cve}'""").fetchone()[0]


def index():
    return json.load(open(f"{SERVE}/cve_index.json"))["cves"]


@pytest.mark.parametrize("cve", CASES)
def test_index_matches_direct_query(cve):
    expected = direct_count(cve)
    total, served = duckdb.connect().execute(
        f"select count(*), count_if(served) from '{SERVE}/cve_hits.parquet' where cve = ?", [cve]).fetchone()
    assert index()[cve]["companies"] == expected == total
    assert served == index()[cve]["inApp"]


def test_kev_only_cves_carry_product_for_fallback():
    bleed = index()["CVE-2023-4966"]  # Citrix Bleed: on KEV, not matched in this scan
    assert not bleed["inScan"] and bleed["kev"] and bleed["family"] == "Citrix NetScaler"


def test_noise_cves_are_flagged():
    assert index()["CVE-2023-44487"]["noise"]
