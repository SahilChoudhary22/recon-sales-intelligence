"""The build over a stream of scans: latest observation wins, and a service first seen in the
newest scan is flagged as new and raises the company's urgency."""
import os

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from ingest.extract import SCHEMA, slim
from pipeline.build import build


def banner(port, module, ts, **extra):
    r = {"ip_str": "198.51.100.7", "port": port, "transport": "tcp", "timestamp": ts, "org": "Acme Test Ltd",
         "_shodan": {"module": module}, "location": {"country_code": "GB"}}
    r.update(extra)
    return slim(r)


def write_scan(root, scan_id, rows):
    os.makedirs(f"{root}/{scan_id}")
    pq.write_table(pa.Table.from_pylist(rows, schema=SCHEMA), f"{root}/{scan_id}/part-000000.parquet")


def test_new_exposure_across_scans(tmp_path):
    web = dict(ssl={"cert": {"subject": {"CN": "www.acme-test.co.uk"}, "issuer": {"CN": "CA"}}})
    write_scan(tmp_path, "scan-2026-10-01", [banner(443, "https", "2026-10-01T10:00:00", **web)])
    write_scan(tmp_path, "scan-2026-11-01", [
        banner(443, "https", "2026-11-01T10:00:00", **web),   # same service, seen again
        banner(3389, "rdp", "2026-11-01T10:05:00"),            # RDP opened since last month
    ])
    funnel = build(f"{tmp_path}/*/*.parquet", f"{tmp_path}/out")

    assert funnel["scans"] == 2
    assert funnel["raw_records"] == 2  # the repeated 443 counts once
    assert funnel["services_new_in_latest_scan"] == 1
    acc = duckdb.sql(f"select * from '{tmp_path}/out/accounts.parquet'").fetchdf()
    row = acc[acc.company_id == "acme-test.co.uk"].iloc[0]
    assert "remote_access" in list(row.signals)  # identity carried from the 443 cert to the RDP port
    assert bool(row.has_new)
    assert row.urgency >= 1.3


def test_single_scan_has_nothing_new(tmp_path):
    write_scan(tmp_path, "scan-2026-11-01", [banner(3389, "rdp", "2026-11-01T10:05:00",
                                                    ssl={"cert": {"subject": {"CN": "acme-test.co.uk"}}})])
    funnel = build(f"{tmp_path}/*/*.parquet", f"{tmp_path}/out")
    assert funnel["scans"] == 1 and "services_new_in_latest_scan" not in funnel
