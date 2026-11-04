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


RDP = {"security": ["SSL"]}  # the scanner's parsed RDP reply: an empty probe on 3389 isn't RDP


def write_scan(root, scan_id, rows):
    os.makedirs(f"{root}/{scan_id}")
    pq.write_table(pa.Table.from_pylist(rows, schema=SCHEMA), f"{root}/{scan_id}/part-000000.parquet")


def test_new_exposure_across_scans(tmp_path):
    web = dict(ssl={"cert": {"subject": {"CN": "www.acme-test.co.uk"}, "issuer": {"CN": "CA"}}})
    write_scan(tmp_path, "scan-2026-10-01", [banner(443, "https", "2026-10-01T10:00:00", **web)])
    write_scan(tmp_path, "scan-2026-11-01", [
        banner(443, "https", "2026-11-01T10:00:00", **web),   # same service, seen again
        banner(3389, "rdp", "2026-11-01T10:05:00", rdp_encryption=RDP),  # RDP opened since last month
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


def test_a_file_covering_new_ip_ranges_is_not_all_new(tmp_path):
    """A file is a few hours of an ongoing crawl. An IP the crawl never saw before is not a newly
    exposed service; a new port on an IP it already knew is. Old observations age out by time."""
    known = dict(ssl={"cert": {"subject": {"CN": "www.acme-test.co.uk"}, "issuer": {"CN": "CA"}}})
    write_scan(tmp_path, "scan-2026-08-01", [banner(22, "ssh", "2026-08-01T10:00:00", **known)])  # > 30 days old
    write_scan(tmp_path, "scan-2026-10-20", [banner(443, "https", "2026-10-20T10:00:00", **known)])
    write_scan(tmp_path, "scan-2026-11-01", [
        banner(3389, "rdp", "2026-11-01T10:05:00", rdp_encryption=RDP),                      # new port on a known IP: new
        banner(3389, "rdp", "2026-11-01T10:06:00", rdp_encryption=RDP, ip_str="203.0.113.9", org="Other Co Ltd"),  # IP never crawled before: not new
    ])
    funnel = build(f"{tmp_path}/*/*.parquet", f"{tmp_path}/out")
    assert funnel["services_new_in_latest_scan"] == 1
    assert funnel["raw_records"] == 3  # the August SSH observation aged out
