"""A signal is a claim a seller makes on a call, so it must hold up against the record behind it.

Each case builds a tiny scan with the record shapes found in the real file, and checks what the
pipeline claims about the company."""
import duckdb

from tests.test_build_scans import banner, write_scan
from pipeline.build import build

# TLS 1.0 still on: a hygiene signal, so the company is always scored and a missing claim can't pass by accident
CERT = {"cert": {"subject": {"CN": "www.acme-test.co.uk"}, "issuer": {"CN": "CA"}}, "versions": ["TLSv1", "TLSv1.2"]}
KEV_PHP = {"CVE-2026-109619": {"cvss": 9.8, "epss": 0.9, "kev": True, "verified": False}}  # a PHP Group CVE on CISA KEV
KEV_APACHE = {"CVE-2021-40438": {"cvss": 9.0, "epss": 0.97, "kev": True, "verified": False}}  # an Apache CVE on CISA KEV


def run(tmp_path, rows):
    write_scan(tmp_path, "scan-2026-11-01", rows)
    build(f"{tmp_path}/*/*.parquet", f"{tmp_path}/out")
    con = duckdb.connect()
    acc = con.sql(f"select company_id, signals from '{tmp_path}/out/accounts.parquet'").fetchall()
    ev = con.sql(f"select signal, evidence from '{tmp_path}/out/evidence.parquet'").fetchall()
    return {c: list(s) for c, s in acc}, dict(ev)


def web(port=443, **kw):
    return banner(port, "https", "2026-11-01T10:00:00", ssl=CERT, **kw)


def test_cve_from_a_distro_package_is_not_claimed(tmp_path):
    # Ubuntu backports fixes into 2.4.41 without changing the version; the KEV match says nothing
    acc, _ = run(tmp_path, [web(product="Apache httpd", version="2.4.41", vulns=KEV_APACHE,
                                cpe23=["cpe:2.3:a:apache:http_server:2.4.41"], http={"server": "Apache/2.4.41 (Ubuntu)"})])
    assert "kev_cve" not in acc["acme-test.co.uk"]


def test_cve_of_a_product_seen_without_a_version_is_not_claimed(tmp_path):
    # PHP is on the page but its version isn't known: no claim about a PHP CVE
    acc, _ = run(tmp_path, [web(product="nginx", vulns=KEV_PHP, cpe23=["cpe:2.3:a:f5:nginx", "cpe:2.3:a:php:php"],
                                http={"server": "nginx"})])
    assert "kev_cve" not in acc["acme-test.co.uk"]


def test_cve_of_a_versioned_product_is_claimed_and_named(tmp_path):
    acc, ev = run(tmp_path, [web(product="nginx", vulns=KEV_PHP, cpe23=["cpe:2.3:a:f5:nginx", "cpe:2.3:a:php:php:7.4.33"],
                                 http={"server": "nginx", "headers": {"X-Powered-By": "PHP/7.4.33"}})])
    assert "kev_cve" in acc["acme-test.co.uk"]
    assert ev["kev_cve"].startswith("PHP 7.4.33 — CVE-2026-109619")  # the CVE's product, not the web server


def test_a_verified_cve_is_claimed_even_on_a_distro_build(tmp_path):
    verified = {"CVE-2021-40438": {"cvss": 9.0, "epss": 0.97, "kev": True, "verified": True}}
    acc, ev = run(tmp_path, [web(product="Apache httpd", version="2.4.41", vulns=verified,
                                 cpe23=["cpe:2.3:a:apache:http_server:2.4.41"], http={"server": "Apache/2.4.41 (Ubuntu)"})])
    assert "kev_cve" in acc["acme-test.co.uk"] and "confirmed by the scanner" in ev["kev_cve"]


def test_end_of_life_comes_from_the_os_release_not_the_upstream_version(tmp_path):
    # nginx 1.24.0 on Ubuntu is 24.04's supported package; Apache 2.4.6 is RHEL/CentOS 7, unsupported
    acc, ev = run(tmp_path, [
        web(product="nginx", version="1.24.0", tags=["eol-product"], http={"server": "nginx/1.24.0 (Ubuntu)"}),
        web(port=8443, product="Apache httpd", version="2.4.6", http={"server": "Apache/2.4.6 (CentOS)"}),
    ])
    assert "eol_product" not in acc["acme-test.co.uk"]
    assert "eol_os" in acc["acme-test.co.uk"] and ev["eol_os"].startswith("RHEL/CentOS 7, support ended June 2024")


def test_a_port_is_not_a_protocol(tmp_path):
    # the industrial probe on port 3001 got a web page back; a database refused us
    acc, _ = run(tmp_path, [
        web(),
        banner(3001, "handpunch", "2026-11-01T10:01:00", data="HTTP/1.1 400 Bad Request\r\nServer: uvicorn"),
        banner(3306, "mysql", "2026-11-01T10:02:00", data="Host '203.0.113.1' is not allowed to connect to this MySQL server"),
    ])
    assert not {"ot_exposed", "database_exposed"} & set(acc["acme-test.co.uk"])
    # a device the scanner recognised as industrial still is
    acc, _ = run(tmp_path / "plc", [web(), banner(502, "modbus", "2026-11-01T10:01:00", tags=["ics"],
                                                   data="Unit ID: 0 -- Slave ID Data: Illegal Function")])
    assert "ot_exposed" in acc["acme-test.co.uk"]


def test_a_standalone_windows_host_leaks_no_domain(tmp_path):
    workgroup = {"dns_domain_name": "WIN-KBF3K6QORMH", "fqdn": "WIN-KBF3K6QORMH", "netbios_domain_name": "WIN-KBF3K6QORMH"}
    joined = {"dns_domain_name": "corp.acme-test.co.uk", "fqdn": "exch01.corp.acme-test.co.uk", "netbios_domain_name": "ACME"}
    acc, _ = run(tmp_path, [web(ntlm=workgroup)])
    assert "ntlm_leak" not in acc["acme-test.co.uk"]
    acc, _ = run(tmp_path / "joined", [web(ntlm=joined)])
    assert "ntlm_leak" in acc["acme-test.co.uk"]


def test_a_honeypot_is_the_whole_ip(tmp_path):
    acc, _ = run(tmp_path, [
        web(),
        banner(23, "telnet", "2026-11-01T10:03:00", tags=["honeypot"], data="login:"),
        banner(3389, "rdp", "2026-11-01T10:04:00", rdp_encryption={"security": ["SSL"]}),  # same IP, untagged
    ])
    assert "acme-test.co.uk" not in acc


def test_end_of_life_software_is_the_component_past_support(tmp_path):
    # the scanner tags the whole host; Apache 2.4 is a supported branch, the PHP 7.4 on it is not
    acc, ev = run(tmp_path, [web(product="Apache httpd", version="2.4.39", tags=["eol-product"],
                                 cpe23=["cpe:2.3:a:apache:http_server:2.4.39", "cpe:2.3:a:php:php:7.4.33"],
                                 http={"server": "Apache/2.4.39 (Win64) PHP/7.4.33"})])
    assert ev["eol_product"] == "PHP 7.4.33, support ended November 2022"
    acc, _ = run(tmp_path / "supported", [web(product="Apache httpd", version="2.4.39", tags=["eol-product"],
                                              cpe23=["cpe:2.3:a:apache:http_server:2.4.39"])])
    assert "eol_product" not in acc["acme-test.co.uk"]


def test_a_cve_needs_what_the_version_cannot_show(tmp_path):
    # CVE-2021-40438 is in Apache 2.4's mod_proxy; Apache 2.2 isn't affected whatever the version range says
    acc, _ = run(tmp_path, [web(product="Apache httpd", version="2.2.11", vulns=KEV_APACHE,
                                cpe23=["cpe:2.3:a:apache:http_server:2.2.11"], http={"server": "Apache/2.2.11 (Unix)"})])
    assert "kev_cve" not in acc["acme-test.co.uk"]
