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
    # the CVE's product, not the web server, and that its branch has no fix
    assert ev["kev_cve"] == "PHP 7.4.33 — CVE-2026-109619 (no upstream fix on the 7.4 branch)"


def test_a_verified_cve_is_claimed_even_on_a_distro_build(tmp_path):
    verified = {"CVE-2021-40438": {"cvss": 9.0, "epss": 0.97, "kev": True, "verified": True}}
    acc, ev = run(tmp_path, [web(product="Apache httpd", version="2.4.41", vulns=verified,
                                 cpe23=["cpe:2.3:a:apache:http_server:2.4.41"], http={"server": "Apache/2.4.41 (Ubuntu)"})])
    assert "kev_cve" in acc["acme-test.co.uk"] and ev["kev_cve"].startswith("Confirmed by the scanner's own test on Apache httpd 2.4.41 — CVE-2021-40438")


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


def test_a_distro_or_iis_patches_its_own_software_not_the_applications_on_it(tmp_path):
    # Exchange on IIS: Exchange's build number moves with every update, IIS's doesn't
    proxyshell = {"CVE-2021-34473": {"cvss": 9.8, "epss": 0.97, "kev": True, "verified": False}}
    acc, ev = run(tmp_path, [web(product="Outlook Web App", vulns=proxyshell, http={"server": "Microsoft-IIS/10.0"},
                                 microsoft_exchange={"name": "Exchange Server 2016 CU19"},
                                 cpe23=["cpe:2.3:a:microsoft:internet_information_services:10.0",
                                        "cpe:2.3:a:microsoft:outlook_web_access:15.1.2242"])])
    assert "kev_cve" in acc["acme-test.co.uk"]
    # WordPress on Ubuntu's Apache: Ubuntu patches Apache, not WordPress
    wp = {"CVE-2026-87902": {"cvss": 9.8, "epss": 0.9, "kev": True, "verified": False}}
    page = '<meta name="generator" content="WordPress 6.7.1" />'
    acc, ev = run(tmp_path / "wp", [web(product="Apache httpd", version="2.4.58", vulns=wp, http={"server": "Apache/2.4.58 (Ubuntu)"},
                                        data=page, cpe23=["cpe:2.3:a:apache:http_server:2.4.58", "cpe:2.3:a:wordpress:wordpress:6.7.1"])])
    assert ev["kev_cve"].startswith("WordPress 6.7.1 — CVE-2026-87902")


def test_a_claim_needs_the_version_in_the_record(tmp_path):
    # the scanner inferred WordPress 6.7.1 from content the record doesn't keep: nothing to show a buyer
    wp = {"CVE-2026-87902": {"cvss": 9.8, "epss": 0.9, "kev": True, "verified": False}}
    acc, _ = run(tmp_path, [web(product="nginx", vulns=wp, http={"server": "nginx"}, data="HTTP/1.1 200 OK",
                                cpe23=["cpe:2.3:a:f5:nginx", "cpe:2.3:a:wordpress:wordpress:6.7.1"])])
    assert "kev_cve" not in acc["acme-test.co.uk"]
    # a release name isn't a version: "Drupal 7" says nothing about the patch level
    drupal = {"CVE-2018-7600": {"cvss": 9.8, "epss": 0.97, "kev": True, "verified": False}}
    acc, _ = run(tmp_path / "drupal", [web(product="Apache httpd", vulns=drupal, data="X-Generator: Drupal 7",
                                           cpe23=["cpe:2.3:a:drupal:drupal:7"])])
    assert "kev_cve" not in acc["acme-test.co.uk"]


def test_a_domain_the_labeller_could_not_place_stays_out_of_the_top_tiers(tmp_path):
    # an open database is material, so the account is ranked; unrecognised, it stays searchable in P3
    rows = [web(), banner(27017, "mongodb", "2026-11-01T10:02:00", mongodb={"databases": []}, data="MongoDB Server Information")]
    write_scan(tmp_path / "scans", "scan-2026-11-01", rows)
    labels = tmp_path / "domain_labels.csv"
    labels.write_text("domain,org_type,industry,confidence\nacme-test.co.uk,unknown,Unknown,low\n")
    build(f"{tmp_path}/scans/*/*.parquet", f"{tmp_path}/out", domain_labels=str(labels))
    tier = duckdb.sql(f"select tier from '{tmp_path}/out/accounts.parquet' where company_id = 'acme-test.co.uk'").fetchall()
    assert tier == [("P3",)]
    build(f"{tmp_path}/scans/*/*.parquet", f"{tmp_path}/out2")
    assert duckdb.sql(f"select tier from '{tmp_path}/out2/accounts.parquet' where company_id = 'acme-test.co.uk'").fetchall() == [("P1",)]


def test_a_known_exploited_cve_needs_its_own_product_not_just_its_vendor(tmp_path):
    # a SharePoint CVE on a plain ASP.NET site: both Microsoft, but ASP.NET isn't SharePoint
    toolshell = {"CVE-2025-53770": {"cvss": 9.8, "epss": 0.9, "kev": True, "verified": False}}
    aspnet = dict(product="Microsoft IIS httpd", vulns=toolshell, http={"server": "Microsoft-IIS/10.0",
                  "headers": {"X-AspNet-Version": "4.0.30319"}}, cpe23=["cpe:2.3:a:microsoft:asp.net:4.0.30319"])
    acc, _ = run(tmp_path, [web(**aspnet)])
    assert "kev_cve" not in acc["acme-test.co.uk"]
    # the same CVE where the service names SharePoint with its build
    sp = dict(product="Microsoft SharePoint", vulns=toolshell, http={"server": "Microsoft-IIS/10.0"},
              data="HTTP/1.1 200 OK\r\nMicrosoftSharePointTeamServices: 16.0.0.10417\r\n",
              cpe23=["cpe:2.3:a:microsoft:sharepoint_server:16.0.0.10417"])
    acc, ev = run(tmp_path / "sp", [web(**sp)])
    assert "kev_cve" in acc["acme-test.co.uk"] and ev["kev_cve"].startswith("SharePoint")


def test_php2shell_is_checked_against_the_fixed_releases(tmp_path):
    # CISA lists no versions; PHP fixed it in 8.3.36 (and 8.2.35, 8.4.27, 8.5.12), and 8.1 has no fix
    def php(ver, d):
        return run(tmp_path / d, [web(product="nginx", vulns=KEV_PHP, cpe23=["cpe:2.3:a:f5:nginx", f"cpe:2.3:a:php:php:{ver}"],
                                      http={"server": "nginx", "headers": {"X-Powered-By": f"PHP/{ver}"}})])[0]["acme-test.co.uk"]
    assert "kev_cve" in php("8.3.12", "a")
    _, ev = run(tmp_path / "e", [web(product="nginx", vulns=KEV_PHP, cpe23=["cpe:2.3:a:f5:nginx", "cpe:2.3:a:php:php:8.3.12"],
                                     http={"server": "nginx", "headers": {"X-Powered-By": "PHP/8.3.12"}})])
    assert ev["kev_cve"] == "PHP 8.3.12 — CVE-2026-109619 (fixed in 8.3.36)"
    assert "kev_cve" not in php("8.3.36", "b")
    assert "kev_cve" in php("8.1.31", "c")
    assert "kev_cve" not in php("8.4.30", "d")


def test_evidence_names_each_cve_under_its_own_product(tmp_path):
    # Apache's CVE and PHP's CVE on one service: the line mustn't put PHP's CVE under Apache
    both = {**KEV_APACHE, **KEV_PHP}
    _, ev = run(tmp_path, [web(product="Apache httpd", version="2.4.49", vulns=both,
                               cpe23=["cpe:2.3:a:apache:http_server:2.4.49", "cpe:2.3:a:php:php:7.4.33"],
                               http={"server": "Apache/2.4.49", "headers": {"X-Powered-By": "PHP/7.4.33"}})])
    parts = dict(p.split(" — ") for p in ev["kev_cve"].split("; "))
    assert parts.get("Apache httpd 2.4.49") == "CVE-2021-40438" and parts.get("PHP 7.4.33") == "CVE-2026-109619 (no upstream fix on the 7.4 branch)"


def test_a_hosters_domain_stays_out_of_the_top_tiers(tmp_path):
    # blind reviews: 0 of 10 hoster-labelled domains were a company a seller could call. A confident
    # label already stops the domain naming the company; a low-confidence one is held back here
    rows = [web(), banner(27017, "mongodb", "2026-11-01T10:02:00", mongodb={"databases": []}, data="MongoDB Server Information")]
    write_scan(tmp_path / "scans", "scan-2026-11-01", rows)
    labels = tmp_path / "domain_labels.csv"
    labels.write_text("domain,org_type,industry,confidence\nacme-test.co.uk,hosting_cloud,Hosting,low\n")
    build(f"{tmp_path}/scans/*/*.parquet", f"{tmp_path}/out", domain_labels=str(labels))
    assert duckdb.sql(f"select tier, held_back from '{tmp_path}/out/accounts.parquet'").fetchall() == [("P3", "hoster")]


def test_tls_cipher_cves_and_patched_ntp_are_not_version_claims(tmp_path):
    # Logjam is a cipher a server still offers (weak TLS), not a flaw of its Apache version
    logjam = {"CVE-2015-4000": {"cvss": 3.7, "epss": 0.99, "kev": False, "verified": True}}
    acc, _ = run(tmp_path, [web(product="Apache httpd", version="2.4.58", vulns=logjam, cpe23=["cpe:2.3:a:apache:http_server:2.4.58"],
                                http={"server": "Apache/2.4.58"})])
    assert "high_epss" not in acc["acme-test.co.uk"]
    # ntpd 4.2.8p17 has the fixes 4.2.8 lacks
    ntp = {"CVE-2016-7434": {"cvss": 7.5, "epss": 0.6, "kev": False, "verified": False}}
    acc, _ = run(tmp_path / "ntp", [web(), banner(123, "ntp", "2026-11-01T10:01:00", product="NTP", version="4.2.8", vulns=ntp,
                                               data="version=\"ntpd 4.2.8p17@1.4004-o\"", cpe23=["cpe:2.3:a:ntp:ntp:4.2.8"])])
    assert "high_epss" not in acc["acme-test.co.uk"]
    # ...while a plain 4.2.8 is claimed
    acc, _ = run(tmp_path / "ntp2", [web(), banner(123, "ntp", "2026-11-01T10:01:00", product="NTP", version="4.2.8", vulns=ntp,
                                                data="version=\"ntpd 4.2.8@1.3265-o\"", cpe23=["cpe:2.3:a:ntp:ntp:4.2.8"])])
    assert "high_epss" in acc["acme-test.co.uk"]


def test_a_camera_port_needs_a_camera_reply(tmp_path):
    acc, _ = run(tmp_path, [web(), banner(37777, "dahua-dvr", "2026-11-01T10:01:00", data="")])
    assert "iot_camera" not in acc["acme-test.co.uk"]
    acc, _ = run(tmp_path / "reply", [web(), banner(37777, "dahua-dvr", "2026-11-01T10:01:00", data="\xa0\x00\x00\x00DVR")])
    assert "iot_camera" in acc["acme-test.co.uk"]


def test_a_fix_note_belongs_to_its_own_cve(tmp_path):
    # CVE-2017-7529 was fixed in nginx 1.12.1; the other CVE on the line wasn't, so the note is the CVE's
    cves = {"CVE-2017-7529": {"cvss": 7.5, "epss": 0.9, "kev": False, "verified": False},
            "CVE-2016-0742": {"cvss": 7.5, "epss": 0.8, "kev": False, "verified": False}}
    _, ev = run(tmp_path, [web(product="nginx", version="1.12.0", vulns=cves, cpe23=["cpe:2.3:a:f5:nginx:1.12.0"],
                               http={"server": "nginx/1.12.0"})])
    assert ev["high_epss"] == "nginx 1.12.0 — CVE-2017-7529 (fixed in 1.12.1), CVE-2016-0742"
    # ...and at 1.12.1 it isn't claimed at all
    _, ev = run(tmp_path / "b", [web(product="nginx", version="1.12.1", vulns=cves, cpe23=["cpe:2.3:a:f5:nginx:1.12.1"],
                                     http={"server": "nginx/1.12.1"})])
    assert ev["high_epss"] == "nginx 1.12.1 — CVE-2016-0742"


def test_php_cgi_cves_and_empty_iscsi_targets_are_not_claimed(tmp_path):
    cgi = {"CVE-2012-1823": {"cvss": 9.8, "epss": 0.97, "kev": True, "verified": False}}
    acc, _ = run(tmp_path, [web(product="Apache httpd", vulns=cgi, cpe23=["cpe:2.3:a:php:php:5.3.29"],
                                http={"server": "Apache", "headers": {"X-Powered-By": "PHP/5.3.29"}})])
    assert "kev_cve" not in acc["acme-test.co.uk"]
    acc, _ = run(tmp_path / "i", [web(), banner(3260, "iscsi", "2026-11-01T10:01:00", iscsi={"targets": []},
                                                 data="Not found any reachable targets")])
    assert "open_directory" not in acc["acme-test.co.uk"]
    listed = "Login Response Success(0x0)\nKey/Value Pairs\nAuthMethod=None\nTargetAddress=10.0.0.5:3260,1\nTargetName=iqn.2004-04.com.qnap:ts-451:iscsi.backup"
    acc, _ = run(tmp_path / "j", [web(), banner(3260, "iscsi", "2026-11-01T10:01:00", iscsi={"targets": [{"name": "backup"}]}, data=listed)])
    assert "open_directory" in acc["acme-test.co.uk"]
