"""Signal catalogue: one row per (asset, signal). Each signal is a SQL predicate over the slim
Parquet schema plus a weight, a sales-facing label and an evidence expression.

Weights encode "how likely is this to turn into an incident soon", roughly:
known-exploited edge device > exposed remote access / databases > exploitable CVE > EOL > hygiene.
"""

# KEV-listed but not a reason to call: HTTP/2 Rapid Reset is flagged on ~every nginx, and the jQuery
# XSS CVEs are inferred from a JS library on the page (client-side, not the server)
NOISE_CVES = "['CVE-2023-44487', 'CVE-2020-11023', 'CVE-2020-11022', 'CVE-2019-11358', 'CVE-2015-9251']"
KEV = f"list_filter(vulns, lambda v: v.kev and not list_contains({NOISE_CVES}, v.cve))"
HIGH_EPSS = f"list_filter(vulns, lambda v: coalesce(v.epss, 0) >= 0.5 and not list_contains({NOISE_CVES}, v.cve))"
CRITICAL = (f"list_filter(vulns, lambda v: coalesce(v.cvss, 0) >= 9 and coalesce(v.epss, 0) >= 0.1 "
            f"and not list_contains({NOISE_CVES}, v.cve))")

EDGE_RE = (r"(?i)(fortigate|fortinet|fortiweb|fortimail|fortiproxy|sonicwall|netscaler|citrix|pulse secure|"
           r"ivanti|globalprotect|pan-os|palo alto|big-?ip|sophos|watchguard|check ?point|cisco asa|anyconnect|"
           r"adaptive security|zyxel|juniper|sangfor|array networks|barracuda|openvpn access server|draytek)")
EDGE = (f"(regexp_matches(coalesce(product, '') || ' ' || coalesce(http_title, ''), '{EDGE_RE}') "
        "or fortinet_device is not null or cert_cn = 'fortinet-subca2001' or cert_o ilike 'fortinet%' "
        "or cert_o ilike '%sonicwall%')")

DB_MODULES = ("'ms-sql','mysql','oracle-tns','ibm-db2-drda','redis','mongodb','elastic','postgresql',"
              "'memcached','couchdb','cassandra','influxdb','clickhouse','mssql'")
OT_MODULES = ("'melsec-q-tcp','codesys','proconos','automated-tank-gauge','modbus','s7','bacnet','dnp3',"
              "'ethernetip','fox','secure-fox','pcworx','omron-tcp','iec-104','general-electric-srtp',"
              "'gesrtp','hart-ip','crimson-v3','dicom','toshiba-pos','handpunch'")
IOT_RE = r"(?i)(hikvision|dahua|webcam|ip camera|dvr|nvr|axis|xiongmai|uniview)"
EOL_OS_RE = r"(?i)(server 2003|server 2008|server 2012|windows xp|windows 7|windows vista)"

# id, category, weight, label, predicate, evidence
SIGNALS = [
    ("edge_kev", "edge", 10.0, "Edge/VPN appliance with known-exploited CVE",
     f"{EDGE} and len({KEV}) > 0",
     f"coalesce(fortinet_device, product, 'appliance') || ' — ' || array_to_string(list_transform({KEV}, lambda v: v.cve)[1:3], ', ')"),
    ("edge_device", "edge", 6.0, "Internet-facing firewall/VPN admin plane",
     EDGE, "coalesce(fortinet_device, product, http_title, cert_o, 'appliance')"),
    ("exchange_onprem", "edge", 7.0, "On-prem Microsoft Exchange exposed",
     "exchange_build is not null or list_contains(service_keys, 'microsoft_exchange') or http_title ilike '%outlook web app%'",
     "coalesce(exchange_build, 'Exchange / OWA')"),
    ("remote_access", "exposure", 7.0, "Remote access open to the internet (RDP/VNC/Telnet/X11)",
     "module in ('rdp','vnc','telnet','x11') or list_has_any(service_keys, ['rdp_encryption','vnc','telnet'])",
     "module || ' on port ' || port"),
    ("database_exposed", "exposure", 7.0, "Database reachable from the internet",
     f"module in ({DB_MODULES}) or list_has_any(service_keys, ['mysql','mongodb','elastic','redis'])",
     "coalesce(product, module) || ' on port ' || port"),
    ("smb_exposed", "exposure", 7.0, "Windows file sharing (SMB) exposed",
     "module = 'smb' or list_contains(service_keys, 'smb') or (port = 445 and module like 'smb%')",
     "'SMB on port ' || port"),
    ("open_directory", "exposure", 5.0, "Open directory / file share listing",
     "list_has_any(service_keys, ['open_dir','iscsi','dav']) or list_contains(tags, 'open-dir')",
     "coalesce(http_title, module) || ' on port ' || port"),
    ("mgmt_exposed", "exposure", 5.0, "Infrastructure management interface exposed",
     "module like 'snmp%' or module like 'ldap%' or module in ('ipmi','mikrotik-routeros-api','mikrotik-winbox','docker','etcd','kubernetes') "
     "or list_has_any(service_keys, ['kubernetes','docker','etcd','mikrotik_routeros','tacacs'])",
     "coalesce(product, module) || ' on port ' || port"),
    ("ot_exposed", "exposure", 8.0, "Industrial / medical / POS protocol on the internet",
     f"module in ({OT_MODULES}) and cloud_provider is null", "module || ' on port ' || port"),
    ("iot_camera", "exposure", 4.0, "IP camera / DVR exposed",
     f"regexp_matches(coalesce(product,'') || ' ' || coalesce(devicetype,'') || ' ' || coalesce(module,''), '{IOT_RE}')",
     "coalesce(product, devicetype, module)"),
    ("kev_cve", "vuln", 8.0, "Runs software with a known-exploited (CISA KEV) CVE",
     f"len({KEV}) > 0",
     f"coalesce(product, module) || ' — ' || array_to_string(list_transform({KEV}, lambda v: v.cve)[1:3], ', ')"),
    ("high_epss", "vuln", 5.0, "CVE likely to be exploited soon (EPSS ≥ 0.5)",
     f"len({HIGH_EPSS}) > 0",
     f"coalesce(product, module) || ' — ' || array_to_string(list_transform({HIGH_EPSS}, lambda v: v.cve)[1:3], ', ')"),
    ("critical_cve", "vuln", 4.0, "Critical CVE (CVSS ≥ 9) with non-trivial exploit odds",
     f"len({CRITICAL}) > 0",
     f"coalesce(product, module) || ' — ' || array_to_string(list_transform({CRITICAL}, lambda v: v.cve)[1:3], ', ')"),
    ("eol_os", "eol", 5.0, "End-of-life operating system",
     f"list_contains(tags, 'eol-os') or regexp_matches(coalesce(ntlm_os, ''), '{EOL_OS_RE}')",
     "coalesce(ntlm_os, os, 'EOL OS') || coalesce(' (' || product || ')', '')"),
    ("eol_product", "eol", 3.0, "End-of-life software version",
     "list_contains(tags, 'eol-product')", "coalesce(product, '') || ' ' || coalesce(version, '')"),
    ("ntlm_leak", "exposure", 3.0, "Leaks internal Windows domain / host names (NTLM)",
     "ntlm_netbios_domain is not null or ntlm_fqdn is not null",
     "coalesce(ntlm_fqdn, ntlm_netbios_domain) || coalesce(' — ' || ntlm_os, '')"),
    ("cert_expired", "hygiene", 2.0, "Expired TLS certificate in production",
     "cert_expired", "coalesce(cert_cn, '') || ' expired ' || coalesce(cert_expires, '')"),
    ("cert_expiring", "hygiene", 2.0, "TLS certificate expires within 30 days",
     "not coalesce(cert_expired, false) and cert_expires is not null "
     "and try_strptime(cert_expires, '%Y%m%d%H%M%SZ') < timestamp '2026-12-01'",
     "coalesce(cert_cn, '') || ' expires ' || cert_expires"),
    ("weak_tls", "hygiene", 1.5, "Still accepts TLS 1.0/1.1 or SSL",
     "list_has_any(tls_versions, ['TLSv1','TLSv1.1','SSLv3','SSLv2'])",
     "array_to_string(list_filter(tls_versions, lambda v: v[1] <> '-'), ', ')"),
    ("self_signed_web", "hygiene", 1.0, "Self-signed certificate on a public service",
     "cert_self_signed and not " + EDGE, "coalesce(cert_cn, '') || ' on port ' || port"),
]

# not risk — they change the pitch (already buys security) and slightly damp priority
MATURITY = [
    ("waf", "http_waf is not null", "WAF in front of web apps"),
    ("security_txt", "http_securitytxt", "Publishes security.txt (has a disclosure process)"),
    ("pqc", "list_contains(tags, 'pqc')", "Post-quantum TLS enabled"),
    ("hsts", "map_contains(http_headers, 'strict-transport-security')", "HSTS enabled"),
]
