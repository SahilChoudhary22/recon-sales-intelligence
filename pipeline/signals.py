"""Signal catalogue: one row per (asset, signal). Each signal is a SQL predicate over the slim
Parquet schema plus a weight, a sales-facing label and an evidence expression.

Weights encode "how likely is this to turn into an incident soon", roughly:
evidence of a breach > known-exploited edge device > exposed remote access / databases > exploitable CVE
> EOL > hygiene.
"""
import re

# KEV-listed but not a reason to call: HTTP/2 Rapid Reset is flagged on ~every nginx, and the jQuery
# XSS CVEs are inferred from a JS library on the page (client-side, not the server). Logjam and FREAK
# are export-grade TLS ciphers, not a flaw of the server's version: the weak-TLS hygiene signal's
# finding, not a "likely to be exploited" one (a blind review rejected both, v9)
NOISE_CVES = ("['CVE-2023-44487', 'CVE-2020-11023', 'CVE-2020-11022', 'CVE-2019-11358', 'CVE-2015-9251', "
              "'CVE-2015-4000', 'CVE-2015-0204']")

# --- which CVE matches hold up --------------------------------------------------------------------
# The scanner matches CVEs to a service from version numbers, and verified the match on only ~1.5% of
# the services carrying a known-exploited CVE. A version match is evidence only when the version shows
# the patch level and belongs to the CVE's product. build.py keeps a match in `vulns_ok` when the
# scanner verified it, or when the build isn't patched in place and the CVE's product was seen with a
# version (for a KEV CVE: a versioned CPE from its CISA vendor; otherwise: the service names exactly one
# versioned product, so the CVE can only be that product's). Measured on this file: 47% of KEV matches
# were on distro builds, 25% named no version, and the top PHP and WordPress KEVs landed on every
# server whose page used PHP or WordPress, version unknown.
#
# Patched in place: distro packages (Ubuntu, Debian, RHEL and rebuilds backport fixes without changing
# the version) and IIS (patched by Windows Update). Their version says nothing about their CVEs; an
# application on top of them (WordPress, Exchange) still has its own version.
# ("Apache/2.4.58 ()" with empty parentheses is Amazon Linux's build)
DISTRO_RE = (r"(?i)(ubuntu|debian|centos|red ?hat|rhel|\.el[5-9]|\bel[5-9]\b|amzn|amazon linux|almalinux|"
             r"rocky|fedora|suse|raspbian|freebsd|deb[0-9]+u[0-9]|/[0-9.]+ \(\))")
# Versions the distributions ship and patch in place. Servers often hide the OS from the header
# (Apache's ServerTokens, and Debian's nginx never names Debian), so a bare "nginx/1.22.1" is Debian 12's
# package as often as not, and RHEL's OpenSSH says "7.4" where upstream says "7.4p1". Treated as
# patched in place unless the header names an upstream build ("(Unix)", "(Win64)").
DISTRO_VERSIONS = {
    "Apache httpd": ["2.2.15", "2.2.22", "2.4.6", "2.4.7", "2.4.10", "2.4.18", "2.4.25", "2.4.29", "2.4.37", "2.4.38",
                     "2.4.41", "2.4.52", "2.4.57", "2.4.58", "2.4.62", "2.4.65"],
    "nginx": ["1.1.19", "1.4.6", "1.10.3", "1.14.0", "1.14.1", "1.14.2", "1.18.0", "1.20.1", "1.22.1", "1.24.0", "1.26.3"],
    "OpenSSH": ["5.3", "6.6.1", "7.4", "8.0", "8.7"],  # RHEL's: no "p1"
    # Debian 9-12 and Ubuntu 18.04-24.04 ship these and patch them in place; Exim's banner names no distro
    "Exim smtpd": ["4.89", "4.90_1", "4.92", "4.93", "4.94.2", "4.95", "4.96", "4.97"],
}
UPSTREAM_BUILD_RE = r"\((Unix|Win32|Win64)\)"
# A distro build (coalesce: a service with no version reads as "not a distro build", not NULL, which
# would drop it from every rule that asks)
PATCHED_IN_PLACE = (
    "coalesce(regexp_matches(concat_ws(' ', http_server, version, os, array_to_string(cpe23, ' '), "
    f"cast(http_headers['x-powered-by'] as varchar)), '{DISTRO_RE}') "
    "or ((" + " or ".join(f"(product = '{p}' and list_contains({v!r}, version))" for p, v in DISTRO_VERSIONS.items())
    + f") and not regexp_matches(coalesce(http_server, ''), '{UPSTREAM_BUILD_RE}')) "
    ", false)")
# what a distro build patches in place: the server software it packages, not an application on top
# (WordPress, Exchange, Jenkins carry their own versions). CPE product names.
DISTRO_PACKAGED = ["http_server", "nginx", "openssh", "php", "openssl", "lighttpd", "squid", "bind", "exim",
                   "dnsmasq", "ntp", "mysql", "mariadb", "postgresql", "proftpd", "vsftpd", "samba", "postfix",
                   "dovecot", "tomcat", "perl", "python", "mod_ssl", "mod_perl", "mod_wsgi"]
# IIS is patched by Windows Update without changing its version: its own CVEs can't be read from it

# A CVE or end-of-life claim needs its product's version in the record a seller can show: a full version
# (with a dot, not a release name like "SharePoint 2016" or "Drupal 7") that appears in the version
# field, server header, X-Powered-By or banner. The scanner also infers versions from content we don't
# keep, and those failed a blind review two times in three. Exchange's build is its own field.
VISIBLE_TEXT = ("concat_ws(' ', version, http_server, cast(http_headers['x-powered-by'] as varchar), banner)")


def version_visible_sql(prod, ver, text="visible"):
    """SQL: the CPE (prod, ver) is a full version that the record itself shows."""
    # ntpd's patch level is part of its version: a CPE of 4.2.8 on a "4.2.8p17" banner is not 4.2.8
    return (f"(({ver} like '%.%' and regexp_matches({text}, '(^|[^0-9.])' || regexp_escape({ver}) || '([^0-9]|$)') "
            f"and not ({prod} = 'ntp' and regexp_matches({text}, regexp_escape({ver}) || 'p[0-9]'))) "
            f"or ({prod} in ('outlook_web_access', 'exchange_server') and exchange_build is not null))")

# An operating system past end of support, read from the package versions each release ships (a
# banner rarely names the OS, but Apache 2.4.29 on Ubuntu is 18.04 and IIS 8.5 is Server 2012 R2).
# Only versions that pin one release; dates are the end of standard security support.
_U, _D = "coalesce(http_server, '') ilike '%ubuntu%'", "coalesce(http_server, '') ilike '%debian%'"
OS_RELEASES = [
    ("Ubuntu 14.04", "2019-04-30", f"(product = 'OpenSSH' and version like '6.6.1p1 Ubuntu%') or (product = 'Apache httpd' and version = '2.4.7' and {_U}) or (product = 'nginx' and version = '1.4.6' and {_U})"),
    ("Ubuntu 16.04", "2021-04-30", f"(product = 'OpenSSH' and version like '7.2p2 Ubuntu%') or (product = 'Apache httpd' and version = '2.4.18' and {_U}) or (product = 'nginx' and version = '1.10.3' and {_U})"),
    ("Ubuntu 18.04", "2023-05-31", f"(product = 'OpenSSH' and version like '7.6p1 Ubuntu%') or (product = 'Apache httpd' and version = '2.4.29' and {_U}) or (product = 'nginx' and version = '1.14.0' and {_U})"),
    ("Ubuntu 20.04", "2025-05-31", f"(product = 'OpenSSH' and version like '8.2p1 Ubuntu%') or (product = 'Apache httpd' and version = '2.4.41' and {_U})"),
    ("Debian 8", "2020-06-30", f"(product = 'OpenSSH' and version like '%deb8u%') or (product = 'Apache httpd' and version = '2.4.10' and {_D})"),
    ("Debian 9", "2022-06-30", f"(product = 'OpenSSH' and version like '%deb9u%') or (product = 'Apache httpd' and version = '2.4.25' and {_D})"),
    ("Debian 10", "2024-06-30", f"(product = 'OpenSSH' and version like '%deb10u%') or (product = 'Apache httpd' and version = '2.4.38' and {_D})"),
    ("Debian 11", "2026-08-31", "product = 'OpenSSH' and version like '%deb11u%'"),
    ("RHEL/CentOS 6", "2020-11-30", "(product = 'OpenSSH' and version = '5.3') or (product = 'Apache httpd' and version = '2.2.15')"),
    ("Amazon Linux 2 or RHEL/CentOS 7", "2026-06-30", "product = 'OpenSSH' and version = '7.4' and cloud_provider = 'Amazon'"),
    ("RHEL/CentOS 7", "2024-06-30", "(product = 'OpenSSH' and version in ('6.6.1', '7.4')) or (product = 'Apache httpd' and version = '2.4.6')"),
    ("CentOS 8", "2021-12-31", "product = 'Apache httpd' and version = '2.4.37' and coalesce(http_server, '') ilike '%centos%'"),
    ("Windows Server 2003", "2015-07-14", "product = 'Microsoft IIS httpd' and version = '6.0'"),
    ("Windows Server 2008", "2020-01-14", "product = 'Microsoft IIS httpd' and version = '7.0'"),
    ("Windows Server 2008 R2", "2020-01-14", "product = 'Microsoft IIS httpd' and version = '7.5'"),
    ("Windows Server 2012", "2023-10-10", "product = 'Microsoft IIS httpd' and version = '8.0'"),
    ("Windows Server 2012 R2", "2023-10-10", "product = 'Microsoft IIS httpd' and version = '8.5'"),
]
OS_RELEASE = "case " + " ".join(f"when {c} then '{r}'" for r, _, c in OS_RELEASES) + " end"
OS_EOL = "case " + " ".join(f"when {c} then date '{d}'" for _, d, c in OS_RELEASES) + " end"

# names for the products a CVE is matched to, as CPEs spell them
# component versions RHEL and its rebuilds freeze (EL 6, 7, 8, 9): fixes are backported into them,
# so neither a CVE nor end of life can be read from them (product as CPEs spell it -> versions)
FROZEN = {"php": ["5.3.3", "5.4.16", "7.2.24"], "openssl": ["1.0.1e", "1.0.2k", "1.1.1k", "3.0.7"]}


def frozen_sql(prod, ver):
    """SQL: the (CPE product, version) pair is a version RHEL freezes."""
    return "(" + " or ".join(f"({prod} = '{p}' and list_contains({v!r}, {ver}))" for p, v in FROZEN.items()) + ")"
# what a version match can't show: (CVE, 'platform' found in the server header/OS, or 'version' prefix
# of the product it belongs to)
CVE_REQUIRES = [
    ("CVE-2024-4577", "platform", "win"),  # PHP-CGI argument injection: Windows only
    ("CVE-2019-11043", "platform", "nginx"),  # PHP-FPM underflow: nginx with PHP-FPM
    ("CVE-2021-40438", "version", "2.4."),  # mod_proxy SSRF: Apache 2.4 only
    ("CVE-2024-38475", "version", "2.4."),  # mod_rewrite escaping: Apache 2.4 only
    ("CVE-2019-0211", "version", "2.4."),  # scoreboard privilege escalation: Apache 2.4 only
    ("CVE-2012-1823", "platform", "php-cgi"),  # PHP-CGI query string: CGI mode only, not mod_php or FPM
]

# A known-exploited CVE is CISA's for one vendor's product, so the service must name that product, not
# just something by the vendor (ASP.NET is not SharePoint, PHP is not PHPMailer). The product the CPE
# names is matched on its words; these are the ones CISA calls something else, or must not match.
GENERIC_WORDS = ["server", "and", "the", "of", "for", "web", "ui", "net", "cli", "open", "source", "enterprise", "edition"]
KEV_PRODUCT_ALIASES = [  # (CPE product, CISA product regex)
    ("http_server", r"^Apache$"),                       # CVE-2021-40438: CISA names the product "Apache"
    ("php", r"FastCGI Process Manager"),                # PHP-FPM ships with PHP
    ("exim", r"Mail Transfer Agent"),
    ("weblogic_server", r"Fusion Middleware"),          # CVE-2020-2551 is WebLogic's IIOP
    ("outlook_web_access", r"Exchange"),                # Outlook Web Access is Exchange's web front end
]
KEV_PRODUCT_DENY = [("ios", r"^(Cisco )?IOS XE")]       # IOS XE's web UI isn't classic IOS
# ...and the entries whose product names no product ("Core" for WordPress and Drupal, "Multiple
# Products"), where the vendor's own product is the one meant
KEV_ANY_PRODUCT = r"^\s*(Multiple\b.*|Core|Framework|Server|Platform)\s*$"


def words(name):
    return [w for w in re.split(r"[^a-z0-9]+", name.lower()) if w and w not in GENERIC_WORDS]


def words_sql(x):
    return (f"list_filter(regexp_split_to_array(lower({x}), '[^a-z0-9]+'), "
            f"lambda w: w <> '' and not list_contains({GENERIC_WORDS!r}, w))")


# Known-exploited CVEs whose catalogue entry names no versions, checked against the vendor's fixed
# releases instead: a version at or past the fix on its branch isn't affected; an older branch with no
# upstream fix is. PHP2Shell (CVE-2026-109618/109619): fixed in 8.5.12, 8.4.27, 8.3.36 and 8.2.35 on
# 2026-10-21; 8.1 and older have no upstream release (github.com/NCSC-NL/php2shell/wiki).
_PHP2SHELL = {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}
FIXED_IN = {"CVE-2026-109618": _PHP2SHELL, "CVE-2026-109619": _PHP2SHELL,
            # nginx range-filter overflow: the scanner's range misses the 1.12.1 backport
            "CVE-2017-7529": {"1.12": "1.12.1", "1.13": "1.13.3"}}


def _ver_sql(v):
    return f"list_transform(string_split(regexp_extract({v}, '^[0-9]+(\\.[0-9]+)*'), '.'), lambda x: try_cast(x as int))"


def fixed_sql(ver, fixes):
    """True when `ver` is at or past the fix on its branch, or on a branch newer than all of them."""
    newest = max(fixes, key=lambda b: [int(x) for x in b.split(".")])
    newer = ".".join(str(int(x) + (i == len(newest.split(".")) - 1)) for i, x in enumerate(newest.split(".")))
    return ("coalesce((" + " or ".join(f"(starts_with({ver}, '{b}.') and {_ver_sql(ver)} >= {_ver_sql(repr(f))})"
                              for b, f in sorted(fixes.items()))
            + f" or {_ver_sql(ver)} >= {_ver_sql(repr(newer))}), false)")

# End-of-life software, decided from the versioned products the service names (its CPEs) against the
# end of upstream security support, not from the scanner's host-wide `eol-product` tag, which names
# supported branches (Apache 2.4) and distro packages. (CPE vendor:product, version regex, name, date)
EOL_BRANCHES = [
    ("php:php", r"^[1-5]\.", "PHP 5", "2018-12-31"),
    ("php:php", r"^7\.0\.", "PHP 7.0", "2019-01-10"),
    ("php:php", r"^7\.1\.", "PHP 7.1", "2019-12-01"),
    ("php:php", r"^7\.2\.", "PHP 7.2", "2020-11-30"),
    ("php:php", r"^7\.3\.", "PHP 7.3", "2021-12-06"),
    ("php:php", r"^7\.4\.", "PHP 7.4", "2022-11-28"),
    ("php:php", r"^8\.0\.", "PHP 8.0", "2023-11-26"),
    ("php:php", r"^8\.1\.", "PHP 8.1", "2025-12-31"),
    ("apache:http_server", r"^(1\.|2\.0\.|2\.2\.)", "Apache httpd 2.2 or older", "2017-07-11"),
    ("apache:tomcat", r"^[1-6]\.", "Tomcat 6 or older", "2016-12-31"),
    ("apache:tomcat", r"^7\.", "Tomcat 7", "2021-03-31"),
    ("apache:tomcat", r"^8\.0\.", "Tomcat 8.0", "2018-06-30"),
    ("apache:tomcat", r"^8\.5\.", "Tomcat 8.5", "2024-03-31"),
    ("openssl:openssl", r"^(0\.|1\.0\.)", "OpenSSL 1.0 or older", "2019-12-31"),
    ("openssl:openssl", r"^1\.1\.", "OpenSSL 1.1", "2023-09-11"),
    # nginx.org supports only the current stable and mainline lines: a stable line ends when the next one
    # ships (each April), a mainline when the stable after it does. Distro builds are excluded above.
    ("f5:nginx", r"^(0\.|1\.[0-9]\.)", "nginx 1.9 or older", "2016-04-26"),
    ("f5:nginx", r"^1\.1[01]\.", "nginx 1.10/1.11", "2017-04-12"),
    ("f5:nginx", r"^1\.1[23]\.", "nginx 1.12/1.13", "2018-04-17"),
    ("f5:nginx", r"^1\.1[45]\.", "nginx 1.14/1.15", "2019-04-23"),
    ("f5:nginx", r"^1\.1[67]\.", "nginx 1.16/1.17", "2020-04-21"),
    ("f5:nginx", r"^1\.1[89]\.", "nginx 1.18/1.19", "2021-04-20"),
    ("f5:nginx", r"^1\.2[01]\.", "nginx 1.20/1.21", "2022-05-24"),
    ("f5:nginx", r"^1\.2[23]\.", "nginx 1.22/1.23", "2023-04-11"),
    ("f5:nginx", r"^1\.2[45]\.", "nginx 1.24/1.25", "2024-04-23"),
    ("f5:nginx", r"^1\.2[67]\.", "nginx 1.26/1.27", "2025-04-23"),
    ("mysql:mysql", r"^(3|4|5\.[0-5])\.", "MySQL 5.5 or older", "2018-12-31"),
    ("mysql:mysql", r"^5\.6\.", "MySQL 5.6", "2021-02-28"),
    ("mysql:mysql", r"^5\.7\.", "MySQL 5.7", "2023-10-31"),
    ("mysql:mysql", r"^8\.0\.", "MySQL 8.0", "2026-04-30"),
    ("oracle:mysql", r"^(3|4|5\.[0-5])\.", "MySQL 5.5 or older", "2018-12-31"),
    ("oracle:mysql", r"^5\.6\.", "MySQL 5.6", "2021-02-28"),
    ("oracle:mysql", r"^5\.7\.", "MySQL 5.7", "2023-10-31"),
    ("oracle:mysql", r"^8\.0\.", "MySQL 8.0", "2026-04-30"),
    ("mariadb:mariadb", r"^(5\.|10\.[01]\.)", "MariaDB 10.1 or older", "2020-10-17"),
    ("mariadb:mariadb", r"^10\.2\.", "MariaDB 10.2", "2022-05-23"),
    ("mariadb:mariadb", r"^10\.3\.", "MariaDB 10.3", "2023-05-25"),
    ("mariadb:mariadb", r"^10\.4\.", "MariaDB 10.4", "2024-06-18"),
    ("mariadb:mariadb", r"^10\.5\.", "MariaDB 10.5", "2025-06-24"),
    ("mariadb:mariadb", r"^10\.6\.", "MariaDB 10.6", "2026-07-06"),
]
# MariaDB's CPEs come under two vendor names
EOL_BRANCHES += [("mariadb_project:mariadb", rx, n, d) for c, rx, n, d in EOL_BRANCHES if c == "mariadb:mariadb"]

CPE_NAMES = {"http_server": "Apache httpd", "php": "PHP", "wordpress": "WordPress", "openssh": "OpenSSH",
             "internet_information_services": "IIS", "exchange_server": "Exchange", "fortios": "FortiOS",
             "tomcat": "Tomcat", "openssl": "OpenSSL", "jenkins": "Jenkins", "confluence": "Confluence", "sharepoint_server": "SharePoint",
             "outlook_web_access": "Exchange (OWA)", "drupal": "Drupal", "joomla": "Joomla", "magento": "Magento",
             "jira": "Jira", "gitlab": "GitLab", "moodle": "Moodle", "mediawiki": "MediaWiki", "exim": "Exim",
             "squid": "Squid", "bind": "BIND", "lighttpd": "lighttpd", "jetty": "Jetty", "mysql": "MySQL",
             "mariadb": "MariaDB"}

KEV = f"list_filter(vulns_ok, lambda v: v.kev and not list_contains({NOISE_CVES}, v.cve))"
HIGH_EPSS = f"list_filter(vulns_ok, lambda v: coalesce(v.epss, 0) >= 0.5 and not list_contains({NOISE_CVES}, v.cve))"
CRITICAL = (f"list_filter(vulns_ok, lambda v: coalesce(v.cvss, 0) >= 9 and coalesce(v.epss, 0) >= 0.1 "
            f"and not list_contains({NOISE_CVES}, v.cve))")


def cve_evidence(matches):
    """'Apache httpd 2.4.58 — CVE-…, CVE-…; PHP 8.4.26 — CVE-2026-109618 (fixed in 8.4.27)': each CVE
    under the product it was matched to (at most two products, three CVEs each, in the order the
    matches are ranked), with the vendor's fix where FIXED_IN has one: after the list when every CVE on
    it shares that fix, otherwise next to its own CVE."""
    m = matches
    first_seen = (f"list_filter(list_transform({m}, lambda v, i: case when list_position("
                  f"list_transform({m}, lambda w: w.seen), v.seen) = i then v.seen end), lambda s: s is not null)")
    cves = f"list_filter({m}, lambda v: v.seen = s)[1:3]"
    fixes = f"list_distinct(list_transform({cves}, lambda v: coalesce(v.fix, '')))"
    line = (f"case when len({fixes}) = 1 and {fixes}[1] <> '' "
            f"then array_to_string(list_transform({cves}, lambda v: v.cve), ', ') || ' (' || {fixes}[1] || ')' "
            f"else array_to_string(list_transform({cves}, lambda v: v.cve || coalesce(' (' || v.fix || ')', '')), ', ') end")
    return f"array_to_string(list_transform({first_seen}[1:2], lambda s: s || ' — ' || {line}), '; ')"


EDGE_RE = (r"(?i)(pfsense|opnsense|fortigate|fortinet|fortiweb|fortimail|fortiproxy|sonicwall|netscaler|citrix|pulse secure|"
           r"ivanti|globalprotect|pan-os|palo alto|sophos|watchguard|check ?point|cisco asa|anyconnect|"
           r"adaptive security|zyxel|juniper|sangfor|array networks|barracuda|openvpn access server|draytek)")
# The appliance itself, from its product fingerprint or its own page. Not a certificate alone: sites
# behind a FortiWeb or FortiMail present Fortinet certificates. And not F5's "Server: BigIP" header,
# which 96% of BIG-IPs send while load-balancing an ordinary website; only its admin/APM pages count.
EDGE = (f"(regexp_matches(coalesce(product, '') || ' ' || coalesce(http_title, ''), '{EDGE_RE}') "
        "or fortinet_device is not null or cert_cn = 'fortinet-subca2001' "
        "or (coalesce(product, '') ilike 'big%ip%' and regexp_matches(coalesce(http_title, '') || ' ' || coalesce(banner, ''), "
        "'(?i)big-ip|configuration utility|/tmui/|f5 dynamic|/my.policy')))")

DB_MODULES = ("'ms-sql','mysql','oracle-tns','ibm-db2-drda','redis','mongodb','elastic','postgresql',"
              "'memcached','couchdb','cassandra','influxdb','clickhouse','mssql'")
OT_MODULES = ("'melsec-q-tcp','codesys','proconos','automated-tank-gauge','modbus','s7','bacnet','dnp3',"
              "'ethernetip','fox','secure-fox','pcworx','omron-tcp','iec-104','general-electric-srtp',"
              "'gesrtp','hart-ip','crimson-v3','dicom','toshiba-pos','handpunch'")
# A port says which probe ran, not what answered: 70% of port-3001 "HandPunch" replies are web pages.
# Port-based detections need a reply in the protocol: not empty, and not a web page or SSH greeting.
PROTO_OK = "(coalesce(trim(banner), '') <> '' and banner not like 'HTTP/%' and banner not like 'SSH-%')"
# answers that mean the service refused us: an IP allow-list, a password, X11 access control
DENIED_RE = (r"(?i)(is not allowed to connect|error 1130|error code: 11(29|30)|-NOAUTH|authentication required|access denied|"
             r"authorization required|no protocol specified|-ERR operation not permitted)")
# industrial products the scanner names but doesn't always tag
OT_PRODUCT_RE = (r"(?i)(niagara|handpunch|schneider|siemens|simatic|rockwell|allen-bradley|omron|mitsubishi|melsec|"
                 r"codesys|3s-smart|modbus|bacnet|dnp3|veeder|tank gauge|general electric|tridium|moxa|lantronix|"
                 r"honeywell|johnson controls|beckhoff|wago|phoenix contact|delta electronics|vertx)")
IOT_RE = r"(?i)(hikvision|dahua|webcam|ip camera|dvr|nvr|axis|xiongmai|uniview)"
# malware the scanner fingerprints that means a victim: remote-access trojans and cryptominers. Offensive
# security tools it also tags (GoPhish, BurpSuite, PowerSploit, Interactsh, C2 frameworks) are what red
# teams and pentesters run, so on a company's IP they point to a security-mature buyer, not a breach.
BREACH_MALWARE_RE = r"(?i)(trojan|xtremerat|darkcomet|njrat|quasar|cryptominer|xmrig)"
# management consoles named by their login page's title (decoy pages, which carry every product's name, excluded)
CONSOLE_TITLE_RE = (r"(?i)(minio console|n8n\.io|portainer|synology diskstation|3cx (webclient|management)|home assistant|"
                    r"phpmyadmin|webmin|proxmox|vmware esxi|vsphere|unifi (os|network)|zabbix|rancher|argo cd|"
                    r"airflow|jupyter|cockpit|cyberpanel|easypanel|routeros|vigor login|kibana|jenkins)")
# Page markers are read at ingest; these narrow them on the text around the match (page_snippet).
# Defaced: the attacker's own change to the page (its title, a script rewriting it, a heading, or injected
# pages listed in the site's menu, "/9a2aa0f6e6e7-htm/"), not a news story quoting "hacked by".
DEFACED = r"""(list_contains(coalesce(page_flags, []), 'defaced') and (coalesce(http_title, '') ilike '%hacked by%' or regexp_matches(coalesce(page_snippet, ''), '(?i)(-htm/?"[^>]*>\s*hacked by|document\.title\s*=\s*"hacked by|<(h1|h2|h3|title|center|font)[^>]*>\s*hacked by|hack3d by)')))"""
# Debug: real debug output, not a framework's plain error page (Spring's "Whitelabel Error Page", an
# ASP.NET 404) that names the framework and nothing else
DEBUG_KIND = r"""(case when list_contains(page_flags, 'phpinfo') then 'phpinfo() page'
    when page_snippet like '%DEBUG = True%' then 'Django debug page'
    when page_snippet like '%Werkzeug Debugger%' then 'Werkzeug debugger'
    when page_snippet like '%Whoops! There was an error%' then 'Laravel debug page'
    when page_snippet like '%Traceback (most recent call last)%' then 'Python stack trace'
    when page_snippet like '%Server Error in ''/'' Application%' and regexp_matches(page_snippet, 'Exception|Stack Trace') then 'ASP.NET error with exception details'
    end)"""
EOL_OS_RE = r"(?i)(server 2003|server 2008|server 2012|windows xp|windows 7|windows vista)"

# id, category, weight, label, predicate, evidence
SIGNALS = [
    ("edge_kev", "edge", 10.0, "Edge/VPN appliance on a version with a known-exploited CVE",
     f"{EDGE} and len({KEV}) > 0", cve_evidence(KEV)),
    ("edge_device", "edge", 6.0, "Firewall/VPN appliance reachable from the internet",
     EDGE, "coalesce(fortinet_device, product, http_title, cert_o, 'appliance')"),
    ("exchange_onprem", "edge", 7.0, "On-prem Microsoft Exchange exposed",
     "exchange_build is not null or list_contains(service_keys, 'microsoft_exchange') or http_title ilike '%outlook web app%'",
     "coalesce(exchange_build, 'Exchange / OWA')"),
    ("remote_access", "exposure", 7.0, "Remote access open to the internet (RDP/VNC/Telnet/X11)",
     f"((module in ('rdp','vnc','telnet','x11') and {PROTO_OK}) or list_has_any(service_keys, ['rdp_encryption','vnc','telnet'])) "
     f"and not regexp_matches(coalesce(banner, ''), '{DENIED_RE}')",
     "module || ' on port ' || port"),
    # Windows Remote Management (5985/5986): PowerShell remoting, a common lateral-movement door. The
    # scanner names it from WinRM's own HTTP reply; 128k services in the 2026-11-01 file
    ("winrm_exposed", "exposure", 5.0, "Windows Remote Management (WinRM) open to the internet",
     "product = 'WinRM'", "'WinRM on port ' || port"),
    ("database_exposed", "exposure", 7.0, "Database reachable from the internet",
     f"((module in ({DB_MODULES}) and {PROTO_OK}) or list_has_any(service_keys, ['mysql','mongodb','elastic','redis'])) "
     f"and not regexp_matches(coalesce(banner, ''), '{DENIED_RE}')",
     "coalesce(product, module) || ' on port ' || port"),
    ("smb_exposed", "exposure", 7.0, "Windows file sharing (SMB) exposed",
     "module = 'smb' or list_contains(service_keys, 'smb') or (port = 445 and module like 'smb%')",
     "'SMB on port ' || port"),
    ("open_directory", "exposure", 5.0, "Open directory / file share listing",
     # iSCSI only when the target answers with its targets, not "Not found any reachable targets"
     "list_has_any(service_keys, ['open_dir','dav']) or list_contains(tags, 'open-dir') or coalesce(ftp_anonymous, false) "
     "or (list_contains(service_keys, 'iscsi') and regexp_matches(coalesce(banner, ''), '(?i)TargetName|TargetAddress'))",
     "coalesce(http_title, module) || ' on port ' || port"),
    # also read at ingest: a database holding a ransom note ("READ_ME_TO_RECOVER_DATA"), a defaced
    # page ("hacked by …"), a cryptominer script; decoy pages never carry these flags
    ("breach_evidence", "breach", 12.0, "Evidence of an existing breach (ransomed database, defaced site, trojan or cryptominer)",
     f"list_contains(tags, 'compromised') or (list_contains(tags, 'malware') and regexp_matches(coalesce(product, ''), '{BREACH_MALWARE_RE}')) "
     f"or len(coalesce(ransom_db, [])) > 0 or {DEFACED} or list_contains(coalesce(page_flags, []), 'miner')",
     "case when len(coalesce(ransom_db, [])) > 0 then coalesce(product, module) || ' on port ' || port || ' holds a ransom note: ' || ransom_db[1] "
     f"when {DEFACED} then 'Web page on port ' || port || ' defaced (\"hacked by\")' "
     "when list_contains(coalesce(page_flags, []), 'miner') then 'Cryptominer script on the web page on port ' || port "
     "else coalesce(product, module) || ' on port ' || port || case when list_contains(tags, 'compromised') then ' (flagged compromised)' else '' end end"),
    ("debug_exposed", "exposure", 4.0, "Debug output exposed (stack trace, debug mode, phpinfo)",
     f"list_has_any(coalesce(page_flags, []), ['debug_page', 'phpinfo']) and {DEBUG_KIND} is not null",
     f"{DEBUG_KIND} || ' on port ' || port"),
    ("ai_exposed", "exposure", 6.0, "Self-hosted AI app or MCP server open to the internet",
     "list_has_any(tags, ['ai', 'mcp'])",
     "coalesce(product, http_title, module) || ' on port ' || port"),
    ("mgmt_exposed", "exposure", 5.0, "Infrastructure management interface exposed",
     f"((module like 'snmp%' or module like 'ldap%' or module in ('ipmi','mikrotik-routeros-api','mikrotik-winbox')) and {PROTO_OK}) "
     "or module in ('docker','etcd','kubernetes') "
     "or list_has_any(service_keys, ['kubernetes','docker','etcd','mikrotik_routeros','tacacs']) "
     "or list_contains(tags, 'devops') "  # the scanner's DevOps tag: Kubernetes, Harbor, Docker, Vault, Consul
     f"or (regexp_matches(coalesce(http_title, ''), '{CONSOLE_TITLE_RE}') and not list_contains(coalesce(page_flags, []), 'decoy'))",
     "coalesce(product, case when regexp_matches(coalesce(http_title, ''), '" + CONSOLE_TITLE_RE + "') then trim(http_title) end, module) || ' on port ' || port"),
    # the scanner's ics/medical tag, or an industrial product it named on an industrial protocol
    ("ot_exposed", "exposure", 8.0, "Industrial / medical / POS protocol on the internet",
     f"(list_has_any(tags, ['ics', 'medical']) or (module in ({OT_MODULES}) and regexp_matches(coalesce(product, ''), '{OT_PRODUCT_RE}'))) "
     "and cloud_provider is null",
     "coalesce(product, module) || ' on port ' || port"),
    ("iot_camera", "exposure", 4.0, "IP camera / DVR exposed",
     # named by the device itself, or by the probe (port 37777 = Dahua) only when the reply is that protocol
     f"(regexp_matches(coalesce(product,'') || ' ' || coalesce(devicetype,''), '{IOT_RE}') "
     f"or (regexp_matches(coalesce(module,''), '{IOT_RE}') and {PROTO_OK}))",
     "coalesce(product, devicetype, module)"),
    ("kev_cve", "vuln", 8.0, "Runs a version affected by a known-exploited (CISA KEV) CVE",
     f"len({KEV}) > 0", cve_evidence(KEV)),
    ("high_epss", "vuln", 5.0, "Runs a version with a CVE likely to be exploited soon (EPSS ≥ 0.5)",
     f"len({HIGH_EPSS}) > 0", cve_evidence(HIGH_EPSS)),
    ("critical_cve", "vuln", 4.0, "Runs a version with a critical CVE (CVSS ≥ 9) and non-trivial exploit odds",
     f"len({CRITICAL}) > 0", cve_evidence(CRITICAL)),
    # the scanner's own tag, Windows names from NTLM, and the release a distro's package versions pin
    ("eol_os", "eol", 5.0, "End-of-life operating system",
     f"list_contains(tags, 'eol-os') or regexp_matches(coalesce(ntlm_os, ''), '{EOL_OS_RE}') "
     "or (os_eol is not null and os_eol < try_cast(ts as timestamp))",
     "coalesce(os_release || ', support ended ' || strftime(os_eol, '%B %Y'), ntlm_os, os, 'EOL OS') "
     "|| coalesce(' (' || concat_ws(' ', product, version) || ')', '')"),
    # upstream end of life for a product the service names with a version; distro packages excluded
    ("eol_product", "eol", 3.0, "End-of-life software version",
     "eol_sw is not null and eol_sw_date < try_cast(ts as timestamp) and not patched_in_place",
     "eol_sw || ', support ended ' || strftime(eol_sw_date, '%B %Y')"),
    # a domain-joined host: a standalone server reports its own name as the "domain" (96% of NTLM replies)
    # its own category: the leak rides on a service (WinRM, RDP, Exchange) that carries its own exposure
    # claim, and the build keeps one claim per service per category
    ("ntlm_leak", "leak", 3.0, "Leaks internal Windows domain / host names (NTLM)",
     "ntlm_dns_domain is not null and lower(ntlm_dns_domain) <> lower(coalesce(ntlm_fqdn, ''))",
     "coalesce(ntlm_fqdn, ntlm_netbios_domain) || coalesce(' — ' || ntlm_os, '')"),
    ("cert_expired", "hygiene", 2.0, "Expired TLS certificate in production",
     "cert_expired", "coalesce(cert_cn, '') || ' expired ' || coalesce(cert_expires, '')"),
    # relative to when it was seen; ACME certificates (Let's Encrypt, ZeroSSL) renew themselves at 30 days
    # left, so for them only the last week means renewal is failing
    ("cert_expiring", "hygiene", 2.0, "TLS certificate expires within 30 days",
     "not coalesce(cert_expired, false) and cert_expires is not null "
     "and try_strptime(cert_expires, '%Y%m%d%H%M%SZ') < try_cast(ts as timestamp) + case when "
     "regexp_matches(coalesce(cert_issuer_o, '') || ' ' || coalesce(cert_issuer_cn, ''), '(?i)let.s encrypt|zerossl') "
     "then interval 7 day else interval 30 day end",
     "coalesce(cert_cn, '') || ' expires ' || cert_expires"),
    ("weak_tls", "hygiene", 1.5, "Still accepts TLS 1.0/1.1 or SSL",
     "list_has_any(tls_versions, ['TLSv1','TLSv1.1','SSLv3','SSLv2'])",
     "array_to_string(list_filter(tls_versions, lambda v: v[1] <> '-'), ', ')"),
    # the certificate's own key or signature is weak: RSA under 2048 bits, or SHA-1/MD5 signed by a CA
    ("weak_cert_crypto", "hygiene", 1.0, "Certificate with a weak key or signature (RSA under 2048 bits, SHA-1/MD5)",
     "(cert_key_type = 'rsa' and cert_key_bits < 2048) "
     "or (regexp_matches(lower(coalesce(cert_sig_alg, '')), 'sha1|md5') and not coalesce(cert_self_signed, false))",
     "coalesce(cert_cn, '') || ' — ' || case when cert_key_type = 'rsa' and cert_key_bits < 2048 then 'RSA ' || cert_key_bits || '-bit key' "
     "else cert_sig_alg end"),
    ("default_page", "hygiene", 0.5, "Default web server page left in place",
     "list_contains(coalesce(page_flags, []), 'default_page')", "coalesce(http_title, 'default page') || ' on port ' || port"),
    ("self_signed_web", "hygiene", 1.0, "Self-signed certificate on a public service",
     "cert_self_signed and not " + EDGE, "coalesce(cert_cn, '') || ' on port ' || port"),
]

# not risk — they change the pitch (already buys security) and slightly damp priority
MATURITY = [
    ("waf", "http_waf is not null", "WAF in front of web apps"),
    ("security_txt", "http_securitytxt", "Publishes security.txt (has a disclosure process)"),
    ("pqc", "list_contains(tags, 'pqc')", "Post-quantum TLS enabled"),
    ("hsts", "map_contains(http_headers, 'strict-transport-security')", "HSTS enabled"),
    ("sso", "list_contains(coalesce(page_flags, []), 'sso')", "Signs in through a cloud identity provider (Okta / Entra ID)"),
]
