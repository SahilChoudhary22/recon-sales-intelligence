"""Stream a Shodan-style NDJSON(.zst) banner file into slim Parquet shards.

One process decompresses; N workers parse with orjson and each writes its own shard.
Only a bounded number of batches are in flight, so memory stays flat regardless of file size.
The raw file is read exactly once: we keep a superset of the fields scoring needs and drop
raw HTML / cert chains / pubkeys, which are most of the bytes.

Repeat-safe for a stream of files: each output dir carries a _manifest.json keyed on the source
(path, size, mtime), so re-running an ingested file is a no-op, and shards are written to
<out_dir>.partial and renamed into place only when the whole file is done, so a crashed run never
looks like a finished scan.

usage: python -m ingest.extract <input.zst|input.jsonl> <out_dir> [--workers 7] [--force]
"""
import argparse
import io
import json
import os
import re
import shutil
import sys
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait

import orjson
import pyarrow as pa
import pyarrow.parquet as pq
import zstandard

BATCH_BYTES = 32 * 1024 * 1024
MANIFEST = "_manifest.json"
SAN_RE = re.compile(r"(?:\*\.)?[a-z0-9_](?:[a-z0-9_-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+", re.I)
SAN_TOKEN_RE = re.compile(r"(?:\\x[0-9a-f]{2}|\\.|.)([^\\]*)", re.S)
HEADERS_KEPT = ("strict-transport-security", "content-security-policy", "x-frame-options",
                "x-powered-by", "server", "location", "www-authenticate")
# top-level keys Shodan adds for specific protocols/products; their presence is itself a signal
SERVICE_KEYS = ("rdp_encryption", "smb", "telnet", "vnc", "mysql", "mongodb", "elastic", "redis",
                "ftp", "snmp", "ssh", "microsoft_exchange", "fortinet", "kubernetes", "docker",
                "etcd", "open_dir", "screenshot", "ldap", "netbios", "msrpc", "mikrotik_routeros",
                "synology_dsm", "hikvision", "dahua", "isakmp", "ntlm", "dns", "sip", "bgp",
                "draytek_vigor", "cisco_ipsla", "mcp", "iscsi", "dav", "tacacs", "plex")

VULN_T = pa.struct([("cve", pa.string()), ("cvss", pa.float32()), ("epss", pa.float32()),
                    ("kev", pa.bool_()), ("verified", pa.bool_())])
SCHEMA = pa.schema([
    ("ip", pa.string()), ("port", pa.int32()), ("transport", pa.string()), ("ts", pa.string()),
    ("org", pa.string()), ("isp", pa.string()), ("asn", pa.string()),
    ("country", pa.string()), ("city", pa.string()),
    ("hostnames", pa.list_(pa.string())), ("domains", pa.list_(pa.string())),
    ("module", pa.string()), ("product", pa.string()), ("version", pa.string()),
    ("os", pa.string()), ("devicetype", pa.string()), ("info", pa.string()),
    ("tags", pa.list_(pa.string())), ("cloud_provider", pa.string()), ("cpe23", pa.list_(pa.string())),
    ("vulns", pa.list_(VULN_T)), ("service_keys", pa.list_(pa.string())),
    ("http_status", pa.int32()), ("http_title", pa.string()), ("http_server", pa.string()),
    ("http_host", pa.string()), ("http_waf", pa.string()), ("http_securitytxt", pa.bool_()),
    ("http_components", pa.list_(pa.string())), ("http_headers", pa.map_(pa.string(), pa.string())),
    ("cert_cn", pa.string()), ("cert_o", pa.string()), ("cert_san", pa.list_(pa.string())),
    ("cert_issuer_cn", pa.string()), ("cert_issuer_o", pa.string()), ("cert_self_signed", pa.bool_()),
    ("cert_expires", pa.string()), ("cert_expired", pa.bool_()),
    ("tls_versions", pa.list_(pa.string())), ("tls_cipher", pa.string()),
    ("ntlm_os", pa.string()), ("ntlm_os_build", pa.string()), ("ntlm_dns_domain", pa.string()),
    ("ntlm_fqdn", pa.string()), ("ntlm_netbios_domain", pa.string()),
    ("fortinet_device", pa.string()), ("exchange_build", pa.string()),
    ("banner", pa.string()),
    # read from the parts of the record not kept whole (page HTML, redirects, cert key, database names)
    ("page_flags", pa.list_(pa.string())), ("redirect_host", pa.string()),
    ("cert_key_type", pa.string()), ("cert_key_bits", pa.int32()), ("cert_sig_alg", pa.string()),
    ("ransom_db", pa.list_(pa.string())), ("ftp_anonymous", pa.bool_()), ("page_snippet", pa.string()),
])


def _s(v, n=300):
    if v is None:
        return None
    v = v if isinstance(v, str) else str(v)
    return v[:n]


def _san(cert):
    # `data` is the DER extension as an escaped string: each dNSName is `\x82` + one length token
    # (`\x10`, `\r` or a printable char) + the name. Strip exactly one token so length bytes that
    # happen to be printable ("r", "*", "?") don't get glued onto the domain.
    for ext in cert.get("extensions") or ():
        if ext.get("name") == "subjectAltName":
            raw = ext.get("data") or ""
            if not isinstance(raw, str):
                raw = raw.decode("latin-1")
            names = set()
            for piece in raw.split("\\x82")[1:]:
                m = SAN_TOKEN_RE.match(piece)
                if m and SAN_RE.fullmatch(m.group(1)):
                    names.add(m.group(1).lower())
            return sorted(names)[:50]
    return []


# Page markers, read from the HTML at ingest so the HTML itself needn't be kept. A page that matches
# several unrelated fingerprints at once is a decoy built to fool scanners (60k records in the
# 2026-11-01 file): it gets only the 'decoy' flag. Measured in docs/technical-notes.md.
PAGE_RX = {
    "defaced": re.compile(r"(?i)hacked\s+by\s|defaced\s+by\s|h4ck3d\s+by"),
    "miner": re.compile(r"(?i)coinhive\.min\.js|cryptonight|webminepool|crypto-?loot"),
    "phpinfo": re.compile(r"<title>phpinfo\(\)</title>"),
    "debug_page": re.compile(r"Whoops! There was an error|you have <code>DEBUG = True|Werkzeug Debugger|"
                             r"Whitelabel Error Page|Server Error in '/' Application|Traceback \(most recent call last\)"),
    "password_form": re.compile(r"(?i)<input[^>]+type=[\"']?password"),
    "sso": re.compile(r"(?i)\.okta\.com|login\.microsoftonline\.com"),
}
DEFAULT_TITLE_RE = re.compile(r"(?i)^\s*(apache2 (ubuntu|debian) default page|iis windows server|welcome to nginx!|"
                              r"test page for the apache|it works!|welcome to centos|iis\d* welcome)")
LOCATION_RE = re.compile(r"(?im)^location:\s*https?://([^/\s:?#]+)")
RANSOM_RE = re.compile(r"(?i)read_?me|readme_to|to_?recover|recover_?your|pwned|ransom|how_to_restore|backup_?your|meow")


def _page_flags(http):
    """(flags, snippet): the page markers, and the text around the first finding, as evidence."""
    html = http.get("html") or ""
    found = {k: m for k, rx in PAGE_RX.items() if html and (m := rx.search(html))}
    flags, snippet = [], None
    if sum(k in found for k in ("defaced", "miner", "phpinfo", "debug_page")) >= 2 or len(found) >= 4:
        flags.append("decoy")
    else:
        flags += list(found)
        m = next((found[k] for k in ("defaced", "miner", "phpinfo", "debug_page") if k in found), None)
        if m:
            snippet = re.sub(r"\s+", " ", html[max(0, m.start() - 80):m.end() + 160])[:300]
    if DEFAULT_TITLE_RE.search(http.get("title") or ""):
        flags.append("default_page")
    return flags, snippet


def _redirect_host(http):
    for rd in http.get("redirects") or ():
        d = rd.get("data") if isinstance(rd, dict) else None
        m = LOCATION_RE.search(d if isinstance(d, str) else "")
        if m:
            host = m.group(1).lower().strip(".")
            return None if re.fullmatch(r"[\d.]+|\[?[0-9a-f:]+\]?", host) else host[:200]
    return None


def _ransom_db(r):
    names = []
    for k in ("mongodb", "elastic", "redis", "couchdb", "cassandra"):
        v = r.get(k)
        if isinstance(v, dict):
            s = orjson.dumps(v).decode()
            names += re.findall(r'"name":"([^"]{1,80})"', s)
            if isinstance(v.get("indices"), dict):
                names += list(v["indices"])[:200]
    return sorted({n[:80] for n in names if RANSOM_RE.search(n)})[:10]


def slim(r):
    sh = r.get("_shodan") or {}
    loc = r.get("location") or {}
    http = r.get("http") or {}
    ssl = r.get("ssl") or {}
    cert = ssl.get("cert") or {}
    subj, iss = cert.get("subject") or {}, cert.get("issuer") or {}
    ntlm = r.get("ntlm") or {}
    hdrs = {k.lower(): v for k, v in (http.get("headers") or {}).items() if isinstance(v, str)}
    vulns = [{"cve": k, "cvss": v.get("cvss"), "epss": v.get("epss"), "kev": bool(v.get("kev")),
              "verified": bool(v.get("verified"))} for k, v in (r.get("vulns") or {}).items()]
    ntlm_os = ntlm.get("os")
    pf = _page_flags(http) if http else ([], None)
    return {
        "ip": r.get("ip_str") or r.get("ipv6"), "port": r.get("port"), "transport": r.get("transport"),
        "ts": r.get("timestamp"), "org": _s(r.get("org")), "isp": _s(r.get("isp")), "asn": r.get("asn"),
        "country": loc.get("country_code"), "city": loc.get("city"),
        "hostnames": (r.get("hostnames") or [])[:50], "domains": (r.get("domains") or [])[:50],
        "module": sh.get("module"), "product": _s(r.get("product")), "version": _s(r.get("version")),
        "os": _s(r.get("os")), "devicetype": _s(r.get("devicetype")), "info": _s(r.get("info")),
        "tags": r.get("tags") or [], "cloud_provider": (r.get("cloud") or {}).get("provider"),
        "cpe23": (r.get("cpe23") or [])[:30], "vulns": vulns,
        "service_keys": [k for k in SERVICE_KEYS if k in r],
        "http_status": http.get("status") if isinstance(http.get("status"), int) else None,
        "http_title": _s(http.get("title")), "http_server": _s(http.get("server")),
        "http_host": _s(http.get("host")), "http_waf": _s(http.get("waf")),
        "http_securitytxt": bool(http.get("securitytxt")) if http else None,
        "http_components": list(http.get("components") or {})[:40],
        "http_headers": [(k, _s(hdrs[k], 200)) for k in HEADERS_KEPT if k in hdrs],
        "cert_cn": _s(subj.get("CN")), "cert_o": _s(subj.get("O")), "cert_san": _san(cert) if cert else [],
        "cert_issuer_cn": _s(iss.get("CN")), "cert_issuer_o": _s(iss.get("O")),
        "cert_self_signed": (subj == iss) if cert else None,
        "cert_expires": cert.get("expires"), "cert_expired": cert.get("expired"),
        "tls_versions": ssl.get("versions") or [], "tls_cipher": (ssl.get("cipher") or {}).get("name"),
        "ntlm_os": _s(", ".join(ntlm_os) if isinstance(ntlm_os, list) else ntlm_os),
        "ntlm_os_build": _s(ntlm.get("os_build")), "ntlm_dns_domain": _s(ntlm.get("dns_domain_name")),
        "ntlm_fqdn": _s(ntlm.get("fqdn")), "ntlm_netbios_domain": _s(ntlm.get("netbios_domain_name")),
        "fortinet_device": _s((r.get("fortinet") or {}).get("device")),
        "exchange_build": _s((r.get("microsoft_exchange") or {}).get("name")),
        "banner": _s(r.get("data"), 512),
        "page_flags": pf[0], "page_snippet": pf[1],
        "redirect_host": _redirect_host(http) if http else None,
        "cert_key_type": _s((cert.get("pubkey") or {}).get("type"), 20),
        "cert_key_bits": (cert.get("pubkey") or {}).get("bits") if isinstance((cert.get("pubkey") or {}).get("bits"), int) else None,
        "cert_sig_alg": _s(cert.get("sig_alg"), 60),
        "ransom_db": _ransom_db(r),
        "ftp_anonymous": bool((r.get("ftp") or {}).get("anonymous")) if isinstance(r.get("ftp"), dict) else None,
    }


def work(args):
    """Parse one batch of raw lines and write it as a Parquet shard. Returns (rows, bad, in_bytes)."""
    idx, chunk, out_dir = args
    rows, bad = [], 0
    for line in chunk.split(b"\n"):
        if not line:
            continue
        try:
            rows.append(slim(orjson.loads(line)))
        except Exception:
            bad += 1
    if rows:
        tbl = pa.Table.from_pylist(rows, schema=SCHEMA)
        pq.write_table(tbl, os.path.join(out_dir, f"part-{idx:06d}.parquet"), compression="zstd")
    return len(rows), bad, len(chunk)


def batches(path):
    f = open(path, "rb")
    is_zstd = f.read(4) == b"\x28\xb5\x2f\xfd"  # sniff: the source file has no extension
    f.seek(0)
    stream = zstandard.ZstdDecompressor().stream_reader(f, read_size=1 << 20) if is_zstd else f
    buf = b""
    while True:
        block = stream.read(BATCH_BYTES)
        if not block:
            break
        buf += block
        cut = buf.rfind(b"\n")
        if cut == -1:
            continue
        yield buf[:cut]
        buf = buf[cut + 1:]
    if buf.strip():
        yield buf


def source_id(path):
    st = os.stat(path)
    return {"source": os.path.abspath(path), "bytes": st.st_size, "mtime": int(st.st_mtime)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("out_dir")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--force", action="store_true", help="re-ingest even if the manifest says it is done")
    a = ap.parse_args()
    src, out = source_id(a.src), a.out_dir.rstrip("/")
    man_path = os.path.join(out, MANIFEST)
    if os.path.exists(man_path) and not a.force and json.load(open(man_path)).get("source_id") == src:
        print(f"already ingested: {a.src} -> {out} (use --force to redo)")
        return 0
    tmp = out + ".partial"
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    t0, rows, bad, nbytes, done = time.time(), 0, 0, 0, 0
    max_inflight = a.workers * 2
    with ProcessPoolExecutor(a.workers) as ex:
        inflight = set()
        for i, chunk in enumerate(batches(a.src)):
            inflight.add(ex.submit(work, (i, chunk, tmp)))
            if len(inflight) >= max_inflight:
                finished, inflight = wait(inflight, return_when=FIRST_COMPLETED)
                for fut in finished:
                    r, b, n = fut.result()
                    rows, bad, nbytes, done = rows + r, bad + b, nbytes + n, done + 1
                el = time.time() - t0
                print(f"[{el:7.0f}s] batches={done} rows={rows:,} bad={bad} "
                      f"raw={nbytes / 1e9:.1f}GB rate={nbytes / 1e6 / el:.0f}MB/s", flush=True)
        for fut in inflight:
            r, b, n = fut.result()
            rows, bad, nbytes = rows + r, bad + b, nbytes + n
    el = time.time() - t0
    with open(os.path.join(tmp, MANIFEST), "w") as f:
        json.dump({"source_id": src, "rows": rows, "bad_lines": bad, "raw_bytes": nbytes,
                   "seconds": round(el, 1), "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, f, indent=2)
    shutil.rmtree(out, ignore_errors=True)
    os.replace(tmp, out)  # atomic on one filesystem: the scan appears complete or not at all
    print(f"DONE rows={rows:,} bad={bad} raw={nbytes / 1e9:.2f}GB in {el:.0f}s "
          f"({nbytes / 1e6 / el:.0f} MB/s, {rows / el:,.0f} rec/s)", flush=True)


if __name__ == "__main__":
    sys.exit(main())
