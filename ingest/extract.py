"""Stream a Shodan-style NDJSON(.zst) banner file into slim Parquet shards.

One process decompresses; N workers parse with orjson and each writes its own shard.
Only a bounded number of batches are in flight, so memory stays flat regardless of file size.
The raw file is read exactly once: we keep a superset of the fields scoring needs and drop
raw HTML / cert chains / pubkeys, which are most of the bytes.

usage: python -m ingest.extract <input.zst|input.jsonl> <out_dir> [--workers 7]
"""
import argparse
import io
import os
import re
import sys
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait

import orjson
import pyarrow as pa
import pyarrow.parquet as pq
import zstandard

BATCH_BYTES = 32 * 1024 * 1024
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("out_dir")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    a = ap.parse_args()
    os.makedirs(a.out_dir, exist_ok=True)
    t0, rows, bad, nbytes, done = time.time(), 0, 0, 0, 0
    max_inflight = a.workers * 2
    with ProcessPoolExecutor(a.workers) as ex:
        inflight = set()
        for i, chunk in enumerate(batches(a.src)):
            inflight.add(ex.submit(work, (i, chunk, a.out_dir)))
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
    print(f"DONE rows={rows:,} bad={bad} raw={nbytes / 1e9:.2f}GB in {el:.0f}s "
          f"({nbytes / 1e6 / el:.0f} MB/s, {rows / el:,.0f} rec/s)", flush=True)


if __name__ == "__main__":
    sys.exit(main())
