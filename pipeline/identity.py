"""Hostname -> company domain resolution, and the static noise lists behind it.

Everything here works on *distinct* strings (hundreds of thousands), never per record.
"""
import re

import tldextract

# offline: use the bundled public-suffix snapshot, never fetch at runtime
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

IP_LIKE = re.compile(r"^\d{1,3}([.-]\d{1,3}){3}$")
# reverse-DNS names that encode the IP or a pool name belong to the ISP, not a customer
DYNAMIC_PTR = re.compile(
    r"(\d{1,3}[-.x]){3}\d{1,3}|\b(dyn|dynamic|dsl|adsl|vdsl|pool|dhcp|cable|static|cust(omer)?|client|"
    r"ppp|pppoe|broadband|fibre|fiber|ftth|cpe|res|home|user|host)\d*[-.]", re.I)

# vendor default certs and placeholder CNs seen on appliances (FortiGate ships "support",
# "fortinet-subca2001", DrayTek "Vigor Router", Traefik/K8s fake certs, ...)
DEFAULT_CERT_DOMAINS = {
    "fortinet.com", "fortiddns.com", "fortidns.com", "forticloud.com", "sonicwall.com", "localhost",
    "example.com", "example.org", "example.net", "default.com", "notexist.com", "invalid", "local",
    "tplinkwifi.net", "tplinkmodem.net", "tplinkrepeater.net", "routerlogin.net", "synology.me",
    "myfritz.net", "fritz.box", "freebox.fr", "fbxos.fr", "dyndns.org", "no-ip.org", "no-ip.com",
    "ddns.net", "duckdns.org", "plex.direct", "mikrotik.com", "draytek.com", "ui.com", "ubnt.com",
    "asuscomm.com", "zyxel.com", "hikvision.com", "dahuasecurity.com", "cluster.local",
    "acme.com", "domain.com", "test.com", "yourdomain.com", "company.com", "mydomain.com",
    # dynamic-DNS providers: their subdomains are anyone's home server, not the provider
    "spdns.org", "spdns.de", "ddnss.de", "freeddns.org", "dyndns.info", "dyndns.biz", "dynv6.net", "hopto.org",
    "zapto.org", "sytes.net", "myftp.org", "myftp.biz", "serveftp.com", "servebeer.com", "ddns.me", "dnsalias.com",
    "dnsalias.net", "dnsalias.org", "homeip.net", "mooo.com", "changeip.com", "3322.org", "oray.net", "myds.me",
    "quickconnect.to", "selfhost.de", "goip.de", "dynu.net", "dynu.com", "kozow.com", "theworkpc.com", "ddns.info",
    "dyndns.tv", "dyndns-server.com", "dyndns-ip.com", "dnsupdate.info", "duckdns.net", "freedynamicdns.net",
    "noip.me", "webhop.me", "redirectme.net", "gotdns.ch", "ddnsfree.com", "ddnsgeek.com", "accesscam.org",
}

# cloud, CDN, hosting and SaaS platforms: their certs/PTRs name the platform, not the customer
INFRA_DOMAINS = {
    "amazonaws.com", "amazon.com", "aws", "cloudfront.net", "awsglobalaccelerator.com", "elb.amazonaws.com",
    "googleusercontent.com", "google.com", "googleapis.com", "1e100.net", "doubleclick.net", "gstatic.com",
    "azure.com", "azurewebsites.net", "cloudapp.net", "windows.net", "microsoft.com", "msedge.net",
    "cloudflare.com", "cloudflare.net", "cloudflaressl.com", "incapsula.com", "imperva.com", "incapdns.net",
    "akamai.com", "akamaiedge.net", "akamaitechnologies.com", "edgekey.net", "edgesuite.net", "fastly.net",
    "linodeusercontent.com", "linode.com", "digitalocean.com", "vultrusercontent.com", "vultr.com",
    "your-server.de", "hetzner.com", "hetzner.cloud", "ovh.net", "ovh.com", "contaboserver.net",
    "scw.cloud", "flyio.net", "fly.dev", "netlify.app", "vercel.app", "herokuapp.com", "github.io",
    "aliyun.com", "aliyuncs.com", "alibabacloud.com", "myqcloud.com", "tencent.com", "huaweicloud.com",
    "hwclouds-dns.com", "cdnhwc3.com", "ctcdn.cn", "oraclecloud.com", "oraclegoviaas.com", "secureserver.net",
    "sakura.ne.jp", "fc2.com", "nazwa.pl", "service-now.com", "salesforce.com", "force.com",
    "jamfcloud.com", "shopify.com", "myshopify.com", "wpengine.com", "squarespace.com", "wixsite.com",
    "peeringdb.com", "colocrossing.com", "datapacket.com", "leaseweb.net", "hostgator.com", "bluehost.com",
    "plesk.com", "cpanel.net", "kubernetes.default", "in-addr.arpa", "ip6.arpa",
}


def registrable(host):
    """'*.mail.acme.co.uk' -> 'acme.co.uk'; None for IPs, bare labels and unknown suffixes."""
    if not host:
        return None
    h = host.strip().strip(".").lower()
    if h.startswith("*."):
        h = h[2:]
    if not h or "." not in h or IP_LIKE.match(h) or " " in h:
        return None
    ext = _EXTRACT(h)
    if not ext.suffix or not ext.domain:
        return None
    return f"{ext.domain}.{ext.suffix}"


def resolve(host, source):
    """Return (domain, reject_reason). source in {cert, ntlm, http_host, ptr}."""
    d = registrable(host)
    if d is None:
        return None, "unparseable"
    if d in DEFAULT_CERT_DOMAINS or d.split(".")[-1] in ("local", "lan", "internal", "corp", "home", "arpa"):
        return None, "default_or_internal"
    if d in INFRA_DOMAINS:
        return None, "infra"
    if source == "ptr" and DYNAMIC_PTR.search(host):
        return None, "dynamic_ptr"
    return d, None
