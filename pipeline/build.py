"""Parquet banners -> scored accounts.

  noise filter  : drop honeypots, CDN edges and "answers-on-every-port" phantom IPs
  identity      : cert CN/SAN > NTLM FQDN > HTTP host > reverse DNS, then business `org` fallback;
                  identity is shared across ports of the same IP unless the IP is shared hosting
  signals       : pipeline/signals.py predicates, one row per (asset, signal)
  scoring       : need x urgency x fit x maturity, per company, with evidence rows

usage: python -m pipeline.build "<parquet glob>" <out_dir>
"""
import argparse
import json
import os
import time

import duckdb
import pyarrow as pa

from pipeline.identity import resolve
from pipeline.signals import (CPE_NAMES, CVE_REQUIRES, EOL_BRANCHES, MATURITY, OS_EOL, OS_RELEASE,
                              PATCHED_IN_PLACE, SIGNALS, frozen_sql)

# Retention and "new" go by observation time, not by file: a delivered file is a few hours of an
# ongoing crawl (this one covers 21:13 to 02:06), not a full re-scan of the internet.
RETAIN_DAYS = 30  # a service not observed in the last 30 days is treated as closed
NEW_DAYS = 7  # a service first observed in the last 7 days, on an IP already seen before then, is new
PHANTOM_PORTS = 50  # an IP answering on more distinct ports than this in one scan is a tarpit/proxy
SHARED_IP_DOMAINS = 5
SHARED_CERT_DOMAINS = 5  # a certificate whose SANs span this many domains is shared (a hoster's, a CDN's)  # an IP serving this many distinct company domains is shared hosting
HOSTER_DOMAINS = 10  # an org whose IPs carry this many distinct company domains is a hoster/ISP
PTR_ZONE_IPS = 20  # a reverse-DNS zone covering this many IPs (and few certs) is an ISP zone
P1_ACCOUNTS, P2_ACCOUNTS = 500, 2500
KEV_PATH = "data/enrichment/cisa_kev.json"  # the CISA catalogue: which vendor each known-exploited CVE belongs to
HOSTER_NAMING_IPS = 30  # ...and a domain naming this many IPs with numbered hosts is a hoster's scheme
NUMBERED_HOST_RE = r"^(\*\.)?[a-z-]*\d{2,}[a-z0-9-]*\."
DYNAMIC_PTR_SQL = (r"(?i)(\d{1,3}[-.x]){3}\d{1,3}|(dyn|dynamic|dsl|adsl|vdsl|pool|dhcp|cable|static|cust|"
                   r"customer|client|ppp|pppoe|broadband|fibre|fiber|ftth|cpe|res|home|user)\d*[-.]")
CONSUMER_RE = r"(?i)(tr-069|tr069|hikvision|dahua|webcam|ip camera|dvr|nvr|mikrotik|router|cpe|zte|huawei home|tp-link|chromecast)"
ISP_ORG_RE = (r"(?i)(telecom|telekom|communicat|broadband|cable|internet|network|mobile|cellular|wireless|"
              r"cloud|hosting|host|datacent|clientes|pool\b|residen|subscriber|customers|gpon|gepon|fttx|wba\b|users\b|data cent|server|colo|isp\b|online|telefonica|verizon|comcast|"
              r"at&t|vodafone|orange|chinanet|unicom|amazon|google|microsoft|alibaba|aliyun|tencent|huawei|"
              r"ovh|hetzner|digitalocean|linode|akamai|cloudflare|incapsula|fastly|oracle|contabo|vultr|"
              r"leaseweb|static pool|dynamic|dsl|fiber|fibre|ftth|\bnet\b|backbone|transit|ix\b|peering|"
              r"vps|dedicated|abuse|spam|claro|movistar|tdc|ntt|kddi|softbank|bezeq|telstra|optus|airtel|jio|"
              r"bsnl|viettel|vnpt|turk|bharti|rostelecom|mts|beeline|charter|spectrum|cox|frontier|centurylink|"
              r"lumen|cogent|level ?3|zayo|hurricane|tata|sify|pldt|globe|singtel|starhub|hinet|chunghwa|kt corp|"
              r"korea telecom|sk broadband|lg ?u|docomo|bell |rogers|shaw|telus|free sas|sfr|bouygues|"
              r"swisscom|proximus|kpn|ziggo|telenor|telia|elisa|cesnet|janet|renater)")


def q(con, sql):
    return con.sql(sql)


def build(glob, out_dir, llm_labels=None, domain_labels=None):
    t0 = time.time()
    os.makedirs(out_dir, exist_ok=True)
    con = duckdb.connect()
    con.execute("set memory_limit='5GB'; set preserve_insertion_order=false;")
    con.execute(f"set temp_directory='{os.path.join(out_dir, '.duck_tmp')}'")
    funnel = {}

    # one scan file or a stream of them: <root>/<scan-id>/*.parquet with scan ids that sort by time
    # union_by_name: scans written before a field was added still read (the missing column is null)
    con.execute(f"""create view scans as select *, regexp_extract(filename, '([^/]+)/[^/]+$', 1) scan,
        try_cast(ts as timestamp) seen from read_parquet('{glob}', filename = true, union_by_name = true)""")
    scan_ids = [r[0] for r in con.execute("select distinct scan from scans order by 1").fetchall()]
    funnel["scans"] = len(scan_ids)
    lo, hi = con.execute("select min(seen), max(seen) from scans").fetchone()
    funnel["observed_from"], funnel["observed_to"] = str(lo)[:19], str(hi)[:19]
    if len(scan_ids) == 1:
        con.execute("create view raw as select * exclude (filename, scan, seen), false is_new from scans")
    else:
        # latest observation wins per service, and only the last RETAIN_DAYS count. A service is new
        # when first observed in the last NEW_DAYS on an IP the crawl had already seen before then, so a
        # file covering a different IP range doesn't make everything in it look new.
        con.execute(f"""create table raw as
            with svc as (select ip, port, transport, min(seen) first_seen from scans group by all),
                 ipf as (select ip, min(seen) ip_first from scans group by ip)
            select s.* exclude (filename, scan, seen),
                   f.first_seen >= timestamp '{hi}' - interval {NEW_DAYS} day
                   and i.ip_first < timestamp '{hi}' - interval {NEW_DAYS} day is_new
            from scans s join svc f using (ip, port, transport) join ipf i using (ip)
            where s.seen >= timestamp '{hi}' - interval {RETAIN_DAYS} day
            qualify row_number() over (partition by ip, port, transport order by s.seen desc) = 1""")
        funnel["services_new_in_latest_scan"] = con.execute("select count(*) from raw where is_new").fetchone()[0]
    # a honeypot is the whole IP: the scanner tags the ports it recognised, and the same IP's other
    # ports (43k records on this file) answer just as falsely. Tor relays aren't anyone's estate.
    con.execute("""create table ip_stats as
        select ip, count(distinct port) n_ports, bool_or(list_contains(tags, 'honeypot')) honeypot_ip
        from raw group by ip""")
    con.execute(f"""create table clean as
        select r.*, row_number() over () rid, {PATCHED_IN_PLACE} patched_in_place,
               {OS_RELEASE} os_release, {OS_EOL} os_eol
        from raw r join ip_stats s using (ip)
        where not s.honeypot_ip and not list_contains(r.tags, 'cdn') and not list_contains(r.tags, 'tor')
          and s.n_ports <= {PHANTOM_PORTS}""")
    funnel.update(con.execute(f"""select count(*) raw_records,
        count(*) filter (where honeypot_ip) honeypot,
        count(*) filter (where list_contains(tags, 'cdn') and not honeypot_ip) cdn,
        count(*) filter (where list_contains(tags, 'tor') and not honeypot_ip and not list_contains(tags, 'cdn')) tor,
        count(*) filter (where n_ports > {PHANTOM_PORTS} and not list_contains(tags, 'cdn') and not honeypot_ip
            and not list_contains(tags, 'tor')) phantom,
        (select count(*) from clean) clean from raw join ip_stats using (ip)""").fetchdf().iloc[0].to_dict())

    # --- CVE matches that hold up (see pipeline/signals.py) ---------------------------------
    # notable matches only (known exploited, EPSS >= 0.1 or CVSS >= 9): what the signals and CVE search use
    kev = json.load(open(KEV_PATH))["vulnerabilities"]
    con.register("kev_arrow", pa.table({"cve": [v["cveID"] for v in kev],
                                         "vendor": [v["vendorProject"] for v in kev]}))
    con.execute("""create table kev_vendor as
        select cve, regexp_replace(lower(vendor), '[^a-z0-9]', '', 'g') vtok from kev_arrow""")
    names = " ".join(f"when '{k}' then '{v}'" for k, v in CPE_NAMES.items())
    con.execute(f"""create table vuln_ok as
        with u as (
            select c.rid, c.product, c.version, c.module, c.patched_in_place, v, kv.vtok,
                   coalesce(c.http_server, '') || ' ' || coalesce(c.os, '') platform,
                   -- the products the service names with a version number, from its CPEs
                   list_transform(list_filter(c.cpe23, lambda x: regexp_matches(split_part(x, ':', 6), '[0-9]')),
                       lambda x: {{'vend': regexp_replace(lower(split_part(x, ':', 4)), '[^a-z0-9]', '', 'g'),
                                   'prod': split_part(x, ':', 5), 'ver': split_part(x, ':', 6)}}) cpe_v,
                   len(list_filter(c.cpe23, lambda x: split_part(x, ':', 3) = 'a'
                       and not regexp_matches(split_part(x, ':', 6), '[0-9]'))) n_unversioned_apps
            from clean c, unnest(c.vulns) t(v) left join kev_vendor kv on kv.cve = v.cve
            where v.kev or coalesce(v.epss, 0) >= 0.1 or coalesce(v.cvss, 0) >= 9),
        m as (
            select *, case
                -- a KEV CVE: its vendor among the versioned products (php ~ "PHP Group")
                when vtok is not null then list_filter(cpe_v, lambda x: x.vend = vtok
                    or (len(x.vend) >= 3 and (starts_with(vtok, x.vend) or starts_with(x.vend, vtok))))[1]
                -- any other CVE: the service names exactly one versioned product, so it's that one's
                when len(cpe_v) = 1 and n_unversioned_apps = 0 then cpe_v[1] end hit
            from u)
        select rid, list({{'cve': v.cve, 'cvss': v.cvss, 'epss': v.epss, 'kev': v.kev, 'verified': v.verified,
            'seen': case when v.verified or hit.ver = version then concat_ws(' ', coalesce(product, module), version)
                         else (case hit.prod {names} else replace(hit.prod, '_', ' ') end) || ' ' || hit.ver end}}) vulns_ok
        from m
        where (v.verified or (not patched_in_place and hit is not null
                              and not {frozen_sql('hit.prod', 'hit.ver')}))
          and not ({" or ".join(f"(v.cve = '{c}' and platform not ilike '%{x}%')" if kind == "platform" else
                                f"(v.cve = '{c}' and hit is not null and not starts_with(hit.ver, '{x}'))"
                                for c, kind, x in CVE_REQUIRES)})
        group by rid""")
    # the oldest end-of-life component a service names with a version (pipeline/signals.py EOL_BRANCHES)
    eol_cases = " ".join(f"when cv = '{c}' and regexp_matches(ver, '{rx}') then date '{d}'" for c, rx, _, d in EOL_BRANCHES)
    con.execute(f"""create table eol_sw as
        select rid, arg_min(name, d) eol_sw, min(d) eol_sw_date from (
            select rid, (case prod {names} else replace(prod, '_', ' ') end) || ' ' || ver name, case {eol_cases} end d
            from (select rid, split_part(x, ':', 4) || ':' || split_part(x, ':', 5) cv, split_part(x, ':', 5) prod,
                         split_part(x, ':', 6) ver
                  from clean, unnest(cpe23) t(x))
            where not {frozen_sql('prod', 'ver')})
        where d is not null group by rid""")
    funnel.update(con.execute("""select count(*) cve_matches_notable,
        count(*) filter (where v.verified) cve_matches_verified,
        (select count(*) from vuln_ok, unnest(vulns_ok)) cve_matches_kept
        from clean, unnest(vulns) t(v) where v.kev or coalesce(v.epss, 0) >= 0.1 or coalesce(v.cvss, 0) >= 9""").fetchdf().iloc[0].to_dict())

    # --- identity candidates ------------------------------------------------------------
    # a certificate's CN names its owner; its SANs can name customers (a hoster's shared certificate)
    con.execute("""create table cand as
        select rid, ip, cert_cn h, 'cert' src, false san from clean where cert_cn is not null
        union all select rid, ip, unnest(list_filter(cert_san, lambda x: x <> coalesce(cert_cn, ''))), 'cert', true
            from clean where len(cert_san) > 0
        union all select rid, ip, ntlm_fqdn, 'ntlm', false from clean where ntlm_fqdn is not null
        union all select rid, ip, ntlm_dns_domain, 'ntlm', false from clean where ntlm_dns_domain is not null
        union all select rid, ip, http_host, 'http_host', false from clean
            where http_host is not null and not regexp_matches(http_host, '^[0-9.:\\[\\]]+$')
        union all select rid, ip, unnest(hostnames), 'ptr', false from clean where len(hostnames) > 0""")
    distinct = con.execute("select distinct h, src from cand where h is not null").fetchall()
    mapped = [(h, s, *resolve(h, s)) for h, s in distinct]
    con.register("hmap_arrow", pa.table({k: [m[i] for m in mapped] for i, k in
                                          enumerate(["h", "src", "domain", "reason"])}))
    con.execute("create table hmap as select * from hmap_arrow")
    funnel["distinct_hostnames"] = len(mapped)

    con.execute("""create table cand_d as
        select c.rid, c.ip, c.src, c.san, c.h, m.domain, cl.asn, cl.org
        from cand c join hmap m using (h, src) join clean cl using (rid)
        where m.domain is not null""")
    # data-driven infra: a domain spread over many ASNs/orgs, a PTR zone covering many IPs, or a
    # hoster's server-naming scheme (vps123.hoster.com, one numbered name per IP) is a platform or an
    # ISP, not a customer
    con.execute(f"""create table infra_auto as
        select domain from cand_d group by domain
        having count(distinct asn) >= 8 or count(distinct org) >= 15
            or (count(distinct ip) filter (where src = 'ptr') >= {PTR_ZONE_IPS}
                and count(distinct ip) filter (where src <> 'ptr') < 0.2 * count(distinct ip))
            or (count(distinct ip) >= {HOSTER_NAMING_IPS}
                and avg(regexp_matches(lower(h), '{NUMBERED_HOST_RE}')::int) >= 0.4)""")
    funnel["infra_domains_auto"] = con.execute("select count(*) from infra_auto").fetchone()[0]
    if domain_labels and os.path.exists(domain_labels):
        con.execute(f"""insert into infra_auto select domain from read_csv_auto('{domain_labels}')
            where org_type in ('isp_telecom', 'hosting_cloud') and confidence <> 'low'""")

    # a certificate's SANs don't name the owner when its CN is a platform's (the hoster's shared
    # certificate) or they span SHARED_CERT_DOMAINS domains; the CN still does
    con.execute(f"""create table shared_cert as
        select c.rid from cand c join hmap m using (h, src) where c.src = 'cert' group by c.rid
        having bool_or(not c.san and (m.reason = 'infra' or m.domain in (select domain from infra_auto)))
            or count(distinct m.domain) filter (where c.san) >= {SHARED_CERT_DOMAINS}""")
    con.execute("""create table rec_ident as
        select rid, ip, arg_min(domain, prio::varchar || ':' || san::int || ':' || domain) domain, min(prio) prio from (
            select *, case src when 'cert' then 1 when 'ntlm' then 2 when 'http_host' then 3 else 4 end prio
            from cand_d where domain not in (select domain from infra_auto)
              and not (san and rid in (select rid from shared_cert))) group by rid, ip""")
    con.execute("""create table ip_ident as
        select ip, count(distinct domain) n_dom, arg_min(domain, prio::varchar || ':' || domain) domain, min(prio) prio
        from rec_ident group by ip""")
    funnel["shared_certificates"] = con.execute("select count(*) from shared_cert").fetchone()[0]

    # --- org classification (business vs ISP/hosting) ---------------------------------------
    # an org whose IPs carry many unrelated company domains is hosting them: that is the strongest
    # ISP/hoster tell in the data, far better than matching on the name
    # ISP customer pools also give themselves away by dynamic reverse DNS and consumer gear
    # (TR-069 home routers, cameras, MikroTik CPEs) on a large share of their IPs
    con.execute(f"""create table org_stats as
        with d as (select org, count(distinct domain) n_domains from cand_d
                   where src <> 'ptr' and domain not in (select domain from infra_auto) group by org),
        ip_feat as (
            select org, ip,
                   bool_or(len(hostnames) > 0 and regexp_matches(hostnames[1], '{DYNAMIC_PTR_SQL}')) dyn,
                   bool_or(regexp_matches(coalesce(product, '') || ' ' || coalesce(devicetype, '') || ' ' || module,
                                          '{CONSUMER_RE}')) consumer,
                   any_value(asn) asn, bool_or(cloud_provider is not null) cloud
            from raw where org is not null group by org, ip)
        select f.org, count(*) n_ips, count(distinct asn) n_asn, avg(cloud::int) cloud_share,
               avg(dyn::int) dyn_share, avg(consumer::int) consumer_share,
               coalesce(any_value(d.n_domains), 0) n_domains,
               regexp_matches(f.org, '{ISP_ORG_RE}') isp_name
        from ip_feat f left join d using (org) group by f.org""")
    con.execute(f"""create table org_class as select org,
        case when isp_name or cloud_share > 0.2 or n_ips > 2048 or n_asn > 3
                  or n_domains >= {HOSTER_DOMAINS}
                  or (n_ips >= 20 and (dyn_share >= 0.15 or consumer_share >= 0.10)) then 'isp_or_hosting'
             else 'business' end org_type, 'heuristic' org_type_source, null::varchar industry
        from org_stats""")
    if llm_labels and os.path.exists(llm_labels):
        con.execute(f"""update org_class set org_type = l.org_type, industry = l.industry,
            org_type_source = 'llm' from read_csv_auto('{llm_labels}') l where org_class.org = l.org""")

    # --- assets with a company -------------------------------------------------------------
    con.execute(f"""create table assets as
        select cl.*,
            case when ii.n_dom >= {SHARED_IP_DOMAINS} then null
                 else coalesce(ri.domain, case when ii.n_dom <= 2 then ii.domain end) end domain,
            case when ii.n_dom >= {SHARED_IP_DOMAINS} then null
                 when ri.domain is not null then ri.prio
                 when ii.n_dom <= 2 and ii.domain is not null then ii.prio + 10 end ident_prio,
            oc.org_type, oc.industry org_industry, oc.org_type_source,
            coalesce(ii.n_dom, 0) >= {SHARED_IP_DOMAINS} shared_ip, coalesce(vo.vulns_ok, []) vulns_ok,
            coalesce(os_.n_domains, 0) org_n_domains, es.eol_sw, es.eol_sw_date
        from clean cl left join rec_ident ri using (rid) left join ip_ident ii on cl.ip = ii.ip
        left join vuln_ok vo using (rid) left join org_stats os_ on cl.org = os_.org left join eol_sw es using (rid)
        left join org_class oc on cl.org = oc.org""")
    con.execute("""alter table assets add column company_id varchar;
        update assets set company_id = coalesce(domain,
            case when org_type = 'business' and not shared_ip then 'org:' || org end)""")
    # one organisation, one account: an org's unnamed services join its own domain when the domain is
    # recognisably the org's: its name is the org's acronym or a word of the org's name (usp.br for
    # UNIVERSIDADE DE SAO PAULO, unam.mx, toronto.edu). Not by share of services: a lab's certificate on
    # many hosts would take a whole university. Never for an org that hosts many organisations (a
    # research network like AMRES or TANet serves dozens of universities and is none of them).
    con.execute(f"""create table org_home as
        with w as (
            select distinct org, domain, split_part(domain, '.', 1) label,
                   list_filter(string_split_regex(lower(strip_accents(org)), '[^a-z0-9]+'),
                       lambda x: x <> '' and x not in ('de', 'of', 'the', 'and', 'del', 'da', 'do', 'des', 'la', 'le',
                                                      'y', 'e', 'for', 'fur', 'di', 'du', 'van', 'von', 'und')) words
            from assets where domain is not null and org is not null and org_n_domains < {HOSTER_DOMAINS}),
        m as (
            select org, domain, (select count(*) from assets a where a.org = w.org and a.domain = w.domain) n from w
            where label = array_to_string(list_transform(words, lambda x: x[1]), '')
               or (len(label) >= 4 and list_contains(words, label) and label not in ('university', 'universidad',
                   'universidade', 'universite', 'universita', 'national', 'nacional', 'college', 'institute', 'instituto',
                   'group', 'bank', 'hospital', 'school', 'city', 'state', 'government', 'ministry', 'telecom', 'network',
                   'networks', 'services', 'technology', 'international', 'global', 'company', 'corporation', 'limited',
                   'systems', 'software', 'data', 'digital', 'cloud', 'online', 'media', 'center', 'centre', 'research')))
        select org, arg_max(domain, n) domain from m group by org""")
    funnel["org_accounts_merged"] = con.execute("""select count(distinct a.org) from assets a join org_home h using (org)
        where a.company_id = 'org:' || a.org""").fetchone()[0]
    con.execute("""update assets set company_id = h.domain from org_home h
        where assets.company_id = 'org:' || assets.org and assets.org = h.org""")
    funnel.update(con.execute("""select count(*) filter (where company_id is not null) attributed_assets,
        count(*) filter (where domain is not null) attributed_by_domain,
        count(*) filter (where domain is null and company_id is not null) attributed_by_org,
        count(*) filter (where shared_ip) shared_hosting_assets,
        count(distinct company_id) companies from assets""").fetchdf().iloc[0].to_dict())

    # --- signals -------------------------------------------------------------------------
    parts = [f"""select rid, company_id, ip, port, product, is_new, '{sid}' signal, '{cat}' category,
                    {w}::double weight, '{label.replace("'", "''")}' label, ({ev})::varchar evidence
                 from assets where company_id is not null and ({pred})"""
             for sid, cat, w, label, pred, ev in SIGNALS]
    con.execute("create table sig_all as " + " union all ".join(parts))
    # one asset counts once per category (its strongest signal); an edge device already scored
    # for a KEV CVE does not also score the same CVE as a generic vuln; and an end-of-life component
    # that is the product a CVE on the same asset belongs to ("PHP 7.4.33") is one fact, not two: it
    # stays as evidence (it's the easiest part to verify) but scores nothing
    con.execute("""create table sig as
        with cve_products as (
            select rid, list(distinct split_part(evidence, ' — ', 1)) seen from sig_all
            where category in ('vuln', 'edge') group by rid),
        ranked as (
            select s.*, row_number() over (partition by s.rid, s.category order by s.weight desc) rn,
                   bool_or(s.signal = 'edge_kev') over (partition by s.rid) has_edge_kev,
                   s.signal = 'eol_product' and list_contains(coalesce(c.seen, []), split_part(s.evidence, ',', 1)) same_fact
            from sig_all s left join cve_products c using (rid))
        select * exclude (rn, has_edge_kev, same_fact, weight), case when same_fact then 0 else weight end weight
        from ranked where rn = 1 and not (has_edge_kev and category = 'vuln')""")
    mparts = [f"select company_id, '{mid}' flag, '{label}' label from assets "
              f"where company_id is not null and ({pred})" for mid, pred, label in MATURITY]
    con.execute("create table maturity as select distinct * from (" + " union all ".join(mparts) + ")")

    # --- company scoring ----------------------------------------------------------------
    con.execute("""create table per_sig as
        select company_id, signal, any_value(label) label, any_value(category) category,
               max(weight) weight, count(distinct ip || ':' || port) filter (where weight > 0) n,
               case when count(*) filter (where weight > 0) = 0 then 0 else
                   least(max(weight) * (1 + ln(count(distinct ip || ':' || port) filter (where weight > 0))), max(weight) * 2.5) end pts,
               bool_or(is_new) any_new
        from sig group by company_id, signal""")
    con.execute(f"""create table accounts as
        with a as (
            select company_id,
                   any_value(domain) filter (where domain is not null) domain,
                   mode(org) filter (where org_type = 'business') business_org,
                   mode(org) top_org, mode(country) country, mode(org_industry) org_industry,
                   bool_or(org_type_source = 'llm') org_confirmed,
                   -- measured on two blind samples: IP-owner / reverse-DNS identities are 0-15% sellable,
                   -- except universities and governments, which really do own their address blocks
                   coalesce(min(ident_prio) in (4, 14), true) weak_identity,
                   -- ...but not a research/education network that carries many organisations' domains
                   bool_or(org_type_source = 'llm' and org_industry in ('Education', 'Government')
                           and org_n_domains < {HOSTER_DOMAINS}) owns_its_ips,
                   count(distinct ip) n_ips, count(*) n_assets, min(ident_prio) ident_prio,
                   list(distinct product) filter (where product is not null)[1:12] products,
                   list(distinct coalesce(fortinet_device, product)) filter (where coalesce(fortinet_device, product) is not null) products_all
            from assets where company_id is not null group by company_id),
        s as (
            select company_id, sum(pts) need,
                   bool_or(signal in ('edge_kev','kev_cve')) has_kev,
                   bool_or(signal in ('eol_os','eol_product')) has_eol,
                   bool_or(signal in ('cert_expired','cert_expiring')) has_cert_issue,
                   bool_or(category = 'breach') has_breach,
                   bool_or(category in ('breach','edge','exposure','vuln','eol')) has_material,
                   bool_or(any_new and category in ('breach','edge','exposure','vuln','eol')) has_new,
                   list(signal order by pts desc) signals,
                   list(label order by pts desc) signal_labels,
                   max(weight) top_weight
            from per_sig group by company_id),
        m as (select company_id, list(flag) maturity, list(label) maturity_labels
              from maturity group by company_id)
        select a.*, s.* exclude (company_id), coalesce(m.maturity, []) maturity,
               coalesce(m.maturity_labels, []) maturity_labels,
               -- already breached outranks could be breached
               1 + 0.5 * has_breach::int + 0.4 * has_kev::int + 0.2 * has_eol::int + 0.1 * has_cert_issue::int
                 + 0.3 * has_new::int urgency,
               (case when ident_prio is null then 0.85      -- business org only
                     when ident_prio <= 3 then 1.0          -- cert / ntlm / http host
                     when ident_prio = 4 then 0.75          -- reverse DNS
                     else 0.9 end)                          -- inherited from another port on the IP
               * (0.75 + 0.25 * least(1, log10(n_ips + 1) / 2)) fit,
               greatest(0.8, 1 - 0.05 * len(coalesce(m.maturity, []))) maturity_factor
        from a join s using (company_id) left join m using (company_id)""")
    con.execute("""alter table accounts add column priority double;
        update accounts set priority = need * urgency * fit * maturity_factor
            * case when has_material then 1 else 0.3 end
            * case when weak_identity and not owns_its_ips then 0.3 else 1 end""")
    con.execute("""alter table accounts add column material_rank bigint;
        update accounts set material_rank = r.rk from (
            select company_id, row_number() over (order by priority desc) rk
            from accounts where has_material) r where accounts.company_id = r.company_id""")
    # score: log-scaled so the top stays spread out; tiers: by rank, sized to what a sales team can
    # actually work (P1 = this week's calls), not percentiles of a long hygiene-only tail
    con.execute(f"""create table accounts_out as
        select *, round(100 * ln(1 + priority) / ln(1 + max(priority) over ()), 1) score,
            case when has_material and material_rank <= {P1_ACCOUNTS} then 'P1'
                 when has_material and material_rank <= {P1_ACCOUNTS + P2_ACCOUNTS} then 'P2'
                 else 'P3' end tier,
            coalesce(domain, business_org, replace(company_id, 'org:', '')) display_name,
            case when ident_prio is null then 'org' when ident_prio = 1 then 'cert'
                 when ident_prio = 2 then 'ntlm' when ident_prio = 3 then 'http_host'
                 when ident_prio = 4 then 'ptr' else 'same_ip' end identity_source,
            case when list_has_any(signals, ['edge_kev','edge_device','exchange_onprem']) then 'Perimeter'
                 when list_contains(signals, 'ot_exposed') then 'OT / IoT'
                 when list_has_any(signals, ['remote_access','database_exposed','smb_exposed','open_directory','mgmt_exposed']) then 'Exposure'
                 when list_has_any(signals, ['kev_cve','high_epss','critical_cve','eol_os','eol_product']) then 'Vulnerability'
                 else 'Hygiene' end play
        from accounts order by priority desc""")
    con.execute(f"copy accounts_out to '{out_dir}/accounts.parquet' (format parquet, compression zstd)")
    con.execute(f"""copy (
        select s.company_id, s.signal, s.label, s.category, s.weight, s.ip, s.port, s.product, s.evidence,
               a.org, a.country, a.cert_cn, a.http_title, a.module
        from (select *, row_number() over (partition by company_id order by weight desc, ip) rn from sig) s
        join assets a using (rid) where s.rn <= 60
    ) to '{out_dir}/evidence.parquet' (format parquet, compression zstd)""")
    con.execute(f"""copy (select org, org_type, org_type_source, n_ips, n_asn, cloud_share
        from org_class join org_stats using (org)) to '{out_dir}/org_class.parquet' (format parquet)""")
    # notable CVEs per service, for every attributed company: the index behind CVE search.
    # Notable = known exploited, EPSS >= 0.1 or CVSS >= 9, and only matches that hold up (vulns_ok)
    con.execute(f"""copy (
        select company_id, ip, port, coalesce(fortinet_device, product) product, is_new,
               vulns_ok cves
        from assets where company_id is not null and len(vulns_ok) > 0
    ) to '{out_dir}/asset_cves.parquet' (format parquet, compression zstd)""")

    funnel["scored_companies"] = con.execute("select count(*) from accounts_out").fetchone()[0]
    funnel["companies_with_material_signal"] = con.execute(
        "select count(*) from accounts_out where has_material").fetchone()[0]
    funnel["signal_rows"] = con.execute("select count(*) from sig").fetchone()[0]
    funnel["signals_by_type"] = dict(con.execute(
        "select signal, count(distinct company_id) from sig group by 1 order by 2 desc").fetchall())
    funnel["build_seconds"] = round(time.time() - t0, 1)
    funnel = {k: (int(v) if hasattr(v, "item") else v) for k, v in funnel.items()}
    with open(f"{out_dir}/funnel.json", "w") as f:
        json.dump(funnel, f, indent=2)
    return funnel


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("glob")
    ap.add_argument("out_dir")
    ap.add_argument("--llm-labels", default="data/labels/org_labels.csv")
    ap.add_argument("--domain-labels", default="data/labels/domain_labels.csv")
    a = ap.parse_args()
    print(json.dumps(build(a.glob, a.out_dir, a.llm_labels, a.domain_labels), indent=2))
