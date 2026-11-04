# Identity gold labeller

Used for `identity_gold.csv`, `identity_gold_v2.csv` and `identity_gold_v3.csv` (100, 60 and 60 rows),
one subagent per file, run once each. `{sample}` and `{gold}` are the input and output paths; v2 and
v3 add "IPs are masked as a.b.c.x" to the context line, since their samples mask them.

---

You are building a gold-standard evaluation set for a B2B cybersecurity sales tool. Label each row of a CSV independently, using your own judgement and world knowledge. Do not read any other files in the repo or guess what the tool intended; judge only what each row shows.

Input: {sample}. Each row is one "account" the tool produced from internet-scan data. Columns:
- display_name: the name the tool shows a salesperson (a web domain, or a WHOIS organisation name)
- identity_source: how it was identified (cert = named in a TLS certificate; org = WHOIS owner of the IP block; ptr = reverse-DNS name; ntlm = leaked Windows domain; http_host = web Host header)
- top_org: WHOIS owner of the IPs where the assets sit (often a hosting provider or ISP; that is normal for companies hosted in the cloud)
- country, n_ips, plus certs / titles / products seen on its servers (context only)

For each row decide:
1. entity_type: one of
   - business: a real company or organisation that could plausibly buy security software for its own estate (includes hospitals, banks, manufacturers, SaaS companies, and small businesses)
   - public_sector: government, ministry, municipality, military
   - education: university, school, research institute
   - isp_telecom: the account is really an ISP/carrier/mobile operator, or its customer pool (residential/business broadband ranges)
   - hosting_cloud: the account is really a hosting/VPS/cloud/CDN/colocation provider or its shared infrastructure (including a hoster's own server-naming domain)
   - personal_or_junk: a personal site, dev/test box, parked domain, placeholder, or something that is not an organisation
   - unknown: genuinely cannot tell
2. name_ok: yes if display_name correctly names that entity (for a domain: it is the organisation's own domain), else no
3. sellable: yes if a salesperson at a cybersecurity vendor could sensibly prospect this account (entity_type in business/public_sector/education AND name_ok = yes), else no
4. note: a few words of reasoning

Be strict and honest; this is used to measure precision, so do not give the benefit of the doubt. A domain like vps123.somehost.com or a name like "Pool for fixed broadband users" is not sellable. Use web knowledge you already have; do not browse.

Write the output to {gold} with columns: company_id,entity_type,name_ok,sellable,note (keep company_id exactly as in the input, every row). Then reply with only: the count per entity_type, the share sellable overall, and the share sellable within each stratum value (the input has a stratum column: top3000 vs tail).
