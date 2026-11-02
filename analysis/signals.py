import sys, json, collections as C
f=open(sys.argv[1])
n=0; cnt=C.Counter(); mods=C.Counter(); ports=C.Counter(); certO=C.Counter(); ntlm_dom=C.Counter()
kev=C.Counter(); prods_vuln=C.Counter(); titles=C.Counter(); http_comp=C.Counter(); waf=C.Counter(); tags=C.Counter()
HOST=('cloud','hosting','amazon','google','microsoft','cloudflare','akamai','incapsula','alibaba','aliyun','tencent','digitalocean','hetzner','ovh','linode','telecom','communications','broadband','mobile','cable','internet','fastly','oracle','huawei','vultr','scaleway','net ')
for line in f:
    r=json.loads(line); n+=1
    org=(r.get('org') or '').lower(); tg=r.get('tags') or []
    for t in tg: tags[t]+=1
    mods[r['_shodan']['module']]+=1; ports[r.get('port')]+=1
    hp='honeypot' in tg
    cnt['honeypot']+=hp
    if hp: continue
    cnt['org_not_hostlike']+= not any(h in org for h in HOST)
    cnt['has_domain']+= bool(r.get('domains'))
    c=((r.get('ssl') or {}).get('cert') or {})
    s=c.get('subject') or {}
    if s.get('O'): certO[s['O']]+=1; cnt['cert_has_O']+=1
    if c: 
        cnt['has_cert']+=1; cnt['cert_expired']+=bool(c.get('expired'))
        cnt['self_signed']+= (c.get('issuer')==c.get('subject'))
    v=(r.get('ssl') or {}).get('versions') or []
    if any(x in v for x in ('TLSv1','SSLv3','SSLv2','TLSv1.1')): cnt['weak_tls']+=1
    if r.get('ntlm'): ntlm_dom[r['ntlm'].get('dns_domain_name')]+=1; cnt['ntlm']+=1
    vu=r.get('vulns') or {}
    if vu:
        cnt['has_vulns']+=1
        if any(x.get('kev') for x in vu.values()): cnt['has_kev']+=1; prods_vuln[r.get('product')]+=1
        for k,x in vu.items():
            if x.get('kev'): kev[k]+=1
        if any((x.get('epss') or 0)>0.5 for x in vu.values()): cnt['epss>0.5']+=1
    h=r.get('http') or {}
    if h:
        if h.get('waf'): waf[h['waf']]+=1
        titles[(h.get('title') or '')[:60]]+=1
        for comp in (h.get('components') or {}): http_comp[comp]+=1
        hd={k.lower() for k in (h.get('headers') or {})}
        cnt['http']+=1; cnt['no_hsts']+= 'strict-transport-security' not in hd; cnt['no_csp']+='content-security-policy' not in hd
        cnt['has_securitytxt']+=bool(h.get('securitytxt'))
    for key in ('rdp_encryption','smb','telnet','vnc','mysql','mongodb','elastic','redis','ftp','snmp','microsoft_exchange','fortinet','kubernetes','open_dir','screenshot','ics'):
        if key in r: cnt['svc:'+key]+=1
p=lambda name,c,k=30: print(f"\n== {name}\n"+"\n".join(f"{v:>7} {k_}" for k_,v in c.most_common(k)))
print("records",n); p("counts",cnt,60); p("tags",tags); p("modules",mods,60); p("ports",ports,40)
p("KEV cves",kev,25); p("products w/ KEV",prods_vuln,20); p("cert O",certO,30); p("ntlm dns domain",ntlm_dom,20)
p("http titles",titles,40); p("waf",waf,15); p("components",http_comp,30)
