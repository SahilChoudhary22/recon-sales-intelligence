import sys, json, re, collections as C
ISPW=re.compile(r'telecom|communications|broadband|cable|internet|network|mobile|cloud|hosting|host|datacenter|data center|server|isp|online|telekom|telefonica|verizon|comcast|at&t|vodafone|orange|chinanet|china |unicom|amazon|google|microsoft|alibaba|aliyun|tencent|huawei|ovh|hetzner|digitalocean|linode|akamai|cloudflare|incapsula|fastly|oracle|contabo|vultr|leaseweb|colo|net |\bnet$|ltd\.? ?$|llc$',re.I)
SL2={'co','com','net','org','gov','edu','ac','or','ne','go','gob'}
def reg(h):
    p=h.lower().lstrip('*.').strip('.').split('.')
    if len(p)<2: return None
    return '.'.join(p[-3:]) if len(p)>=3 and p[-2] in SL2 and len(p[-1])==2 else '.'.join(p[-2:])
VENDOR={'fortinet.com','sonicwall.com','localhost','example.com','cloudflare.com','amazonaws.com','incapsula.com','imperva.com','googleusercontent.com','akamai.com','microsoft.com','azurewebsites.net','cloudfront.net','fortigate','fortiddns.com','synology.me','myfritz.net','dyndns.org','no-ip.org'}
n=0; id_src=C.Counter(); strong=C.Counter(); comps=C.defaultdict(set); ex=[]
for line in open(sys.argv[1]):
    r=json.loads(line); tg=set(r.get('tags') or [])
    if 'honeypot' in tg or 'cdn' in tg: continue
    n+=1
    c=((r.get('ssl') or {}).get('cert') or {}); s=c.get('subject') or {}
    ident=None
    cn=s.get('CN') or ''
    d=reg(cn) if '.' in cn else None
    if d and d not in VENDOR and not re.match(r'^\d',d): ident=('cert_cn',d)
    elif r.get('ntlm') and '.' in (r['ntlm'].get('dns_domain_name') or ''):
        dd=reg(r['ntlm']['dns_domain_name'])
        if dd and not dd.endswith(('.local','.lan','.internal','.corp')): ident=('ntlm_fqdn',dd)
        else: ident=('ntlm_internal',r['ntlm']['dns_domain_name'])
    if not ident and r.get('org') and not ISPW.search(r['org']): ident=('business_org',r['org'])
    id_src[ident[0] if ident else 'none']+=1
    p=(r.get('product') or '').lower(); m=r['_shodan']['module']
    vu=r.get('vulns') or {}
    st= ('forti' in p or 'sonicwall' in p or 'netscaler' in p or 'pulse' in p or 'big-ip' in p or 'bigip' in p or 'exchange' in m or r.get('microsoft_exchange')) \
        or any(x.get('kev') for k,x in vu.items() if k!='CVE-2023-44487') \
        or m in ('rdp','ms-sql','mysql','redis','mongodb','telnet','vnc','smb','elastic') or 'eol-os' in tg
    if st:
        strong[ident[0] if ident else 'none']+=1
        if ident: comps[ident[0]].add(ident[1])
        if ident and ident[0] in ('cert_cn','business_org','ntlm_fqdn') and len(ex)<25: ex.append((ident, r.get('org'), r.get('port'), r.get('product')))
print("clean records",n); print("identity source (all clean):",id_src.most_common())
print("strong-signal records by identity:",strong.most_common())
print("distinct identities w/ strong signal (1% sample):",{k:len(v) for k,v in comps.items()})
print("\nexamples:"); [print(" ",e) for e in ex]
