import sys, json, re, collections as C
SL2={'co','com','net','org','gov','edu','ac','or','ne','go','gob','nic','mil','ltd','plc','sch'}
def reg(h):
    p=h.lower().strip('.').split('.')
    if len(p)<2: return None
    return '.'.join(p[-3:]) if len(p)>=3 and (p[-2] in SL2) and len(p[-1])==2 else '.'.join(p[-2:])
HOSTD=set('amazonaws.com cloudfront.net googleusercontent.com linodeusercontent.com akamaitechnologies.com cloudflare.com azure.com bc.googleusercontent.com vultrusercontent.com your-server.de hetzner.com ovh.net contaboserver.net digitalocean.com aliyun.com 1e100.net localhost incapdns.net akamaiedge.net fastly.net comcast.net verizon.net rr.com spectrum.com sbcglobal.net myvzw.com t-mobile.com chinanet.cn.net secureserver.net amazon.com google.com fbcdn.net edgekey.net'.split())
DYN=re.compile(r'(\d{1,3}[-.]){3}\d{1,3}|dyn|dsl|pool|dhcp|cable|static|customer|client|ppp|broadband|host-|ip-')
f=open(sys.argv[1]); comp=C.defaultdict(lambda: C.Counter()); src=C.Counter(); n=0; assigned=0
rat=C.Counter(); lsp=[]; ot=C.Counter()
RATS=('rat','blackshades','poison-ivy','njrat','backdoor')
OT=('melsec','codesys','proconos','automated-tank-gauge','dicom','modbus','s7','bacnet','dnp3','toshiba-pos','handpunch','fox','ethernetip')
for line in f:
    r=json.loads(line); n+=1
    tg=r.get('tags') or []
    if 'honeypot' in tg: continue
    m=r['_shodan']['module']
    if any(x in m for x in RATS): rat[(r.get('org'),bool(r.get('cloud')),tuple(r.get('domains') or []))]+=1
    if any(x in m for x in OT): ot[(m,r.get('org'))]+=1
    if m=='language-server-protocol' and len(lsp)<3: lsp.append((r.get('port'),r.get('org'),r.get('data','')[:300]))
    cands=[]
    c=((r.get('ssl') or {}).get('cert') or {})
    cn=(c.get('subject') or {}).get('CN') or ''
    if cn and '.' in cn and not cn.startswith('*.') or cn.startswith('*.'): cands.append(('cert_cn',reg(cn.lstrip('*.'))))
    for h in r.get('hostnames') or []:
        if not DYN.search(h): cands.append(('hostname',reg(h)))
    for d in r.get('domains') or []: cands.append(('domain',d.lower()))
    cands=[(s,d) for s,d in cands if d and d not in HOSTD]
    if cands:
        s,d=cands[0]; src[s]+=1; assigned+=1; comp[d]['assets']+=1
        if r.get('vulns'): comp[d]['vuln']+=1
        comp[d]['ports_'+str(r.get('port'))]+=0
print("records",n,"assigned to a company domain",assigned, f"{assigned/n:.1%}")
print("by source",src.most_common())
print("distinct company domains",len(comp))
sizes=C.Counter(min(v['assets'],10) for v in comp.values()); print("assets per domain (capped 10)",sorted(sizes.items()))
print("\ntop domains by assets:"); [print(f"{v['assets']:>6} {k}") for k,v in sorted(comp.items(),key=lambda x:-x[1]['assets'])[:40]]
print("\nRAT/C2 detections (org, is_cloud, domains):"); [print(c,k) for k,c in rat.most_common(15)]
print("\nOT modules (module, org):"); [print(c,k) for k,c in ot.most_common(20)]
print("\nLSP samples:"); [print(x) for x in lsp]
