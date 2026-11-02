import sys, json, collections as C
f=open(sys.argv[1]); n=0; cat=C.Counter(); mods=C.Counter(); prods=C.Counter(); kev=C.Counter(); withdom=C.Counter(); ex=C.defaultdict(list)
EDGE=('fortinet','fortigate','sonicwall','netscaler','citrix','pulse secure','ivanti','globalprotect','palo alto','sophos','f5 big-ip','bigip','cisco asa','anyconnect','checkpoint','check point','juniper','watchguard','zyxel','mikrotik','draytek','exchange','outlook web','owa','vpn')
RISKY={'rdp':'remote','vnc':'remote','telnet':'remote','ms-sql':'db','mysql':'db','oracle-tns':'db','redis':'db','mongodb':'db','elastic':'db','ibm-db2-drda':'db','smb':'files','ftp':'files','snmp':'mgmt','x11':'remote','ldap-tcp':'mgmt','kubernetes':'devops','docker':'devops','etcd':'devops'}
for line in f:
    r=json.loads(line); n+=1; tg=set(r.get('tags') or [])
    if 'honeypot' in tg: cat['honeypot']+=1; continue
    if 'cdn' in tg: cat['cdn']+=1; continue
    cat['clean']+=1
    m=r['_shodan']['module']; mods[m]+=1; p=(r.get('product') or ''); prods[p]+=1
    hay=(p+' '+((r.get('http') or {}).get('title') or '')+' '+m+' '+str(((r.get('ssl') or {}).get('cert') or {}).get('subject'))).lower()
    has_d=bool(r.get('domains')) or bool(((r.get('ssl') or {}).get('cert') or {}).get('subject',{}).get('CN'))
    sig=[]
    if any(e in hay for e in EDGE): sig.append('edge_device')
    for k,v in RISKY.items():
        if k in m or k in r: sig.append('exposed_'+v)
    vu=r.get('vulns') or {}
    if any(x.get('kev') for k,x in vu.items() if k!='CVE-2023-44487'): sig.append('kev_non_rapidreset')
    if any((x.get('epss') or 0)>0.5 for x in vu.values()): sig.append('epss>0.5')
    if 'eol-os' in tg or 'eol-product' in tg: sig.append('eol')
    if r.get('ntlm'): sig.append('ntlm_leak')
    c=((r.get('ssl') or {}).get('cert') or {})
    if c.get('expired'): sig.append('cert_expired')
    for s in set(sig):
        cat['sig:'+s]+=1; withdom[s]+=has_d
        if has_d and len(ex[s])<3: ex[s].append((r.get('ip_str'),r.get('port'),r.get('org'),(r.get('domains') or [c.get('subject',{}).get('CN')])[:2],p))
    for k,x in vu.items():
        if x.get('kev'): kev[k]+=1
print("records",n); print(json.dumps(dict(cat.most_common()),indent=0))
print("\nsignal -> share attributable to a domain/cert:"); [print(f"  {s:22} {cat['sig:'+s]:>6}  with_domain {withdom[s]/max(cat['sig:'+s],1):.0%}") for s in withdom]
print("\nclean modules:",mods.most_common(30)); print("\nclean products:",prods.most_common(30)); print("\nKEV on clean:",kev.most_common(15))
print("\nexamples:"); [print(s,e) for s,v in ex.items() for e in v]
