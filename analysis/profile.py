import sys, json, collections
N=int(sys.argv[1])
top=collections.Counter(); sub=collections.defaultdict(collections.Counter)
ports=collections.Counter(); modules=collections.Counter(); countries=collections.Counter(); tags=collections.Counter()
products=collections.Counter(); vulns_n=0; vuln_ids=collections.Counter(); orgs=collections.Counter(); ssl_exp=0; ssl_n=0
cpe=collections.Counter(); bytes_=0; n=0; domains=0; asns=collections.Counter(); ts=collections.Counter()
for line in sys.stdin:
    n+=1; bytes_+=len(line)
    try: r=json.loads(line)
    except Exception: continue
    for k,v in r.items():
        top[k]+=1
        if isinstance(v,dict):
            for k2 in v: sub[k][k2]+=1
    ports[r.get('port')]+=1
    modules[(r.get('_shodan') or {}).get('module')]+=1
    countries[(r.get('location') or {}).get('country_code')]+=1
    for t in r.get('tags') or []: tags[t]+=1
    products[r.get('product')]+=1
    if r.get('vulns'):
        vulns_n+=1
        for v in r['vulns']: vuln_ids[v]+=1
    orgs[r.get('org')]+=1
    if r.get('domains'): domains+=1
    asns[r.get('asn')]+=1
    ts[(r.get('timestamp') or '')[:10]]+=1
    for c in r.get('cpe23') or r.get('cpe') or []: cpe[c]+=1
    s=r.get('ssl')
    if s:
        ssl_n+=1
        if (s.get('cert') or {}).get('expired'): ssl_exp+=1
    if n>=N: break
p=lambda name,c,k=25: print(f"\n== {name}\n"+"\n".join(f"{v:>8} {k_}" for k_,v in c.most_common(k)))
print("records",n,"avg bytes",bytes_//max(n,1),"est total records",int(118285419974/(bytes_/n)))
p("top-level keys",top,80)
for k in ['_shodan','http','ssl','location','opts']: p("sub:"+k,sub[k],40)
p("ports",ports,40); p("modules",modules,40); p("countries",countries,15); p("tags",tags,30)
p("products",products,40); print("\nwith vulns",vulns_n); p("vuln ids",vuln_ids,20)
p("orgs",orgs,25); print("\nwith domains",domains,"ssl",ssl_n,"ssl expired",ssl_exp); p("dates",ts,10); p("cpe",cpe,25)
