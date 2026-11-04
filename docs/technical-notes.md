# Recon: technical notes

The reference behind the [write-up](../README.md). Recon turns about five hours of raw internet-scan banners (13.4M records) into a ranked list of companies
that need security help **now**, with the evidence a salesperson can open a conversation with.

Profiling scripts and their outputs: [`analysis/`](../analysis/). Architecture diagrams: [`architecture.md`](architecture.md).

---

## 1. What the data is

The file is **about five hours of a Shodan-style crawl** (observed 2026-10-31 21:13 to 2026-11-01 02:06 UTC):
13,384,515 NDJSON records, one per `IP:port` across 4.1M IPs, 17 GB zstd / 118 GB raw. Each record has the IP, port, WHOIS `org`/ASN, hostnames,
the detected product/version, HTTP data (headers, title, WAF, security.txt), the TLS certificate and
supported versions, `tags`, and inferred `vulns` (CVE, CVSS, EPSS, CISA-KEV flag).

There are no company records. So the real problem is two problems:
**which assets are risky** and **whose assets are they**.

The pipeline was designed from a profile of a 1% systematic sample (every 100th record across the
whole file), made before any pipeline code was written. Most of what follows came out of that, and out of reviewing the top of the
ranking after each full run.

## 2. The traps (what makes a naive ranking wrong)

| Trap | Size | What goes wrong |
|---|---|---|
| **CDN edges** (`cdn` tag) | 5.6M records (42%) | CDN IPs answer on every port, so the scanner "finds" RAT C2 servers, PLCs and language servers on Incapsula/Google/Cloudflare. Phantom services. |
| **Phantom IPs** (answer on > 50 ports) | 1.55M records (12%) | Tarpits and proxies that respond to everything. Invisible in a 1% sample; found only on the full run. |
| **Honeypots** | 246k records (1.8%) | Each advertises 80–170 fake CVEs. A "most CVEs" ranking puts decoys first. |
| **Over-reported KEV CVEs** | ~every nginx | CVE-2023-44487 (HTTP/2 Rapid Reset) is KEV-listed and matched on nearly every nginx. The jQuery XSS CVEs (CVE-2020-11023 etc.) come from a JS library on the *page*, not the server. Counting them makes "KEV" meaningless. |
| **WHOIS `org` and reverse DNS name the ISP** | most records | `hinet.net`, `telecomitalia.it` and "Clientes Residenciales" are carriers and their customer pools, not buyers. |
| **Hosters' naming schemes** | 1.8k domains | `vps123.hoster.com` on hundreds of IPs looks like one big company. |
| **Vendor default certificates** | thousands | FortiGate ships CN `support` / `fortinet-subca2001`; Traefik, Kubernetes and DrayTek have their own placeholders. |

## 3. The signals

Every signal is a SQL predicate over the slim schema with a weight, a sales-facing label and an
evidence string ([`pipeline/signals.py`](../pipeline/signals.py)). Counts are companies, full file:

| Signal | Companies | Why it means "call now" |
|---|---|---|
| Exposed firewall/VPN admin plane (FortiGate on 541/10443, NetScaler, SonicWall, Pulse/Ivanti, BIG-IP…) | 9,461 | The #1 ransomware initial-access vector |
| Edge appliance **with** a KEV CVE | 38 | The above, already known-exploited |
| On-prem Exchange / OWA | 803 | ProxyShell-class surface; cloud-email pitch |
| RDP / VNC / Telnet / X11 open | 1,069 | Direct remote access |
| Database reachable (MS-SQL, MySQL, Oracle, Redis, Mongo…) | 3,429 | Data exposure |
| SMB / open directories | 1,278 | Data exposure, lateral movement |
| OT / medical / POS protocols (non-cloud only) | 6,258 | Compliance-driven buyer |
| Self-hosted AI app or MCP server (LiteLLM, Ollama, Dify, Flowise, MCP) | 170 | New attack surface: leaked keys, data and agent tools |
| Evidence of a breach (ransomed database, remote-access trojan, cryptominer; red-team tools excluded) | 2 | Already compromised: an incident-response call |
| KEV CVE (noise CVEs excluded) | 16,272 | Known exploited in the wild |
| EPSS ≥ 0.5 | 15,741 | Likely to be exploited soon |
| EOL Windows (from NTLM OS build) / EOL software | 2,618 / 35,918 | Unpatchable |
| NTLM leaks internal AD domain | 11,304 | Recon handed to attackers |
| Expired / expiring certs, TLS 1.0/1.1, self-signed | many | Hygiene: points to a thin or absent security team |

**Maturity signals** (WAF, security.txt, post-quantum TLS, HSTS) don't hide an account. They
change the pitch from "first security purchase" to "consolidation / coverage gaps" (15,943 accounts).

## 4. How a company is identified

1. **Candidate names per record**, strongest first: TLS cert CN/SAN → NTLM FQDN (leaked AD
   domain) → HTTP Host → reverse DNS. Each is reduced to a registrable domain with the offline public
   suffix list, after removing vendor default certs, `.local`/`.corp`, and known cloud/SaaS/CDN domains.
2. **Data-driven infrastructure detection:** a domain is a platform or ISP (not a customer) if it
   spans ≥ 8 ASNs or ≥ 15 orgs, if it's a reverse-DNS zone over ≥ 20 IPs with almost no certs, or if
   it names ≥ 30 IPs with numbered hostnames (a hoster's scheme).
3. **Identity is shared across ports of the same IP:** the FortiGate on port 541 has no useful cert,
   but port 443 on the same IP names the company. Shared-hosting IPs (≥ 5 distinct domains) are excluded.
4. **Fallback to the WHOIS org** only when it looks like a business. An org is ISP/hoster if its IPs
   carry ≥ 10 unrelated company domains (it's hosting them), if ≥ 15% of its IPs have dynamic reverse
   DNS or ≥ 10% are consumer gear (TR-069 routers, cameras), or if its name/size/cloud share says so.
   LLM labels settle the long tail (§7). IP-owner and reverse-DNS identities only reach P1/P2 when labeled education/government (measured, §8).

Result: 917k assets attributed to 298k companies; **83,934 companies with a material risk signal**.

## 5. Scoring

`priority = need × urgency × fit × maturity`

- **Need:** for each signal, `weight × (1 + ln n_assets)`, capped at 2.5× weight. Diminishing returns,
  so 500 nginx boxes don't drown out one exposed FortiGate. Each asset counts once per category, and
  an edge device already scored for its KEV CVE isn't scored again as a generic vuln.
- **Urgency:** ×1.4 with a KEV CVE, ×1.2 with EOL, ×1.1 with cert problems.
- **Fit:** identity confidence (cert/NTLM/HTTP host 1.0, same-IP 0.9, WHOIS org 0.85, reverse DNS
  0.75) × footprint size.
- **Maturity:** −5% per maturity flag (floor 0.8).

The score is log-scaled to 0–100. **Tiers are sized to sales capacity, not percentiles:** P1 = top 500
(this week's calls), P2 = next 2,500, P3 = the rest.

## 6. Architecture and scale

```
.zst ─► ingest/extract.py (1 zstd reader → 7 orjson workers) ─► Parquet shards (once per file)
                                                                   │ DuckDB
   pipeline/build.py: noise filter → identity → signals → company scores + evidence
                                                                   │
   pipeline/export.py ─► serving store: versioned Parquet, IPs masked to /24, count cube
                                                                   │ DuckDB
   api/ (FastAPI, read-only) ─► web/ (React + Vite + Tailwind) and mcp_server/
```

| Step | Measured on this file (MacBook Air, 8 GB RAM, 8 cores) |
|---|---|
| Ingest 118 GB raw → 1.2 GB Parquet (100× smaller) | **882 s, 134 MB/s, 15k records/s**, flat memory |
| Full build (13.4M rows → scored accounts) | ~3.5 min |
| Export to the serving store (83,934 accounts, evidence, CVE hits, count cube) | ~20 s; 39 MB of Parquet |

**Volume in production (hundreds to thousands of files a month):** a zstd frame can't be split, so
the unit of parallelism is the file. Ingest is stateless per file, so N workers on a file queue scale
linearly: ~15 min/file/machine means ~100 files a day per machine, and 1,000 files a month needs
1–2 machines. The build is plain SQL over Parquet, so it moves unchanged to DuckDB-on-object-storage or
a warehouse. The build recomputes the retained window on every run, which is right at this volume;
the incremental design for a full stream (state tables merged per file, only touched companies
re-scored, global statistics on a schedule) is in [architecture.md](architecture.md#7-the-production-path).
Scan-over-scan changes (newly exposed RDP, a new KEV CVE on a known FortiGate) are where "right now"
timing signals come from once there is more than one file.

The app never holds the market: it asks the read API ([`api/`](../api/)) for one page, the counts and
the filter badges, and the API answers with DuckDB over the serving store. Measured at 1×, 10× and
100× the current size in [architecture.md](architecture.md#5-serving-the-read-api).


### A stream of scan files

Each scan file is ingested into its own folder (`data/parquet/<scan-id>/`). A `_manifest.json`
keyed on the source path, size and mtime makes re-running an ingested file a no-op, and shards are
written to `<scan-id>.partial` and renamed into place only when the whole file is done. A file is a
few hours of an ongoing crawl, not a re-scan of the internet, so retention and "new" go by observation
time, not by file: the build keeps the latest observation per `ip:port:transport` seen in the last 30
days, and a service is new when it was first observed in the last 7 days on an IP the crawl had
already seen before then. A file that covers a fresh IP range therefore doesn't make everything in it
look new. A company whose material risk includes a new service gets urgency ×1.3 and a "Newly exposed"
play. Covered by `tests/test_build_scans.py`.

## 7. Where an LLM is used, how it's checked, and what it costs

**Where:** one place only. It classifies **distinct names** behind ranked accounts (WHOIS orgs and
domains) as carrier / hoster / business / government / education, and gives an industry. Rules can't
know that "Etihad Etisalat" is a carrier or "Kamatera" a hoster; a model can. Labels only overrule
the heuristics at medium/high confidence. It is a **batch enrichment step**, not a runtime call: the
app never calls an LLM, so it's fast, free per view, and its ranking is stable.

**How the labels in this repo were produced:** Claude Haiku with exactly the instructions in
[`pipeline/llm_label.py`](../pipeline/llm_label.py), run as a parallel batch outside the script (no API key
was configured for the script itself):
- [`pipeline/label_queue.py`](../pipeline/label_queue.py) queues the names of unlabeled top-tier accounts.
- [`pipeline/merge_labels.py`](../pipeline/merge_labels.py) validates every label (allowed values, every
  ID present) and writes the same cache/CSV format as the API path.
- Two rounds were run: 3,000 names, then 1,430 names promoted by re-ranking. Unlabeled names in the
  top tiers dropped 3,000 → 1,430 → 92. All 4,430 labels were valid.

`llm_label.py` is the production path for a file stream (batched 40 per request, `messages.parse` +
Pydantic schema, disk cache, per-call token logging).

**Cost** (`data/labels/llm_usage.json`):
- Measured for the batch run: **1.51M tokens for 4,430 labels → $0.15–$0.75** at Haiku 5.5 prices
  ($0.10 / $0.50 per million input/output tokens). It's a range because the run's accounting doesn't
  split input from output, and it includes orchestration overhead, so it overstates the API path.
- Estimate for the API path: ~40 names per request at ~2.5k in + ~2k out ≈ **$0.08 per 3,000 names**.
  Roughly cents per file in production, and falling, because the cache carries over (orgs repeat
  month to month).

**How it's checked:** compared against the blind gold labels (§8). On names both labeled,
buyer-vs-infrastructure agreement is **83% (gold v1, n=47) and 87% (gold v2, n=38)**. The main
error is calling small ISPs/hosters "business": 7 cases in gold v1, 3 of which were low-confidence
and therefore already ignored by design.

No LLM writes the outreach copy: the opening line in the app is filled in from observed facts, so it
can't invent a vulnerability.

## 8. How it was measured

There are no ground-truth sales outcomes, so the metric is **top-tier precision**: the share of
P1/P2 accounts a seller could actually prospect (a real organisation, correctly named). Each gold
set is a seeded random sample, labeled **blind** by a separate reviewer agent that never saw the
pipeline (strict rubric in the agent prompt, files in [`data/eval/`](../data/eval/)). Each change was
measured on a **fresh** sample that hadn't influenced any tuning, then that sample was retired:

| Pipeline state | Measured on (fresh, blind) | Top-tier precision |
|---|---|---|
| Rules only (identity heuristics, noise filters) | gold v1: 60 P1/P2 accounts | **43%** (26/60) |
| + LLM labels on the top 3,000 names | gold v2: 60 new P1/P2 accounts | **53%** (32/60) |
| + weak identities need edu/gov confirmation, + 2nd label round | gold v3: 60 new P1/P2 accounts (holdout) | **62%** (37/60) |

With n = 60 the 95% interval is about ±12 points: 43% → 62% is a real gain, while the step-by-step
figures are indicative. The final build (identity ties broken deterministically) scores 61% (36/59) on
the same holdout. Re-scored in-sample, the final build reaches 65% (v1) and 68% (v2). That's
optimistic, since those sets informed the rules, and is reported only for completeness.

**What the gold sets showed, and the change each one drove:**
- gold v1: identity by TLS cert was 62% sellable, by WHOIS org **15%** (21 of 26 were ISPs/hosters).
  → LLM labels for org/domain type.
- gold v2: cert 70%; WHOIS org 0/8 and reverse DNS 0/4, even with labels, except universities and
  governments, which really own their address space.
  → IP-owner / reverse-DNS accounts only reach P1/P2 when labeled education/government
  (others stay searchable in P3).
- gold v3 (holdout): ISPs/hosters are down to 6/60. The remaining error is **single-IP personal or
  junk sites** (random-string domains, hobby blogs, test boxes): single-IP accounts are 50% sellable
  vs 72% for multi-IP. That's the next fix, and it would need a fresh gold v4 to measure.

**Other checks:** honeypot / CDN / phantom records can't reach any tier by construction. The top 50
was reviewed after every full build, and each rule in §2/§4 came from that loop. Tests:
`uv run pytest -q` (extractor, multi-scan build, CVE index, the API's query layer, the MCP server).

## 9. Key decisions

- **Profile before building.** The most damaging problems (CDN phantoms, honeypots, ISP identities)
  only show up when you look at the raw records.
- **Develop on a 1% sample, run the full file once.** Iterations took seconds, not 15 minutes.
  The extractor keeps a superset of fields so the 17 GB file is read once.
- **Rule-based, explainable scores** over a learned model: there are no labels to learn from, and a
  seller has to be able to say *why* an account is hot.
- **DuckDB for the build and the API:** in-process (no server), queries Parquet in place, reads only
  the columns and row groups a query touches, and spills to disk, so the 13.4M-row build fits an 8 GB
  laptop. The work stays plain SQL, portable to a warehouse, and one dialect serves batch and API.
- **Batch scoring, a read-only API for serving:** scores are computed per build, offline; the API only
  queries the published store, and the browser holds one page at a time.
- **IPs masked to /24 in anything published:** a list of vulnerable hosts mustn't double as a
  target list. Full IPs stay in the local build.

## 10. Limitations and next steps

- One file means no change-over-time signals yet. Those are the strongest "right now" triggers. The
  serving store keeps the last three builds and each account records the build it was first ranked
  in, so "new since you last ran this search" works as soon as a second file is processed.
- CVEs are inferred from version banners, not verified exploitation.
- No firmographics (headcount, revenue); footprint size is a proxy. Joining a firmographic source
  on domain is the obvious next step.
- Large universities rank high because of large, open networks. Real buyers, but a seller may want
  to filter them (industry filter in the app).

## 11. Running it

```bash
uv sync
uv run python -m ingest.extract ~/Downloads/b2_download_file_by_id data/parquet/scan-2026-11-01
uv run python -m pipeline.build "data/parquet/scan-2026-11-01/*.parquet" data/build/full
uv run python -m pipeline.llm_label data/build/full        # optional, needs ANTHROPIC_API_KEY
uv run python -m pipeline.build "data/parquet/scan-2026-11-01/*.parquet" data/build/full
uv run python -m pipeline.export data/build/full          # serving store in data/serve/<build>, data/serve/current
uv run uvicorn api.app:app --port 8787                     # read API, docs at /api/docs
cd web && npm install && npm run dev                       # proxies /api to :8787
uv run pytest -q
uv run python -m api.bench --scales 1,10,100               # query latency over synthetic 10x and 100x stores
```

Deploy (nginx for the app, the API container, an ngrok connector for the public URL and a Tailscale
sidecar for private access, see `deploy/`): `deploy/push.sh bluedragon`
(needs `TS_AUTHKEY` in the host's `.env`; refuses to ship a store that isn't IP-masked, and copies a
build before moving the host's `current` pointer to it).

## 12. The product surfaces

- **One catalogue** ([`web/src/catalog.json`](../web/src/catalog.json)): products, sectors and the ten
  signal templates, each rule written as data (an OR of clauses, each an AND of conditions on signals,
  KEV, tier, maturity, new). The export compiles every rule to SQL ([`api/rules.py`](../api/rules.py))
  and stores each template's membership as a column, so the app, the API and the MCP server agree on
  what a template matches.
- **CVE in the news** ([`pipeline/cve_index.py`](../pipeline/cve_index.py)): notable CVEs per service
  (KEV, EPSS ≥ 0.1 or CVSS ≥ 9) for every attributed company, about 879k company-CVE pairs over 1,701
  CVEs, plus a lookup enriched from the CISA KEV catalogue (date added, ransomware use, vendor and
  product mapped to a software family for the fallback search). Tested against a direct query over the
  build (`tests/test_cve_index.py`).
- **Peer benchmark** ([`pipeline/export.py`](../pipeline/export.py)): risk = need × urgency, ranked within
  industry + country, then industry, then country, over all 131k scored companies, minimum 30 peers.
  Peer industries use the keyword rules for every company, and an industry group is used only when it
  agrees with the industry the app shows.
- **Exposure brief** ([`web/src/Brief.tsx`](../web/src/Brief.tsx), `?brief=<account>`): printable, evidence
  only, with fixed guidance per signal ([`web/src/guidance.ts`](../web/src/guidance.ts)).
- **Ideal customer profile, filters, lists and saved searches** ([`web/src/`](../web/src/)): every filter
  takes several values, the profile is a default layer under every view, an account can sit in several
  lists, and a saved search reports what is new since its last run. They are kept per user in the app
  database behind sign-in; how, and what changes in production, is in [architecture.md](architecture.md#6-lists-and-saved-searches).
- **MCP server** ([`mcp_server/`](../mcp_server/)): ten deterministic tools on the API's query layer and app database;
  protocol tests in `tests/test_mcp_server.py`, accuracy evaluation in `mcp_server/eval/`.
