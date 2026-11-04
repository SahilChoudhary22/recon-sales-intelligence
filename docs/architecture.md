# Recon: architecture and data flow

How a scan file becomes ranked accounts, how the app reads them, and how that keeps up when hundreds
to thousands of files arrive each month. Each diagram marks what is **built** (in this repo, run on the supplied file)
and what is **designed** (the production shape the built pieces slot into).

## 1. What happened to this file (built)

One file, 13.4M banners (about five hours of crawl, 4.1M IPs), processed once. The numbers are what
each step kept.

```mermaid
flowchart TD
  scan(["Scan file, 1 Nov 2026<br/>17 GB zstd, 118 GB NDJSON<br/>13,384,515 banners"])
  scan --> extract["Stream and slim (ingest/extract.py)<br/>1 reader + 7 parsers, flat memory<br/>keep ~40 fields, drop HTML and cert chains<br/>15 min"]
  extract --> lake[("Parquet, 1.2 GB")]
  lake --> noise["Remove noise (pipeline/build.py)"]
  noise -.->|"5.6M CDN edges"| dropped(["dropped"])
  noise -.->|"1.55M phantom IPs"| dropped
  noise -.->|"246k honeypots"| dropped
  noise --> real["5.99M real services"]
  real --> identity["Identify the company<br/>TLS cert, AD domain, HTTP host,<br/>reverse DNS, IP owner;<br/>carried across ports of one IP;<br/>hosters and ISP pools excluded"]
  labels[("LLM label cache<br/>4,430 names")] --> identity
  identity --> attributed["917k services, 298k companies"]
  attributed --> signals["20 risk signals per service<br/>(pipeline/signals.py)"]
  signals --> score["Score per company<br/>need x urgency x fit, tiers P1 / P2 / P3"]
  score --> risky["83,810 companies with real risk"]
  risky --> export["Export (pipeline/export.py)<br/>all 83,810, IPs masked to /24, software families,<br/>sector, peer ranks, template flags, count cube"]
  risky --> cveidx["CVE hits (pipeline/cve_index.py)<br/>1,701 CVEs, 878,683 company matches"]
  kev[("CISA KEV v2026.11.03")] --> cveidx
  export --> published[("Serving store<br/>data/serve/&lt;build&gt;, 39 MB")]
  cveidx --> published
  published --> api["Read API (api/)<br/>DuckDB over Parquet"]
  api --> app["Web app"]
  api --> mcp["MCP server"]
```

## 2. Continuous ingestion (designed around the built pieces)

Files are independent, and a zstd file can't be split, so the file is the unit of work.

```mermaid
flowchart TB
  subgraph arrive["Arrival"]
    bucket[("Object storage<br/>new scan files")]:::designed --> event["New-object event"]:::designed
    event --> queue[["Work queue<br/>one message per file"]]:::designed
  end
  subgraph ingest["Ingest"]
    queue --> w1["Worker"] & w2["Worker"] & w3["Worker ..."]
    w1 & w2 & w3 --> lake[("Parquet by scan<br/>scan-id/part-*.parquet<br/>+ _manifest.json")]
  end
  subgraph build["Build"]
    lake --> merge["Merge scans<br/>latest observation per service wins<br/>absent 3 scans = closed"]
    merge --> fresh["Flag new exposures<br/>first seen in the newest scan"]
    fresh --> score["Identity, signals, scores"]
    labels[("Label cache<br/>only unseen names go to the LLM")] --> score
    kev[("CISA KEV, refreshed daily")]:::designed --> index
    score --> index[("Serving store, one folder per build<br/>'current' pointer swapped atomically")]
  end
  subgraph use["Use"]
    index --> api["Read API<br/>DuckDB, count cube"]
    api --> app["App and MCP server"]
    index --> agents["Saved searches and signal agents<br/>re-run on each new build"]:::designed
    agents --> crm["CRM tasks and alerts"]:::designed
    enrich[("Enrichment by domain<br/>firmographics, contacts")]:::designed --> app
  end
  classDef designed stroke-dasharray: 6 4
```

Solid boxes are built and ran on the supplied file; dashed boxes are designed. Everything from
"Parquet by scan" onwards is the code in this repo.

**Throughput.** Measured: 118 GB raw in 882 s (134 MB/s) on one 8 GB laptop, about 15 minutes per
file. 1,000 files a month is about 250 machine-hours, roughly a third of one machine running
continuously, so a small worker pool handles bursts. The build is SQL over Parquet (DuckDB), so the
same queries move to a warehouse or DuckDB on object storage when one machine is no longer enough.

**Repeat-safe.** Each scan folder carries a `_manifest.json` keyed on the source file's path, size and
modification time, so a re-delivered file is skipped. Shards are written to `scan-id.partial` and
renamed into place only when the whole file is done, so a crashed worker never leaves a scan that
looks finished.

**Incremental (designed, not built).** Today the build recomputes everything in the retained window
(about 4 minutes for 13M rows). That stops working well before a month of files: some inputs are
global (hoster and ISP classification, the score's normalisation, tier ranks, peer ranks), so one file
can move every account. The production build keeps state tables (latest observation per service,
first-seen per service, hostname to domain), merges each file into them, re-scores only the companies
it touched, and recomputes the global statistics on a schedule rather than per file. See section 6.

## 3. One new file arriving

```mermaid
sequenceDiagram
  participant Store as Object storage
  participant Q as Queue
  participant W as Ingest worker
  participant B as Build
  participant L as Label cache / LLM
  participant A as App and MCP
  participant S as Signal agents
  Store->>Q: new file event
  Q->>W: file to ingest
  W->>W: manifest says new? stream, slim, write .partial
  W->>B: rename into place (scan complete)
  B->>B: merge with earlier scans, latest wins
  B->>B: flag services first seen in this scan
  B->>L: names never labelled before
  L-->>B: carrier / hoster / business, industry
  B->>A: write data/serve/<build>, then move 'current'
  B->>S: build landed
  S->>A: each saved search: since_build = its last run, not in the owner's lists
  S-->>A: "N new" on the search, CRM tasks
```

## 4. What is kept, dropped and masked

```mermaid
flowchart LR
  R["Raw banner<br/>HTML, headers, cert chain,<br/>full IP, every CVE"] -->|"slim: ~40 fields"| PQ["Parquet<br/>full IP, product, notable fields"]
  PQ -->|"build"| AC["Company scores and evidence<br/>full IP, local only"]
  AC -->|"export: mask to /24"| PUB["Serving store<br/>API, app, MCP<br/>203.0.113.x:443"]
  R -.->|"raw HTML, cert chains, pubkeys"| DROP["Not kept"]
```

Full IP addresses never leave the local build: everything the API serves is masked to the /24 network.
The export checks every evidence row for a full IPv4 address and refuses to publish the build if it
finds one, and the deploy script refuses a store whose metadata isn't marked masked.

## 5. Serving: the read API

The app used to download every account as one JSON file and filter in the browser, which capped the
export at the top 15,000 of 83,810 risky companies and would not survive a larger market. Now the
browser holds one page, and everything it shows is computed on the server.

```mermaid
flowchart LR
  subgraph store["Serving store: data/serve/&lt;build&gt;/ (Parquet, masked)"]
    acc[("accounts.parquet<br/>sorted by priority,<br/>one flag column per template")]
    byid[("accounts_by_id.parquet<br/>sorted by id")]
    ev[("evidence.parquet<br/>sorted by company")]
    cube[("cube.parquet<br/>counts per template x country<br/>x sector x industry x size")]
    hits[("cve_hits.parquet<br/>sorted by CVE")]
  end
  api["Read API (FastAPI + DuckDB)<br/>POST /api/search, /counts, /facets, /cve<br/>GET /api/accounts/{id}, /evidence"]
  acc --> api
  byid --> api
  ev --> api
  cube --> api
  hits --> api
  api --> app["Web app<br/>one page at a time"]
  api --> mcp["MCP server<br/>same query layer"]
```

- **Two query paths.** Anything that filters only on template, country, sector, industry and estate
  size (the template counts in the nav and every badge in the profile) is answered from the count
  cube. The cube's size depends on how many of those combinations exist, not on how many accounts
  there are: 7,613 rows at 83k accounts and still 7,613 at 8.4M. Everything else (name search,
  software, identity strength, a list of ids) is SQL over `accounts.parquet`.
- **Badges that answer "what if I pick this?"** Each facet leaves its own filter out, so with GB
  chosen the country badges still show every other country's count given the rest of the profile.
- **Layout does the indexing.** Lookups by id read a copy of the accounts sorted by id, evidence is
  sorted by company and CVE hits by CVE, so Parquet's row-group statistics skip almost every row group
  (account by id: 37 ms at 8.4M accounts, evidence 20 ms). A ranked page is DuckDB's top-N, which keeps
  only the rows it needs while scanning.
- **Template rules computed once per build.** Each rule (an OR of AND clauses, stored as data in the
  catalogue) is evaluated by the export into a boolean column. Queries read one column instead of
  testing signal lists on every row, and a test checks every column against its rule.
- **New builds without downtime.** The export writes `data/serve/<build>.partial`, checks it, renames
  it and swaps the `current` link; the API notices the pointer moved and opens the new build. The last
  three builds are kept for rollback and for diffs.
- **One query layer.** The MCP server calls the same `api/store.py`, so an assistant and the app can't
  disagree about a count.

### How it scales

`uv run python -m api.bench` times every query the app makes, uncached, over the real store and over
synthetic stores 10× and 100× its size (every account copied with its evidence, priorities jittered so
the copies interleave; country, sector, industry and size keep their real distribution). Median of 15
runs, MacBook Air, 8 GB RAM:

| Query (ms, median) | 1× (83,744) | 10× (837,440) | 100× (8,374,400) |
| --- | --- | --- | --- |
| Template counts (cube) | 0.8 | 0.8 | 0.8 |
| Profile badges (cube) | 3.2 | 3.3 | 3.3 |
| First page, whole market | 8.1 | 14 | 70 |
| First page, template + profile | 7.4 | 23 | 91 |
| Page 50 (offset 5,000) | 16 | 17 | 76 |
| Name search | 9.8 | 29 | 158 |
| Template counts (live, strong identity) | 2.0 | 8.1 | 70 |
| Toolbar facets (live) | 4.0 | 12 | 91 |
| Account by id | 3.0 | 5.3 | 37 |
| Evidence by id | 1.8 | 2.6 | 20 |
| CVE search (OpenSSH CVE) | 30 | 99 | — |
| Store size | 45 MB | 301 MB | 879 MB |
| Cube rows | 7,613 | 7,613 | 7,613 |

What this says:

- **The counts don't grow.** The nav counts and the profile badges, the queries the app sends most
  (every click in the profile), come from the cube in 1 to 3 ms at every size: the cube has 7,613 rows
  at 83k accounts and at 8.4M.
- **The live paths grow less than linearly and stay interactive.** At 8.4M accounts, 100 times
  today, a filtered ranked page takes about 90 ms and the toolbar badges about 90 ms on one laptop.
  Name search (160 ms) is a scan; a search index is the fix when it matters. CVE search was measured to
  10× (100 ms); at 100× its 88M-row table needs the same treatment as the accounts (partition by CVE).
- **Keep the batch build off the serving machine.** Measured while a re-export ran on the same
  laptop, the 100× live paths took 0.3 to 1.5 s, five to ten times slower. Ingest and build run on
  workers; the API runs alone.
- **Where it changes.** Past roughly ten times this (tens of millions of accounts, many concurrent
  users), the same API moves onto a store with real indexes: ClickHouse (or Postgres with the right
  indexes) partitioned by country, a search index for names, and the cube materialised per build. The
  API contract, the app and the MCP server stay as they are.
- **The served table grows with companies, not banners.** Raw records grow with every file (billions
  a year); the served table is one row per company with real risk. 13.4M banners give 83,810 of them,
  and there are a few hundred million companies in the world at most, so the read side meets
  "millions" long before "billions". The billions stay in the batch layer: Parquet partitioned by
  observation date and SQL that moves to a warehouse unchanged.

## 6. Scale review: what holds, what changed, what is designed

A separate review looked for decisions that would not hold at 10×, 100× or 1,000× the files, or with
many users. Each finding was checked against the code and the data before acting on it.

| Finding | Status |
| --- | --- |
| The app downloads every account and filters in the browser, so the export was capped at 15,000 | **Fixed:** read API, count cube, all 83,810 accounts served |
| A file is about five hours of crawl (21:13 to 02:06), but retention was "the last 3 files" and "new" meant "first seen in the newest file", so a file covering a fresh IP range would look entirely new | **Fixed:** 30-day retention by observation time; new means first seen in the last 7 days on an IP the crawl already knew (`tests/test_build_scans.py`) |
| Company id ties broken arbitrarily: about 15% of certificates name several domains at the same priority | **Fixed:** deterministic tie-break. It showed why ids matter: the change renamed 1,179 accounts between two builds, which "new since you last ran it" would have reported as new, so the export re-baselines (`--rebaseline`) when the rules change. **Designed:** a company registry with aliases (`acme.co.uk` and `acme.com`, `org:Acme` gaining a domain), so renames neither look new nor orphan list entries |
| Publishing was in place: a reader could see a half-written export | **Fixed:** versioned store, checked before an atomic pointer swap |
| No history: each build overwrote the last | **Partly fixed:** last three builds kept; each account records the build it was first ranked in, which is what "new since you last ran this search" uses. **Designed:** a per-build diff table (entered P1, fixed since last scan) |
| Schema changes would break reads of older scans | **Fixed:** `union_by_name` when reading scans. **Designed:** a schema version in each scan's manifest |
| Hard-coded dates (certificate expiry against 1 December, scan date strings) | **Fixed:** expiry relative to when the service was seen; scan dates come from the data |
| The build recomputes everything, and some inputs are global (hoster detection, score normalisation, tiers, peer ranks) | **Designed:** state tables merged per file, touched companies re-scored, global statistics on a schedule (section 2). The docs no longer claim this is built |
| Steps bound by Python memory: 3.8M distinct hostnames resolved in Python each build, peer ranks in Python | **Designed:** a persistent resolved-name table (only new names resolved), peer ranks as SQL window functions |
| 3,513 small Parquet files (~350 KB) for one input | **Designed:** one writer per worker with ~128 MB row groups, partitioned by observation date |
| KEV status: scoring uses the scanner's flag, CVE search uses today's CISA catalogue | **Designed:** join the catalogue in the build, so a CVE added to KEV after the scan raises the score |
| Thresholds are counts over whatever data is retained (hoster needs 10 domains, ISP pool 20 PTR IPs) | **Partly addressed** by the fixed 30-day window. **Designed:** ratios within the window |
| Ingest idempotency keyed on path, size and modification time | **Designed:** content hash, scan id derived from the observation times |
| Data-quality gates | **Partly fixed:** the export fails on a full IP, duplicate ids or evidence for unknown accounts. **Designed:** row-count and null-rate drift checks against the previous build |
| LLM label cache has no model or prompt version | **Designed:** version in the cache key; relabel on change |
| Per-user state (lists, statuses, saved searches) lives in the browser | **Designed:** the app database (Postgres): lists, list items, saved searches, runs; a scheduler re-runs saved searches per build |

Already fine at scale, left alone: ingest streams with bounded memory and renames atomically, DuckDB
spills to disk, CVE results grow with the number of CVEs rather than companies, evidence is capped
per company, and LLM cost grows with distinct new names, not records.
