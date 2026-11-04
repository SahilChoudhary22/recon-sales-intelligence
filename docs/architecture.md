# Recon: architecture and data flow

Recon has three layers, each sized for a stream of hundreds to thousands of scan files a month:

1. **Batch:** each scan file is streamed once into Parquet, then a SQL build turns the retained
   observations into scored companies.
2. **Serving store:** every build publishes a versioned, IP-masked set of Parquet files, laid out for
   the queries the product makes, plus a pre-aggregated count cube.
3. **Read API:** FastAPI and DuckDB over the serving store. The web app and the MCP server both use
   it, so they always give the same answer.

Diagrams mark what runs in this repo on the supplied file (solid) and the production pieces it slots
into (dashed).

```mermaid
flowchart LR
  files[("Scan files")] --> ingest["Ingest<br/>one worker per file"]
  ingest --> lake[("Parquet by scan")]
  lake --> build["Build<br/>noise, identity, signals, scores"]
  build --> store[("Serving store<br/>one folder per build")]
  store --> api["Read API<br/>DuckDB"]
  api --> app["Web app"]
  api --> mcp["MCP server"]
```

## 1. One file through the pipeline

The supplied file: 13.4M banners covering about five hours of crawl (2026-10-31 21:13 to 2026-11-01
02:06 UTC) over 4.1M IPs. The numbers are what each step kept.

```mermaid
flowchart TD
  scan(["Scan file<br/>17 GB zstd, 118 GB NDJSON<br/>13,384,515 banners"])
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
  risky --> export["Export (pipeline/export.py)<br/>IPs masked to /24, software families,<br/>sector, peer ranks, template flags, count cube"]
  risky --> cveidx["CVE hits (pipeline/cve_index.py)<br/>1,701 CVEs, 878,683 company matches"]
  kev[("CISA KEV v2026.11.03")] --> cveidx
  export --> published[("Serving store<br/>data/serve/&lt;build&gt;, 45 MB")]
  cveidx --> published
  published --> api["Read API (api/)<br/>DuckDB over Parquet"]
  api --> app["Web app"]
  api --> mcp["MCP server"]
```

## 2. A continuous stream of files

A zstd file can't be split and files are independent, so the file is the unit of work.

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
    lake --> merge["Merge observations<br/>latest per service wins,<br/>last 30 days retained"]
    merge --> fresh["Flag new exposures<br/>first seen in 7 days<br/>on an IP already known"]
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

- **Throughput.** 118 GB raw in 882 s (134 MB/s) on one 8 GB laptop, about 15 minutes per file.
  1,000 files a month is about 250 machine-hours, a third of one machine running continuously, so a
  small worker pool absorbs bursts.
- **Repeat-safe ingest.** Each scan folder carries a `_manifest.json` keyed on the source file, so a
  re-delivered file is skipped. Shards are written to `scan-id.partial` and renamed only when the
  whole file is done, so a crashed worker never leaves a scan that looks finished.
- **Time, not files, defines the window.** A file is a few hours of an ongoing crawl, not a re-scan
  of the internet. The build keeps the latest observation of each `ip:port:transport` seen in the
  last 30 days. A service is *new* when it was first observed in the last 7 days on an IP the crawl
  had already seen before then, so a file that covers a fresh IP range doesn't make everything in it
  look new. New exposure raises urgency ×1.3 and feeds the "Newly exposed" template.
- **Schema evolution.** Scans are read with `union_by_name`, so a field added later reads as null in
  older scans instead of breaking the build.
- **Deterministic identity.** Account ids are the keys that lists and saved searches hold, so every
  identity choice has a total order: when a certificate names several domains at the same priority,
  the tie is broken by name. A rebuild of the same data gives the same ids.

## 3. One new file arriving

```mermaid
sequenceDiagram
  participant Store as Object storage
  participant Q as Queue
  participant W as Ingest worker
  participant B as Build
  participant L as Label cache / LLM
  participant A as Read API
  participant S as Saved-search runner
  Store->>Q: new file event
  Q->>W: file to ingest
  W->>W: manifest says new? stream, slim, write .partial
  W->>B: rename into place (scan complete)
  B->>B: merge the last 30 days, latest observation wins
  B->>B: flag services first seen this week on known IPs
  B->>L: names never labelled before
  L-->>B: carrier / hoster / business, industry
  B->>A: write data/serve/<build>, check it, move 'current'
  B->>S: build landed
  S->>A: each saved search: first ranked after its last run, not in the owner's lists
  S-->>S: "N new" on the search, CRM tasks
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

The browser never holds the market. It asks for one page of accounts, the counts and the filter
badges, and the API computes each of them over the serving store.

```mermaid
flowchart LR
  subgraph store["Serving store: data/serve/&lt;build&gt;/ (Parquet, masked)"]
    acc[("accounts.parquet<br/>one flag column per template")]
    byid[("accounts_by_id.parquet<br/>sorted by id")]
    ev[("evidence.parquet<br/>sorted by company")]
    cube[("cube.parquet<br/>counts per template x country<br/>x sector x industry x size")]
    hits[("cve_hits.parquet<br/>sorted by CVE")]
  end
  api["Read API (FastAPI + DuckDB)<br/>POST /api/search, /counts, /facets, /cve, /export.csv<br/>GET /api/accounts/{id}, /evidence, /meta"]
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
  cube. The cube grows with the number of those combinations, not with accounts: about 7,600 rows at
  84k accounts and the same at 8.4M. Everything else (name search, software, identity strength, a
  list of ids, "not in my lists") is SQL over `accounts.parquet`.
- **Badges that answer "what if I pick this?"** Each facet leaves its own filter out: with GB chosen,
  the country badges still show what every other country would add under the rest of the filters.
- **Layout does the indexing.** Lookups by id read a copy of the accounts sorted by id, evidence is
  sorted by company and CVE hits by CVE, so Parquet's row-group statistics skip almost every row group.
  A ranked page is DuckDB's top-N, which keeps only the rows it needs while scanning.
- **Template rules computed once per build.** Each rule (an OR of AND clauses, stored as data in the
  catalogue) is compiled to SQL and evaluated by the export into a boolean column, so a query reads one
  column instead of testing signal lists on every row. A test checks every column against its rule.
- **Builds swap atomically.** The export writes `data/serve/<build>.partial`, checks it (no full IPs,
  unique ids, no evidence for unknown accounts), renames it and moves the `current` link. The API
  opens the new build on its next request, with no restart. The last three builds are kept for
  rollback and comparison.
- **Read-only.** The API never writes; the build is the only writer, so the serving side needs no
  locking and scales by adding read replicas of the same files.

### Measured at 1×, 10× and 100×

`uv run python -m api.bench` times every query the app makes, uncached, over the real store and over
synthetic stores 10× and 100× its size. Each account is copied with its evidence and CVE rows, its
priority jittered so the copies interleave, and country, sector, industry and size keep their real
distribution. Median of 15 runs on a MacBook Air with 8 GB RAM:

| Query (ms) | 83,744 accounts | 837,440 | 8,374,400 |
| --- | --- | --- | --- |
| Template counts (cube) | 0.8 | 0.8 | 0.8 |
| Profile badges (cube) | 3.2 | 3.3 | 3.3 |
| Ranked page, whole market | 8.1 | 14 | 70 |
| Ranked page, template + profile | 7.4 | 23 | 91 |
| Page 50 (offset 5,000) | 16 | 17 | 76 |
| Name search | 9.8 | 29 | 158 |
| Template counts (live, strong identity) | 2.0 | 8.1 | 70 |
| Toolbar badges (live) | 4.0 | 12 | 91 |
| Account by id | 3.0 | 5.3 | 37 |
| Evidence by id | 1.8 | 2.6 | 20 |
| CVE search (an OpenSSH CVE) | 30 | 99 | not run |
| Store size | 45 MB | 301 MB | 879 MB |
| Cube rows | 7,613 | 7,613 | 7,613 |

- **The most frequent queries don't grow.** The nav counts and the profile badges, sent on every
  click in the profile, come from the cube in 1 to 3 ms at every size.
- **The live paths stay interactive at 100×.** A filtered, ranked page and the toolbar badges take
  about 90 ms at 8.4M accounts on one laptop. Name search (158 ms) is a scan, the first candidate for a
  search index. CVE search runs to 10×; its 88M-row table at 100× is partitioned by CVE in production.
- **Batch and serving run on separate machines.** Measured while a re-export ran on the same laptop,
  the 100× live paths took 0.3 to 1.5 s, five to ten times slower.
- **The served table grows with companies, not banners.** Raw records grow with every file, billions
  a year; the served table is one row per company with real risk. 13.4M banners give 83,810 of them,
  and there are a few hundred million companies in the world at most, so the read side meets millions
  long before billions. The billions stay in the batch layer, as Parquet and SQL.

## 6. Lists and saved searches

A seller works in **lists** (named sets of accounts, each account with one status: to contact,
contacted, meeting booked, not a fit) and **saved searches** (a view, its filters and the profile it
was saved with).

- **"New since you last ran it" comes from the data.** Each account records the build it was first
  ranked in (`first_ranked`, carried over from build to build by id). A saved search remembers the
  build it last ran on, so "new since then and in none of my lists" is one query:
  `first_ranked > last_run` and `id not in (my listed ids)`. Nothing per user is snapshotted, however
  large the results.
- **Re-baselining.** `first_ranked` follows account ids, so a change to the identity rules (which can
  rename a company) is published with `--rebaseline`, marking everything present as already seen.
  Otherwise renamed companies would surface as new.
- **Where the state lives.** In this deployment, lists and saved searches are kept per browser, and
  the MCP server hands accounts to the app with an import link. In production they are rows in the
  app database (Postgres: workspaces, lists, list items, saved searches, runs) behind the same API,
  shared with a team and synced to the CRM, with a runner that re-executes each saved search when a
  build lands and notifies its owner.

## 7. The production path

What runs here is sized for this file and for 10 to 100 times more accounts. These are the changes
for a full stream of files and many users, with the point at which each is needed:

| Part | In this repo | At production scale |
| --- | --- | --- |
| Build | Recomputes the 30-day window: about 4 minutes for 13M observations | State tables (latest observation per service, first seen per service, hostname to domain) merged per file; only touched companies re-scored; global statistics (hoster detection, score normalisation, tiers, peer ranks) recomputed on a schedule. Needed once a rebuild no longer fits between files |
| Name resolution and peer ranks | Python over the distinct hostnames (3.8M) and all scored companies | A persistent resolved-name table, so only new names are resolved; peer ranks as SQL window functions |
| Parquet layout | One shard per 32 MB of input | One writer per worker with ~128 MB row groups, partitioned by observation date |
| Company identity | Deterministic choice per build | A company registry with aliases (`acme.co.uk` and `acme.com`, an IP owner gaining a domain), so renames neither look new nor orphan list entries |
| KEV in scoring | The scanner's KEV flag at scan time | The CISA catalogue joined in the build, so a CVE added to KEV after the scan raises the score |
| Thresholds (hoster, ISP pool) | Counts over the 30-day window | Ratios within the window |
| Ingest idempotency | Keyed on source path, size and modification time | Content hash; scan id from the observation times |
| Data quality | The export fails on a full IP, duplicate ids or orphan evidence | Plus row-count and null-rate drift checks against the previous build |
| LLM label cache | Keyed by name | Keyed by name, model and prompt version, so a prompt change relabels |
| Serving store | Parquet on local disk, DuckDB in the API process | Past tens of millions of accounts or many concurrent users: the same API on ClickHouse (or Postgres with indexes), partitioned by country, a search index for names, the cube materialised per build |
| User state | Per browser | Postgres behind the API, with workspaces and a saved-search runner |

Unchanged at any scale: ingest streams with bounded memory and renames atomically, DuckDB spills to
disk, CVE results grow with the number of CVEs rather than companies, evidence is capped per company,
and LLM cost grows with distinct new names, not records.
