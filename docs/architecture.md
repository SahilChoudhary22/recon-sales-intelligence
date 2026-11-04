# Recon: architecture and data flow

How a scan file becomes ranked accounts, and how that keeps up when hundreds to thousands of files
arrive each month. Each diagram marks what is **built** (in this repo, run on the supplied file)
and what is **designed** (the production shape the built pieces slot into).

## 1. What happened to this file (built)

One file, 13.4M banners, processed once. The numbers are what each step kept.

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
  identity --> attributed["918k services, 297k companies"]
  attributed --> signals["20 risk signals per service<br/>(pipeline/signals.py)"]
  signals --> score["Score per company<br/>need x urgency x fit, tiers P1 / P2 / P3"]
  score --> risky["83,748 companies with real risk"]
  risky --> export["Export (pipeline/export.py)<br/>top 15,000, IPs masked to /24,<br/>software families, sector, peer ranks"]
  risky --> cveidx["CVE index (pipeline/cve_index.py)<br/>1,701 CVEs, 54,856 companies"]
  kev[("CISA KEV v2026.11.03")] --> cveidx
  export --> published[("Published data")]
  cveidx --> published
  published --> app["Web app (static)"]
  published --> mcp["MCP server"]
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
    score --> index[("Accounts, CVE index,<br/>peer ranks")]
  end
  subgraph use["Use"]
    index --> app["App and MCP server"]
    index --> agents["Signal agents<br/>re-run each template on new scans"]:::designed
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

**Incremental.** Today the build recomputes everything (about 3 minutes for 13M rows). At production
volume it would recompute only companies touched by new files: scores depend on each company's
latest services, so untouched companies keep their score.

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
  B->>A: publish accounts, CVE index, peer ranks
  B->>S: newly matching accounts per template
  S-->>A: "Newly exposed" view, CRM tasks
```

## 4. What is kept, dropped and masked

```mermaid
flowchart LR
  R["Raw banner<br/>HTML, headers, cert chain,<br/>full IP, every CVE"] -->|"slim: ~40 fields"| PQ["Parquet<br/>full IP, product, notable fields"]
  PQ -->|"build"| AC["Company scores and evidence<br/>full IP, local only"]
  AC -->|"export: mask to /24"| PUB["Published data<br/>app, CVE index, MCP<br/>203.0.113.x:443"]
  R -.->|"raw HTML, cert chains, pubkeys"| DROP["Not kept"]
```

Full IP addresses never leave the local build: everything the app, the CVE index and the MCP server
read is masked to the /24 network, and the deploy script refuses to ship an unmasked export.
