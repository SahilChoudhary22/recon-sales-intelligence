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
| **Honeypots** | 293k records (2.2%) | Each advertises 80–170 fake CVEs. A "most CVEs" ranking puts decoys first. The scanner tags the ports it recognised; the same IP's other ports (43k records) are just as fake, so the whole IP goes. |
| **Over-reported KEV CVEs** | ~every nginx | CVE-2023-44487 (HTTP/2 Rapid Reset) is KEV-listed and matched on nearly every nginx. The jQuery XSS CVEs (CVE-2020-11023 etc.) come from a JS library on the *page*, not the server. Counting them makes "KEV" meaningless. |
| **WHOIS `org` and reverse DNS name the ISP** | most records | `hinet.net`, `telecomitalia.it` and "Clientes Residenciales" are carriers and their customer pools, not buyers. |
| **Hosters' naming schemes** | 1.8k domains | `vps123.hoster.com` on hundreds of IPs looks like one big company. |
| **Vendor default certificates** | thousands | FortiGate ships CN `support` / `fortinet-subca2001`; Traefik, Kubernetes and DrayTek have their own placeholders. |
| **Tor relays** | 431 records | Not anyone's estate; some imitate a VPN login page. Dropped. |

### What the scan claims vs. what it shows

The traps above are records to drop. These are fields that say more than the record supports. Each
one was found by checking a signal against the raw records behind it, after an early build ranked on
them (§8 has the before/after).

| Field | What it seems to say | What it actually shows | Rule now |
|---|---|---|---|
| `vulns` (CVE matches) | "this server has CVE-X" | A match from a version number; verified on 1.5% of services with a KEV CVE. 47% of KEV matches were on distro builds (Ubuntu, Debian, RHEL backport fixes without changing the version), 25% named no version at all, and the top PHP and WordPress KEVs landed on every server whose page used PHP or WordPress | Kept only when verified, or when the CVE's product was seen with a version that shows its patch level: not software a distro build patches in place (Apache, nginx, PHP, OpenSSL, OpenSSH… when the header, the distro markers, Amazon Linux's `Apache/x ()` or a version the distros ship says it's a distro build; an application on top, like WordPress or Exchange, keeps its own version), not a version RHEL freezes, not IIS (Windows Update), and a full version that appears in the record itself (version field, server header, `X-Powered-By` or banner; not a release name like "SharePoint 2016" — the scanner also infers versions from page content the record doesn't keep, and a blind review rejected 19 of 30 such claims) — and seen (for a known-exploited CVE, a versioned CPE that is CISA's product, not just its vendor: ASP.NET doesn't carry SharePoint's CVEs, nor PHP PHPMailer's; for other CVEs, the only versioned product on the service). Preconditions a version can't show are checked where known (CVE-2024-4577 needs Windows, CVE-2019-11043 nginx with PHP-FPM, CVE-2012-1823 PHP-CGI, which a banner doesn't show, the Apache mod_proxy/mod_rewrite CVEs Apache 2.4), and a KEV CVE that CISA lists without versions is checked against the vendor's fixed releases (PHP2Shell: 8.2.35, 8.3.36, 8.4.27, 8.5.12; 8.1 and older unfixed), and the evidence names the fix ("PHP 8.4.26 — CVE-2026-109618 (fixed in 8.4.27)"). A CVE the scanner confirmed with its own test is kept, and the evidence says so ("Confirmed by the scanner's own test on …"); ntpd's patch level counts as part of its version (4.2.8p17 isn't 4.2.8). 321k of 3.3M notable matches hold up. The evidence names each CVE under its own product ("Apache httpd 2.4.49 — CVE-2021-40438; PHP 7.4.33 — CVE-2026-109619") |
| `eol-product` tag | "end-of-life software" | A tag on the whole host, shown against the web server: every `nginx/1.24.0 (Ubuntu)` is tagged though Ubuntu 24.04 supports it until 2029, Apache 2.4 (a supported branch) is tagged when the PHP beside it is old, and `Apache/2.4.6 (CentOS)` (RHEL/CentOS 7, unsupported since June 2024) isn't tagged at all | Not used. End-of-life software is decided from the versioned products a service names, against the end of upstream support (PHP ≤ 8.1, Apache ≤ 2.2, nginx lines older than the current stable and mainline, MySQL ≤ 8.0, MariaDB ≤ 10.6, Tomcat ≤ 8.5, OpenSSL ≤ 1.1), only when that version appears in the record, never on distro builds, and the evidence names the component ("PHP 7.4.33, support ended November 2022"): 8,279 companies, from 35,693. The OS release is read from the package versions each release ships (OpenSSH `7.4` = RHEL/CentOS 7, Apache 2.4.29 on Ubuntu = 18.04, IIS 8.5 = Server 2012 R2) and dated: 9,945 companies with an end-of-life OS, from 2,508 |
| `module` (which probe ran) | "an industrial controller / database / remote desktop" | The port, not the protocol: 70% of port-3001 "HandPunch" replies are web pages, 29% of MySQL replies are "host not allowed" (error 1130), Redis answers `-NOAUTH`, X11 "access denied" | A port-based detection needs a reply in that protocol (not empty, not a web page or SSH greeting) and no refusal; so does a camera or DVR named only by the probe (602 of 609 Dahua-port hits were empty replies). OT needs the scanner's `ics`/`medical` tag or an industrial product: 185 companies, from 6,071 |
| `Server: BigIP`, Fortinet certificates | "firewall/VPN admin interface" | 96% of BIG-IPs are load-balancing an ordinary website; FortiWeb and FortiMail certificates front sites | The appliance's own fingerprint, login or admin page |
| NTLM `dns_domain` | "leaks the internal AD domain" | 96% of replies are standalone servers whose "domain" is their own name | A domain different from the host name |
| Certificate SANs | "this company runs it" | A hoster's shared certificate lists its customers; the alphabetically first SAN named the account | The CN names the owner; SANs are ignored when the CN is a platform's or they span 5+ domains |
| WHOIS org + domain | two accounts | UNIVERSIDADE DE SAO PAULO and usp.br ranked twice | An org's unnamed services join its own domain when the domain is the org's acronym or a word of its name (1,494 orgs); never for a network that hosts many organisations |
| Let's Encrypt expiry | "certificate expiring" | ACME certificates renew themselves at 30 days left | Expiring means the last 7 days for them |

## 3. The signals

Every signal is a SQL predicate over the slim schema with a weight, a sales-facing label and an
evidence string ([`pipeline/signals.py`](../pipeline/signals.py)), held to the rules above.
Counts are companies, full file:

| Signal | Companies | Why it means "call now" |
|---|---|---|
| Firewall/VPN appliance reachable (FortiGate, NetScaler, SonicWall, Ivanti/Pulse, Palo Alto, BIG-IP admin…) | 7,640 | The #1 ransomware initial-access vector |
| Edge appliance on a version **with** a KEV CVE | 18 | The above, already known-exploited |
| On-prem Exchange / OWA | 798 | ProxyShell-class surface; cloud-email pitch |
| RDP / VNC / Telnet / X11 answering, no refusal | 898 | Direct remote access |
| Database answering, no refusal (MS-SQL, MySQL, Oracle, Redis, Mongo…) | 2,677 | Data exposure |
| SMB / open directories (an iSCSI target only when it lists its targets) | 1,070 | Data exposure, lateral movement |
| OT / medical / POS devices (scanner's `ics`/`medical` tag or an industrial product; non-cloud) | 185 | Compliance-driven buyer |
| Self-hosted AI app or MCP server (LiteLLM, Ollama, Dify, Flowise, MCP) | 169 | New attack surface: leaked keys, data and agent tools |
| Evidence of a breach (ransomed database, remote-access trojan, cryptominer; red-team tools excluded) | 2 | Already compromised: an incident-response call |
| Version affected by a KEV CVE (attributable matches only, the CVE's own product; noise CVEs excluded) | 3,966 | Known exploited in the wild |
| Version with an EPSS ≥ 0.5 CVE (not export-grade TLS ciphers, Logjam and FREAK: that's weak TLS) | 2,460 | Likely to be exploited soon |
| End-of-life OS (NTLM, IIS version, distro release) / EOL component (PHP, Apache, nginx, MySQL, MariaDB, Tomcat, OpenSSL; not distro builds) | 9,945 / 8,279 | Unpatchable |
| NTLM leaks an internal AD domain | 2,522 | Recon handed to attackers |
| Expired / expiring certs, TLS 1.0/1.1, self-signed | many | Hygiene: points to a thin or absent security team |

**Maturity signals** (WAF, security.txt, post-quantum TLS, HSTS) don't hide an account. They
change the pitch from "first security purchase" to "consolidation / coverage gaps" (6,891 accounts).

## 4. How a company is identified

1. **Candidate names per record**, strongest first: TLS cert CN, then its SANs → NTLM FQDN (leaked AD
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

5. **One organisation, one account:** an org's unnamed services join its own domain when the domain
   is the org's acronym or a word of its name (usp.br for UNIVERSIDADE DE SAO PAULO).
6. **Who can't reach P1/P2** (still searchable, in P3), measured on every blind review (§8): an address
   block known only by its owner's name (9/52 sellable, 7 of those universities or governments), unless
   it's a university or government that owns its IPs; a domain the labeller couldn't place, unknown with low confidence (43/141); a domain it
   labelled a hoster or an ISP (1/14). Domains it labelled a business were 81% sellable (170/211).

Result: 907k assets attributed to 295k companies; **38,099 companies with a material risk signal**.

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

**In production, outcomes join the score.** The weights are set by judgement because a take-home has no
sales outcomes; the blind reviews (§8) check them instead. The product already records the outcome
labels: every account carries a seller's status (to contact, contacted, meeting booked, not a fit). In
production the score would gain a performance term: the recent meeting rate against the not-a-fit rate
for accounts like this one, by signal, template, industry and size, with recent outcomes weighted more.
Triggers that keep booking meetings rise and ones that keep failing sink, and the same statuses show
whether a change to the rules helped.

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
| Export to the serving store (38,099 accounts, evidence, CVE hits, count cube) | ~10 s |

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

**Where:** one place in the pipeline. (Agents were also used to build and measure it: the audit and
the blind reviewers in §8.) It classifies **distinct names** behind ranked accounts (WHOIS orgs and
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
- Five rounds were run: 3,000 names, then 1,430 promoted by re-ranking; after the claims rebuild
  1,539, then 1,014 and 345 promoted once unrecognised domains left P1/P2 (§8). Unlabeled names in the
  top tiers ended at 91 of 3,000. All 7,328 labels were valid.

`llm_label.py` is the production path for a file stream (batched 40 per request, `messages.parse` +
Pydantic schema, disk cache, per-call token logging).

**Cost** (`data/labels/llm_usage.json`):
- Measured for the batch runs: **2.57M tokens for 7,328 labels → $0.26–$1.28** at Haiku 5.5 prices
  ($0.10 / $0.50 per million input/output tokens). It's a range because the run's accounting doesn't
  split input from output, and it includes orchestration overhead, so it overstates the API path.
- Estimate for the API path: ~40 names per request at ~2.5k in + ~2k out ≈ **$0.08 per 3,000 names**.
  Roughly cents per file in production, and falling, because the cache carries over (orgs repeat
  month to month).

**Cutting the cost further.** Labelling is already cheap because it runs once per distinct name. In
production, in order of effort:
- **Batch API.** Labelling is an offline job, so the Message Batches API halves its price (results
  usually within the hour, always within 24) with no other change. OpenAI offers the same pattern.
- **Low effort.** Claude Haiku 5.5 reasons by default; a one-word label doesn't need it, so low effort
  cuts the hidden reasoning tokens.
- **Short, typed answers.** Output costs five times input on Haiku ($0.50 vs $0.10 per million), so
  labels come back as compact structured output with no explanations.
- **Prompt caching, when the prompt grows.** Cached input reads cost a tenth of the normal price, but
  Haiku 5.5 caches only prefixes of 512 tokens or more. Today's instructions are shorter, so caching
  saves nothing yet; it pays once the prompt carries worked examples to raise accuracy.
- **A cheap first stage.** The largest saving is a cascade: a cheap classifier labels the names it is
  confident about, and only the rest reach the LLM. Two candidates: a new non-generative model such
  as Jev (TypeSafe AI, announced 15 September 2026, early access; [InfoQ](https://infoq.com/news/2026/10/typesafe-ai-jev-released),
  [The Batch](https://www.deeplearning.ai/the-batch/models-built-to-do-one-thing-well)), which takes typed
  questions per request and returns probabilities instead of text, at a listed $0.042 per million
  input tokens with free output; or a small classifier trained on the 7,328 labels already collected,
  which runs locally for free. Jev's speed and accuracy figures are the vendor's own so far, so I'd pick
  between the two by agreement with the blind gold labels (§8), and on cost.

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
the same holdout. Re-scored on today's final build, the gold accounts it still puts in P1/P2 (23, 22
and 20 of them) are 96%, 91% and 95% sellable: the later rules mostly moved out the unsellable ones.
That's in-sample and optimistic, since those sets informed the rules, so the headline figure is the
fresh claims holdout below (v10).

**Claims, not just accounts.** The gold sets above measure whether an account is a real, correctly
named organisation. They don't measure whether what Recon says about it is true, and that was the
larger gap: the scanner's CVE, end-of-life and protocol verdicts were taken at face value (§2, "What the
scan claims vs. what it shows"). [`pipeline/claims_sample.py`](../pipeline/claims_sample.py) draws
random P1/P2 accounts, each with up to four risk claims (hygiene left out) and the raw scan fields
behind each claim (the exact record: IP, port and observation time), IPs masked; two blind reviewers
judged each claim supported, unsupported or unclear; [`pipeline/evaluate_claims.py`](../pipeline/evaluate_claims.py) scores them per build.

| Sample (blind) | Build | Claims rejected | Confirmed | Unclear | Accounts sellable |
|---|---|---|---|---|---|
| claims v4: 60 + 60, shuffled together | before | 44% (59/135) | 46% | 10% | 60% (36/60) |
| | after the first fixes | 21% (21/102) | 59% | 21% | 65% (39/60) |
| claims v5: 60 new | + distro, RHEL, CVE-precondition and end-of-life fixes | 7% (8/119) | 64% | 29% | 73% (44/60) |
| claims v6: 30 claims a later change added | + per-product distro/IIS rule | 63% (19/30) | 20% | 17% | 63% (19/30) |
| claims v7: 60 new | + claims need the version in the record | 4% (5/118) | 72% | 24% | 60% (36/60) |
| claims v8: 60 new (holdout) | + label rounds 3–5, unrecognised domains out of P1/P2 | 6% (8/131) | 71% | 23% | 72% (43/60) |
| claims v9: 60 new (holdout) | + CISA product (not vendor), CVEs per product, IP owners and hosters out of P1/P2, tier-first order | 4% (5/116) | 74% | 22% | 80% (48/60) |
| **claims v10: 60 new (holdout)** | **final: + Logjam/FREAK as weak TLS, ntpd patch levels, camera ports need a reply** | **6% (6/109)** | **66%** | **28%** | **77% (46/60)** |

What each step showed and what it changed:
- **v4** (before vs. after, blind to which) drove Amazon Linux and RHEL's frozen PHP/OpenSSL versions,
  CVE preconditions and end of life per component.
- **v5** was the first holdout. Its rejections were a long tail (distro-shipped Exim and nginx
  versions, configuration-dependent CVEs), which drove treating versions the distros ship as patched
  unless the header names an upstream build.
- **v6** checked only the claims a later change added. Making a distro build cover only the software it
  packages (so WordPress on Ubuntu, or Exchange on IIS, keep their own versions) brought back real
  Exchange matches, but the reviewer rejected 19 of 30 added claims: the scanner had inferred
  application versions from content the record doesn't keep, or named a release ("SharePoint 2016",
  "Drupal 7") rather than a version. So a CVE or end-of-life claim now needs its full version in the
  record itself; that removes 17 of the 19 and keeps all 6 confirmed.
- **v7** measured that: 4% rejected, but only 60% of accounts sellable. 1,539 names had reached the top
  tiers since the last label round, and across v4, v5 and v7 the domains the labeller could not place
  (unknown, low confidence) were 34% sellable (27/80) against 84% (110/131) for those it labelled a
  business, government or school. So those stay out of P1/P2 (still searchable), and three label
  rounds covered the names promoted in their place (1,539, 1,014 and 345 names; 91 left unlabeled).
- **v8** was a holdout. Its first review showed each claim the record found by IP and port, and
  for 16 of 131 claims that IP:port carried several sites (shared hosting), so the reviewer had seen a
  neighbour's reply; the sample was rebuilt with the exact record (IP, port, observation time) and
  reviewed again by fresh reviewers, which is the row above. Samples before v8 had the same flaw on
  about 13% of claims, so their rates are approximate; the before/after comparison in v4 used one
  method for both halves.

- **v9** followed a review of the whole project by a separate reviewer agent, which found three errors
  the samples hadn't caught (each count is from the build before the fix): SharePoint, Exchange and Office CVEs claimed on
  plain ASP.NET sites, because a known-exploited CVE was matched to its CISA vendor rather than its
  product (26 companies, 10 in P1/P2); evidence lines that listed one product's CVEs under another's
  name ("Apache httpd 2.4.58 — " then PHP CVEs, 519 companies); and P1 places held by ISP ranges and
  hosters known only by their registration name ("Red de Servicios IP", "Leased Line- LAN Range"),
  which a ×0.3 weight hadn't kept out. Across every review so far (548 verdicts), address blocks known
  only by their owner's name were 17% sellable (9/52, 7 of them universities, schools and governments, which own
  their address space), domains
  labelled a hoster or ISP 7% (1/14), and labelled businesses 81% (170/211); so the first two now
  stay out of P1/P2. Low-confidence business labels were 59% (24/41), the same as an unlabelled
  domain, so they stay in. Search also ordered by score alone, which put 179 held-back accounts above
  the last P1; it now orders by tier, then score. v9's rejections: Logjam and FREAK (export-grade TLS
  ciphers, not a version's flaw) claimed as "likely to be exploited" (533 companies), ntpd 4.2.8 claimed
  on a 4.2.8p17 banner, an empty reply on a Dahua camera port (602 of 609 such hits), and Heartbleed
  from the scanner's own test, worded as an Apache version CVE (now "Confirmed by the scanner's own test
  on …").
- **v10** is the final holdout, on the build those fixes produced. Its 6 rejections: CVE-2012-1823
  (PHP-CGI only) on three servers running PHP as an Apache module, an iSCSI port answering "Not found any
  reachable targets", Ubuntu 12.04's packaged nginx 1.1.19 taken as upstream, and a domain on a shared
  IONOS address whose reply was another site. The first five drove the last rules (PHP-CGI needs to show
  in the banner, iSCSI needs listed targets, Debian and Ubuntu's Exim and nginx versions are distro
  builds, nginx's CVE-2017-7529 is fixed in 1.12.1); on the final build those five claims are no longer
  made, which is in-sample and so not a new rate.

The two PHP2Shell CVEs (CVE-2026-109618/109619, added by CISA on 2026-10-26) are 29 of v10's 31
"unclear": newer than the reviewers' knowledge. CISA's catalogue gives no affected versions, so they're
checked against PHP's fixed releases (8.2.35, 8.3.36, 8.4.27 and 8.5.12; 8.1 and older have none).
About 7,000 services in the scan run a fixed release, and the scanner attached neither CVE to any of
them: all 7,155 matches are on affected versions, and the evidence names the fix or says the branch
has none. The 8 rejections in v8: a video-management server whose header imitates Apache, an LDAP directory called a
management interface, a MongoDB status page that's likely a decoy, a PHPMailer CVE listed under PHP,
the scanner's own MS17-010 verification (not visible in the record), a NetScaler cookie in front of a
web app, and an empty reply on a DVR port. In v8, one-IP accounts were 81% sellable (26/32) and larger
estates 61% (17/28).

Scoring was also tried with diminishing weight for each further kind of problem (to reduce the
university share of P1, a third). It promoted one-site hobby and junk domains whose only finding was an
old PHP version, the largest error the identity samples had found, so it was reverted: breadth is a fair
proxy for a real organisation's estate, and the sector filter is how a seller narrows to commercial.

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
  (KEV, EPSS ≥ 0.1 or CVSS ≥ 9) for every attributed company, 39,146 company-CVE pairs over 828
  CVEs, plus a lookup enriched from the CISA KEV catalogue (date added, ransomware use, vendor and
  product mapped to a software family for the fallback search). Tested against a direct query over the
  build (`tests/test_cve_index.py`).
- **Peer benchmark** ([`pipeline/export.py`](../pipeline/export.py)): risk = need × urgency, ranked within
  industry + country, then industry, then country, over all 94,375 scored companies, minimum 30 peers.
  Peer industries use the keyword rules for every company, and an industry group is used only when it
  agrees with the industry the app shows.
- **Exposure brief** ([`web/src/Brief.tsx`](../web/src/Brief.tsx), `?brief=<account>`): printable, evidence
  only, with fixed guidance per signal ([`web/src/guidance.ts`](../web/src/guidance.ts)).
- **Ideal customer profile, filters, lists and saved searches** ([`web/src/`](../web/src/)): every filter
  takes several values, the profile is a default layer under every view, an account can sit in several
  lists, and a saved search reports what is new since its last run. They are kept per user in the app
  database behind sign-in; how, and what changes in production, is in [architecture.md](architecture.md#6-lists-and-saved-searches).
- **MCP server** ([`mcp_server/`](../mcp_server/)): eleven deterministic tools on the API's query layer and app database;
  protocol tests in `tests/test_mcp_server.py`, accuracy evaluation in `mcp_server/eval/`.
