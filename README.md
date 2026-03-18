# MXray.py

High-performance async email domain analyzer for deliverability diagnostics. Processes email lists or domain lists at scale, producing enriched CSVs with DNS records, MX provider classification, website status, spam trap detection, optional catch-all probing, domain risk scoring, and per-address risk flags.

## What It Does

Given an input file of email addresses or domains, the tool runs a full diagnostic pipeline on every unique domain:

1. **DNS lookups** — MX, A, NS, SPF, and DMARC (with cascading organizational domain fallback)
2. **MX provider classification** — Maps MX records to ~40 known providers (Google, Microsoft, Yahoo, Proofpoint, Mimecast, Barracuda, etc.)
3. **Website check** — HTTP fetch with parking page detection, SEO spam/gambling detection, and hacked medical site identification
4. **Spam trap detection** — Matches MX records against known trap infrastructure (Erinn network, jellyfish.systems, emaildbox.pro, catchservers, etc.)
5. **Disposable email detection** — Identifies disposable/throwaway MX providers (Mailinator, Guerrilla Mail, TempMail, etc.)
6. **Parked domain detection** — Via MX patterns, NS patterns, and HTTP content analysis
7. **Typo detection** — Damerau-Levenshtein distance-1 matching against the MAGY 2025 canonical consumer domain list (Gmail, Outlook, Yahoo, iCloud, and ~300 regional variants)
8. **Null MX detection** — Flags RFC 7505 null MX records (domains that explicitly reject all mail)
9. **Optional catch-all probing** — With `--catch-all`, performs a low-volume SMTP `RCPT TO` probe against MX hosts and labels domains as `accept_all`, `rejects_random`, `inconclusive`, or `skipped`
10. **Risk scoring** — Produces domain-level and email-level risk scores and levels (`Low`, `Medium`, `High`, `Critical`) based on combined signals
11. **MX intelligence** — Maps MX hosts to provider, infrastructure family, risk tier, and signal flags using [`mx_rules.json`](/Users/tomsather/scripts/github/NewMXTool/mx_rules.json)
12. **Optional WHOIS enrichment** — With `--whois`, fetches organizational-domain registration age and status as an extra risk signal
13. **Cohort and cluster analysis** — Detects typo-heavy cohorts, risky infrastructure clusters, and repeated suspicious MX families across a client list
14. **Overrides and history** — Supports local allowlist/known-bad overrides and keeps a lightweight per-domain history file for change detection

At the email level, it also flags:

- **Role accounts** — info@, admin@, postmaster@, sales@, etc.
- **Disposamail patterns** — Exactly 10-character local parts matching the Spamhaus "letters then numbers" stuffed-address pattern
- **Engagement risk** — If engagement columns are present in the CSV, flags never-engaged, 12+ month stale, and 18+ month recycled trap risk addresses

## Requirements

- Python 3.8+
- `dnspython` (async DNS resolution)
- `aiohttp` (async HTTP)

```bash
pip install dnspython aiohttp
```

## Usage

```bash
# Basic — text file with one domain or email per line
python3 MXray.py domains.txt

# CSV with auto-detected email column
python3 MXray.py subscribers.csv csv

# Resume a large run from row 150000
python3 MXray.py subscribers.csv csv 150000

# Add low-volume SMTP catch-all probing
python3 MXray.py subscribers.csv csv --catch-all

# DNS-only run (skip website fetches)
python3 MXray.py subscribers.csv csv --dns-only

# Add WHOIS / domain-age enrichment
python3 MXray.py subscribers.csv csv --whois
```

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `input_file` | Yes | — | Path to input file |
| `file_type` | No | Auto-detected from extension | `txt` (one entry per line) or `csv` |
| `skip_rows` | No | `0` | Number of data rows to skip (for resuming interrupted runs) |

### Flags

| Flag | Description |
|------|-------------|
| `--catch-all` | Enable low-volume SMTP catch-all probing against MX hosts |
| `--dns-only` | Skip website checks and only use DNS plus optional SMTP probing |
| `--whois` | Enable WHOIS / registry-age enrichment for organizational domains |

### Input Formats

**Text file** — One email address or bare domain per line:
```
user@example.com
anotherdomain.org
someone@healthcare.edu
```

**CSV file** — The tool auto-detects the email column by header name (`email`, `e-mail`, `email_address`) or by scanning for `@` in the first data row. It also auto-detects engagement columns (`time since last engagement`, `opens`, `clicks`) if present.

## Output

The tool produces two CSV files per run:

### Domain-level CSV (`*_domain_analysis_*.csv`)

One row per unique domain with fields:

| Field | Description |
|-------|-------------|
| `domain` | The domain analyzed |
| `has_mx` | Whether valid MX records exist |
| `has_a` | Whether A records exist |
| `has_spf` | Whether an SPF record exists |
| `has_dmarc` | Whether a DMARC record exists (checked at domain and org domain) |
| `mx_category` | Provider classification (Google, Microsoft, Yahoo, Proofpoint, etc.) |
| `mx_provider` | Specific named provider or infrastructure label |
| `mx_family` | Normalized infrastructure family / parent domain for the MX |
| `mx_risk_tier` | MX risk tier such as `low`, `contextual`, `elevated`, or `high` |
| `mx_signal_flags` | Pipe-delimited MX flags such as `forwarding`, `routing`, `shared-hosting`, or `known-bad` |
| `website_status` | `live`, `parked`, `spam`, `dead`, `error`, or `unknown` |
| `website_details` | Detail string (HTTP status, parking phrase, spam type) |
| `redirect_url` | Final URL after redirects |
| `catch_all_status` | `accept_all`, `rejects_random`, `inconclusive`, or `skipped` |
| `catch_all_details` | Catch-all probe detail string |
| `is_disposable_mx` | MX matches a known disposable email provider |
| `is_trap_mx` | MX matches known spam trap infrastructure |
| `possible_typo_of` | If within 1 edit of a MAGY domain, shows the canonical match |
| `domain_age` | Human-readable domain age string |
| `domain_created_at` | Parsed creation date in `YYYY-MM-DD` when available |
| `domain_age_days` | Parsed age in days when available |
| `whois_status` | `ok`, `skipped`, `unsupported`, `unparsed`, or `error` |
| `whois_details` | WHOIS lookup detail string |
| `override_status` | `allowlisted`, `known_bad`, or blank |
| `override_reason` | Explanation of the override source |
| `cluster_family` | Cluster key used for MX-family grouping |
| `cluster_size` | Number of domains in the MX-family cluster |
| `cluster_risky_domains` | Number of risky domains in the cluster |
| `cluster_risky_ratio` | Risky-domain ratio within the cluster |
| `cluster_flag` | Cluster label such as `risky-cluster` |
| `cohort_total_domains` | Number of unique domains in the run |
| `cohort_typo_ratio` | Portion of domains flagged as typo domains |
| `cohort_risky_cluster_ratio` | Portion of domains in risky MX clusters |
| `cohort_typo_anomaly` | Whether the run crossed the cohort typo threshold |
| `cohort_risky_cluster_anomaly` | Whether the run crossed the risky-cluster threshold |
| `historical_seen_before` | Whether the domain existed in the local history file |
| `historical_last_risk_level` | Previous risk level from history |
| `historical_last_risk_score` | Previous risk score from history |
| `historical_status_changed` | Whether status or risk level changed since history |
| `status` | Final classification: `Valid`, `Invalid`, `Parked`, `Trap`, `Disposable`, `Suspicious`, `Unknown` |
| `reason` | Human-readable explanation of the status |
| `risk_score` | Domain spam-trap / deliverability risk score from 0-100 |
| `risk_level` | `Low`, `Medium`, `High`, or `Critical` |
| `risk_factors` | Pipe-delimited explanation of signals that contributed to the score |

### Email-level CSV (`*_email_analysis_*.csv`)

One row per input row. Preserves all original columns and appends the domain-level fields plus:

| Field | Description |
|-------|-------------|
| `is_role_account` | Local part matches a known role account (info, admin, postmaster, etc.) |
| `is_disposamail_pattern` | 10-char local part matching Spamhaus stuffed-address pattern |
| `engagement_risk` | Risk flag based on engagement data (if columns are present) |
| `email_risk_score` | Combined mailbox-level risk score from 0-100 |
| `email_risk_level` | `Low`, `Medium`, `High`, or `Critical` |
| `email_risk_factors` | Pipe-delimited explanation of the email-level score |

## Configuration

Tunable constants at the top of the script:

| Constant | Default | Description |
|----------|---------|-------------|
| `DNS_CONCURRENCY` | 500 | Max concurrent DNS queries |
| `HTTP_CONCURRENCY` | 80 | Max concurrent HTTP requests |
| `SMTP_CONCURRENCY` | 20 | Max concurrent SMTP catch-all probes |
| `WHOIS_CONCURRENCY` | 20 | Max concurrent WHOIS lookups |
| `QUERY_TIMEOUT` | 5s | DNS query timeout |
| `CONN_TIMEOUT` | 5s | HTTP connection timeout |
| `SMTP_TIMEOUT` | 8s | SMTP connection / response timeout |
| `WHOIS_TIMEOUT` | 8s | WHOIS connection / response timeout |
| `MAX_HTML_SIZE` | 128 KB | Max HTML bytes read per website check |
| `CHECK_WEBSITE` | `True` | Set to `False` for DNS-only runs (much faster) |

DNS resolution uses Google (8.8.8.8), Cloudflare (1.1.1.1), and Quad9 (9.9.9.9) public resolvers by default.

## MX Rules

MX intelligence is driven by [`mx_rules.json`](/Users/tomsather/scripts/github/NewMXTool/mx_rules.json). Each rule can define:

- `name`
- `family`
- `category`
- `risk_tier`
- `risk_weight`
- `flags`
- `patterns`

That lets you tune suspicious provider heuristics without editing Python. A good workflow is to add new trap or forwarding families there first, then only touch code if you need a new kind of signal.

## Performance

The tool is designed for large list processing (100K–1M+ rows). Key design choices:

- **Fully async** — DNS and HTTP run concurrently via `asyncio` with semaphore-controlled concurrency
- **Domain-level deduplication** — Each unique domain is processed once, then cached and mapped back to all rows
- **Three-tier LRU caching** — DNS results (100K capacity), website results (50K), and domain analysis results (500K)
- **Chunked streaming** — Processes input in 50K-row chunks to bound memory usage
- **Resolver recycling** — Periodically resets the DNS resolver between chunks to prevent pycares file descriptor exhaustion
- **Fail-fast website cache** — Dead/errored sites are cached separately to avoid re-checking
- **Second-pass scoring** — Unique domains are processed first, then cohort/cluster/history signals are applied before final CSV export

## Catch-All Notes

Catch-all probing is off by default. It opens an SMTP session, sends `EHLO` / `HELO`, `MAIL FROM`, and one random `RCPT TO`, then stops before `DATA`.

- Treat `accept_all` as a strong risk signal, not proof of a spam trap
- Treat `rejects_random` as helpful but not definitive
- Treat `inconclusive` as normal on some providers, especially from residential IPs or rate-limited networks
- Use the feature carefully on large lists; some providers tarpits or throttle SMTP probes

## WHOIS Notes

WHOIS enrichment is off by default. It queries the organizational domain, asks IANA for the correct WHOIS server, then tries to parse the creation date from the registry response.

- Treat WHOIS age as a helpful extra signal, not a required one
- Some TLDs do not expose a parseable creation date
- Some registries rate-limit or block repeated lookups
- `unparsed` and `unsupported` are normal outcomes on part of the domain universe

## Overrides And Tuning

Local override files:

- [`domain_allowlist.csv`](/Users/tomsather/scripts/github/NewMXTool/domain_allowlist.csv)
- [`domain_known_bad.csv`](/Users/tomsather/scripts/github/NewMXTool/domain_known_bad.csv)
- [`domain_suppressions.csv`](/Users/tomsather/scripts/github/NewMXTool/domain_suppressions.csv)

Use them for:

- Domains that look suspicious but are legitimate for your clients
- Domains you already know should be reviewed or suppressed
- Quick tuning without changing Python code

## Additional Outputs

Each run also writes:

- `*_review_queue_*.csv` — Domains that are high risk, critical, overridden, or cluster-flagged
- `*_cluster_summary_*.csv` — MX-family cluster rollup
- `*_cohort_summary_*.json` — Run-level anomaly summary
- `mxray_history.jsonl` — Local append-only history file created on first run and used for change detection in future runs
