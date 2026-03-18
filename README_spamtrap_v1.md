# Spam Trap Detection Engine v1

`spamtrap_v1.py` scores emails/domains for spam-trap risk using deterministic rules and DNS enrichment.

## What It Does
- Accepts mixed input rows: full email addresses and plain domains.
- Extracts/normalizes domains and writes a unique-domain file for the run.
- Resolves DNS signals per unique domain: `MX`, `A`, `SPF`, `DMARC`.
- Applies risk logic for:
  - known trap/disposable MX patterns
  - suppression-domain matches (`domain_suppressions.csv`)
  - typo domains near Gmail/Yahoo/Microsoft domains
  - local-part pattern (`letters + digits`, length exactly `10`)
- Maps domain results back to each original input row.
- Outputs a report-only CSV (`Flagged`/`Clear`) with reason codes.

## Files
- Script: `/Users/tomsather/scripts/github/NewMXTool/spamtrap_v1.py`
- Rules config: `/Users/tomsather/scripts/github/NewMXTool/spamtrap_rules.json`
- Suppression list: `/Users/tomsather/scripts/github/NewMXTool/domain_suppressions.csv`
- Provider domain catalogs:
  - `/Users/tomsather/Downloads/Gmail, Microsoft and Yahoo domains - Gmail.csv`
  - `/Users/tomsather/Downloads/Gmail, Microsoft and Yahoo domains - Yahoo_AOL.csv`
  - `/Users/tomsather/Downloads/Gmail, Microsoft and Yahoo domains - Microsoft.tsv`

## Input Format
### TXT input
- One value per line.
- Value can be:
  - an email (example: `user@example.com`)
  - a domain (example: `example.com`)

### CSV input
- Pass `csv` and the `email_column` index.
- The selected column may contain emails or domains.

## Provider File Format Expectations
- Gmail CSV: one domain per line or CSV with `Domain` header.
- Yahoo/AOL CSV: CSV, ideally with `Domain` header.
- Microsoft TSV: TSV, ideally with `Domain` header.
- Domains only; no `@` addresses in provider files.

## Usage
```bash
python3 /Users/tomsather/scripts/github/NewMXTool/spamtrap_v1.py <input_file> [txt|csv] [email_column]
```

Examples:
```bash
python3 /Users/tomsather/scripts/github/NewMXTool/spamtrap_v1.py /path/list.txt txt
python3 /Users/tomsather/scripts/github/NewMXTool/spamtrap_v1.py /path/list.csv csv 0
```

## Outputs Per Run
- Main scored output:
  - `<input_base>_spamtrap_v1_<timestamp>_<processid>.csv`
- Unique domains file used by resolver/scorer:
  - `<input_base>_unique_domains_<timestamp>_<processid>.txt`

## Key Output Columns
- `email`, `domain`
- `mx_records`, `has_mx`, `has_a`, `has_spf`, `has_dmarc`
- `suppression_domain_match`
- `typo_domain_match`, `typo_domain_provider`, `typo_canonical_domain`
- `risk_score`, `risk_band`, `status`
- `reason_codes`

## Risk Bands
- `High`: `risk_score >= 80`
- `Medium`: `50 <= risk_score < 80`
- `Low`: `risk_score < 50`

## Notes
- This is report-only logic; it does not suppress addresses automatically.
- DNS lookup failures are handled conservatively and annotated in `reason_codes`.
- Scoring weights and thresholds are configurable in `spamtrap_rules.json`.
