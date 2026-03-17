# Passive Recon Suite — APT-Level OSINT Collection Framework

Fully passive, modular OSINT reconnaissance framework for authorized red team / penetration testing engagements. Zero active scanning — all data sourced from public APIs, certificate transparency logs, DNS records, web archives, and code repositories.

## Legal Disclaimer

**This tool is intended for authorized security testing only.** Ensure you have written authorization before running this against any target. Unauthorized reconnaissance may violate local, state, and federal laws.

## Project Structure

```
.
├── recon_master.sh              # Orchestrator — runs all modules in sequence
├── setup.sh                     # Dependency installer (Kali/Ubuntu/Parrot)
├── config/
│   ├── api_keys.conf.example    # Template — copy to api_keys.conf and populate
│   └── .gitkeep
├── modules/
│   ├── 01_asn_enum.sh           # ASN & IP ownership mapping
│   ├── 02_cert_transparency.sh  # Certificate transparency log mining
│   ├── 03_passive_dns.sh        # Passive DNS & historical records
│   ├── 04_subdomain_passive.sh  # Passive subdomain enumeration (10+ sources)
│   ├── 05_url_corpus.sh         # URL corpus (Wayback, CommonCrawl, gau)
│   ├── 06_live_hosts.sh         # Live host fingerprinting (httpx, nmap)
│   ├── 07_js_analysis.sh        # JavaScript secret & endpoint extraction
│   ├── 08_cloud_enum.sh         # Cloud storage enumeration (S3/Azure/GCP)
│   ├── 09_tech_fingerprint.sh   # Tech stack & CVE candidate mapping
│   ├── 10_screenshots.sh        # Visual reconnaissance (EyeWitness/gowitness)
│   ├── 11_dorks.sh              # GitHub/GitLab/Google dorking
│   └── 12_report.sh             # HTML + JSON + TXT report generation
├── lib/
│   └── common.sh                # Shared functions (logging, validation, locking)
├── requirements/
│   ├── apt-packages.txt         # System packages
│   ├── go-tools.txt             # Go tool install paths
│   ├── pip-packages.txt         # Python packages
│   └── git-repos.txt            # Git-cloned tools
├── .gitignore
├── .env.example                 # Environment variable template
└── LICENSE
```

## Quick Start

```bash
# 1. Clone and enter
git clone <repo_url> && cd recon-suite

# 2. Install dependencies (Kali/Ubuntu/Parrot)
chmod +x setup.sh && ./setup.sh

# 3. Configure API keys
cp config/api_keys.conf.example config/api_keys.conf
$EDITOR config/api_keys.conf

# 4. Run against target (requires written authorization)
./recon_master.sh -t target.com -i hosts.txt
```

## Usage

```
./recon_master.sh -t <target_domain> -i <input_file> [options]

Required:
  -t  Target domain (e.g., target.com)
  -i  Input file with hostnames/IPs (one per line)

Options:
  -o  Output directory      (default: ./output)
  -k  API keys config file  (default: ./config/api_keys.conf)
  -T  Thread count           (default: 10)
  -s  Skip modules           (comma-separated, e.g., "08,10")
  -h  Help
```

## Environment Variables / API Keys

All keys go in `config/api_keys.conf`. None are required — modules degrade gracefully without them, but coverage increases significantly with keys.

| Variable | Source | Modules |
|----------|--------|---------|
| `SHODAN_API_KEY` | https://account.shodan.io | 04, 06, 09, 11 |
| `SECURITYTRAILS_API_KEY` | https://securitytrails.com/app/account/credentials | 03 |
| `GITHUB_TOKEN` | https://github.com/settings/tokens (read-only, no write) | 11 |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | https://search.censys.io/account/api | 02 |
| `VIRUSTOTAL_API_KEY` | https://www.virustotal.com/gui/user/api-key | 02, 03 |
| `HUNTER_API_KEY` | https://hunter.io/api-keys | (reserved) |
| `WHOISXML_API_KEY` | https://user.whoisxmlapi.com/products | 03 |
| `IPINFO_TOKEN` | https://ipinfo.io/account/token | 01 |

## Running Tests / Validation

```bash
# Validate all scripts parse correctly
bash -n recon_master.sh
for f in modules/*.sh lib/*.sh; do bash -n "$f"; done

# Dry run — check tool availability
./setup.sh  # prints install status

# Run single module (skip the rest)
./recon_master.sh -t target.com -i hosts.txt -s "02,03,04,05,06,07,08,09,10,11,12"
```

## Output

Results are written to `output/<target>/` with per-module directories (`01_asn/`, `02_certs/`, etc.). Module 12 generates:

- `12_report/report.html` — full interactive HTML report
- `12_report/report.json` — machine-readable summary
- `12_report/summary.txt` — plaintext executive summary

## Module Reference

| # | Module | Active? | Description |
|---|--------|---------|-------------|
| 01 | ASN Enum | Passive | IP→ASN mapping, CIDR expansion, WHOIS cross-ref |
| 02 | Cert Transparency | Passive | crt.sh, Censys, live cert SANs, internal naming |
| 03 | Passive DNS | Passive | SecurityTrails, DNSdumpster, VT, TXT/MX analysis |
| 04 | Subdomain Enum | Passive | subfinder, amass, RapidDNS, OTX, Shodan, 8+ sources |
| 05 | URL Corpus | Passive | Wayback, CommonCrawl, gau, URLScan |
| 06 | Live Hosts | Semi* | httpx probe (single GET per host), nmap -sV, Shodan |
| 07 | JS Analysis | Semi* | Download+grep JS files for secrets/endpoints |
| 08 | Cloud Enum | Semi* | HEAD requests to S3/Azure/GCP bucket permutations |
| 09 | Tech Fingerprint | Semi* | WhatWeb, nuclei tech templates, CVE mapping |
| 10 | Screenshots | Semi* | EyeWitness / gowitness |
| 11 | Dorking | Passive | GitHub/GitLab API search, Google dork URL gen |
| 12 | Report | Local | HTML/JSON/TXT aggregation |

*Semi-passive: makes HTTP requests to target infrastructure (one probe per host).

## Breaking Changes / Migration from v1

- Module scripts moved from root to `modules/` directory
- `api_keys.conf` moved from root to `config/api_keys.conf`
- Added `lib/common.sh` shared library (auto-sourced by all modules)
- Input validation added — `TARGET` must be a valid domain
- All file writes use flock-based locking for parallel safety
