#!/usr/bin/env bash
# =============================================================================
# PASSIVE RECON MASTER — orchestrates all modules in sequence
# Usage: ./recon_master.sh -t target.com -i input_hosts.txt [-o output_dir] [-k api_keys.conf]
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="${SCRIPT_DIR}/modules"
LIB_DIR="${SCRIPT_DIR}/lib"

# Source shared library
# shellcheck source=lib/common.sh
source "${LIB_DIR}/common.sh"

# ── Defaults ─────────────────────────────────────────────────────────────────
TARGET=""
INPUT_FILE=""
OUTPUT_DIR="${SCRIPT_DIR}/output"
API_KEYS_FILE="${SCRIPT_DIR}/config/api_keys.conf"
THREADS=10
SKIP_MODULES=""
CURL_TIMEOUT=20

usage() {
  cat <<EOF
Usage: $0 -t <target_domain> -i <input_file> [options]

Options:
  -t  Target domain (e.g., target.com)
  -i  Input file with hostnames/IPs (one per line)
  -o  Output directory (default: ./output)
  -k  API keys config file (default: ./config/api_keys.conf)
  -T  Threads (default: 10)
  -s  Skip modules (comma-separated, e.g., "08,10")
  -h  Help

Modules:
  01  ASN & IP ownership mapping
  02  Certificate transparency
  03  Passive DNS & historical records
  04  Subdomain enumeration (passive)
  05  URL corpus (Wayback, CommonCrawl, gau)
  06  Live host fingerprinting (httpx)
  07  JavaScript analysis (LinkFinder, SecretFinder)
  08  Cloud storage enumeration (S3, Azure, GCP)
  09  Tech stack & version fingerprinting
  10  Screenshots (EyeWitness)
  11  GitHub/GitLab/Code dorking
  12  Report consolidation
EOF
  exit 0
}

banner() {
  echo -e "\033[1m\033[0;36m"
  echo "══════════════════════════════════════════════════════"
  echo "  PASSIVE RECON SUITE — APT-Level OSINT Collection"
  echo "══════════════════════════════════════════════════════"
  echo -e "\033[0m"
}

# ── Argument parsing ──────────────────────────────────────────────────────────
while getopts "t:i:o:k:T:s:h" opt; do
  case $opt in
    t) TARGET="$OPTARG" ;;
    i) INPUT_FILE="$OPTARG" ;;
    o) OUTPUT_DIR="$OPTARG" ;;
    k) API_KEYS_FILE="$OPTARG" ;;
    T) THREADS="$OPTARG" ;;
    s) SKIP_MODULES="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

# ── Validate inputs ──────────────────────────────────────────────────────────
[[ -z "$TARGET" ]]     && err "Target domain required (-t)" && usage
[[ -z "$INPUT_FILE" ]] && err "Input file required (-i)"    && usage
[[ ! -f "$INPUT_FILE" ]] && err "Input file not found: $INPUT_FILE" && exit 1

# Critical: validate TARGET to prevent command injection
validate_domain "$TARGET" || exit 1

# Validate THREADS is numeric
if [[ ! "$THREADS" =~ ^[0-9]+$ ]] || [[ "$THREADS" -lt 1 ]] || [[ "$THREADS" -gt 100 ]]; then
  err "Threads must be a number between 1-100"
  exit 1
fi

# ── Load API keys safely ─────────────────────────────────────────────────────
# Instead of blindly sourcing (which executes arbitrary code), parse key=value only
load_api_keys() {
  local keyfile="$1"
  [[ ! -f "$keyfile" ]] && return 1

  while IFS='=' read -r key value; do
    # Skip comments and empty lines
    [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
    # Strip leading/trailing whitespace
    key=$(echo "$key" | xargs)
    value=$(echo "$value" | xargs | sed 's/^"//; s/"$//')
    # Only allow known key names (whitelist)
    case "$key" in
      SHODAN_API_KEY|SECURITYTRAILS_API_KEY|GITHUB_TOKEN|\
      CENSYS_API_ID|CENSYS_API_SECRET|VIRUSTOTAL_API_KEY|\
      HUNTER_API_KEY|WHOISXML_API_KEY|IPINFO_TOKEN)
        # Validate value contains only safe characters
        if [[ "$value" =~ ^[a-zA-Z0-9_.:/-]*$ ]]; then
          export "$key=$value"
        else
          warn "Skipping $key — value contains invalid characters"
        fi
        ;;
    esac
  done < "$keyfile"
  return 0
}

if [[ -f "$API_KEYS_FILE" ]]; then
  load_api_keys "$API_KEYS_FILE"
  log "API keys loaded from $API_KEYS_FILE"
else
  warn "No API keys file found at $API_KEYS_FILE — modules will run in limited mode"
fi

# ── Output directory structure ────────────────────────────────────────────────
TARGET_DIR="${OUTPUT_DIR}/$(sanitize_filename "$TARGET")"

# Restrict output directory permissions
umask 0077

DIR_ASN="${TARGET_DIR}/01_asn"
DIR_CERTS="${TARGET_DIR}/02_certs"
DIR_DNS="${TARGET_DIR}/03_dns"
DIR_SUBDOMAINS="${TARGET_DIR}/04_subdomains"
DIR_URLS="${TARGET_DIR}/05_urls"
DIR_HOSTS="${TARGET_DIR}/06_hosts"
DIR_JS="${TARGET_DIR}/07_js"
DIR_CLOUD="${TARGET_DIR}/08_cloud"
DIR_TECH="${TARGET_DIR}/09_tech"
DIR_SCREENSHOTS="${TARGET_DIR}/10_screenshots"
DIR_DORKS="${TARGET_DIR}/11_dorks"
DIR_REPORT="${TARGET_DIR}/12_report"

for dir in "$DIR_ASN" "$DIR_CERTS" "$DIR_DNS" "$DIR_SUBDOMAINS" "$DIR_URLS" \
           "$DIR_HOSTS" "$DIR_JS" "$DIR_CLOUD" "$DIR_TECH" "$DIR_SCREENSHOTS" \
           "$DIR_DORKS" "$DIR_REPORT"; do
  mkdir -p "$dir"
done

# Export everything for child modules
export TARGET INPUT_FILE OUTPUT_DIR TARGET_DIR THREADS CURL_TIMEOUT
export SHODAN_API_KEY SECURITYTRAILS_API_KEY GITHUB_TOKEN
export CENSYS_API_ID CENSYS_API_SECRET VIRUSTOTAL_API_KEY
export HUNTER_API_KEY WHOISXML_API_KEY IPINFO_TOKEN
export DIR_ASN DIR_CERTS DIR_DNS DIR_SUBDOMAINS DIR_URLS DIR_HOSTS
export DIR_JS DIR_CLOUD DIR_TECH DIR_SCREENSHOTS DIR_DORKS DIR_REPORT
export LIB_DIR

# ── Run module helper ─────────────────────────────────────────────────────────
run_module() {
  local num="$1"
  local name="$2"
  local script="${MODULES_DIR}/${num}_${name}.sh"

  # Check if skipped
  if echo "$SKIP_MODULES" | grep -qw "$num"; then
    warn "Skipping module ${num}: ${name}"
    return 0
  fi

  if [[ ! -f "$script" ]]; then
    err "Module not found: $script"
    return 1
  fi

  echo ""
  echo -e "\033[1m\033[0;36m━━━ Module ${num}: ${name} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  local start_time
  start_time=$(date +%s)

  bash "$script" 2>&1 | tee "${TARGET_DIR}/module_${num}.log"
  local status=${PIPESTATUS[0]}

  local end_time
  end_time=$(date +%s)
  local elapsed=$((end_time - start_time))

  if [[ $status -eq 0 ]]; then
    log "Module ${num} completed in ${elapsed}s"
  else
    err "Module ${num} exited with status $status — check ${TARGET_DIR}/module_${num}.log"
  fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
banner
info "Target:      $TARGET"
info "Input file:  $INPUT_FILE"
info "Output:      $TARGET_DIR"
info "Threads:     $THREADS"
info "Start time:  $(date)"
echo ""

run_module "01" "asn_enum"
run_module "02" "cert_transparency"
run_module "03" "passive_dns"
run_module "04" "subdomain_passive"
run_module "05" "url_corpus"
run_module "06" "live_hosts"
run_module "07" "js_analysis"
run_module "08" "cloud_enum"
run_module "09" "tech_fingerprint"
run_module "10" "screenshots"
run_module "11" "dorks"
run_module "12" "report"

echo ""
log "All modules complete. Results: ${TARGET_DIR}"
log "Final report: ${TARGET_DIR}/12_report/report.html"
