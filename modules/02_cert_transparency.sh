#!/usr/bin/env bash
# =============================================================================
# MODULE 02 — Certificate Transparency
# Input:  $TARGET, $INPUT_FILE
# Output: $DIR_CERTS/
#   domains_from_certs.txt   — all unique domains/subdomains found in CT logs
#   cert_details.json        — structured cert data
#   internal_naming.txt      — SANs matching internal patterns
#   wildcard_certs.txt       — wildcard certs (*.target.com)
# =============================================================================

set -euo pipefail
source "${LIB_DIR}/common.sh"
OUT="${DIR_CERTS}"


touch "${OUT}/domains_from_certs.txt"
touch "${OUT}/wildcard_certs.txt"
touch "${OUT}/internal_naming.txt"

# ── Step 1: crt.sh wildcard query ─────────────────────────────────────────────
info "Querying crt.sh for %.${TARGET}..."

crtsh_query() {
  local query="$1"
  curl -s --max-time 30 \
    "https://crt.sh/?q=${query}&output=json" \
    -H "Accept: application/json" \
    -H "User-Agent: Mozilla/5.0" 2>/dev/null || echo "[]"
}

# Wildcard subdomain search
raw=$(crtsh_query "%.${TARGET}")

if echo "$raw" | jq -e '.[0]' &>/dev/null; then
  echo "$raw" | jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\*\.//g' | \
    tr '[:upper:]' '[:lower:]' | \
    grep -E "^[a-z0-9]" | \
    sort -u >> "${OUT}/domains_from_certs.txt"

  # Wildcards specifically
  echo "$raw" | jq -r '.[].name_value' 2>/dev/null | \
    grep '^\*\.' >> "${OUT}/wildcard_certs.txt" || true

  # Save raw cert details
  echo "$raw" | jq '[.[] | {
    id: .id,
    logged_at: .logged_at,
    not_before: .not_before,
    not_after: .not_after,
    common_name: .common_name,
    name_value: .name_value,
    issuer_name: .issuer_name
  }]' > "${OUT}/cert_details.json" 2>/dev/null || echo "[]" > "${OUT}/cert_details.json"

  log "crt.sh returned $(echo "$raw" | jq 'length' 2>/dev/null || echo 0) cert records"
else
  warn "crt.sh returned no results or timed out"
fi

sleep 2

# ── Step 2: crt.sh org name search ────────────────────────────────────────────
# Extracts certs issued to org across ALL domains they own (not just target.com)
info "Querying crt.sh by organization name..."

# Derive org name from domain (strip TLD, capitalize) — user can override
ORG_NAME=$(echo "$TARGET" | sed 's/\..*//' | sed 's/-/ /g')
info "  Org name guess: '$ORG_NAME' (edit module to override)"

org_raw=$(curl -s --max-time 30 \
  "https://crt.sh/?O=${ORG_NAME// /+}&output=json" \
  -H "Accept: application/json" 2>/dev/null || echo "[]")

if echo "$org_raw" | jq -e '.[0]' &>/dev/null; then
  echo "$org_raw" | jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\*\.//g' | tr '[:upper:]' '[:lower:]' | \
    sort -u >> "${OUT}/domains_from_certs_org.txt"
  log "Org search found $(wc -l < "${OUT}/domains_from_certs_org.txt") additional domains"
fi

sleep 2

# ── Step 3: Censys cert search ────────────────────────────────────────────────
if [[ -n "${CENSYS_API_ID:-}" && -n "${CENSYS_API_SECRET:-}" ]]; then
  info "Querying Censys certificate search..."

  censys_query() {
    local query="$1"
    curl -s --max-time 30 \
      "https://search.censys.io/api/v1/search/certificates" \
      -u "${CENSYS_API_ID}:${CENSYS_API_SECRET}" \
      -H "Content-Type: application/json" \
      -d "{
        \"query\": \"${query}\",
        \"page\": 1,
        \"fields\": [\"parsed.names\", \"parsed.subject.common_name\", \"parsed.subject.organization\"],
        \"flatten\": true
      }" 2>/dev/null || echo '{}'
  }

  # Search by domain
  censys_data=$(censys_query "parsed.names: ${TARGET}")
  echo "$censys_data" | jq -r \
    '.results[]."parsed.names"[]? // empty' 2>/dev/null | \
    grep -iE "\.${TARGET}$" | \
    sort -u >> "${OUT}/domains_from_certs.txt" || true

  # Search by org
  censys_org=$(censys_query "parsed.subject.organization: \"${ORG_NAME}\"")
  echo "$censys_org" | jq -r \
    '.results[]."parsed.names"[]? // empty' 2>/dev/null | \
    sort -u >> "${OUT}/censys_org_domains.txt" || true

  log "Censys queries complete"
else
  warn "CENSYS_API_ID/SECRET not set — skipping Censys"
fi

# ── Step 4: SAN internal naming pattern detection ─────────────────────────────
info "Detecting internal naming patterns in SANs..."

# Patterns that suggest internal/non-public infrastructure
INTERNAL_PATTERNS=(
  "dev\." "staging\." "stage\." "uat\." "test\." "qa\."
  "internal\." "corp\." "intranet\." "vpn\." "admin\."
  "mgmt\." "management\." "monitor\." "api-" "api\."
  "jenkins\." "jira\." "confluence\." "gitlab\." "git\."
  "k8s\." "kube\." "rancher\." "harbor\." "nexus\."
  "backup\." "bak\." "-old\." "-new\." "legacy\."
  "mail\." "smtp\." "mx\." "ftp\." "sftp\."
  "db\." "database\." "mysql\." "postgres\." "mongo\."
  "redis\." "elastic\." "kibana\." "grafana\." "prometheus\."
  "ldap\." "ad\." "dc\."
)

pattern_regex=$(printf "|%s" "${INTERNAL_PATTERNS[@]}")
pattern_regex="${pattern_regex:1}"  # remove leading |

grep -iE "($pattern_regex)" "${OUT}/domains_from_certs.txt" \
  > "${OUT}/internal_naming.txt" 2>/dev/null || true

log "Found $(wc -l < "${OUT}/internal_naming.txt") potentially internal hostnames from cert SANs"

# ── Step 5: Fetch cert details via openssl for input hosts ────────────────────
info "Pulling live cert details from input hostnames..."
echo "" > "${OUT}/live_cert_details.txt"

while IFS= read -r host; do
  [[ -z "$host" || "$host" =~ ^[0-9] ]] && continue

  cert_info=$(echo | timeout 8 openssl s_client -connect "${host}:443" \
    -servername "$host" 2>/dev/null | \
    openssl x509 -noout -text 2>/dev/null || true)

  if [[ -n "$cert_info" ]]; then
    echo "=== $host ===" >> "${OUT}/live_cert_details.txt"
    echo "$cert_info" | grep -E "Subject:|Issuer:|Not Before|Not After|DNS:" \
      >> "${OUT}/live_cert_details.txt"
    echo "" >> "${OUT}/live_cert_details.txt"

    # Extract additional SANs from live cert
    echo "$cert_info" | grep -oP '(?<=DNS:)[^,\s]+' | \
      sed 's/\*\.//g' >> "${OUT}/domains_from_certs.txt" || true
  fi
done < "$INPUT_FILE"

# ── Step 6: VirusTotal passive DNS from cert domains ──────────────────────────
if [[ -n "${VIRUSTOTAL_API_KEY:-}" ]]; then
  info "Querying VirusTotal for subdomains..."
  vt_data=$(curl -s --max-time 20 \
    "https://www.virustotal.com/api/v3/domains/${TARGET}/subdomains?limit=40" \
    -H "x-apikey: ${VIRUSTOTAL_API_KEY}" 2>/dev/null || echo '{}')

  echo "$vt_data" | jq -r '.data[].id // empty' 2>/dev/null \
    >> "${OUT}/domains_from_certs.txt" || true
  log "VirusTotal subdomains added"
fi

# ── Final dedup ───────────────────────────────────────────────────────────────
sort -u "${OUT}/domains_from_certs.txt" -o "${OUT}/domains_from_certs.txt"

# Also merge org certs if they exist
[[ -f "${OUT}/domains_from_certs_org.txt" ]] && \
  cat "${OUT}/domains_from_certs_org.txt" >> "${OUT}/domains_from_certs.txt" && \
  sort -u "${OUT}/domains_from_certs.txt" -o "${OUT}/domains_from_certs.txt"

# Export for downstream modules
cp "${OUT}/domains_from_certs.txt" "${TARGET_DIR}/all_discovered_domains.txt"

echo ""
echo "── Module 02 Summary ──────────────────────────────────────"
echo "  Total unique domains from CT:   $(wc -l < "${OUT}/domains_from_certs.txt")"
echo "  Internal-pattern hostnames:     $(wc -l < "${OUT}/internal_naming.txt")"
echo "  Wildcard certs:                 $(wc -l < "${OUT}/wildcard_certs.txt")"
echo "────────────────────────────────────────────────────────────"
