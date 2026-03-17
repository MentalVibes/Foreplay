#!/usr/bin/env bash
# =============================================================================
# MODULE 04 — Subdomain Enumeration (Passive Only)
# Input:  $TARGET
# Output: $DIR_SUBDOMAINS/
#   all_subdomains.txt    — deduplicated master list
#   live_subdomains.txt   — subdomains that resolve
#   source_breakdown.txt  — which source found what
# =============================================================================

set -euo pipefail
source "${LIB_DIR}/common.sh"
OUT="${DIR_SUBDOMAINS}"


touch "${OUT}/all_subdomains.txt"

# ── Helper: add subdomains from source ────────────────────────────────────────
add_source() {
  local source="$1"
  local file="$2"
  local count=0

  if [[ -f "$file" ]]; then
    # Normalize: lowercase, strip wildcards, filter to target domain only
    grep -iE "\.${TARGET}$|^${TARGET}$" "$file" 2>/dev/null | \
      sed 's/\*\.//g' | \
      tr '[:upper:]' '[:lower:]' | \
      grep -E '^[a-z0-9]' >> "${OUT}/all_subdomains.txt" || true
    count=$(grep -iE "\.${TARGET}$|^${TARGET}$" "$file" 2>/dev/null | wc -l || echo 0)
    echo "${source}: ${count}" >> "${OUT}/source_breakdown.txt"
  fi
}

# ── Pull in Module 02 and 03 results ─────────────────────────────────────────
info "Importing domains from cert transparency (Module 02)..."
[[ -f "${DIR_CERTS}/domains_from_certs.txt" ]] && \
  add_source "cert_transparency" "${DIR_CERTS}/domains_from_certs.txt"

info "Importing subdomains from passive DNS (Module 03)..."
[[ -f "${DIR_DNS}/subdomains_passive.txt" ]] && \
  add_source "securitytrails" "${DIR_DNS}/subdomains_passive.txt"

# ── Tool: subfinder (passive, uses APIs internally) ───────────────────────────
if command -v subfinder &>/dev/null; then
  info "Running subfinder (passive)..."
  subfinder -d "$TARGET" \
    -all \
    -silent \
    -o "${OUT}/subfinder_out.txt" \
    2>/dev/null || true
  add_source "subfinder" "${OUT}/subfinder_out.txt"
  log "subfinder: $(wc -l < "${OUT}/subfinder_out.txt" 2>/dev/null || echo 0) results"
else
  warn "subfinder not installed — go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
fi

# ── Tool: amass passive ───────────────────────────────────────────────────────
if command -v amass &>/dev/null; then
  info "Running amass (passive mode only)..."
  amass enum \
    -passive \
    -d "$TARGET" \
    -timeout 10 \
    -o "${OUT}/amass_passive_out.txt" \
    2>/dev/null || true
  add_source "amass_passive" "${OUT}/amass_passive_out.txt"
  log "amass passive: $(wc -l < "${OUT}/amass_passive_out.txt" 2>/dev/null || echo 0) results"
else
  warn "amass not installed — go install -v github.com/owasp-amass/amass/v4/...@master"
fi

# ── Source: RapidDNS (free, no key) ──────────────────────────────────────────
info "Querying RapidDNS..."
rapid=$(curl -s --max-time 20 \
  "https://rapiddns.io/subdomain/${TARGET}?full=1&down=1" \
  -H "User-Agent: Mozilla/5.0" 2>/dev/null || true)

echo "$rapid" | grep -oP "[a-zA-Z0-9._-]+\.${TARGET}" | \
  tr '[:upper:]' '[:lower:]' | \
  sort -u > "${OUT}/rapiddns_out.txt" 2>/dev/null || true
add_source "rapiddns" "${OUT}/rapiddns_out.txt"

sleep 1

# ── Source: riddler.io (free) ─────────────────────────────────────────────────
info "Querying riddler.io..."
riddler=$(curl -s --max-time 20 \
  "https://riddler.io/search/exportcsv?q=pld:${TARGET}" \
  -H "User-Agent: Mozilla/5.0" 2>/dev/null || true)

echo "$riddler" | grep -oP "[a-zA-Z0-9._-]+\.${TARGET}" | \
  sort -u > "${OUT}/riddler_out.txt" 2>/dev/null || true
add_source "riddler" "${OUT}/riddler_out.txt"

sleep 1

# ── Source: urlscan.io (free) ─────────────────────────────────────────────────
info "Querying urlscan.io..."
urlscan=$(curl -s --max-time 20 \
  "https://urlscan.io/api/v1/search/?q=domain:${TARGET}&size=100" \
  -H "User-Agent: Mozilla/5.0" 2>/dev/null || echo '{}')

echo "$urlscan" | jq -r \
  '.results[]?.page.domain // empty' 2>/dev/null | \
  grep -iE "\.${TARGET}$|^${TARGET}$" | \
  sort -u > "${OUT}/urlscan_domains.txt" || true

echo "$urlscan" | jq -r \
  '.results[]?.page.url // empty' 2>/dev/null | \
  sort -u > "${OUT}/urlscan_urls.txt" || true

add_source "urlscan" "${OUT}/urlscan_domains.txt"

sleep 1

# ── Source: AlienVault OTX (free) ─────────────────────────────────────────────
info "Querying AlienVault OTX..."
otx=$(curl -s --max-time 20 \
  "https://otx.alienvault.com/api/v1/indicators/domain/${TARGET}/passive_dns" \
  -H "User-Agent: Mozilla/5.0" 2>/dev/null || echo '{}')

echo "$otx" | jq -r \
  '.passive_dns[]?.hostname // empty' 2>/dev/null | \
  grep -iE "\.${TARGET}$" | \
  sort -u > "${OUT}/otx_out.txt" || true
add_source "alienvault_otx" "${OUT}/otx_out.txt"

sleep 1

# ── Source: HackerTarget (free, limited) ──────────────────────────────────────
info "Querying HackerTarget..."
ht=$(curl -s --max-time 20 \
  "https://api.hackertarget.com/hostsearch/?q=${TARGET}" \
  -H "User-Agent: Mozilla/5.0" 2>/dev/null || true)

echo "$ht" | grep -oP "[a-zA-Z0-9._-]+\.${TARGET}" | \
  sort -u > "${OUT}/hackertarget_out.txt" || true
add_source "hackertarget" "${OUT}/hackertarget_out.txt"

sleep 1

# ── Source: ThreatCrowd (free) ────────────────────────────────────────────────
info "Querying ThreatCrowd..."
tc=$(curl -s --max-time 20 \
  "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=${TARGET}" \
  2>/dev/null || echo '{}')

echo "$tc" | jq -r '.subdomains[]? // empty' 2>/dev/null | \
  sort -u > "${OUT}/threatcrowd_out.txt" || true
add_source "threatcrowd" "${OUT}/threatcrowd_out.txt"

sleep 1

# ── Source: Shodan hostnames ──────────────────────────────────────────────────
if [[ -n "${SHODAN_API_KEY:-}" ]]; then
  info "Querying Shodan for subdomains..."
  shodan_dns=$(curl -s --max-time 20 \
    "https://api.shodan.io/dns/domain/${TARGET}?key=${SHODAN_API_KEY}" \
    2>/dev/null || echo '{}')

  echo "$shodan_dns" | jq -r \
    '.subdomains[]? // empty' 2>/dev/null | \
    awk -v d="$TARGET" '{print $0"."d}' | \
    sort -u > "${OUT}/shodan_subdomains.txt" || true
  add_source "shodan" "${OUT}/shodan_subdomains.txt"
  log "Shodan subdomains complete"
else
  warn "SHODAN_API_KEY not set — skipping Shodan subdomain enum"
fi

# ── Final deduplication ───────────────────────────────────────────────────────
info "Deduplicating and resolving live subdomains..."
sort -u "${OUT}/all_subdomains.txt" -o "${OUT}/all_subdomains.txt"

total=$(wc -l < "${OUT}/all_subdomains.txt")
log "Total unique subdomains before resolution: $total"

# ── DNS resolution check (passive — just checking if they resolve) ─────────────
touch "${OUT}/live_subdomains.txt"
touch "${OUT}/dead_subdomains.txt"

while IFS= read -r sub; do
  [[ -z "$sub" ]] && continue
  if dig +short A "$sub" 2>/dev/null | grep -qE '^[0-9]'; then
    echo "$sub" >> "${OUT}/live_subdomains.txt"
  else
    echo "$sub" >> "${OUT}/dead_subdomains.txt"
  fi
done < "${OUT}/all_subdomains.txt"

sort -u "${OUT}/live_subdomains.txt" -o "${OUT}/live_subdomains.txt"

# Feed into master list and next modules
cp "${OUT}/live_subdomains.txt" "${TARGET_DIR}/live_subdomains.txt"
cat "${OUT}/all_subdomains.txt" >> "${TARGET_DIR}/all_discovered_domains.txt"
sort -u "${TARGET_DIR}/all_discovered_domains.txt" \
     -o "${TARGET_DIR}/all_discovered_domains.txt"

echo ""
echo "── Module 04 Summary ──────────────────────────────────────"
echo "  Total unique subdomains:    $(wc -l < "${OUT}/all_subdomains.txt")"
echo "  Live (resolve):             $(wc -l < "${OUT}/live_subdomains.txt")"
echo "  Dead / no DNS:              $(wc -l < "${OUT}/dead_subdomains.txt")"
echo ""
cat "${OUT}/source_breakdown.txt" 2>/dev/null || true
echo "────────────────────────────────────────────────────────────"
