#!/usr/bin/env bash
# =============================================================================
# MODULE 09 — Tech Stack & Version Fingerprinting
# Input:  $TARGET_DIR/all_live_urls.txt
# Output: $DIR_TECH/
#   whatweb_results.json    — full whatweb output
#   wappalyzer_results.json — wappalyzer CLI output
#   nuclei_tech.json        — nuclei tech detect templates
#   version_matrix.csv      — per-host: server, cms, framework, version
#   cve_candidates.txt      — versions mapped to known CVEs
# =============================================================================

set -euo pipefail
source "${LIB_DIR}/common.sh"
OUT="${DIR_TECH}"


LIVE_URLS="${TARGET_DIR}/all_live_urls.txt"
[[ ! -f "$LIVE_URLS" ]] && warn "No live URLs file found" && exit 0

# ── WhatWeb ───────────────────────────────────────────────────────────────────
if command -v whatweb &>/dev/null; then
  info "Running WhatWeb fingerprinting..."
  whatweb \
    --aggression 3 \
    --input-file="$LIVE_URLS" \
    --log-json="${OUT}/whatweb_results.json" \
    --log-verbose="${OUT}/whatweb_verbose.txt" \
    --color=never \
    --no-errors \
    2>/dev/null || true
  log "WhatWeb complete: $(wc -l < "${OUT}/whatweb_results.json" 2>/dev/null || echo 0) hosts"
else
  warn "whatweb not installed — sudo gem install whatweb OR apt install whatweb"
fi

# ── Wappalyzer CLI ────────────────────────────────────────────────────────────
if command -v wappalyzer &>/dev/null; then
  info "Running Wappalyzer..."
  touch "${OUT}/wappalyzer_results.json"
  echo "[" > "${OUT}/wappalyzer_results.json"
  first=true

  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    result=$(wappalyzer "$url" 2>/dev/null | jq -c '. + {"url": "'"$url"'"}' || echo '{}')
    [[ "$first" == "true" ]] && first=false || echo "," >> "${OUT}/wappalyzer_results.json"
    echo "$result" >> "${OUT}/wappalyzer_results.json"
  done < "$LIVE_URLS"
  echo "]" >> "${OUT}/wappalyzer_results.json"
  log "Wappalyzer complete"
else
  warn "wappalyzer not installed — npm install -g wappalyzer"
fi

# ── Nuclei technology detection ───────────────────────────────────────────────
if command -v nuclei &>/dev/null; then
  info "Running nuclei tech detection templates..."
  nuclei \
    -l "$LIVE_URLS" \
    -t technologies/ \
    -t exposures/ \
    -t misconfiguration/http-missing-security-headers.yaml \
    -t misconfiguration/cors-misconfiguration.yaml \
    -t misconfiguration/x-frame-options.yaml \
    -t misconfiguration/clickjacking.yaml \
    -t misconfiguration/csp-injection.yaml \
    -t misconfiguration/content-security-policy.yaml \
    -t exposed-panels/ \
    -t default-logins/ \
    -t takeovers/ \
    -threads "$THREADS" \
    -silent \
    -json \
    -o "${OUT}/nuclei_tech.json" \
    2>/dev/null || true
  log "Nuclei complete: $(wc -l < "${OUT}/nuclei_tech.json" 2>/dev/null || echo 0) findings"
else
  warn "nuclei not installed — go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
fi

# ── Header-based fingerprinting (curl fallback / supplement) ──────────────────
info "Extracting security headers and server signatures..."
echo "host,server,x-powered-by,x-generator,x-aspnet,via,set-cookie-flags,content-security-policy,x-frame-options,hsts" \
  > "${OUT}/version_matrix.csv"

while IFS= read -r url; do
  [[ -z "$url" ]] && continue

  headers=$(curl -s --max-time 12 -I -L --max-redirs 3 \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    "$url" 2>/dev/null || true)

  server=$(echo "$headers"       | grep -i "^server:"           | head -1 | cut -d: -f2- | xargs)
  powered=$(echo "$headers"      | grep -i "^x-powered-by:"     | head -1 | cut -d: -f2- | xargs)
  generator=$(echo "$headers"    | grep -i "^x-generator:"      | head -1 | cut -d: -f2- | xargs)
  aspnet=$(echo "$headers"       | grep -i "^x-aspnet"          | head -1 | cut -d: -f2- | xargs)
  via=$(echo "$headers"          | grep -i "^via:"              | head -1 | cut -d: -f2- | xargs)
  csp=$(echo "$headers"          | grep -i "^content-security"  | head -1 | cut -d: -f2- | xargs)
  xframe=$(echo "$headers"       | grep -i "^x-frame-options"   | head -1 | cut -d: -f2- | xargs)
  hsts=$(echo "$headers"         | grep -i "^strict-transport"  | head -1 | cut -d: -f2- | xargs)

  echo "\"$url\",\"$server\",\"$powered\",\"$generator\",\"$aspnet\",\"$via\",,\"$csp\",\"$xframe\",\"$hsts\"" \
    >> "${OUT}/version_matrix.csv"

  sleep 0.2
done < "$LIVE_URLS"

# ── Extract version numbers and map to CVEs via searchsploit ──────────────────
info "Mapping detected versions to CVE candidates..."

if command -v searchsploit &>/dev/null; then
  # Extract versions from WhatWeb results
  if [[ -f "${OUT}/whatweb_results.json" ]]; then
    # Parse product:version pairs
    grep -oP '"[A-Za-z][A-Za-z0-9_-]+":\{"detected_versions":\["[^"]+"\]' \
      "${OUT}/whatweb_results.json" 2>/dev/null | \
      grep -oP '"[A-Za-z][^"]+"\]:.*?"([0-9][^"]+)"' | \
      sed 's/[":{}]//g' | \
      sort -u | while IFS= read -r product_ver; do
        product=$(echo "$product_ver" | awk '{print $1}')
        version=$(echo "$product_ver" | awk '{print $2}')
        if [[ -n "$product" && -n "$version" ]]; then
          results=$(searchsploit "$product" "$version" --json 2>/dev/null | \
            jq -r '.RESULTS_EXPLOIT[]? | "\(.Title) | EDB-\(.EDB_ID)"' 2>/dev/null || true)
          if [[ -n "$results" ]]; then
            echo "=== $product $version ===" >> "${OUT}/cve_candidates.txt"
            echo "$results" >> "${OUT}/cve_candidates.txt"
            echo "" >> "${OUT}/cve_candidates.txt"
          fi
        fi
      done
  fi

  # Also check server versions from CSV
  awk -F'"' 'NR>1 && $4!="" {print $2, $4}' "${OUT}/version_matrix.csv" 2>/dev/null | \
    while read -r url server; do
      [[ -z "$server" ]] && continue
      results=$(searchsploit "$server" --json 2>/dev/null | \
        jq -r '.RESULTS_EXPLOIT[]? | "\(.Title) | EDB-\(.EDB_ID)"' 2>/dev/null || true)
      if [[ -n "$results" ]]; then
        echo "=== $url — Server: $server ===" >> "${OUT}/cve_candidates.txt"
        echo "$results" >> "${OUT}/cve_candidates.txt"
        echo "" >> "${OUT}/cve_candidates.txt"
      fi
    done

  log "CVE candidate mapping complete"
else
  warn "searchsploit not installed — sudo apt install exploitdb"
fi

# ── Takeover check ────────────────────────────────────────────────────────────
if command -v subjack &>/dev/null; then
  info "Checking for subdomain takeover opportunities..."
  [[ -f "${TARGET_DIR}/live_subdomains.txt" ]] && \
    subjack \
      -w "${TARGET_DIR}/live_subdomains.txt" \
      -t "$THREADS" \
      -o "${OUT}/takeover_candidates.txt" \
      -ssl \
      2>/dev/null || true
  log "Takeover check complete"
elif command -v subzy &>/dev/null; then
  [[ -f "${TARGET_DIR}/live_subdomains.txt" ]] && \
    subzy run \
      --targets "${TARGET_DIR}/live_subdomains.txt" \
      --output "${OUT}/takeover_candidates.txt" \
      2>/dev/null || true
else
  warn "subjack/subzy not installed for takeover detection"
fi

echo ""
echo "── Module 09 Summary ──────────────────────────────────────"
echo "  Hosts fingerprinted:       $(wc -l < "$LIVE_URLS")"
echo "  CVE candidates:            $(grep -c '^===' "${OUT}/cve_candidates.txt" 2>/dev/null || echo 0)"
echo "  Nuclei findings:           $(wc -l < "${OUT}/nuclei_tech.json" 2>/dev/null || echo 0)"
echo "  Takeover candidates:       $(wc -l < "${OUT}/takeover_candidates.txt" 2>/dev/null || echo 0)"
echo "────────────────────────────────────────────────────────────"
