#!/usr/bin/env bash
# =============================================================================
# MODULE 06 — Live Host Fingerprinting
# Touches targets once per host with a single HTTP request (httpx)
# Input:  $TARGET_DIR/live_subdomains.txt, $INPUT_FILE
# Output: $DIR_HOSTS/
#   httpx_full.json        — full structured fingerprint per host
#   live_https.txt         — HTTPS responding hosts
#   live_http.txt          — HTTP responding hosts
#   server_headers.txt     — server header values
#   cms_detected.txt       — CMS identifications
#   interesting_hosts.txt  — hosts with login/admin/api in title or path
#   shodan_host_data.json  — Shodan enrichment per host
# =============================================================================

set -euo pipefail
source "${LIB_DIR}/common.sh"
OUT="${DIR_HOSTS}"


# Build host list (subdomains + original input, both ports)
HOST_LIST="${OUT}/host_scan_list.txt"
touch "$HOST_LIST"

# From live subdomains (Module 04)
[[ -f "${TARGET_DIR}/live_subdomains.txt" ]] && \
  cat "${TARGET_DIR}/live_subdomains.txt" >> "$HOST_LIST"

# From input file
cat "$INPUT_FILE" >> "$HOST_LIST"
sort -u "$HOST_LIST" -o "$HOST_LIST"

log "Scanning $(wc -l < "$HOST_LIST") hosts"

# ── Step 1: httpx full fingerprint ────────────────────────────────────────────
if command -v httpx &>/dev/null; then
  info "Running httpx fingerprint (single probe per host)..."

  httpx \
    -l "$HOST_LIST" \
    -ports 80,443,8080,8443,8000,8001,8008,8888,9090,9443,3000,4000,4443,5000,7443 \
    -threads "$THREADS" \
    -follow-redirects \
    -max-redirects 3 \
    -title \
    -tech-detect \
    -server \
    -status-code \
    -content-length \
    -content-type \
    -web-server \
    -ip \
    -cname \
    -cdn \
    -tls-grab \
    -favicon \
    -hash sha256 \
    -screenshot \
    -screenshot-timeout 15 \
    -json \
    -o "${OUT}/httpx_full.json" \
    2>/dev/null || warn "httpx completed with some errors"

  log "httpx complete: $(wc -l < "${OUT}/httpx_full.json" 2>/dev/null || echo 0) live hosts"

  # ── Parse httpx JSON into useful views ────────────────────────────────────
  info "Parsing httpx results..."

  # HTTPS hosts
  jq -r 'select(.scheme=="https") | .url' \
    "${OUT}/httpx_full.json" 2>/dev/null | \
    sort -u > "${OUT}/live_https.txt" || true

  # HTTP hosts  
  jq -r 'select(.scheme=="http") | .url' \
    "${OUT}/httpx_full.json" 2>/dev/null | \
    sort -u > "${OUT}/live_http.txt" || true

  # Server headers
  jq -r 'select(.webserver != null) | "\(.url) | \(.webserver)"' \
    "${OUT}/httpx_full.json" 2>/dev/null | \
    sort -u > "${OUT}/server_headers.txt" || true

  # All detected technologies
  jq -r 'select(.technologies != null) | "\(.url) | \(.technologies | join(", "))"' \
    "${OUT}/httpx_full.json" 2>/dev/null | \
    sort > "${OUT}/technologies_detected.txt" || true

  # CMS detection
  jq -r 'select(.technologies != null) | .technologies[]? | select(test("WordPress|Drupal|Joomla|Magento|Shopify|Ghost|Squarespace|Wix|TYPO3|DotNetNuke|Sitecore|Adobe Experience|HubSpot CMS|Kentico"; "i"))' \
    "${OUT}/httpx_full.json" 2>/dev/null | \
    sort -u > "${OUT}/cms_detected_tech.txt" || true

  jq -r 'select(.technologies != null) | "\(.url) → \(.technologies | map(select(test("WordPress|Drupal|Joomla|Magento|Shopify|Ghost|TYPO3|Sitecore|HubSpot CMS|Kentico"; "i"))) | join(", "))" | select(. | test("→ .+"))' \
    "${OUT}/httpx_full.json" 2>/dev/null | \
    sort > "${OUT}/cms_detected.txt" || true

  # Hosts with interesting titles
  jq -r 'select(.title != null) | select(.title | test("login|admin|dashboard|portal|upload|sign in|signin|authentication|manage|control panel|cms|cpanel|phpmyadmin|webmin|configuration"; "i")) | "\(.url) | \(.title)"' \
    "${OUT}/httpx_full.json" 2>/dev/null | \
    sort > "${OUT}/interesting_titles.txt" || true

  # TLS certificate info
  jq -r 'select(.tls != null) | "\(.url) | Subject: \(.tls.subject_cn // "?") | Issuer: \(.tls.issuer_org // "?") | Expires: \(.tls.not_after // "?")"' \
    "${OUT}/httpx_full.json" 2>/dev/null | \
    sort > "${OUT}/tls_details.txt" || true

  # Hosts with non-standard ports (more likely shadow IT)
  jq -r 'select(.port != null) | select(.port | IN(80,443) | not) | "\(.url) | Port: \(.port) | \(.webserver // "?")"' \
    "${OUT}/httpx_full.json" 2>/dev/null | \
    sort > "${OUT}/nonstandard_ports.txt" || true

  # CDN-behind hosts (useful — real IPs may still be accessible directly)
  jq -r 'select(.cdn != null and .cdn != "") | "\(.url) | CDN: \(.cdn) | IP: \(.host // "?")"' \
    "${OUT}/httpx_full.json" 2>/dev/null | \
    sort > "${OUT}/cdn_hosts.txt" || true

  # Hosts NOT behind CDN — direct IP exposure
  jq -r 'select(.cdn == null or .cdn == "") | "\(.url) | IP: \(.host // "?")"' \
    "${OUT}/httpx_full.json" 2>/dev/null | \
    sort > "${OUT}/direct_ip_hosts.txt" || true

  # Redirect chains (may reveal internal hostnames)
  jq -r 'select(.final_url != null and .final_url != .url) | "\(.url) → \(.final_url)"' \
    "${OUT}/httpx_full.json" 2>/dev/null | \
    sort > "${OUT}/redirect_chains.txt" || true

  # Status code breakdown
  for code in 200 301 302 401 403 404 500 503; do
    count=$(jq -r "select(.status_code==$code) | .url" \
      "${OUT}/httpx_full.json" 2>/dev/null | wc -l || echo 0)
    echo "HTTP $code: $count" >> "${OUT}/status_code_summary.txt"
  done

  # 401/403 — locked but confirmed exists (high value targets)
  jq -r 'select(.status_code == 401 or .status_code == 403) | "\(.status_code) | \(.url) | \(.title // "no title")"' \
    "${OUT}/httpx_full.json" 2>/dev/null | \
    sort > "${OUT}/access_controlled.txt" || true

  log "httpx parsing complete"

else
  warn "httpx not installed — go install github.com/projectdiscovery/httpx/cmd/httpx@latest"

  # Fallback: curl-based basic check
  info "Falling back to curl-based probing..."
  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    for scheme in https http; do
      resp=$(curl -s --max-time 10 -I \
        -L --max-redirs 3 \
        -o /dev/null \
        -w "%{http_code}|%{url_effective}|%{content_type}" \
        "${scheme}://${host}" 2>/dev/null || true)
      if [[ "$resp" != "000|"* ]]; then
        server=$(curl -s --max-time 8 -I \
          "${scheme}://${host}" 2>/dev/null | \
          grep -i "^server:" | head -1 || true)
        echo "${scheme}://${host} | $resp | $server" >> "${OUT}/curl_probe.txt"
      fi
    done
  done < "$HOST_LIST"
fi

# ── Step 2: nmap version scan on live web hosts ───────────────────────────────
if command -v nmap &>/dev/null; then
  info "Running nmap service/version detection on web ports..."

  # Build IP list from httpx results or input
  jq -r '.host // empty' "${OUT}/httpx_full.json" 2>/dev/null | \
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
    sort -u > "${OUT}/live_ips_for_nmap.txt" || true

  if [[ -s "${OUT}/live_ips_for_nmap.txt" ]]; then
    nmap \
      -sV \
      --version-intensity 5 \
      -O \
      --osscan-guess \
      -p 80,443,8080,8443,8000,8888,9090,3000,4000,5000 \
      -iL "${OUT}/live_ips_for_nmap.txt" \
      --script "http-headers,http-server-header,http-title,http-generator,ssl-cert,banner" \
      -oX "${OUT}/nmap_web_scan.xml" \
      -oN "${OUT}/nmap_web_scan.txt" \
      --open \
      -T3 \
      2>/dev/null || warn "nmap completed with errors"

    log "nmap complete — see ${OUT}/nmap_web_scan.txt"
  else
    warn "No IPs extracted for nmap — skipping"
  fi
else
  warn "nmap not installed — skipping OS/version detection"
fi

# ── Step 3: Shodan enrichment per discovered host ─────────────────────────────
if [[ -n "${SHODAN_API_KEY:-}" ]]; then
  info "Enriching hosts via Shodan API..."
  echo "[]" > "${OUT}/shodan_host_data.json"

  jq -r '.host // empty' "${OUT}/httpx_full.json" 2>/dev/null | \
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
    sort -u | while IFS= read -r ip; do
      [[ -z "$ip" ]] && continue
      shodan_data=$(curl -s --max-time 15 \
        "https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}" \
        2>/dev/null || echo '{}')

      if echo "$shodan_data" | jq -e '.ip_str' &>/dev/null; then
        # Extract useful fields
        echo "$shodan_data" | jq '{
          ip: .ip_str,
          org: .org,
          isp: .isp,
          os: .os,
          ports: .ports,
          vulns: (.vulns // {} | keys),
          hostnames: .hostnames,
          tags: .tags,
          data: [.data[]? | {
            port: .port,
            transport: .transport,
            product: .product,
            version: .version,
            cpe: .cpe,
            banner: .data[0:200]
          }]
        }' >> "${OUT}/shodan_host_data.json" 2>/dev/null || true

        # Extract CVEs from Shodan
        echo "$shodan_data" | jq -r \
          '(.vulns // {} | keys[]) | "\($ip) | \(.)"' 2>/dev/null \
          >> "${OUT}/shodan_cves.txt" 2>/dev/null || true
      fi
      sleep 1
    done

  log "Shodan enrichment complete"
else
  warn "SHODAN_API_KEY not set — skipping Shodan host enrichment"
fi

# ── Step 4: Interesting host consolidation ────────────────────────────────────
info "Consolidating interesting hosts..."
cat \
  "${OUT}/interesting_titles.txt" \
  "${OUT}/nonstandard_ports.txt" \
  "${OUT}/access_controlled.txt" \
  "${OUT}/cms_detected.txt" \
  2>/dev/null | \
  sort -u > "${OUT}/interesting_hosts.txt"

# Export live URLs for downstream modules
cat "${OUT}/live_https.txt" "${OUT}/live_http.txt" 2>/dev/null | \
  sort -u > "${TARGET_DIR}/all_live_urls.txt"

echo ""
echo "── Module 06 Summary ──────────────────────────────────────"
echo "  Live HTTPS hosts:       $(wc -l < "${OUT}/live_https.txt" 2>/dev/null || echo 0)"
echo "  Live HTTP hosts:        $(wc -l < "${OUT}/live_http.txt" 2>/dev/null || echo 0)"
echo "  CMS detected:           $(wc -l < "${OUT}/cms_detected.txt" 2>/dev/null || echo 0)"
echo "  Interesting titles:     $(wc -l < "${OUT}/interesting_titles.txt" 2>/dev/null || echo 0)"
echo "  Access controlled:      $(wc -l < "${OUT}/access_controlled.txt" 2>/dev/null || echo 0)"
echo "  Non-standard ports:     $(wc -l < "${OUT}/nonstandard_ports.txt" 2>/dev/null || echo 0)"
echo "  Shodan CVEs found:      $(wc -l < "${OUT}/shodan_cves.txt" 2>/dev/null || echo 0)"
cat "${OUT}/status_code_summary.txt" 2>/dev/null | sed 's/^/  /'
echo "────────────────────────────────────────────────────────────"
