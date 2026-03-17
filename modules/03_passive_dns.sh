#!/usr/bin/env bash
# =============================================================================
# MODULE 03 — Passive DNS & Historical Records
# Input:  $TARGET, $INPUT_FILE, $DIR_CERTS/domains_from_certs.txt
# Output: $DIR_DNS/
#   passive_dns.json         — all passive DNS records
#   historical_ips.txt       — IPs that previously resolved to target domains
#   mx_records.txt           — mail infrastructure
#   txt_records.txt          — TXT records (SPF, DKIM, verification tokens)
#   dns_changes.txt          — historical DNS changes (SecurityTrails)
#   subdomains_passive.txt   — additional subdomains from DNS sources
# =============================================================================

set -euo pipefail
source "${LIB_DIR}/common.sh"
OUT="${DIR_DNS}"


touch "${OUT}/historical_ips.txt"
touch "${OUT}/subdomains_passive.txt"
touch "${OUT}/mx_records.txt"
touch "${OUT}/txt_records.txt"

# ── Step 1: SecurityTrails ────────────────────────────────────────────────────
if [[ -n "${SECURITYTRAILS_API_KEY:-}" ]]; then
  info "Querying SecurityTrails..."

  st_get() {
    curl -s --max-time 20 \
      "https://api.securitytrails.com/v1/${1}" \
      -H "apikey: ${SECURITYTRAILS_API_KEY}" \
      -H "Accept: application/json" 2>/dev/null || echo '{}'
  }

  # Current DNS records
  dns_current=$(st_get "domain/${TARGET}")
  echo "$dns_current" | jq '.' > "${OUT}/st_current_dns.json" 2>/dev/null || true

  # Extract A records
  echo "$dns_current" | jq -r \
    '.current_dns.a.values[]?.ip // empty' 2>/dev/null \
    >> "${OUT}/historical_ips.txt" || true

  # Extract MX
  echo "$dns_current" | jq -r \
    '.current_dns.mx.values[]?.hostname // empty' 2>/dev/null \
    >> "${OUT}/mx_records.txt" || true

  # Extract TXT (SPF, DKIM, verif tokens leak technology/vendors)
  echo "$dns_current" | jq -r \
    '.current_dns.txt.values[]?.value // empty' 2>/dev/null \
    >> "${OUT}/txt_records.txt" || true

  sleep 1

  # Historical A record changes
  hist_a=$(st_get "history/${TARGET}/dns/a")
  echo "$hist_a" | jq -r \
    '.records[].values[]?.ip // empty' 2>/dev/null \
    >> "${OUT}/historical_ips.txt" || true
  echo "$hist_a" | jq '.' > "${OUT}/st_historical_a.json" 2>/dev/null || true

  sleep 1

  # Historical NS
  hist_ns=$(st_get "history/${TARGET}/dns/ns")
  echo "$hist_ns" | jq '.' > "${OUT}/st_historical_ns.json" 2>/dev/null || true

  sleep 1

  # Subdomain enumeration from SecurityTrails
  subdomains=$(st_get "domain/${TARGET}/subdomains?children_only=false&include_inactive=true")
  echo "$subdomains" | jq -r '.subdomains[]? // empty' 2>/dev/null | \
    awk -v d="$TARGET" '{print $0 "." d}' \
    >> "${OUT}/subdomains_passive.txt" || true

  sleep 1

  # Associated domains (other domains on same IPs historically)
  while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    assoc=$(st_get "ips/nearby/${ip}")
    echo "$assoc" | jq -r '.blocks[]?.hostnames[]? // empty' 2>/dev/null \
      >> "${OUT}/associated_domains_by_ip.txt" || true
    sleep 0.5
  done < "${TARGET_DIR}/01_asn/resolved_ips.txt" 2>/dev/null || true

  log "SecurityTrails queries complete"
else
  warn "SECURITYTRAILS_API_KEY not set — skipping SecurityTrails"
fi

# ── Step 2: DNSdumpster (free, no API key) ────────────────────────────────────
info "Querying DNSdumpster..."
# DNSdumpster requires a CSRF token — scrape it first
csrf=$(curl -s --max-time 15 "https://dnsdumpster.com/" \
  -c "${OUT}/dnsdumpster_cookies.txt" 2>/dev/null | \
  grep -oP '(?<=csrfmiddlewaretoken" value=")[^"]+' | head -1 || true)

if [[ -n "$csrf" ]]; then
  dns_dump=$(curl -s --max-time 30 \
    "https://dnsdumpster.com/" \
    -b "${OUT}/dnsdumpster_cookies.txt" \
    -c "${OUT}/dnsdumpster_cookies.txt" \
    -H "Referer: https://dnsdumpster.com/" \
    -d "csrfmiddlewaretoken=${csrf}&targetip=${TARGET}&user=free" \
    2>/dev/null || true)

  if [[ -n "$dns_dump" ]]; then
    echo "$dns_dump" | grep -oP '[a-zA-Z0-9._-]+\.'"${TARGET}" | \
      sort -u >> "${OUT}/subdomains_passive.txt" || true
    log "DNSdumpster returned results"
  fi
else
  warn "DNSdumpster CSRF extraction failed — site may have changed"
fi
rm -f "${OUT}/dnsdumpster_cookies.txt"

# ── Step 3: ViewDNS.info (free API) ──────────────────────────────────────────
info "Querying ViewDNS for reverse IP lookup..."
while IFS= read -r ip; do
  [[ -z "$ip" ]] && continue

  viewdns=$(curl -s --max-time 15 \
    "https://api.viewdns.info/reverseip/?host=${ip}&apikey=free&output=json" \
    2>/dev/null || echo '{}')

  echo "$viewdns" | jq -r \
    '.response.domains[]?.name // empty' 2>/dev/null \
    >> "${OUT}/shared_hosting_domains.txt" || true
  sleep 1
done < "${TARGET_DIR}/01_asn/resolved_ips.txt" 2>/dev/null || true

# ── Step 4: Passive DNS via VirusTotal ────────────────────────────────────────
if [[ -n "${VIRUSTOTAL_API_KEY:-}" ]]; then
  info "Querying VirusTotal passive DNS..."

  # Domain resolutions
  vt_resolutions=$(curl -s --max-time 20 \
    "https://www.virustotal.com/api/v3/domains/${TARGET}/resolutions?limit=40" \
    -H "x-apikey: ${VIRUSTOTAL_API_KEY}" 2>/dev/null || echo '{}')

  echo "$vt_resolutions" | jq -r \
    '.data[].attributes.ip_address // empty' 2>/dev/null \
    >> "${OUT}/historical_ips.txt" || true
  echo "$vt_resolutions" | jq '.' > "${OUT}/vt_resolutions.json" 2>/dev/null || true

  sleep 1

  # Reverse DNS — what domains have resolved to each of our IPs?
  while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    vt_ip=$(curl -s --max-time 15 \
      "https://www.virustotal.com/api/v3/ip_addresses/${ip}/resolutions?limit=20" \
      -H "x-apikey: ${VIRUSTOTAL_API_KEY}" 2>/dev/null || echo '{}')

    echo "$vt_ip" | jq -r \
      '.data[].attributes.host_name // empty' 2>/dev/null \
      >> "${OUT}/associated_domains_by_ip.txt" || true
    sleep 0.5
  done < "${TARGET_DIR}/01_asn/resolved_ips.txt" 2>/dev/null || true

  log "VirusTotal passive DNS complete"
fi

# ── Step 5: WhoisXML passive DNS ─────────────────────────────────────────────
if [[ -n "${WHOISXML_API_KEY:-}" ]]; then
  info "Querying WhoisXML passive DNS..."
  wx_data=$(curl -s --max-time 20 \
    "https://dns-history.whoisxmlapi.com/api/v1?apiKey=${WHOISXML_API_KEY}&domain=${TARGET}&type=A" \
    2>/dev/null || echo '{}')

  echo "$wx_data" | jq -r \
    '.data.records[]?.answer[]?.rdata // empty' 2>/dev/null \
    >> "${OUT}/historical_ips.txt" || true
  log "WhoisXML passive DNS complete"
fi

# ── Step 6: DNS record brute analysis (TXT record vendor fingerprinting) ──────
info "Analyzing TXT records for technology vendors..."

# Common TXT record patterns that reveal vendors/services
declare -A VENDOR_PATTERNS=(
  ["google-site-verification"]="Google Workspace / GSuite"
  ["MS=ms"]="Microsoft 365 / Azure AD"
  ["v=spf1"]="Email SPF - reveals mail providers"
  ["atlassian-domain-verification"]="Atlassian (Jira/Confluence)"
  ["docusign"]="DocuSign"
  ["stripe"]="Stripe Payments"
  ["amazonses"]="Amazon SES"
  ["sendgrid"]="SendGrid"
  ["mailgun"]="Mailgun"
  ["mandrill"]="Mandrill/Mailchimp"
  ["_dmarc"]="DMARC policy"
  ["zoho-verification"]="Zoho"
  ["hubspot"]="HubSpot CRM"
  ["salesforce"]="Salesforce"
  ["_acme-challenge"]="Let's Encrypt / ACME"
  ["keybase-site-verification"]="Keybase"
  ["facebook-domain-verification"]="Facebook"
)

echo "# TXT Record Vendor Analysis" > "${OUT}/txt_vendor_fingerprint.txt"
echo "# Domain: $TARGET" >> "${OUT}/txt_vendor_fingerprint.txt"
echo "" >> "${OUT}/txt_vendor_fingerprint.txt"

# Direct dig for TXT records across domain and common subdomains
for subdomain in "" "mail." "smtp." "email." "_dmarc." "autodiscover."; do
  host="${subdomain}${TARGET}"
  records=$(dig +short TXT "$host" 2>/dev/null || true)
  if [[ -n "$records" ]]; then
    echo "=== $host ===" >> "${OUT}/txt_records.txt"
    echo "$records" >> "${OUT}/txt_records.txt"

    for pattern in "${!VENDOR_PATTERNS[@]}"; do
      if echo "$records" | grep -qi "$pattern"; then
        echo "[VENDOR] ${VENDOR_PATTERNS[$pattern]} — found in $host TXT" \
          >> "${OUT}/txt_vendor_fingerprint.txt"
      fi
    done
  fi
done

# ── Step 7: MX record analysis ────────────────────────────────────────────────
info "Analyzing MX records for mail infrastructure..."
dig +short MX "$TARGET" 2>/dev/null >> "${OUT}/mx_records.txt" || true

# MX fingerprinting
if grep -qi "google\|gmail" "${OUT}/mx_records.txt" 2>/dev/null; then
  echo "[MAIL] Google Workspace" >> "${OUT}/txt_vendor_fingerprint.txt"
elif grep -qi "outlook\|protection\.outlook\|mail\.protection" "${OUT}/mx_records.txt" 2>/dev/null; then
  echo "[MAIL] Microsoft 365 / Exchange Online" >> "${OUT}/txt_vendor_fingerprint.txt"
elif grep -qi "mimecast" "${OUT}/mx_records.txt" 2>/dev/null; then
  echo "[MAIL] Mimecast (email security gateway)" >> "${OUT}/txt_vendor_fingerprint.txt"
elif grep -qi "proofpoint" "${OUT}/mx_records.txt" 2>/dev/null; then
  echo "[MAIL] Proofpoint (email security gateway)" >> "${OUT}/txt_vendor_fingerprint.txt"
fi

# ── Final dedup ───────────────────────────────────────────────────────────────
sort -u "${OUT}/historical_ips.txt"      -o "${OUT}/historical_ips.txt"
sort -u "${OUT}/subdomains_passive.txt"  -o "${OUT}/subdomains_passive.txt"
sort -u "${OUT}/mx_records.txt"          -o "${OUT}/mx_records.txt"

# Feed into shared domain list
cat "${OUT}/subdomains_passive.txt" >> "${TARGET_DIR}/all_discovered_domains.txt"
sort -u "${TARGET_DIR}/all_discovered_domains.txt" \
     -o "${TARGET_DIR}/all_discovered_domains.txt"

echo ""
echo "── Module 03 Summary ──────────────────────────────────────"
echo "  Historical IPs:          $(wc -l < "${OUT}/historical_ips.txt")"
echo "  Passive subdomains:      $(wc -l < "${OUT}/subdomains_passive.txt")"
echo "  Vendor fingerprints:     $(grep -c '\[' "${OUT}/txt_vendor_fingerprint.txt" 2>/dev/null || echo 0)"
echo "────────────────────────────────────────────────────────────"
