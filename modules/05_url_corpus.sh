#!/usr/bin/env bash
# =============================================================================
# MODULE 05 — URL Corpus (Wayback, CommonCrawl, gau, urlscan)
# Purely passive — reads from existing indices, zero active scanning
# Input:  $TARGET, $DIR_SUBDOMAINS/live_subdomains.txt
# Output: $DIR_URLS/
#   all_urls.txt              — master URL list
#   sensitive_urls.txt        — login, upload, admin, api, backup patterns
#   parameters.txt            — unique parameters discovered
#   interesting_extensions.txt — juicy file extensions
#   api_endpoints.txt         — /api/, /v1/, /graphql etc.
#   js_files.txt              — all JS file URLs (fed into Module 07)
# =============================================================================

set -euo pipefail
source "${LIB_DIR}/common.sh"
OUT="${DIR_URLS}"


touch "${OUT}/all_urls.txt"

# ── Target list: main domain + live subdomains ────────────────────────────────
DOMAIN_LIST="${OUT}/domain_scope.txt"
echo "$TARGET" > "$DOMAIN_LIST"
[[ -f "${TARGET_DIR}/live_subdomains.txt" ]] && \
  cat "${TARGET_DIR}/live_subdomains.txt" >> "$DOMAIN_LIST"
sort -u "$DOMAIN_LIST" -o "$DOMAIN_LIST"

log "Pulling URLs for $(wc -l < "$DOMAIN_LIST") domains/subdomains"

# ── Tool: gau (fetches from Wayback, CommonCrawl, OTX, URLScan) ──────────────
if command -v gau &>/dev/null; then
  info "Running gau across all domains..."
  while IFS= read -r domain; do
    [[ -z "$domain" ]] && continue
    gau \
      --threads "$THREADS" \
      --subs \
      --blacklist png,jpg,gif,jpeg,ico,svg,woff,woff2,ttf,eot,mp4,mp3,zip,gz \
      "$domain" \
      2>/dev/null >> "${OUT}/all_urls.txt" || true
    sleep 0.5
  done < "$DOMAIN_LIST"
  log "gau complete: $(wc -l < "${OUT}/all_urls.txt") URLs"
else
  warn "gau not installed — go install github.com/lc/gau/v2/cmd/gau@latest"
fi

# ── Tool: waybackurls ─────────────────────────────────────────────────────────
if command -v waybackurls &>/dev/null; then
  info "Running waybackurls..."
  cat "$DOMAIN_LIST" | waybackurls 2>/dev/null \
    >> "${OUT}/all_urls.txt" || true
  log "waybackurls appended"
else
  warn "waybackurls not installed — go install github.com/tomnomnom/waybackurls@latest"
fi

# ── Direct Wayback CDX API (no tool needed, just curl) ────────────────────────
info "Querying Wayback CDX API directly..."
while IFS= read -r domain; do
  [[ -z "$domain" ]] && continue

  # CDX API: get all URLs, collapse on URL key, output just the URL
  curl -s --max-time 60 \
    "http://web.archive.org/cdx/search/cdx?\
url=*.${domain}/*\
&output=text\
&fl=original\
&collapse=urlkey\
&filter=statuscode:200\
&limit=50000" \
    2>/dev/null >> "${OUT}/all_urls.txt" || true
  sleep 1
done < "$DOMAIN_LIST"

# ── CommonCrawl index query ────────────────────────────────────────────────────
# https://commoncrawl.org/the-data/get-started/
info "Querying CommonCrawl index..."

# Get current index list
CC_INDEX=$(curl -s --max-time 15 \
  "https://index.commoncrawl.org/collinfo.json" 2>/dev/null | \
  jq -r '.[0].cdx-api' 2>/dev/null || \
  echo "https://index.commoncrawl.org/CC-MAIN-2024-10-index")

while IFS= read -r domain; do
  [[ -z "$domain" ]] && continue
  curl -s --max-time 30 \
    "${CC_INDEX}?url=*.${domain}&output=text&fl=url&limit=10000" \
    2>/dev/null >> "${OUT}/all_urls.txt" || true
  sleep 1
done < "$DOMAIN_LIST"

# ── URLScan.io search ─────────────────────────────────────────────────────────
info "Querying URLScan.io..."
while IFS= read -r domain; do
  [[ -z "$domain" ]] && continue
  urlscan=$(curl -s --max-time 20 \
    "https://urlscan.io/api/v1/search/?q=domain:${domain}&size=100&fields=page.url" \
    2>/dev/null || echo '{}')
  echo "$urlscan" | jq -r '.results[]?.page.url // empty' 2>/dev/null \
    >> "${OUT}/all_urls.txt" || true
  sleep 1
done < "$DOMAIN_LIST"

# ── Final URL deduplication ───────────────────────────────────────────────────
info "Deduplicating URL corpus..."
sort -u "${OUT}/all_urls.txt" -o "${OUT}/all_urls.txt"
total_urls=$(wc -l < "${OUT}/all_urls.txt")
log "Total unique URLs: $total_urls"

# ── Filter: Sensitive URL patterns ────────────────────────────────────────────
info "Filtering for sensitive patterns..."

# Login / auth
grep -iE \
  "/(login|signin|sign-in|auth|authenticate|sso|oauth|saml|ldap|token|session)" \
  "${OUT}/all_urls.txt" | sort -u > "${OUT}/auth_urls.txt" || true

# Upload endpoints
grep -iE \
  "/(upload|file|import|attach|document|media|image|avatar|photo|doc)" \
  "${OUT}/all_urls.txt" | sort -u > "${OUT}/upload_urls.txt" || true

# Admin panels
grep -iE \
  "/(admin|administrator|wp-admin|phpmyadmin|cpanel|plesk|webmin|manage|management|dashboard|console|portal|backend|cms|control)" \
  "${OUT}/all_urls.txt" | sort -u > "${OUT}/admin_urls.txt" || true

# API endpoints
grep -iE \
  "/(api|v[0-9]+|graphql|rest|soap|rpc|swagger|openapi|redoc|api-docs|json|xml|wsdl)" \
  "${OUT}/all_urls.txt" | sort -u > "${OUT}/api_endpoints.txt" || true

# Configuration / backup files
grep -iE \
  "\.(env|config|cfg|conf|ini|yaml|yml|xml|json|bak|backup|old|sql|db|sqlite|log|txt|csv|key|pem|crt|p12|pfx)\
|/(config|settings|configuration|backup|backups|dump|export|data)" \
  "${OUT}/all_urls.txt" | sort -u > "${OUT}/config_and_backup_urls.txt" || true

# Indexed directories
grep -iE \
  "/$|\?dir=|/directory|index\.php\?|directory-listing|indexof" \
  "${OUT}/all_urls.txt" | sort -u > "${OUT}/directory_urls.txt" || true

# JavaScript files
grep -iE "\.js(\?|$)|\.mjs(\?|$)|\.jsx(\?|$)" \
  "${OUT}/all_urls.txt" | sort -u > "${OUT}/js_files.txt" || true

# Interesting file extensions
grep -iE \
  "\.(pdf|xls|xlsx|doc|docx|ppt|pptx|csv|zip|tar|gz|7z|rar|bz2)" \
  "${OUT}/all_urls.txt" | sort -u > "${OUT}/documents.txt" || true

# Version control exposure
grep -iE \
  "(/\.git|/\.svn|/\.hg|/\.bzr|/CVS|\.git/config|/wp-content|/\.env)" \
  "${OUT}/all_urls.txt" | sort -u > "${OUT}/vcs_exposure.txt" || true

# Error / debug pages
grep -iE \
  "/(error|debug|trace|stack|phpinfo|test|dev|staging|beta|demo|probe)" \
  "${OUT}/all_urls.txt" | sort -u > "${OUT}/debug_urls.txt" || true

# Consolidate sensitive
cat "${OUT}/auth_urls.txt" \
    "${OUT}/upload_urls.txt" \
    "${OUT}/admin_urls.txt" \
    "${OUT}/config_and_backup_urls.txt" \
    "${OUT}/vcs_exposure.txt" \
    "${OUT}/debug_urls.txt" | \
  sort -u > "${OUT}/sensitive_urls.txt"

# ── Parameter extraction ──────────────────────────────────────────────────────
info "Extracting URL parameters..."

# Extract all unique parameter names
grep -oP '(?<=\?|&)[a-zA-Z0-9_-]+=?' "${OUT}/all_urls.txt" 2>/dev/null | \
  sed 's/=$//' | \
  sort -u > "${OUT}/parameters.txt" || true

# High-value parameters (common IDOR / injection targets)
grep -iE \
  "(\?|&)(id|uid|user|userid|account|acct|order|file|path|url|redirect|return|next|back|dest|target|token|key|api_key|secret|password|pass|pwd|cmd|exec|query|q|search|s|lang|locale|format|type|action|module|page|cat|category|sort|order|dir|download|include|require|load|src|source|data|payload|xml|json)=" \
  "${OUT}/all_urls.txt" | sort -u > "${OUT}/high_value_params.txt" || true

log "Parameters found: $(wc -l < "${OUT}/parameters.txt")"
log "High-value params: $(wc -l < "${OUT}/high_value_params.txt")"

# ── Export JS files for Module 07 ─────────────────────────────────────────────
cp "${OUT}/js_files.txt" "${TARGET_DIR}/js_files_for_analysis.txt"

echo ""
echo "── Module 05 Summary ──────────────────────────────────────"
echo "  Total URLs:             $(wc -l < "${OUT}/all_urls.txt")"
echo "  Sensitive URLs:         $(wc -l < "${OUT}/sensitive_urls.txt")"
echo "  Auth/Login:             $(wc -l < "${OUT}/auth_urls.txt")"
echo "  Upload endpoints:       $(wc -l < "${OUT}/upload_urls.txt")"
echo "  Admin panels:           $(wc -l < "${OUT}/admin_urls.txt")"
echo "  API endpoints:          $(wc -l < "${OUT}/api_endpoints.txt")"
echo "  Config/Backup files:    $(wc -l < "${OUT}/config_and_backup_urls.txt")"
echo "  VCS exposure:           $(wc -l < "${OUT}/vcs_exposure.txt")"
echo "  JS files:               $(wc -l < "${OUT}/js_files.txt")"
echo "  Documents leaked:       $(wc -l < "${OUT}/documents.txt")"
echo "  Unique parameters:      $(wc -l < "${OUT}/parameters.txt")"
echo "────────────────────────────────────────────────────────────"
