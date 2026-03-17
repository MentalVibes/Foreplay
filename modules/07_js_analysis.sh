#!/usr/bin/env bash
# =============================================================================
# MODULE 07 — JavaScript Analysis (LinkFinder + SecretFinder + manual grep)
# Input:  $TARGET_DIR/js_files_for_analysis.txt (from Module 05)
#         $TARGET_DIR/all_live_urls.txt (from Module 06)
# Output: $DIR_JS/
#   endpoints_from_js.txt    — API/internal endpoints extracted
#   secrets_from_js.txt      — potential keys, tokens, passwords
#   internal_hosts_js.txt    — internal hostnames/IPs in JS
#   cloud_refs_js.txt        — S3, Azure, GCP references in JS
#   js_libraries.txt         — frameworks and their versions (CVE surface)
# =============================================================================

set -euo pipefail
source "${LIB_DIR}/common.sh"
OUT="${DIR_JS}"


JS_DOWNLOAD_DIR="${OUT}/downloaded_js"
mkdir -p "$JS_DOWNLOAD_DIR"

touch "${OUT}/endpoints_from_js.txt"
touch "${OUT}/secrets_from_js.txt"
touch "${OUT}/internal_hosts_js.txt"
touch "${OUT}/cloud_refs_js.txt"

# ── Combine JS file URLs ──────────────────────────────────────────────────────
JS_URLS="${OUT}/js_url_list.txt"
touch "$JS_URLS"

[[ -f "${TARGET_DIR}/js_files_for_analysis.txt" ]] && \
  cat "${TARGET_DIR}/js_files_for_analysis.txt" >> "$JS_URLS"

# Also crawl live hosts for JS files using a single GET (not spidering)
if [[ -f "${TARGET_DIR}/all_live_urls.txt" ]]; then
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    # Fetch page and extract script src attributes
    curl -s --max-time 15 -L "$url" 2>/dev/null | \
      grep -oP '(?<=src=")[^"]+\.js[^"]*' | \
      while read -r jsref; do
        if [[ "$jsref" =~ ^https?:// ]]; then
          echo "$jsref" >> "$JS_URLS"
        elif [[ "$jsref" =~ ^/ ]]; then
          base=$(echo "$url" | grep -oP 'https?://[^/]+')
          echo "${base}${jsref}" >> "$JS_URLS"
        fi
      done
  done < "${TARGET_DIR}/all_live_urls.txt"
fi

sort -u "$JS_URLS" -o "$JS_URLS"
log "Total JS files to analyze: $(wc -l < "$JS_URLS")"

# ── Download JS files ─────────────────────────────────────────────────────────
info "Downloading JS files for analysis..."
downloaded=0
while IFS= read -r jsurl; do
  [[ -z "$jsurl" ]] && continue

  # Safe filename
  fname=$(echo "$jsurl" | md5sum | cut -d' ' -f1).js
  fpath="${JS_DOWNLOAD_DIR}/${fname}"

  curl -s --max-time 20 -L \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    "$jsurl" \
    -o "$fpath" 2>/dev/null || true

  if [[ -s "$fpath" ]]; then
    echo "$jsurl $fpath" >> "${OUT}/js_url_to_file_map.txt"
    ((downloaded++)) || true
  fi
  sleep 0.2
done < "$JS_URLS"
log "Downloaded $downloaded JS files"

# ── LinkFinder — endpoint extraction ─────────────────────────────────────────
if command -v python3 &>/dev/null && [[ -f "${HOME}/tools/LinkFinder/linkfinder.py" ]]; then
  info "Running LinkFinder on downloaded JS..."
  while IFS= read -r line; do
    jsurl=$(echo "$line" | awk '{print $1}')
    jspath=$(echo "$line" | awk '{print $2}')
    [[ ! -f "$jspath" ]] && continue

    python3 "${HOME}/tools/LinkFinder/linkfinder.py" \
      -i "$jspath" \
      -o cli 2>/dev/null | \
      grep -v "^#\|linkfinder\|Usage" | \
      grep -v "^$" | \
      awk -v url="$jsurl" '{print url " | " $0}' \
      >> "${OUT}/endpoints_from_js.txt" || true
  done < "${OUT}/js_url_to_file_map.txt"
  log "LinkFinder complete"
else
  warn "LinkFinder not found at ~/tools/LinkFinder/linkfinder.py"
  warn "  git clone https://github.com/GerbenJavado/LinkFinder ~/tools/LinkFinder"

  # Fallback: manual endpoint extraction with regex
  info "Running manual endpoint extraction (LinkFinder fallback)..."
  find "$JS_DOWNLOAD_DIR" -name "*.js" -size +0c | while read -r jspath; do
    # REST API patterns
    grep -oP $'["\047`](/[a-zA-Z0-9_/.-]{2,}|https?://[a-zA-Z0-9._/-]+)["\047`]' \
      "$jspath" 2>/dev/null | \
      tr -d $'"\047` ' | \
      grep -v "^//$\|^/$" | \
      sort -u >> "${OUT}/endpoints_from_js.txt" || true
  done
fi

# ── SecretFinder — secrets in JS ─────────────────────────────────────────────
if command -v python3 &>/dev/null && [[ -f "${HOME}/tools/SecretFinder/SecretFinder.py" ]]; then
  info "Running SecretFinder on downloaded JS..."
  while IFS= read -r line; do
    jsurl=$(echo "$line" | awk '{print $1}')
    jspath=$(echo "$line" | awk '{print $2}')
    [[ ! -f "$jspath" ]] && continue

    python3 "${HOME}/tools/SecretFinder/SecretFinder.py" \
      -i "$jspath" \
      -o cli 2>/dev/null | \
      grep -v "^$\|SecretFinder\|Usage" | \
      awk -v url="$jsurl" '{print url " | " $0}' \
      >> "${OUT}/secrets_from_js.txt" || true
  done < "${OUT}/js_url_to_file_map.txt"
  log "SecretFinder complete"
else
  warn "SecretFinder not found at ~/tools/SecretFinder/SecretFinder.py"
  warn "  git clone https://github.com/m4ll0k/SecretFinder ~/tools/SecretFinder"
fi

# ── Manual secret pattern grep (always runs as baseline) ──────────────────────
info "Running secret pattern grep across all JS files..."

# Write patterns to a temp file (avoids associative array quoting issues)
PATTERN_FILE="${OUT}/secret_patterns.tmp"
cat > "$PATTERN_FILE" <<'PATTERNS'
AWS Access Key|AKIA[0-9A-Z]{16}
AWS Secret Key|(?i)(aws_secret|aws_key|secret_key)[\"\s:=]+[A-Za-z0-9+/]{40}
Google API Key|AIza[0-9A-Za-z\-_]{35}
Google OAuth|[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com
Stripe Key|[sp]k_(test|live)_[0-9a-zA-Z]{24,}
Slack Token|xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}
Slack Webhook|hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[0-9a-zA-Z]{24}
GitHub Token|ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}
JWT Token|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}
Private Key|-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY
Basic Auth|(?i)(password|passwd|pwd|pass)[\"\s:=]+.{4,}
API Key generic|(?i)(api_key|apikey|api-key)[\"\s:=]+[a-zA-Z0-9_-]{16,}
Bearer Token|(?i)bearer\s+[a-zA-Z0-9_.-]{20,}
Auth Header|(?i)(authorization|x-api-key)[\"\s:=]+.{10,}
Database URL|(mysql|postgres|mongodb|redis|mssql|jdbc)[+a-z]*://[^\s]{10,}
Internal URL|https?://(localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)
SendGrid Key|SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}
Twilio SID|(?i)twilio.{0,30}[0-9a-fA-F]{32}
Mailgun Key|key-[0-9a-zA-Z]{32}
Firebase|AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}
PATTERNS

SECRETS_MANUAL="${OUT}/secrets_manual_grep.txt"
echo "# Manual Secret Pattern Scan" > "$SECRETS_MANUAL"
echo "# Generated: $(date)" >> "$SECRETS_MANUAL"
echo "" >> "$SECRETS_MANUAL"

while IFS='|' read -r label pattern; do
  [[ -z "$label" || -z "$pattern" ]] && continue
  matches=$(grep -rhoP "$pattern" "$JS_DOWNLOAD_DIR" 2>/dev/null | sort -u || true)
  if [[ -n "$matches" ]]; then
    echo "=== $label ===" >> "$SECRETS_MANUAL"
    echo "$matches" >> "$SECRETS_MANUAL"
    echo "" >> "$SECRETS_MANUAL"
    echo "$matches" | awk -v l="$label" '{print "[" l "] " $0}' >> "${OUT}/secrets_from_js.txt"
  fi
done < "$PATTERN_FILE"
rm -f "$PATTERN_FILE"
log "Manual secret scan complete"

# ── Internal host extraction ──────────────────────────────────────────────────
info "Extracting internal hostnames and IPs from JS..."
grep -rhoP \
  '(https?://)?(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+|[a-z0-9-]+\.(internal|corp|local|lan|intranet|dev|stage|staging|uat))[:/][^\s<>]{0,100}' \
  "$JS_DOWNLOAD_DIR" 2>/dev/null | \
  sort -u >> "${OUT}/internal_hosts_js.txt" || true

# ── Cloud storage references in JS ────────────────────────────────────────────
info "Extracting cloud storage references..."
grep -rhoP \
  '(s3://[a-z0-9._-]+|https?://[a-z0-9._-]+\.s3[.-][a-z0-9-]*.amazonaws\.com[^\s<>]*|https?://[a-z0-9]+\.blob\.core\.windows\.net[^\s<>]*|https?://storage\.googleapis\.com/[^\s<>]*)' \
  "$JS_DOWNLOAD_DIR" 2>/dev/null | \
  sort -u >> "${OUT}/cloud_refs_js.txt" || true

# ── Library version fingerprinting ────────────────────────────────────────────
info "Fingerprinting JS library versions..."
{
  grep -rhoP 'jquery[/-]?v?(\d+\.\d+\.\d+)' "$JS_DOWNLOAD_DIR" 2>/dev/null | sort -u | sed 's/^/jQuery: /'
  grep -rhoP 'angular[/-]?v?(\d+\.\d+\.\d+)' "$JS_DOWNLOAD_DIR" 2>/dev/null | sort -u | sed 's/^/Angular: /'
  grep -rhoP 'react[/-]?v?(\d+\.\d+\.\d+)' "$JS_DOWNLOAD_DIR" 2>/dev/null | sort -u | sed 's/^/React: /'
  grep -rhoP 'vue[/-]?v?(\d+\.\d+\.\d+)' "$JS_DOWNLOAD_DIR" 2>/dev/null | sort -u | sed 's/^/Vue: /'
  grep -rhoP 'bootstrap[/-]?v?(\d+\.\d+\.\d+)' "$JS_DOWNLOAD_DIR" 2>/dev/null | sort -u | sed 's/^/Bootstrap: /'
  grep -rhoP 'lodash[/-]?v?(\d+\.\d+\.\d+)' "$JS_DOWNLOAD_DIR" 2>/dev/null | sort -u | sed 's/^/Lodash: /'
  grep -rhoP 'moment[/-]?v?(\d+\.\d+\.\d+)' "$JS_DOWNLOAD_DIR" 2>/dev/null | sort -u | sed 's/^/Moment.js: /'
  grep -rhoP 'axios[/-]?v?(\d+\.\d+\.\d+)' "$JS_DOWNLOAD_DIR" 2>/dev/null | sort -u | sed 's/^/Axios: /'
  grep -rhoP 'webpack[/-]?v?(\d+\.\d+\.\d+)' "$JS_DOWNLOAD_DIR" 2>/dev/null | sort -u | sed 's/^/Webpack: /'
} | sort -u > "${OUT}/js_libraries.txt" 2>/dev/null || true

# ── nuclei JS secret templates ────────────────────────────────────────────────
if command -v nuclei &>/dev/null; then
  info "Running nuclei JS/exposure templates..."
  [[ -f "${TARGET_DIR}/all_live_urls.txt" ]] && \
    nuclei \
      -l "${TARGET_DIR}/all_live_urls.txt" \
      -t exposures/tokens/ \
      -t exposures/files/ \
      -t exposures/apis/ \
      -t misconfiguration/ \
      -silent \
      -json \
      -o "${OUT}/nuclei_exposures.json" \
      2>/dev/null || true
  log "nuclei exposure scan complete"
fi

echo ""
echo "── Module 07 Summary ──────────────────────────────────────"
echo "  JS files analyzed:         $(wc -l < "${OUT}/js_url_to_file_map.txt" 2>/dev/null || echo 0)"
echo "  Endpoints extracted:       $(sort -u "${OUT}/endpoints_from_js.txt" 2>/dev/null | wc -l || echo 0)"
echo "  Secrets found:             $(sort -u "${OUT}/secrets_from_js.txt" 2>/dev/null | wc -l || echo 0)"
echo "  Internal hosts in JS:      $(wc -l < "${OUT}/internal_hosts_js.txt" 2>/dev/null || echo 0)"
echo "  Cloud refs in JS:          $(wc -l < "${OUT}/cloud_refs_js.txt" 2>/dev/null || echo 0)"
echo "  JS libraries fingerprinted:$(wc -l < "${OUT}/js_libraries.txt" 2>/dev/null || echo 0)"
echo "────────────────────────────────────────────────────────────"
