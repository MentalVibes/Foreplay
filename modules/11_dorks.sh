#!/usr/bin/env bash
# =============================================================================
# MODULE 11 — GitHub / GitLab / Pastebin / Code Dorking
# Fully passive — uses APIs and search, zero target contact
# Input:  $TARGET, $GITHUB_TOKEN
# Output: $DIR_DORKS/
#   github_secrets.txt      — potential secrets found in GitHub code
#   github_endpoints.txt    — internal URLs/hostnames in GitHub code
#   github_repos.txt        — repos mentioning target
#   gitlab_public.txt       — public GitLab repos
#   pastebin_hits.txt       — pastes mentioning target
#   google_dork_urls.txt    — URLs to run manually in browser
# =============================================================================

set -euo pipefail
source "${LIB_DIR}/common.sh"
OUT="${DIR_DORKS}"


touch "${OUT}/github_secrets.txt" "${OUT}/github_endpoints.txt" "${OUT}/github_repos.txt"

DOMAIN_NODOT=$(echo "$TARGET" | tr '.' '_')
BASE=$(echo "$TARGET" | sed 's/\..*//')

# ── GitHub Code Search via API ────────────────────────────────────────────────
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  info "Running GitHub code search via API..."

  gh_search() {
    local query="$1"
    local label="$2"
    local outfile="$3"

    local encoded_query
    encoded_query=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$query'))" 2>/dev/null || \
      echo "$query" | sed 's/ /+/g; s/"/%22/g')

    local result
    result=$(curl -s --max-time 20 \
      "https://api.github.com/search/code?q=${encoded_query}&per_page=30" \
      -H "Authorization: token ${GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github.v3+json" \
      2>/dev/null || echo '{}')

    local count
    count=$(echo "$result" | jq -r '.total_count // 0' 2>/dev/null || echo 0)

    if [[ "$count" -gt 0 ]]; then
      echo "" >> "$outfile"
      echo "=== [$label] ($count results) ===" >> "$outfile"
      echo "$result" | jq -r '.items[]? | "\(.repository.full_name) | \(.path) | \(.html_url)"' \
        2>/dev/null >> "$outfile" || true
      log "GitHub [$label]: $count results"
    fi

    sleep 2  # GitHub rate limit: 30 code search requests/min with auth
  }

  # Secret / credential queries
  gh_search "\"${TARGET}\" password"           "password"           "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" secret"             "secret"             "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" api_key"            "api_key"            "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" apikey"             "apikey"             "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" token"              "token"              "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" DB_PASSWORD"        "DB_PASSWORD"        "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" DB_HOST"            "DB_HOST"            "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" smtp"               "smtp"               "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" BEGIN PRIVATE KEY"  "private_key"        "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" jdbc"               "jdbc"               "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" connection_string"  "connection_string"  "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" aws_access"         "aws_access"         "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" bearer"             "bearer"             "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" authorization"      "authorization"      "${OUT}/github_secrets.txt"

  # Internal infrastructure queries
  gh_search "\"${TARGET}\" internal"           "internal"           "${OUT}/github_endpoints.txt"
  gh_search "\"${TARGET}\" vpn"                "vpn"                "${OUT}/github_endpoints.txt"
  gh_search "\"${TARGET}\" intranet"           "intranet"           "${OUT}/github_endpoints.txt"
  gh_search "\"${TARGET}\" staging"            "staging"            "${OUT}/github_endpoints.txt"
  gh_search "\"${TARGET}\" dev."               "dev_host"           "${OUT}/github_endpoints.txt"
  gh_search "\"${TARGET}\" 192.168"            "internal_ip"        "${OUT}/github_endpoints.txt"
  gh_search "\"${TARGET}\" 10.0."              "internal_ip_10"     "${OUT}/github_endpoints.txt"

  # Extension-specific queries
  gh_search "\"${TARGET}\" extension:env"       "dotenv"             "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" extension:pem"       "pem_cert"           "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" extension:cfg"       "config_file"        "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" extension:conf"      "conf_file"          "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" extension:json"      "json_file"          "${OUT}/github_endpoints.txt"
  gh_search "\"${TARGET}\" extension:yaml"      "yaml_file"          "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" extension:yml"       "yml_file"           "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" extension:sql"       "sql_dump"           "${OUT}/github_secrets.txt"
  gh_search "\"${TARGET}\" extension:log"       "log_file"           "${OUT}/github_secrets.txt"

  # Find repos mentioning target
  repos=$(curl -s --max-time 15 \
    "https://api.github.com/search/repositories?q=${TARGET}&per_page=30" \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github.v3+json" 2>/dev/null || echo '{}')

  echo "$repos" | jq -r \
    '.items[]? | "\(.full_name) | Stars: \(.stargazers_count) | \(.html_url) | \(.description // "")"' \
    2>/dev/null >> "${OUT}/github_repos.txt" || true

  log "GitHub API search complete"

else
  warn "GITHUB_TOKEN not set — GitHub search will be severely rate limited"
  warn "  Create a token: https://github.com/settings/tokens (no write scopes needed)"

  # Unauthenticated search (very limited, 10 req/min)
  info "Attempting unauthenticated GitHub search (limited)..."
  for query in "\"${TARGET}\" password" "\"${TARGET}\" api_key"; do
    encoded=$(echo "$query" | sed 's/ /+/g; s/"/%22/g')
    curl -s --max-time 20 \
      "https://api.github.com/search/code?q=${encoded}&per_page=10" \
      -H "Accept: application/vnd.github.v3+json" 2>/dev/null | \
      jq -r '.items[]? | "\(.repository.full_name) | \(.path) | \(.html_url)"' \
      >> "${OUT}/github_secrets.txt" || true
    sleep 10
  done
fi

# ── trufflehog on discovered GitHub repos ─────────────────────────────────────
if command -v trufflehog &>/dev/null; then
  info "Running trufflehog on GitHub org/repos..."

  # If we found repos, scan them
  if [[ -s "${OUT}/github_repos.txt" ]]; then
    while IFS='|' read -r repo_full rest; do
      repo_full=$(echo "$repo_full" | xargs)
      [[ -z "$repo_full" ]] && continue
      trufflehog github \
        --repo "https://github.com/${repo_full}" \
        --only-verified \
        --json \
        2>/dev/null >> "${OUT}/trufflehog_results.json" || true
      sleep 2
    done < "${OUT}/github_repos.txt"
  fi

  # Also scan the org directly if it matches target
  trufflehog github \
    --org "$BASE" \
    --only-verified \
    --json \
    2>/dev/null >> "${OUT}/trufflehog_results.json" || true

  log "trufflehog complete: $(wc -l < "${OUT}/trufflehog_results.json" 2>/dev/null || echo 0) findings"
else
  warn "trufflehog not installed — go install github.com/trufflesecurity/trufflehog/v3@latest"
fi

# ── GitLab public instance search ─────────────────────────────────────────────
info "Querying GitLab.com for public repos..."
gitlab_results=$(curl -s --max-time 20 \
  "https://gitlab.com/api/v4/projects?search=${BASE}&visibility=public&per_page=20" \
  -H "User-Agent: Mozilla/5.0" 2>/dev/null || echo '[]')

echo "$gitlab_results" | jq -r \
  '.[]? | "\(.path_with_namespace) | \(.web_url) | \(.description // "")"' \
  2>/dev/null > "${OUT}/gitlab_public.txt" || true

log "GitLab: $(wc -l < "${OUT}/gitlab_public.txt") public repos"

# Scan any found GitLab repos with trufflehog
if command -v trufflehog &>/dev/null && [[ -s "${OUT}/gitlab_public.txt" ]]; then
  while IFS='|' read -r _ url rest; do
    url=$(echo "$url" | xargs)
    [[ -z "$url" ]] && continue
    trufflehog gitlab \
      --repo "$url" \
      --only-verified \
      --json \
      2>/dev/null >> "${OUT}/trufflehog_results.json" || true
    sleep 2
  done < "${OUT}/gitlab_public.txt"
fi

# ── Self-hosted GitLab / Gitea discovery via Shodan ───────────────────────────
if [[ -n "${SHODAN_API_KEY:-}" ]]; then
  info "Searching Shodan for self-hosted git servers..."
  # Self-hosted GitLab
  curl -s --max-time 15 \
    "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=http.title:\"GitLab\"+hostname:${TARGET}&facets=port" \
    2>/dev/null | \
    jq -r '.matches[]? | "\(.ip_str):\(.port) | \(.hostnames | join(","))"' \
    >> "${OUT}/selfhosted_git.txt" || true

  # Gitea
  curl -s --max-time 15 \
    "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=http.title:\"Gitea\"+hostname:${TARGET}" \
    2>/dev/null | \
    jq -r '.matches[]? | "\(.ip_str):\(.port) | \(.hostnames | join(","))"' \
    >> "${OUT}/selfhosted_git.txt" || true

  log "Self-hosted git discovery complete"
fi

# ── Pastebin / Paste site search ──────────────────────────────────────────────
info "Searching paste sites for target mentions..."

# GreyNoise and IntelligenceX have APIs but require paid plans
# publicwww.com indexes source code
# These are search queries to run in browser — document them
cat > "${OUT}/paste_search_queries.txt" <<EOF
# Run these searches manually in browser (automation is blocked):

# Google/Bing paste searches:
site:pastebin.com "${TARGET}"
site:paste.ee "${TARGET}"
site:ghostbin.com "${TARGET}"
site:pastebin.pl "${TARGET}"
site:hastebin.com "${TARGET}"
site:controlc.com "${TARGET}"
site:justpaste.it "${TARGET}"
"${TARGET}" password site:pastebin.com
"${TARGET}" api_key site:pastebin.com
"@${TARGET}" site:pastebin.com

# publicwww.com (source code search engine):
https://publicwww.com/websites/"${TARGET}"/
https://publicwww.com/websites/"api.${TARGET}"/

# grep.app (searches GitHub code):
https://grep.app/search?q=${TARGET}+password

# SearchCode:
https://searchcode.com/?q="${TARGET}"+password

# GitLab search:
https://gitlab.com/search?search=${TARGET}&scope=blobs

# Sourcegraph:
https://sourcegraph.com/search?q=${TARGET}+password&patternType=regexp
EOF

log "Paste search query file generated"

# ── Google Dork URL Generation ────────────────────────────────────────────────
info "Generating Google dork URLs..."

BASE_ENCODE=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${TARGET}'))" 2>/dev/null || \
  echo "$TARGET" | sed 's/\./%2E/g')

cat > "${OUT}/google_dork_urls.txt" <<EOF
# === GOOGLE DORKS FOR: ${TARGET} ===
# Open these in browser with Google logged out / incognito
# Use VPN / separate browser session to avoid association

# ── File Type Exposure ──────────────────────────────────────────────────────
https://www.google.com/search?q=site:${TARGET}+filetype:pdf+"confidential"
https://www.google.com/search?q=site:${TARGET}+filetype:xlsx+OR+filetype:csv
https://www.google.com/search?q=site:${TARGET}+filetype:doc+OR+filetype:docx+"internal"
https://www.google.com/search?q=site:${TARGET}+ext:env+OR+ext:config+OR+ext:bak+OR+ext:sql
https://www.google.com/search?q=site:${TARGET}+ext:pem+OR+ext:key+OR+ext:p12+OR+ext:pfx
https://www.google.com/search?q=site:${TARGET}+ext:log+OR+ext:txt+"error"

# ── Admin / Login Panels ────────────────────────────────────────────────────
https://www.google.com/search?q=site:${TARGET}+inurl:admin
https://www.google.com/search?q=site:${TARGET}+inurl:login
https://www.google.com/search?q=site:${TARGET}+inurl:wp-admin
https://www.google.com/search?q=site:${TARGET}+inurl:phpmyadmin
https://www.google.com/search?q=site:${TARGET}+inurl:cpanel
https://www.google.com/search?q=site:${TARGET}+inurl:webmail
https://www.google.com/search?q=site:${TARGET}+intitle:"admin panel"
https://www.google.com/search?q=site:${TARGET}+intitle:"dashboard"
https://www.google.com/search?q=site:${TARGET}+intitle:"control panel"
https://www.google.com/search?q=site:${TARGET}+inurl:"/manager/html"
https://www.google.com/search?q=site:${TARGET}+inurl:"/wp-login.php"

# ── Upload Endpoints ─────────────────────────────────────────────────────────
https://www.google.com/search?q=site:${TARGET}+inurl:upload
https://www.google.com/search?q=site:${TARGET}+inurl:file+upload
https://www.google.com/search?q=site:${TARGET}+inurl:import
https://www.google.com/search?q=site:${TARGET}+inurl:attach

# ── Directory Indexing ────────────────────────────────────────────────────────
https://www.google.com/search?q=site:${TARGET}+intitle:"index+of"
https://www.google.com/search?q=site:${TARGET}+intitle:"index+of"+"/uploads"
https://www.google.com/search?q=site:${TARGET}+intitle:"index+of"+"/backup"
https://www.google.com/search?q=site:${TARGET}+intitle:"index+of"+".git"
https://www.google.com/search?q=site:${TARGET}+intitle:"index+of"+"/config"
https://www.google.com/search?q=site:${TARGET}+intitle:"Directory+Listing"

# ── Error Pages / Debug ───────────────────────────────────────────────────────
https://www.google.com/search?q=site:${TARGET}+intitle:"phpinfo()"
https://www.google.com/search?q=site:${TARGET}+intitle:"PHP+Version"
https://www.google.com/search?q=site:${TARGET}+"sql+syntax"
https://www.google.com/search?q=site:${TARGET}+"ORA-01756"
https://www.google.com/search?q=site:${TARGET}+"mysql_fetch_array"
https://www.google.com/search?q=site:${TARGET}+"stack+trace"
https://www.google.com/search?q=site:${TARGET}+"Warning:+include"
https://www.google.com/search?q=site:${TARGET}+"Fatal+error"

# ── API & Swagger ─────────────────────────────────────────────────────────────
https://www.google.com/search?q=site:${TARGET}+inurl:swagger
https://www.google.com/search?q=site:${TARGET}+inurl:api-docs
https://www.google.com/search?q=site:${TARGET}+inurl:openapi
https://www.google.com/search?q=site:${TARGET}+inurl:graphql
https://www.google.com/search?q=site:${TARGET}+inurl:redoc
https://www.google.com/search?q=site:${TARGET}+inurl:wsdl
https://www.google.com/search?q=site:${TARGET}+inurl:".json"+"api"

# ── SharePoint / OneDrive / O365 ─────────────────────────────────────────────
https://www.google.com/search?q=site:${BASE}.sharepoint.com
https://www.google.com/search?q=site:${BASE}.sharepoint.com+filetype:xlsx+OR+filetype:docx
https://www.google.com/search?q=site:${BASE}.sharepoint.com+"confidential"
https://www.google.com/search?q=site:${BASE}-my.sharepoint.com
https://www.google.com/search?q=site:${BASE}.sharepoint.com+inurl:"/sites/"
https://www.google.com/search?q="1drv.ms"+"${TARGET}"

# ── VCS Exposure ──────────────────────────────────────────────────────────────
https://www.google.com/search?q=site:${TARGET}+inurl:"/.git"
https://www.google.com/search?q=site:${TARGET}+inurl:"/.svn"
https://www.google.com/search?q=site:${TARGET}+"[core]"+filetype:cfg

# ── S3 / Cloud Storage ────────────────────────────────────────────────────────
https://www.google.com/search?q=site:s3.amazonaws.com+"${BASE}"
https://www.google.com/search?q=site:blob.core.windows.net+"${BASE}"
https://www.google.com/search?q=site:storage.googleapis.com+"${BASE}"

# ── GitHub / Repo Searches ────────────────────────────────────────────────────
https://github.com/search?q="${TARGET}"+password&type=code
https://github.com/search?q="${TARGET}"+secret&type=code
https://github.com/search?q="${TARGET}"+api_key&type=code
https://github.com/search?q="${TARGET}"+token&type=code
https://github.com/search?q="${TARGET}"+extension:env&type=code
https://github.com/search?q="${TARGET}"+extension:sql&type=code
https://github.com/search?q="${TARGET}"+DB_PASSWORD&type=code
https://github.com/search?q="${TARGET}"+BEGIN+PRIVATE+KEY&type=code
https://grep.app/search?q=${TARGET}+password

# ── Shodan (browser) ─────────────────────────────────────────────────────────
https://www.shodan.io/search?query=hostname:${TARGET}
https://www.shodan.io/search?query=hostname:${TARGET}+http.title:login
https://www.shodan.io/search?query=hostname:${TARGET}+http.title:admin
https://www.shodan.io/search?query=hostname:${TARGET}+product:Apache

# ── Censys (browser) ─────────────────────────────────────────────────────────
https://search.censys.io/hosts?q=dns.names%3A${TARGET}

# ── Intelligence X ────────────────────────────────────────────────────────────
https://intelx.io/?s=${TARGET}

# ── Leak Sites ───────────────────────────────────────────────────────────────
https://haveibeenpwned.com/DomainSearch
# (requires domain verification — use client access)
EOF

log "Generated $(grep -c 'https://' "${OUT}/google_dork_urls.txt") dork URLs"

# ── Shodan dorks via API ──────────────────────────────────────────────────────
if [[ -n "${SHODAN_API_KEY:-}" ]]; then
  info "Running Shodan queries via API..."

  declare -A SHODAN_QUERIES=(
    ["login_pages"]="hostname:${TARGET} http.title:login"
    ["admin_panels"]="hostname:${TARGET} http.title:admin"
    ["default_pages"]="hostname:${TARGET} http.title:\"Welcome to\" OR http.title:\"IIS Windows\""
    ["phpmyadmin"]="hostname:${TARGET} http.title:phpMyAdmin"
    ["jenkins"]="hostname:${TARGET} http.title:Jenkins"
    ["jira"]="hostname:${TARGET} http.title:Jira"
    ["confluence"]="hostname:${TARGET} http.title:Confluence"
    ["grafana"]="hostname:${TARGET} http.title:Grafana"
    ["kibana"]="hostname:${TARGET} http.title:Kibana"
    ["gitlab"]="hostname:${TARGET} http.title:GitLab"
    ["swagger"]="hostname:${TARGET} http.title:Swagger"
    ["elastic"]="hostname:${TARGET} port:9200"
    ["mongodb"]="hostname:${TARGET} port:27017"
    ["redis"]="hostname:${TARGET} port:6379"
    ["rdp"]="hostname:${TARGET} port:3389"
    ["vnc"]="hostname:${TARGET} port:5900"
    ["ftp"]="hostname:${TARGET} port:21"
  )

  for label in "${!SHODAN_QUERIES[@]}"; do
    query="${SHODAN_QUERIES[$label]}"
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$query'))" 2>/dev/null || \
      echo "$query" | sed 's/ /+/g; s/:/%3A/g')

    result=$(curl -s --max-time 20 \
      "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=${encoded}&facets=port" \
      2>/dev/null || echo '{}')

    count=$(echo "$result" | jq -r '.total // 0' 2>/dev/null || echo 0)
    if [[ "$count" -gt 0 ]]; then
      echo "" >> "${OUT}/shodan_dork_results.txt"
      echo "=== [$label] ($count) ===" >> "${OUT}/shodan_dork_results.txt"
      echo "$result" | jq -r \
        '.matches[]? | "\(.ip_str):\(.port) | \(.hostnames | join(",")) | \(.product // "") \(.version // "")"' \
        2>/dev/null >> "${OUT}/shodan_dork_results.txt" || true
      log "Shodan [$label]: $count results"
    fi
    sleep 1
  done
fi

echo ""
echo "── Module 11 Summary ──────────────────────────────────────"
echo "  GitHub secret hits:       $(grep -c '^===' "${OUT}/github_secrets.txt" 2>/dev/null || echo 0)"
echo "  GitHub endpoint hits:     $(grep -c '^===' "${OUT}/github_endpoints.txt" 2>/dev/null || echo 0)"
echo "  GitHub repos found:       $(wc -l < "${OUT}/github_repos.txt" 2>/dev/null || echo 0)"
echo "  GitLab public repos:      $(wc -l < "${OUT}/gitlab_public.txt" 2>/dev/null || echo 0)"
echo "  Dork URLs generated:      $(grep -c 'https://' "${OUT}/google_dork_urls.txt" 2>/dev/null || echo 0)"
echo "  Shodan dork results:      $(grep -c '^===' "${OUT}/shodan_dork_results.txt" 2>/dev/null || echo 0)"
echo ""
echo "  ⚠  MANUAL ACTION REQUIRED:"
echo "     Open ${OUT}/google_dork_urls.txt in browser (incognito/VPN)"
echo "     Open ${OUT}/paste_search_queries.txt for paste site searches"
echo "────────────────────────────────────────────────────────────"
