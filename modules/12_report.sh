#!/usr/bin/env bash
# =============================================================================
# MODULE 12 — Report Consolidation
# Aggregates all module outputs into a structured HTML report
# Per-host records include: IP, hostname, port, server, OS, CMS,
# framework/version, TLS cert, open findings, CVEs, secrets, cloud exposure
# =============================================================================

set -euo pipefail
source "${LIB_DIR}/common.sh"
OUT="${DIR_REPORT}"


REPORT_HTML="${OUT}/report.html"
REPORT_JSON="${OUT}/report.json"

# ── Helper: safe file read ─────────────────────────────────────────────────────
safe_count() { wc -l < "$1" 2>/dev/null || echo 0; }
safe_cat()   { [[ -f "$1" ]] && cat "$1" || echo ""; }

info "Generating report for $TARGET..."

# ── Build JSON summary ─────────────────────────────────────────────────────────
jq -n \
  --arg target "$TARGET" \
  --arg date "$(date -u +"%Y-%m-%d %H:%M UTC")" \
  --arg asns "$(safe_cat "${DIR_ASN}/org_asns.txt" | tr '\n' ',')" \
  --arg cidrs "$(safe_count "${DIR_ASN}/all_cidrs_final.txt")" \
  --arg subdomains "$(safe_count "${DIR_SUBDOMAINS}/all_subdomains.txt")" \
  --arg live "$(safe_count "${TARGET_DIR}/live_subdomains.txt")" \
  --arg total_urls "$(safe_count "${DIR_URLS}/all_urls.txt")" \
  --arg sensitive "$(safe_count "${DIR_URLS}/sensitive_urls.txt")" \
  --arg js_secrets "$(safe_count "${DIR_JS}/secrets_from_js.txt")" \
  --arg cloud "$(safe_count "${DIR_CLOUD}/cloud_all.txt")" \
  --arg github_hits "$(safe_count "${DIR_DORKS}/github_secrets.txt")" \
  '{
    target: $target, generated: $date,
    asns: $asns, cidr_blocks: $cidrs,
    subdomains_total: $subdomains, subdomains_live: $live,
    total_urls: $total_urls, sensitive_urls: $sensitive,
    js_secrets: $js_secrets, cloud_findings: $cloud,
    github_hits: $github_hits
  }' > "$REPORT_JSON"

# ── Generate HTML report ───────────────────────────────────────────────────────
cat > "$REPORT_HTML" <<HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>OSINT Report — ${TARGET}</title>
<style>
  :root {
    --bg: #0d1117; --card: #161b22; --border: #30363d;
    --text: #c9d1d9; --dim: #8b949e; --green: #3fb950;
    --red: #f85149; --yellow: #d29922; --blue: #58a6ff;
    --orange: #e3b341; --purple: #bc8cff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', monospace; font-size: 14px; }
  .container { max-width: 1400px; margin: 0 auto; padding: 24px; }
  h1 { font-size: 1.6rem; color: var(--blue); border-bottom: 1px solid var(--border); padding-bottom: 12px; margin-bottom: 20px; }
  h2 { font-size: 1.1rem; color: var(--blue); margin: 24px 0 12px; border-left: 3px solid var(--blue); padding-left: 10px; }
  h3 { font-size: 0.95rem; color: var(--dim); margin: 12px 0 6px; }
  .meta { color: var(--dim); font-size: 0.85rem; margin-bottom: 24px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
  .stat-card .value { font-size: 1.8rem; font-weight: bold; color: var(--green); }
  .stat-card .label { font-size: 0.8rem; color: var(--dim); margin-top: 4px; }
  .stat-card.warn .value { color: var(--red); }
  .stat-card.info .value { color: var(--blue); }
  .stat-card.caution .value { color: var(--yellow); }
  table { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 0.82rem; }
  th { background: #21262d; color: var(--dim); text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.5px; }
  td { padding: 7px 10px; border-bottom: 1px solid var(--border); vertical-align: top; word-break: break-all; }
  tr:hover td { background: #1c2128; }
  .badge { display: inline-block; padding: 2px 7px; border-radius: 12px; font-size: 0.72rem; font-weight: 600; }
  .badge-red    { background: rgba(248,81,73,0.15); color: var(--red); }
  .badge-green  { background: rgba(63,185,80,0.15); color: var(--green); }
  .badge-yellow { background: rgba(210,153,34,0.15); color: var(--yellow); }
  .badge-blue   { background: rgba(88,166,255,0.15); color: var(--blue); }
  .badge-purple { background: rgba(188,140,255,0.15); color: var(--purple); }
  .section { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; }
  pre { background: #0d1117; border: 1px solid var(--border); border-radius: 4px; padding: 10px; overflow-x: auto; font-size: 0.78rem; color: #7ee787; white-space: pre-wrap; max-height: 400px; overflow-y: auto; }
  .severity-critical { border-left: 4px solid var(--red); }
  .severity-high     { border-left: 4px solid var(--orange); }
  .severity-medium   { border-left: 4px solid var(--yellow); }
  .finding { padding: 12px; margin-bottom: 8px; background: #0d1117; border-radius: 4px; }
  a { color: var(--blue); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .tabs { display: flex; gap: 4px; margin-bottom: -1px; }
  .tab { padding: 8px 16px; cursor: pointer; border: 1px solid var(--border); border-bottom: none; border-radius: 4px 4px 0 0; background: var(--card); color: var(--dim); font-size: 0.82rem; }
  .tab.active { background: var(--bg); color: var(--text); border-bottom: 1px solid var(--bg); }
  .tab-content { display: none; }
  .tab-content.active { display: block; }
</style>
</head>
<body>
<div class="container">

<h1>🔍 OSINT Reconnaissance Report — ${TARGET}</h1>
<div class="meta">Generated: $(date -u +"%Y-%m-%d %H:%M UTC") &nbsp;|&nbsp; Passive recon only &nbsp;|&nbsp; Classification: CONFIDENTIAL</div>

<!-- ── Summary Stats ── -->
<div class="grid">
  <div class="stat-card info">
    <div class="value">$(safe_count "${DIR_SUBDOMAINS}/all_subdomains.txt")</div>
    <div class="label">Subdomains Found</div>
  </div>
  <div class="stat-card info">
    <div class="value">$(safe_count "${TARGET_DIR}/live_subdomains.txt")</div>
    <div class="label">Live Hosts</div>
  </div>
  <div class="stat-card info">
    <div class="value">$(safe_count "${DIR_URLS}/all_urls.txt")</div>
    <div class="label">Total URLs</div>
  </div>
  <div class="stat-card warn">
    <div class="value">$(safe_count "${DIR_URLS}/sensitive_urls.txt")</div>
    <div class="label">Sensitive URLs</div>
  </div>
  <div class="stat-card warn">
    <div class="value">$(safe_count "${DIR_JS}/secrets_from_js.txt")</div>
    <div class="label">Secrets in JS</div>
  </div>
  <div class="stat-card caution">
    <div class="value">$(safe_count "${DIR_CLOUD}/cloud_all.txt")</div>
    <div class="label">Cloud Findings</div>
  </div>
  <div class="stat-card warn">
    <div class="value">$(safe_count "${DIR_TECH}/cve_candidates.txt")</div>
    <div class="label">CVE Candidates</div>
  </div>
  <div class="stat-card caution">
    <div class="value">$(safe_count "${DIR_DORKS}/github_secrets.txt")</div>
    <div class="label">GitHub Hits</div>
  </div>
</div>

<!-- ── ASN & Infrastructure ── -->
<div class="section">
<h2>01. ASN & Infrastructure</h2>
<table>
<tr><th>ASN(s)</th><th>CIDRs</th><th>Resolved IPs</th></tr>
<tr>
  <td>$(safe_cat "${DIR_ASN}/org_asns.txt" | tr '\n' ' ')</td>
  <td>$(safe_count "${DIR_ASN}/all_cidrs_final.txt")</td>
  <td>$(safe_count "${DIR_ASN}/resolved_ips.txt")</td>
</tr>
</table>
<h3>CIDR Blocks</h3>
<pre>$(safe_cat "${DIR_ASN}/all_cidrs_final.txt" | head -50)</pre>
</div>

<!-- ── Certificate Transparency ── -->
<div class="section">
<h2>02. Certificate Transparency</h2>
<table>
<tr><th>Source</th><th>Count</th></tr>
<tr><td>CT Logs (crt.sh + Censys)</td><td>$(safe_count "${DIR_CERTS}/domains_from_certs.txt")</td></tr>
<tr><td>Internal-pattern hostnames</td><td>$(safe_count "${DIR_CERTS}/internal_naming.txt")</td></tr>
<tr><td>Wildcard certificates</td><td>$(safe_count "${DIR_CERTS}/wildcard_certs.txt")</td></tr>
</table>
<h3>Internal / Shadow IT Hostnames (from SANs)</h3>
<pre>$(safe_cat "${DIR_CERTS}/internal_naming.txt" | head -100)</pre>
</div>

<!-- ── Vendor Fingerprint ── -->
<div class="section">
<h2>03. Technology Vendor Fingerprint (TXT/MX Records)</h2>
<pre>$(safe_cat "${DIR_DNS}/txt_vendor_fingerprint.txt")</pre>
</div>

<!-- ── Live Host Fingerprint Table ── -->
<div class="section">
<h2>06. Live Host Fingerprint Matrix</h2>
<table>
<tr><th>URL</th><th>Status</th><th>Server</th><th>CMS / Tech</th><th>Title</th></tr>
HTMLEOF

# Inject rows from httpx JSON
if [[ -f "${DIR_HOSTS}/httpx_full.json" ]]; then
  while IFS= read -r line; do
    url=$(echo "$line" | jq -r '.url // ""' 2>/dev/null)
    status=$(echo "$line" | jq -r '.status_code // ""' 2>/dev/null)
    server=$(echo "$line" | jq -r '.webserver // ""' 2>/dev/null)
    tech=$(echo "$line" | jq -r '.technologies // [] | join(", ")' 2>/dev/null)
    title=$(echo "$line" | jq -r '.title // ""' 2>/dev/null | sed 's/</\&lt;/g; s/>/\&gt;/g')

    # Color-code status
    badge_class="badge-blue"
    [[ "$status" == "200" ]] && badge_class="badge-green"
    [[ "$status" == "401" || "$status" == "403" ]] && badge_class="badge-yellow"
    [[ "$status" == "5"* ]] && badge_class="badge-red"

    echo "<tr><td><a href=\"$url\" target=\"_blank\">$url</a></td><td><span class=\"badge $badge_class\">$status</span></td><td>$server</td><td>$tech</td><td>$title</td></tr>" \
      >> "$REPORT_HTML"
  done < "${DIR_HOSTS}/httpx_full.json"
fi

cat >> "$REPORT_HTML" <<HTMLEOF
</table>
</div>

<!-- ── Sensitive URLs ── -->
<div class="section severity-high">
<h2>⚠ Sensitive URL Categories</h2>
<table>
<tr><th>Category</th><th>Count</th><th>Sample (first 5)</th></tr>
<tr><td><span class="badge badge-red">Auth/Login</span></td>
  <td>$(safe_count "${DIR_URLS}/auth_urls.txt")</td>
  <td><pre style="max-height:80px">$(safe_cat "${DIR_URLS}/auth_urls.txt" | head -5)</pre></td></tr>
<tr><td><span class="badge badge-red">Upload Endpoints</span></td>
  <td>$(safe_count "${DIR_URLS}/upload_urls.txt")</td>
  <td><pre style="max-height:80px">$(safe_cat "${DIR_URLS}/upload_urls.txt" | head -5)</pre></td></tr>
<tr><td><span class="badge badge-red">Admin Panels</span></td>
  <td>$(safe_count "${DIR_URLS}/admin_urls.txt")</td>
  <td><pre style="max-height:80px">$(safe_cat "${DIR_URLS}/admin_urls.txt" | head -5)</pre></td></tr>
<tr><td><span class="badge badge-yellow">API Endpoints</span></td>
  <td>$(safe_count "${DIR_URLS}/api_endpoints.txt")</td>
  <td><pre style="max-height:80px">$(safe_cat "${DIR_URLS}/api_endpoints.txt" | head -5)</pre></td></tr>
<tr><td><span class="badge badge-red">Config/Backup</span></td>
  <td>$(safe_count "${DIR_URLS}/config_and_backup_urls.txt")</td>
  <td><pre style="max-height:80px">$(safe_cat "${DIR_URLS}/config_and_backup_urls.txt" | head -5)</pre></td></tr>
<tr><td><span class="badge badge-red">VCS Exposure</span></td>
  <td>$(safe_count "${DIR_URLS}/vcs_exposure.txt")</td>
  <td><pre style="max-height:80px">$(safe_cat "${DIR_URLS}/vcs_exposure.txt" | head -5)</pre></td></tr>
<tr><td><span class="badge badge-yellow">Documents Leaked</span></td>
  <td>$(safe_count "${DIR_URLS}/documents.txt")</td>
  <td><pre style="max-height:80px">$(safe_cat "${DIR_URLS}/documents.txt" | head -5)</pre></td></tr>
</table>
</div>

<!-- ── JS Secrets ── -->
<div class="section severity-critical">
<h2>🔑 Secrets Found in JavaScript</h2>
<pre>$(safe_cat "${DIR_JS}/secrets_from_js.txt" | head -100)</pre>
<h3>Internal Hosts Referenced in JS</h3>
<pre>$(safe_cat "${DIR_JS}/internal_hosts_js.txt" | head -50)</pre>
<h3>Cloud Storage References in JS</h3>
<pre>$(safe_cat "${DIR_JS}/cloud_refs_js.txt" | head -30)</pre>
</div>

<!-- ── Cloud Storage ── -->
<div class="section severity-high">
<h2>☁ Cloud Storage Exposure</h2>
<pre>$(safe_cat "${DIR_CLOUD}/cloud_all.txt")</pre>
<h3>Open Bucket Contents (Sample)</h3>
<pre>$(safe_cat "${DIR_CLOUD}/bucket_contents.txt" | head -50)</pre>
</div>

<!-- ── GitHub Findings ── -->
<div class="section severity-high">
<h2>🐙 GitHub / Code Repository Findings</h2>
<h3>Secrets in Code</h3>
<pre>$(safe_cat "${DIR_DORKS}/github_secrets.txt" | head -80)</pre>
<h3>Internal Endpoints in Code</h3>
<pre>$(safe_cat "${DIR_DORKS}/github_endpoints.txt" | head -50)</pre>
</div>

<!-- ── CVE Candidates ── -->
<div class="section severity-high">
<h2>🛡 CVE Candidates (Version-Based)</h2>
<pre>$(safe_cat "${DIR_TECH}/cve_candidates.txt" | head -100)</pre>
<h3>Shodan CVEs</h3>
<pre>$(safe_cat "${DIR_HOSTS}/shodan_cves.txt" | head -50)</pre>
</div>

<!-- ── Access Controlled (401/403) ── -->
<div class="section severity-medium">
<h2>🔒 Access Controlled Endpoints (401/403)</h2>
<pre>$(safe_cat "${DIR_HOSTS}/access_controlled.txt" | head -80)</pre>
</div>

<!-- ── High-value Parameters ── -->
<div class="section severity-medium">
<h2>📌 High-Value URL Parameters</h2>
<pre>$(safe_cat "${DIR_URLS}/high_value_params.txt" | head -80)</pre>
</div>

<!-- ── Non-Standard Ports ── -->
<div class="section">
<h2>🔌 Non-Standard Port Exposure</h2>
<pre>$(safe_cat "${DIR_HOSTS}/nonstandard_ports.txt")</pre>
</div>

<!-- ── Redirect Chains ── -->
<div class="section">
<h2>↩ Redirect Chains (Internal Hostname Leakage)</h2>
<pre>$(safe_cat "${DIR_HOSTS}/redirect_chains.txt" | head -50)</pre>
</div>

<!-- ── Manual Actions Required ── -->
<div class="section severity-medium">
<h2>📋 Manual Actions Required</h2>
<p style="color:var(--yellow); margin-bottom:10px;">The following require browser-based dorking (open in incognito/VPN):</p>
<p><a href="../11_dorks/google_dork_urls.txt">→ Google Dork URLs (open in browser)</a></p>
<p><a href="../11_dorks/paste_search_queries.txt">→ Paste Site Search Queries</a></p>
<p><a href="../10_screenshots/eyewitness/report.html">→ EyeWitness Screenshot Report</a></p>
</div>

</div>
<script>
  // Tab functionality if needed in future extension
  document.querySelectorAll('.tab').forEach(t => {
    t.addEventListener('click', () => {
      const group = t.closest('.tabs').dataset.group;
      document.querySelectorAll('[data-group="'+group+'"] .tab').forEach(x => x.classList.remove('active'));
      document.querySelectorAll('#'+group+' .tab-content').forEach(x => x.classList.remove('active'));
      t.classList.add('active');
      document.getElementById(t.dataset.target).classList.add('active');
    });
  });
</script>
</body>
</html>
HTMLEOF

# ── Also generate a flat text summary ──────────────────────────────────────────
cat > "${OUT}/summary.txt" <<EOF
═══════════════════════════════════════════════════════════════
OSINT RECON SUMMARY — ${TARGET}
Generated: $(date -u +"%Y-%m-%d %H:%M UTC")
═══════════════════════════════════════════════════════════════

INFRASTRUCTURE
  ASNs:               $(safe_cat "${DIR_ASN}/org_asns.txt" | tr '\n' ' ')
  CIDR blocks:        $(safe_count "${DIR_ASN}/all_cidrs_final.txt")
  Resolved IPs:       $(safe_count "${DIR_ASN}/resolved_ips.txt")

DISCOVERY
  Total subdomains:   $(safe_count "${DIR_SUBDOMAINS}/all_subdomains.txt")
  Live subdomains:    $(safe_count "${TARGET_DIR}/live_subdomains.txt")
  Total URLs:         $(safe_count "${DIR_URLS}/all_urls.txt")
  CT domains:         $(safe_count "${DIR_CERTS}/domains_from_certs.txt")
  Internal SANs:      $(safe_count "${DIR_CERTS}/internal_naming.txt")

HIGH PRIORITY FINDINGS
  Sensitive URLs:     $(safe_count "${DIR_URLS}/sensitive_urls.txt")
  Auth/Login pages:   $(safe_count "${DIR_URLS}/auth_urls.txt")
  Upload endpoints:   $(safe_count "${DIR_URLS}/upload_urls.txt")
  Admin panels:       $(safe_count "${DIR_URLS}/admin_urls.txt")
  API endpoints:      $(safe_count "${DIR_URLS}/api_endpoints.txt")
  Config/Backup:      $(safe_count "${DIR_URLS}/config_and_backup_urls.txt")
  VCS exposure:       $(safe_count "${DIR_URLS}/vcs_exposure.txt")
  401/403 targets:    $(safe_count "${DIR_HOSTS}/access_controlled.txt")

SECRETS & CODE
  JS secrets found:   $(safe_count "${DIR_JS}/secrets_from_js.txt")
  Internal hosts/JS:  $(safe_count "${DIR_JS}/internal_hosts_js.txt")
  GitHub hits:        $(grep -c '^===' "${DIR_DORKS}/github_secrets.txt" 2>/dev/null || echo 0)

CLOUD
  Cloud findings:     $(safe_count "${DIR_CLOUD}/cloud_all.txt")
  Open buckets:       $(grep -c '^OPEN' "${DIR_CLOUD}/cloud_all.txt" 2>/dev/null || echo 0)
  Exposed files:      $(safe_count "${DIR_CLOUD}/bucket_contents.txt")

VULNERABILITIES
  CVE candidates:     $(grep -c '^===' "${DIR_TECH}/cve_candidates.txt" 2>/dev/null || echo 0)
  Shodan CVEs:        $(safe_count "${DIR_HOSTS}/shodan_cves.txt")
  Takeover cands:     $(safe_count "${DIR_TECH}/takeover_candidates.txt")

REPORT
  HTML Report:        ${REPORT_HTML}
  Raw data:           ${TARGET_DIR}/
═══════════════════════════════════════════════════════════════
EOF

log "Report generated: $REPORT_HTML"
log "Summary: ${OUT}/summary.txt"
cat "${OUT}/summary.txt"
