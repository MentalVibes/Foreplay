#!/usr/bin/env bash
# =============================================================================
# MODULE 01 — ASN & IP Ownership Mapping
# Input:  $INPUT_FILE (hostnames/IPs), $TARGET
# Output: $DIR_ASN/
#   asn_records.json     — per-IP ASN data
#   cidrs.txt            — all CIDR blocks owned by same org
#   all_ips.txt          — expanded IP list from CIDRs
#   org_asns.txt         — all ASNs tied to the org
# =============================================================================

set -euo pipefail
source "${LIB_DIR}/common.sh"
OUT="${DIR_ASN}"


# ── Dependency check ──────────────────────────────────────────────────────────
for tool in curl jq whois amass; do
  if ! command -v "$tool" &>/dev/null; then
    warn "Missing: $tool — install it for full coverage"
  fi
done

# ── Step 1: Resolve all hostnames to IPs ─────────────────────────────────────
info "Resolving hostnames to IPs..."
touch "${OUT}/resolved_ips.txt"

while IFS= read -r host; do
  [[ -z "$host" || "$host" =~ ^# ]] && continue

  # Already an IP?
  if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "$host" >> "${OUT}/resolved_ips.txt"
  else
    # Resolve via dig, fallback to host command
    resolved=$(dig +short "$host" A 2>/dev/null | grep -E '^[0-9]' || true)
    if [[ -n "$resolved" ]]; then
      echo "$resolved" >> "${OUT}/resolved_ips.txt"
      echo "$host -> $resolved" >> "${OUT}/hostname_ip_map.txt"
    fi
  fi
done < "$INPUT_FILE"

sort -u "${OUT}/resolved_ips.txt" -o "${OUT}/resolved_ips.txt"
log "Resolved $(wc -l < "${OUT}/resolved_ips.txt") unique IPs"

# ── Step 2: IP → ASN via BGPView API ─────────────────────────────────────────
info "Querying BGPView for ASN data..."
echo "[]" > "${OUT}/asn_records.json"
touch "${OUT}/org_asns.txt"

while IFS= read -r ip; do
  [[ -z "$ip" ]] && continue

  response=$(curl -s --max-time 10 \
    "https://api.bgpview.io/ip/${ip}" \
    -H "Accept: application/json" 2>/dev/null || echo '{}')

  if echo "$response" | jq -e '.status == "ok"' &>/dev/null; then
    # Extract ASN
    asn=$(echo "$response" | jq -r '.data.prefixes[0].asn.asn // empty' 2>/dev/null || true)
    org=$(echo "$response" | jq -r '.data.prefixes[0].asn.name // empty' 2>/dev/null || true)
    prefix=$(echo "$response" | jq -r '.data.prefixes[0].prefix // empty' 2>/dev/null || true)

    if [[ -n "$asn" ]]; then
      echo "AS${asn}" >> "${OUT}/org_asns.txt"
      jq --arg ip "$ip" --arg asn "AS${asn}" --arg org "$org" --arg prefix "$prefix" \
        '. += [{"ip": $ip, "asn": $asn, "org": $org, "prefix": $prefix}]' \
        "${OUT}/asn_records.json" > "${OUT}/asn_records.tmp.json" && \
        mv "${OUT}/asn_records.tmp.json" "${OUT}/asn_records.json"

      echo "$ip -> AS${asn} ($org) [$prefix]" >> "${OUT}/asn_summary.txt"
    fi
  fi

  sleep 0.5  # rate limit courtesy
done < "${OUT}/resolved_ips.txt"

sort -u "${OUT}/org_asns.txt" -o "${OUT}/org_asns.txt"
log "Found ASNs: $(cat "${OUT}/org_asns.txt" | tr '\n' ' ')"

# ── Step 3: ASN → All Prefixes via BGPView ────────────────────────────────────
info "Expanding ASNs to all owned CIDR prefixes..."
touch "${OUT}/cidrs.txt"

while IFS= read -r asn; do
  [[ -z "$asn" ]] && continue
  asn_num="${asn#AS}"

  prefix_data=$(curl -s --max-time 15 \
    "https://api.bgpview.io/asn/${asn_num}/prefixes" \
    -H "Accept: application/json" 2>/dev/null || echo '{}')

  # IPv4 prefixes
  echo "$prefix_data" | jq -r \
    '.data.ipv4_prefixes[].prefix // empty' 2>/dev/null >> "${OUT}/cidrs.txt" || true

  sleep 0.5
done < "${OUT}/org_asns.txt"

sort -u "${OUT}/cidrs.txt" -o "${OUT}/cidrs.txt"
log "Found $(wc -l < "${OUT}/cidrs.txt") CIDR blocks"

# ── Step 4: WHOIS org name cross-reference ────────────────────────────────────
info "Running WHOIS for org name cross-reference..."
touch "${OUT}/whois_orgs.txt"

# Get org name from first IP's whois
first_ip=$(head -1 "${OUT}/resolved_ips.txt")
if [[ -n "$first_ip" ]] && command -v whois &>/dev/null; then
  whois "$first_ip" 2>/dev/null | grep -iE "^(org-name|organization|orgname|descr|netname):" \
    >> "${OUT}/whois_orgs.txt" || true
fi

# ── Step 5: Amass intel (passive ASN + reverse whois) ─────────────────────────
if command -v amass &>/dev/null; then
  info "Running amass intel (passive)..."

  # From domain
  amass intel -passive -d "$TARGET" -timeout 5 \
    > "${OUT}/amass_intel_domain.txt" 2>/dev/null || true

  # From each ASN
  while IFS= read -r asn; do
    [[ -z "$asn" ]] && continue
    asn_num="${asn#AS}"
    amass intel -passive -asn "$asn_num" -timeout 5 \
      >> "${OUT}/amass_intel_asn.txt" 2>/dev/null || true
  done < "${OUT}/org_asns.txt"

  # Reverse whois from target domain
  amass intel -passive -whois -d "$TARGET" -timeout 5 \
    > "${OUT}/amass_reverse_whois.txt" 2>/dev/null || true

  log "amass intel complete"
else
  warn "amass not installed — skipping amass intel"
fi

# ── Step 6: Hurricane Electric cross-reference ────────────────────────────────
info "Pulling ASN prefix data from HE BGP..."
while IFS= read -r asn; do
  [[ -z "$asn" ]] && continue
  asn_num="${asn#AS}"
  curl -s --max-time 10 \
    "https://bgp.he.net/AS${asn_num}#_prefixes" \
    -H "User-Agent: Mozilla/5.0" 2>/dev/null | \
    grep -oP '\d+\.\d+\.\d+\.\d+/\d+' >> "${OUT}/he_prefixes.txt" || true
  sleep 1
done < "${OUT}/org_asns.txt"

[[ -f "${OUT}/he_prefixes.txt" ]] && \
  sort -u "${OUT}/he_prefixes.txt" -o "${OUT}/he_prefixes.txt"

# ── Step 7: Consolidate all CIDRs ─────────────────────────────────────────────
info "Consolidating all CIDR sources..."
cat "${OUT}/cidrs.txt" "${OUT}/he_prefixes.txt" 2>/dev/null | \
  sort -u > "${OUT}/all_cidrs_final.txt"

log "Total unique CIDRs: $(wc -l < "${OUT}/all_cidrs_final.txt")"

# ── Step 8: ipinfo.io enrichment on input IPs ─────────────────────────────────
if [[ -n "${IPINFO_TOKEN:-}" ]]; then
  info "Enriching IPs via ipinfo.io..."
  echo "[" > "${OUT}/ipinfo_enriched.json"
  first=true

  while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    data=$(curl -s --max-time 8 \
      "https://ipinfo.io/${ip}?token=${IPINFO_TOKEN}" 2>/dev/null || echo '{}')

    [[ "$first" == "true" ]] && first=false || echo "," >> "${OUT}/ipinfo_enriched.json"
    echo "$data" >> "${OUT}/ipinfo_enriched.json"
    sleep 0.3
  done < "${OUT}/resolved_ips.txt"
  echo "]" >> "${OUT}/ipinfo_enriched.json"
  log "ipinfo enrichment saved"
else
  warn "IPINFO_TOKEN not set — skipping ipinfo enrichment"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "── Module 01 Summary ──────────────────────────────────────"
echo "  Resolved IPs:   $(wc -l < "${OUT}/resolved_ips.txt")"
echo "  ASNs found:     $(wc -l < "${OUT}/org_asns.txt")"
echo "  CIDR blocks:    $(wc -l < "${OUT}/all_cidrs_final.txt")"
echo "  Output dir:     ${OUT}"
echo "────────────────────────────────────────────────────────────"
