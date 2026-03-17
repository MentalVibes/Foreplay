#!/usr/bin/env bash
# =============================================================================
# MODULE 01 — ASN & IP Ownership Mapping
# Input:  $INPUT_FILE (hostnames/IPs), $TARGET
# Output: $DIR_ASN/
#   asn_records.json     — per-IP ASN data
#   cidrs.txt            — all CIDR blocks owned by same org
#   all_cidrs_final.txt  — consolidated CIDRs from all sources
#   org_asns.txt         — all ASNs tied to the org
#
# CHANGELOG:
#   BGPView (api.bgpview.io) shut down Nov 26, 2025.
#   Replaced with RIPEstat (stat.ripe.net) — free, no auth, RIPE NCC maintained.
#   Endpoints used:
#     - network-info:    IP → ASN + prefix
#     - as-overview:     ASN → holder name
#     - ris-prefixes:    ASN → all originated prefixes
#     - routing-status:  ASN → visibility/announced space
# =============================================================================

set -euo pipefail
source "${LIB_DIR}/common.sh"
OUT="${DIR_ASN}"

for tool in curl jq whois; do
  check_tool "$tool" || true
done

# ── Step 1: Resolve all hostnames to IPs ─────────────────────────────────────
info "Resolving hostnames to IPs..."
touch "${OUT}/resolved_ips.txt" "${OUT}/hostname_ip_map.txt"

while IFS= read -r host || [[ -n "$host" ]]; do
  [[ -z "$host" || "$host" =~ ^# ]] && continue
  host=$(echo "$host" | tr -d '[:space:]')

  if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "$host" >> "${OUT}/resolved_ips.txt"
  else
    resolved=$(dig +short "$host" A 2>/dev/null | grep -E '^[0-9]' || true)
    if [[ -n "$resolved" ]]; then
      echo "$resolved" >> "${OUT}/resolved_ips.txt"
      echo "$host -> $resolved" >> "${OUT}/hostname_ip_map.txt"
    fi
  fi
done < "$INPUT_FILE"

sort -u "${OUT}/resolved_ips.txt" -o "${OUT}/resolved_ips.txt"
log "Resolved $(wc -l < "${OUT}/resolved_ips.txt") unique IPs"

# ── Step 2: IP → ASN via RIPEstat network-info ───────────────────────────────
info "Querying RIPEstat for ASN data..."
echo "[]" > "${OUT}/asn_records.json"
touch "${OUT}/org_asns.txt"

while IFS= read -r ip; do
  [[ -z "$ip" ]] && continue

  response=$(curl -s --max-time 10 \
    "https://stat.ripe.net/data/network-info/data.json?resource=${ip}" \
    -H "Accept: application/json" 2>/dev/null || echo '{}')

  if echo "$response" | jq -e '.data.asns[0]' &>/dev/null; then
    asn=$(echo "$response" | jq -r '.data.asns[0] // empty' 2>/dev/null || true)
    prefix=$(echo "$response" | jq -r '.data.prefix // empty' 2>/dev/null || true)

    org=""
    if [[ -n "$asn" ]]; then
      # Get ASN holder name
      as_info=$(curl -s --max-time 8 \
        "https://stat.ripe.net/data/as-overview/data.json?resource=AS${asn}" \
        -H "Accept: application/json" 2>/dev/null || echo '{}')
      org=$(echo "$as_info" | jq -r '.data.holder // empty' 2>/dev/null || true)

      echo "AS${asn}" >> "${OUT}/org_asns.txt"
      jq --arg ip "$ip" --arg asn "AS${asn}" --arg org "$org" --arg prefix "$prefix" \
        '. += [{"ip": $ip, "asn": $asn, "org": $org, "prefix": $prefix}]' \
        "${OUT}/asn_records.json" > "${OUT}/asn_records.tmp.json" && \
        mv "${OUT}/asn_records.tmp.json" "${OUT}/asn_records.json"

      echo "$ip -> AS${asn} ($org) [$prefix]" >> "${OUT}/asn_summary.txt"
    fi
  fi

  sleep 0.5
done < "${OUT}/resolved_ips.txt"

sort -u "${OUT}/org_asns.txt" -o "${OUT}/org_asns.txt"
log "Found ASNs: $(cat "${OUT}/org_asns.txt" | tr '\n' ' ')"

# ── Step 3: ASN → All Prefixes via RIPEstat ris-prefixes ─────────────────────
info "Expanding ASNs to all owned CIDR prefixes..."
touch "${OUT}/cidrs.txt"

while IFS= read -r asn; do
  [[ -z "$asn" ]] && continue
  asn_num="${asn#AS}"
  [[ ! "$asn_num" =~ ^[0-9]+$ ]] && continue

  prefix_data=$(curl -s --max-time 15 \
    "https://stat.ripe.net/data/ris-prefixes/data.json?resource=AS${asn_num}&list_prefixes=true&af=v4" \
    -H "Accept: application/json" 2>/dev/null || echo '{}')

  # Extract originated IPv4 prefixes
  echo "$prefix_data" | jq -r \
    '.data.prefixes.v4.originating[]? // empty' 2>/dev/null >> "${OUT}/cidrs.txt" || true

  sleep 0.5
done < "${OUT}/org_asns.txt"

sort -u "${OUT}/cidrs.txt" -o "${OUT}/cidrs.txt"
log "Found $(wc -l < "${OUT}/cidrs.txt") CIDR blocks"

# ── Step 4: WHOIS org name cross-reference ────────────────────────────────────
info "Running WHOIS for org name cross-reference..."
touch "${OUT}/whois_orgs.txt"

first_ip=$(head -1 "${OUT}/resolved_ips.txt" 2>/dev/null || true)
if [[ -n "$first_ip" ]] && check_tool whois; then
  whois "$first_ip" 2>/dev/null | grep -iE "^(org-name|organization|orgname|descr|netname):" \
    >> "${OUT}/whois_orgs.txt" || true
fi

# ── Step 5: Amass intel (passive ASN + reverse whois) ─────────────────────────
if check_tool amass; then
  info "Running amass intel (passive)..."

  amass intel -passive -d "$TARGET" -timeout 5 \
    > "${OUT}/amass_intel_domain.txt" 2>/dev/null || true

  while IFS= read -r asn; do
    [[ -z "$asn" ]] && continue
    asn_num="${asn#AS}"
    [[ ! "$asn_num" =~ ^[0-9]+$ ]] && continue
    amass intel -passive -asn "$asn_num" -timeout 5 \
      >> "${OUT}/amass_intel_asn.txt" 2>/dev/null || true
  done < "${OUT}/org_asns.txt"

  amass intel -passive -whois -d "$TARGET" -timeout 5 \
    > "${OUT}/amass_reverse_whois.txt" 2>/dev/null || true

  log "amass intel complete"
fi

# ── Step 6: Hurricane Electric cross-reference ────────────────────────────────
info "Pulling ASN prefix data from HE BGP..."
touch "${OUT}/he_prefixes.txt"

while IFS= read -r asn; do
  [[ -z "$asn" ]] && continue
  asn_num="${asn#AS}"
  [[ ! "$asn_num" =~ ^[0-9]+$ ]] && continue
  curl -s --max-time 10 \
    "https://bgp.he.net/AS${asn_num}#_prefixes" \
    -H "User-Agent: Mozilla/5.0" 2>/dev/null | \
    grep -oP '\d+\.\d+\.\d+\.\d+/\d+' >> "${OUT}/he_prefixes.txt" || true
  sleep 1
done < "${OUT}/org_asns.txt"

[[ -f "${OUT}/he_prefixes.txt" ]] && \
  sort -u "${OUT}/he_prefixes.txt" -o "${OUT}/he_prefixes.txt"

# ── Step 7: RIPEstat routing-status enrichment ────────────────────────────────
info "Enriching ASN routing status via RIPEstat..."
while IFS= read -r asn; do
  [[ -z "$asn" ]] && continue
  asn_num="${asn#AS}"
  [[ ! "$asn_num" =~ ^[0-9]+$ ]] && continue

  routing=$(curl -s --max-time 10 \
    "https://stat.ripe.net/data/routing-status/data.json?resource=AS${asn_num}" \
    -H "Accept: application/json" 2>/dev/null || echo '{}')

  announced=$(echo "$routing" | jq -r '.data.announced_space.v4.prefixes // 0' 2>/dev/null || echo 0)
  visibility=$(echo "$routing" | jq -r '.data.visibility.v4.ris_peers_seeing // 0' 2>/dev/null || echo 0)
  echo "AS${asn_num} | Announced v4 prefixes: $announced | RIS visibility: $visibility" \
    >> "${OUT}/routing_status.txt"
  sleep 0.5
done < "${OUT}/org_asns.txt"

# ── Step 8: Consolidate all CIDRs ────────────────────────────────────────────
info "Consolidating all CIDR sources..."
cat "${OUT}/cidrs.txt" "${OUT}/he_prefixes.txt" 2>/dev/null | \
  sort -u > "${OUT}/all_cidrs_final.txt"

log "Total unique CIDRs: $(wc -l < "${OUT}/all_cidrs_final.txt")"

# ── Step 9: ipinfo.io enrichment on input IPs ────────────────────────────────
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
