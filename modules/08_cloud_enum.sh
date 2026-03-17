#!/usr/bin/env bash
# =============================================================================
# MODULE 08 — Cloud Storage Enumeration (S3, Azure Blob, GCP)
# Passive: unauthenticated HEAD/GET on permuted bucket names
# Input:  $TARGET
# Output: $DIR_CLOUD/
#   s3_found.txt          — accessible S3 buckets
#   azure_found.txt       — accessible Azure Blob accounts
#   gcp_found.txt         — accessible GCP buckets
#   cloud_all.txt         — all findings consolidated
#   bucket_contents.txt   — file listings from open buckets
# =============================================================================

set -euo pipefail
source "${LIB_DIR}/common.sh"
OUT="${DIR_CLOUD}"


touch "${OUT}/s3_found.txt" "${OUT}/azure_found.txt" "${OUT}/gcp_found.txt"

# ── Generate bucket name permutations ─────────────────────────────────────────
info "Generating bucket name permutations..."

# Base keywords from target domain
BASE=$(echo "$TARGET" | sed 's/\..*//')           # target (no TLD)
BASE_NODASH=$(echo "$BASE" | tr -d '-')           # targetcompany
BASE_WORDS=$(echo "$BASE" | tr '-' ' ')           # target company (space separated)

PERMUTATIONS_FILE="${OUT}/bucket_permutations.txt"

# Suffixes and prefixes
SUFFIXES=("" "-dev" "-prod" "-staging" "-stage" "-uat" "-test" "-qa" "-demo"
  "-backup" "-backups" "-bak" "-data" "-assets" "-static" "-media" "-files"
  "-uploads" "-upload" "-images" "-img" "-logs" "-log" "-cdn" "-content"
  "-public" "-private" "-secret" "-internal" "-corp" "-web" "-app" "-api"
  "-archive" "-export" "-dump" "-old" "-new" "-tmp" "-temp" "-cache"
  "-config" "-configs" "-admin" "-mgmt" "-infra" "-ops" "-devops" "-cicd"
  "-build" "-builds" "-artifacts" "-releases" "-packages")

PREFIXES=("" "dev-" "prod-" "staging-" "test-" "backup-" "data-" "assets-"
  "static-" "media-" "files-" "upload-" "logs-" "internal-" "corp-"
  "www-" "mail-" "app-" "api-" "cdn-")

> "$PERMUTATIONS_FILE"

for prefix in "${PREFIXES[@]}"; do
  for suffix in "${SUFFIXES[@]}"; do
    echo "${prefix}${BASE}${suffix}"        >> "$PERMUTATIONS_FILE"
    echo "${prefix}${BASE_NODASH}${suffix}" >> "$PERMUTATIONS_FILE"
  done
done

# Also add permutations from company name words
for word in $BASE_WORDS; do
  for suffix in "" "-backup" "-data" "-assets" "-uploads" "-logs"; do
    echo "${word}${suffix}" >> "$PERMUTATIONS_FILE"
  done
done

# Add refs found in JS analysis
if [[ -f "${DIR_JS}/cloud_refs_js.txt" ]]; then
  grep -oP 's3://\K[a-z0-9._-]+|(?<=//)[a-z0-9._-]+(?=\.s3[.-])' \
    "${DIR_JS}/cloud_refs_js.txt" 2>/dev/null >> "$PERMUTATIONS_FILE" || true
  grep -oP '(?<=//)[a-z0-9]+(?=\.blob\.core\.windows\.net)' \
    "${DIR_JS}/cloud_refs_js.txt" 2>/dev/null >> "${OUT}/azure_permutations.txt" || true
  grep -oP '(?<=googleapis\.com/)[a-z0-9._-]+' \
    "${DIR_JS}/cloud_refs_js.txt" 2>/dev/null >> "${OUT}/gcp_permutations.txt" || true
fi

sort -u "$PERMUTATIONS_FILE" -o "$PERMUTATIONS_FILE"
log "Generated $(wc -l < "$PERMUTATIONS_FILE") permutations"

# ── cloud_enum (best all-in-one tool) ────────────────────────────────────────
if command -v cloud_enum &>/dev/null || python3 -c "import cloud_enum" &>/dev/null 2>&1; then
  info "Running cloud_enum..."
  cloud_enum \
    -k "$BASE" \
    -k "$BASE_NODASH" \
    --threads "$THREADS" \
    -l "${OUT}/cloud_enum_results.txt" \
    2>/dev/null || true
  log "cloud_enum complete"

elif [[ -f "${HOME}/tools/cloud_enum/cloud_enum.py" ]]; then
  python3 "${HOME}/tools/cloud_enum/cloud_enum.py" \
    -k "$BASE" \
    -k "$BASE_NODASH" \
    --threads "$THREADS" \
    -l "${OUT}/cloud_enum_results.txt" \
    2>/dev/null || true
  log "cloud_enum complete"
else
  warn "cloud_enum not found — pip install cloud-enum OR git clone https://github.com/initstring/cloud_enum ~/tools/cloud_enum"
fi

# ── S3 Enumeration ────────────────────────────────────────────────────────────
info "Probing S3 buckets..."

check_s3() {
  local bucket="$1"
  local url="https://${bucket}.s3.amazonaws.com"
  local response
  response=$(curl -s --max-time 8 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")

  case "$response" in
    200)
      log "[S3-OPEN] $bucket — PUBLIC READ"
      echo "OPEN|$bucket|$url" >> "${OUT}/s3_found.txt"
      # Try to list contents
      content=$(curl -s --max-time 15 "$url" 2>/dev/null | \
        grep -oP '(?<=<Key>)[^<]+' | head -50 || true)
      if [[ -n "$content" ]]; then
        echo "=== $bucket ===" >> "${OUT}/bucket_contents.txt"
        echo "$content" >> "${OUT}/bucket_contents.txt"
      fi
      ;;
    403)
      # Bucket exists but access denied — still useful intelligence
      echo "EXISTS-DENIED|$bucket|$url" >> "${OUT}/s3_found.txt"
      ;;
    301|302)
      # Redirect — bucket exists in different region
      echo "EXISTS-REDIRECT|$bucket|$url" >> "${OUT}/s3_found.txt"
      ;;
    404)
      :  # Bucket does not exist
      ;;
  esac
}

export -f check_s3
export OUT

# Run S3 checks in parallel
if command -v parallel &>/dev/null; then
  cat "$PERMUTATIONS_FILE" | \
    parallel -j "$THREADS" --delay 0.1 check_s3 {} 2>/dev/null
else
  while IFS= read -r bucket; do
    check_s3 "$bucket"
    sleep 0.1
  done < "$PERMUTATIONS_FILE"
fi

# ── s3scanner ────────────────────────────────────────────────────────────────
if command -v s3scanner &>/dev/null; then
  info "Running s3scanner..."
  s3scanner scan \
    --buckets-file "$PERMUTATIONS_FILE" \
    --threads "$THREADS" \
    --out-file "${OUT}/s3scanner_results.json" \
    2>/dev/null || true
  log "s3scanner complete"
else
  warn "s3scanner not installed — pip install s3scanner"
fi

# ── Azure Blob Enumeration ────────────────────────────────────────────────────
info "Probing Azure Blob Storage accounts..."

AZURE_PERMS="${OUT}/azure_permutations.txt"
# Azure account names: 3-24 chars, lowercase alphanumeric only
cat "$PERMUTATIONS_FILE" | \
  tr -d '-_.' | \
  awk 'length>=3 && length<=24' | \
  sort -u > "$AZURE_PERMS" 2>/dev/null || true

check_azure() {
  local account="$1"
  local url="https://${account}.blob.core.windows.net"
  local response
  response=$(curl -s --max-time 8 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")

  case "$response" in
    200|400)
      # 400 = account exists (needs container name)
      log "[AZURE] Account exists: $account"
      echo "EXISTS|$account|$url" >> "${OUT}/azure_found.txt"

      # Try common container names
      for container in "\$web" "public" "files" "uploads" "data" "assets" "static" "media" "backup" "logs"; do
        cont_url="${url}/${container}?restype=container&comp=list"
        cont_resp=$(curl -s --max-time 8 -o /dev/null -w "%{http_code}" "$cont_url" 2>/dev/null || echo "000")
        if [[ "$cont_resp" == "200" ]]; then
          log "[AZURE-OPEN] ${account}/${container}"
          echo "OPEN|$account|$container|$cont_url" >> "${OUT}/azure_found.txt"
          curl -s --max-time 15 "$cont_url" 2>/dev/null | \
            grep -oP '(?<=<Name>)[^<]+' | head -50 | \
            awk -v a="$account" -v c="$container" '{print a "/" c "/" $0}' \
            >> "${OUT}/bucket_contents.txt" || true
        fi
      done
      ;;
  esac
}

export -f check_azure

if command -v parallel &>/dev/null; then
  cat "$AZURE_PERMS" | \
    parallel -j "$THREADS" --delay 0.1 check_azure {} 2>/dev/null
else
  while IFS= read -r account; do
    check_azure "$account"
    sleep 0.15
  done < "$AZURE_PERMS"
fi

# ── GCP Bucket Enumeration ────────────────────────────────────────────────────
info "Probing GCP Cloud Storage buckets..."

check_gcp() {
  local bucket="$1"
  local url="https://storage.googleapis.com/${bucket}"
  local response
  response=$(curl -s --max-time 8 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")

  case "$response" in
    200)
      log "[GCP-OPEN] $bucket — PUBLIC READ"
      echo "OPEN|$bucket|$url" >> "${OUT}/gcp_found.txt"
      curl -s --max-time 15 "$url" 2>/dev/null | \
        grep -oP '(?<=<Key>)[^<]+' | head -50 | \
        awk -v b="$bucket" '{print b "/" $0}' \
        >> "${OUT}/bucket_contents.txt" || true
      ;;
    403)
      echo "EXISTS-DENIED|$bucket|$url" >> "${OUT}/gcp_found.txt"
      ;;
  esac
}

export -f check_gcp

if command -v parallel &>/dev/null; then
  cat "$PERMUTATIONS_FILE" | \
    parallel -j "$THREADS" --delay 0.1 check_gcp {} 2>/dev/null
else
  while IFS= read -r bucket; do
    check_gcp "$bucket"
    sleep 0.1
  done < "$PERMUTATIONS_FILE"
fi

# ── Consolidate ───────────────────────────────────────────────────────────────
cat \
  "${OUT}/s3_found.txt" \
  "${OUT}/azure_found.txt" \
  "${OUT}/gcp_found.txt" \
  2>/dev/null | sort -u > "${OUT}/cloud_all.txt"

echo ""
echo "── Module 08 Summary ──────────────────────────────────────"
echo "  S3 buckets found:         $(grep -c 'OPEN\|EXISTS' "${OUT}/s3_found.txt" 2>/dev/null || echo 0)"
echo "  S3 OPEN (public read):    $(grep -c '^OPEN' "${OUT}/s3_found.txt" 2>/dev/null || echo 0)"
echo "  Azure accounts found:     $(grep -c 'OPEN\|EXISTS' "${OUT}/azure_found.txt" 2>/dev/null || echo 0)"
echo "  GCP buckets found:        $(grep -c 'OPEN\|EXISTS' "${OUT}/gcp_found.txt" 2>/dev/null || echo 0)"
echo "  Files listed from open:   $(wc -l < "${OUT}/bucket_contents.txt" 2>/dev/null || echo 0)"
echo "────────────────────────────────────────────────────────────"
