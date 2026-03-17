#!/usr/bin/env bash
# =============================================================================
# lib/common.sh — Shared functions for all modules
# Sourced by recon_master.sh before any module runs
# =============================================================================

# ── Logging ───────────────────────────────────────────────────────────────────
log()  { echo -e "\033[0;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
err()  { echo -e "\033[0;31m[✗]\033[0m $*"; }
info() { echo -e "\033[0;36m[*]\033[0m $*"; }

# ── Input Validation ─────────────────────────────────────────────────────────
# Validate domain: only allows a-z, 0-9, hyphens, dots. No shell metacharacters.
validate_domain() {
  local domain="$1"
  if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]]; then
    err "Invalid domain: '$domain' — must contain only alphanumeric, hyphens, dots"
    return 1
  fi
  if [[ ${#domain} -gt 253 ]]; then
    err "Domain too long: ${#domain} chars (max 253)"
    return 1
  fi
  return 0
}

# Validate IP address
validate_ip() {
  local ip="$1"
  if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    return 0
  fi
  return 1
}

# Sanitize a string for use in filenames — strips anything not alnum/hyphen/dot/underscore
sanitize_filename() {
  echo "$1" | tr -cd 'a-zA-Z0-9._-'
}

# ── Safe file operations with flock ──────────────────────────────────────────
# Append to file with flock to prevent corruption during parallel writes
safe_append() {
  local file="$1"
  local content="$2"
  (
    flock -x 200
    echo "$content" >> "$file"
  ) 200>"${file}.lock"
}

# ── Rate-limited curl wrapper ────────────────────────────────────────────────
# Adds User-Agent, timeout, and silent error handling
rcurl() {
  curl -s --max-time "${CURL_TIMEOUT:-20}" \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    "$@" 2>/dev/null || echo ''
}

# ── Safe file count ──────────────────────────────────────────────────────────
safe_count() {
  if [[ -f "$1" && -s "$1" ]]; then
    wc -l < "$1"
  else
    echo 0
  fi
}

safe_cat() {
  [[ -f "$1" ]] && cat "$1" || echo ""
}

# ── Dependency check ─────────────────────────────────────────────────────────
check_tool() {
  local tool="$1"
  if ! command -v "$tool" &>/dev/null; then
    warn "Missing tool: $tool"
    return 1
  fi
  return 0
}

require_tool() {
  local tool="$1"
  local install_hint="${2:-}"
  if ! command -v "$tool" &>/dev/null; then
    err "Required tool missing: $tool"
    [[ -n "$install_hint" ]] && info "  Install: $install_hint"
    return 1
  fi
  return 0
}

# ── Ensure output directory exists ───────────────────────────────────────────
ensure_dir() {
  local dir="$1"
  [[ -d "$dir" ]] || mkdir -p "$dir"
}
