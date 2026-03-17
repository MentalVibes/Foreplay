#!/usr/bin/env bash
# =============================================================================
# SETUP — Install all dependencies for the recon suite
# Tested on: Kali Linux, Ubuntu 22.04+, ParrotOS
# Run as non-root (will sudo where needed)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="${HOME}/tools"
REQUIREMENTS_DIR="${SCRIPT_DIR}/requirements"

log()  { echo -e "\033[0;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
info() { echo -e "\033[0;36m[*]\033[0m $*"; }

mkdir -p "$TOOLS_DIR"

# ── System dependencies ───────────────────────────────────────────────────────
log "Installing system packages..."
if [[ -f "${REQUIREMENTS_DIR}/apt-packages.txt" ]]; then
  # Read packages, skip comments/blanks
  mapfile -t packages < <(grep -v '^\s*#\|^\s*$' "${REQUIREMENTS_DIR}/apt-packages.txt")
  sudo apt-get update -qq
  sudo apt-get install -y "${packages[@]}" 2>/dev/null || true
else
  warn "apt-packages.txt not found — skipping system packages"
fi

# ── Go tools ─────────────────────────────────────────────────────────────────
export GOPATH="${HOME}/go"
export PATH="${PATH}:${GOPATH}/bin"

log "Installing Go tools..."

if [[ -f "${REQUIREMENTS_DIR}/go-tools.txt" ]]; then
  while IFS='|' read -r pkg name; do
    [[ -z "$pkg" || "$pkg" =~ ^# ]] && continue
    pkg=$(echo "$pkg" | xargs)
    name=$(echo "$name" | xargs)
    if ! command -v "$name" &>/dev/null; then
      info "  Installing $name..."
      go install "$pkg" 2>/dev/null && log "  ✓ $name" || warn "  ✗ $name failed"
    else
      log "  ✓ $name (already installed)"
    fi
  done < "${REQUIREMENTS_DIR}/go-tools.txt"
fi

# Update nuclei templates
if command -v nuclei &>/dev/null; then
  nuclei -update-templates 2>/dev/null || true
  log "Nuclei templates updated"
fi

# ── Python tools ──────────────────────────────────────────────────────────────
log "Installing Python tools..."
if [[ -f "${REQUIREMENTS_DIR}/pip-packages.txt" ]]; then
  pip3 install --quiet --upgrade -r "${REQUIREMENTS_DIR}/pip-packages.txt" 2>/dev/null || true
fi

# ── Ruby tools ────────────────────────────────────────────────────────────────
log "Installing Ruby tools..."
sudo gem install whatweb --quiet 2>/dev/null || warn "whatweb gem install failed"

# ── Git-cloned tools ─────────────────────────────────────────────────────────
log "Cloning additional tools..."

if [[ -f "${REQUIREMENTS_DIR}/git-repos.txt" ]]; then
  while IFS='|' read -r repo dirname; do
    [[ -z "$repo" || "$repo" =~ ^# ]] && continue
    repo=$(echo "$repo" | xargs)
    dirname=$(echo "$dirname" | xargs)
    target_dir="${TOOLS_DIR}/${dirname}"

    if [[ ! -d "$target_dir" ]]; then
      git clone --quiet "$repo" "$target_dir" 2>/dev/null && \
        log "  ✓ $dirname" || warn "  ✗ $dirname clone failed"
    else
      log "  ✓ $dirname (exists)"
    fi
  done < "${REQUIREMENTS_DIR}/git-repos.txt"
fi

# Install Python deps for cloned tools
for reqfile in "${TOOLS_DIR}"/*/requirements.txt; do
  [[ -f "$reqfile" ]] && pip3 install -r "$reqfile" --quiet 2>/dev/null || true
done

[[ -f "${TOOLS_DIR}/EyeWitness/Python/setup/setup.sh" ]] && \
  bash "${TOOLS_DIR}/EyeWitness/Python/setup/setup.sh" 2>/dev/null || true

# ── exploitdb for searchsploit ────────────────────────────────────────────────
if ! command -v searchsploit &>/dev/null; then
  log "Installing exploitdb (searchsploit)..."
  sudo apt-get install -y exploitdb 2>/dev/null || \
    (git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb 2>/dev/null && \
    sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit 2>/dev/null) || true
fi

# ── Update PATH permanently ───────────────────────────────────────────────────
if ! grep -q "GOPATH" "${HOME}/.bashrc" 2>/dev/null; then
  {
    echo ''
    echo 'export GOPATH="${HOME}/go"'
    echo 'export PATH="${PATH}:${GOPATH}/bin"'
  } >> "${HOME}/.bashrc"
  log "GOPATH added to .bashrc — run: source ~/.bashrc"
fi

# ── Set permissions ──────────────────────────────────────────────────────────
log "Setting executable permissions..."
chmod +x "${SCRIPT_DIR}/recon_master.sh"
chmod +x "${SCRIPT_DIR}"/modules/*.sh

# ── Create config from example if missing ─────────────────────────────────────
if [[ ! -f "${SCRIPT_DIR}/config/api_keys.conf" ]] && \
   [[ -f "${SCRIPT_DIR}/config/api_keys.conf.example" ]]; then
  cp "${SCRIPT_DIR}/config/api_keys.conf.example" "${SCRIPT_DIR}/config/api_keys.conf"
  chmod 600 "${SCRIPT_DIR}/config/api_keys.conf"
  log "Created config/api_keys.conf from example — edit it with your API keys"
fi

# ── Verify installations ──────────────────────────────────────────────────────
echo ""
log "═══ Installation Status ═══"
for tool in amass subfinder httpx nuclei gau waybackurls trufflehog gowitness \
            whatweb nmap searchsploit jq curl python3 git parallel dig whois; do
  if command -v "$tool" &>/dev/null; then
    echo -e "  \033[0;32m✓\033[0m $tool"
  else
    echo -e "  \033[0;31m✗\033[0m $tool (not found)"
  fi
done

echo ""
for tool_dir in LinkFinder SecretFinder EyeWitness cloud_enum; do
  if [[ -d "${TOOLS_DIR}/${tool_dir}" ]]; then
    echo -e "  \033[0;32m✓\033[0m ${tool_dir} (${TOOLS_DIR}/${tool_dir})"
  else
    echo -e "  \033[0;31m✗\033[0m ${tool_dir} (missing)"
  fi
done

echo ""
log "Setup complete. Next steps:"
echo "  1. Edit config/api_keys.conf and add your API keys"
echo "  2. source ~/.bashrc"
echo "  3. ./recon_master.sh -t target.com -i hosts.txt"
