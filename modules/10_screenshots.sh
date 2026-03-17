#!/usr/bin/env bash
# =============================================================================
# MODULE 10 — Screenshots (EyeWitness / gowitness)
# Input:  $TARGET_DIR/all_live_urls.txt
# Output: $DIR_SCREENSHOTS/
#   eyewitness/            — full EyeWitness HTML report
#   gowitness.db           — gowitness sqlite database
#   screenshots/           — individual PNG files
# =============================================================================

set -euo pipefail
source "${LIB_DIR}/common.sh"
OUT="${DIR_SCREENSHOTS}"


LIVE_URLS="${TARGET_DIR}/all_live_urls.txt"
[[ ! -f "$LIVE_URLS" ]] && warn "No live URLs found" && exit 0

# ── EyeWitness ────────────────────────────────────────────────────────────────
if command -v eyewitness &>/dev/null || [[ -f "${HOME}/tools/EyeWitness/Python/EyeWitness.py" ]]; then
  info "Running EyeWitness..."

  EW_CMD="eyewitness"
  [[ ! $(command -v eyewitness) ]] && \
    EW_CMD="python3 ${HOME}/tools/EyeWitness/Python/EyeWitness.py"

  $EW_CMD \
    --web \
    -f "$LIVE_URLS" \
    --timeout 20 \
    --threads "$THREADS" \
    --resolve \
    --prepend-https \
    -d "${OUT}/eyewitness" \
    --no-prompt \
    2>/dev/null || true

  log "EyeWitness complete — report: ${OUT}/eyewitness/report.html"
else
  warn "EyeWitness not installed — git clone https://github.com/RedSiege/EyeWitness ~/tools/EyeWitness && ~/tools/EyeWitness/Python/setup/setup.sh"
fi

# ── gowitness (alternative, often faster) ─────────────────────────────────────
if command -v gowitness &>/dev/null; then
  info "Running gowitness..."
  mkdir -p "${OUT}/gowitness_screens"

  gowitness file \
    -f "$LIVE_URLS" \
    --threads "$THREADS" \
    --timeout 20 \
    --screenshot-path "${OUT}/gowitness_screens" \
    --db-path "${OUT}/gowitness.db" \
    2>/dev/null || true

  # Generate HTML report
  gowitness report generate \
    --db-path "${OUT}/gowitness.db" \
    --screenshot-path "${OUT}/gowitness_screens" \
    --open 2>/dev/null || true

  log "gowitness complete"
else
  warn "gowitness not installed — go install github.com/sensepost/gowitness@latest"
fi

echo ""
echo "── Module 10 Summary ──────────────────────────────────────"
echo "  URLs screenshotted:     $(wc -l < "$LIVE_URLS")"
echo "  EyeWitness report:      ${OUT}/eyewitness/report.html"
echo "  Gowitness DB:           ${OUT}/gowitness.db"
echo "────────────────────────────────────────────────────────────"
