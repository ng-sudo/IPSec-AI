#!/usr/bin/env bash
# =============================================================================
# run_scenario.sh — PS 26160 IPSecAI Testbed
# =============================================================================
# Top-level orchestrator script. Runs a complete scenario end-to-end:
#
#   1. render_configs.py   — render strongSwan configs from templates
#   2. setup_namespaces.sh — create network namespaces and veth pair
#   3. deploy_scenario.sh  — install configs and start strongSwan
#   4. capture.sh          — start PCAP capture (background)
#   5. generate_traffic.sh — generate IPsec-protected traffic
#   6. validate_tunnel.sh  — verify SA establishment
#   7. teardown_namespaces.sh — clean up (always runs, even on failure)
#
# Every step is a gate: if any step fails, the script exits non-zero.
# teardown always runs (via trap) to prevent namespace leaks.
#
# Usage:
#   sudo ./run_scenario.sh <scenario_id> [OPTIONS]
#
# Options:
#   --no-teardown     — skip teardown (useful for debugging)
#   --no-capture      — skip PCAP capture (faster for config testing)
#   --no-traffic      — skip traffic generation
#   --timeout N       — SA establishment timeout in seconds (default: 30)
#   --psk SECRET      — use this PSK instead of auto-generating
#   --traffic-type TYPE — capture and generate one traffic type
#   --legacy          — use ipsec.conf instead of swanctl.conf
#   --dry-run         — render and validate configs only, no execution
#
# Exit codes:
#   0  — scenario completed successfully
#   1  — argument / prerequisite error
#   2  — render / config error
#   3  — namespace setup error
#   4  — deployment / SA establishment error
#   5  — capture error
#   6  — traffic generation error (non-fatal by default)
#   7  — validation error
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTBED_DIR="$(dirname "$SCRIPT_DIR")"
VALIDATE_DIR="${TESTBED_DIR}/validate"

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log_info()  { echo "[INFO]  $(date -u +%H:%M:%S) $*"; }
log_warn()  { echo "[WARN]  $(date -u +%H:%M:%S) $*" >&2; }
log_error() { echo "[ERROR] $(date -u +%H:%M:%S) $*" >&2; }
log_step()  { echo ""; echo "================================================================"; echo "STEP: $*"; echo "================================================================"; }
log_banner(){ echo ""; echo "################################################################"; echo "# $*"; echo "################################################################"; echo ""; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
    cat >&2 <<EOF
Usage: $0 <scenario_id> [OPTIONS]

Options:
  --no-teardown     Skip teardown (for debugging)
  --no-capture      Skip PCAP capture
  --no-traffic      Skip traffic generation
  --timeout N       SA establishment timeout (default: 30s)
  --psk SECRET      Use this PSK
  --legacy          Use ipsec.conf instead of swanctl.conf
  --dry-run         Validate configs only, no execution

Example:
  sudo $0 scen_01_tunnel_aes128cbc_sha256_dh14_pfs_ipv4
EOF
    exit 1
fi

SCENARIO_ID="$1"
shift

DO_TEARDOWN=true
DO_CAPTURE=true
DO_TRAFFIC=true
SA_TIMEOUT=30
PSK_ARG=""
LEGACY_ARG=""
TRAFFIC_TYPE=""
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-teardown)  DO_TEARDOWN=false; shift ;;
        --no-capture)   DO_CAPTURE=false;  shift ;;
        --no-traffic)   DO_TRAFFIC=false;  shift ;;
        --timeout)      SA_TIMEOUT="$2";   shift 2 ;;
        --psk)          PSK_ARG="--psk $2"; shift 2 ;;
        --traffic-type) TRAFFIC_TYPE="$2"; shift 2 ;;
        --legacy)       LEGACY_ARG="--legacy"; shift ;;
        --dry-run)      DRY_RUN=true;      shift ;;
        --help|-h)
            echo "Usage: $0 <scenario_id> [OPTIONS]"
            exit 0
            ;;
        *)
            log_error "Unknown argument: $1"
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (or with sudo)."
    exit 1
fi

# ---------------------------------------------------------------------------
# Timing
# ---------------------------------------------------------------------------
SCENARIO_START=$(date +%s)

# ---------------------------------------------------------------------------
# Trap for cleanup
# ---------------------------------------------------------------------------
CAPTURE_PID=""
TEARDOWN_DONE=false

cleanup() {
    local exit_code=$?
    echo ""
    log_info "Cleanup triggered (exit code: $exit_code)"

    # Stop background capture if running
    if [[ -n "$CAPTURE_PID" ]] && kill -0 "$CAPTURE_PID" 2>/dev/null; then
        log_info "Stopping background capture (PID: $CAPTURE_PID)"
        kill -TERM "$CAPTURE_PID" 2>/dev/null || true
        wait "$CAPTURE_PID" 2>/dev/null || true
    fi

    # Teardown namespaces
    if $DO_TEARDOWN && ! $TEARDOWN_DONE; then
        log_info "Running teardown..."
        bash "${SCRIPT_DIR}/teardown_namespaces.sh" 2>/dev/null || true
        TEARDOWN_DONE=true
    fi

    SCENARIO_END=$(date +%s)
    ELAPSED=$(( SCENARIO_END - SCENARIO_START ))
    echo ""
    log_info "Scenario ${SCENARIO_ID} finished in ${ELAPSED}s (exit: $exit_code)"
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
log_banner "PS 26160 IPSecAI Testbed — Running Scenario: $SCENARIO_ID"
log_info "Start time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log_info "Options:"
log_info "  Teardown:  $DO_TEARDOWN"
log_info "  Capture:   $DO_CAPTURE"
log_info "  Traffic:   $DO_TRAFFIC"
log_info "  SA timeout: ${SA_TIMEOUT}s"
log_info "  Traffic type: ${TRAFFIC_TYPE:-scenario defaults}"
log_info "  Dry-run:   $DRY_RUN"

# ---------------------------------------------------------------------------
# STEP 1: Render configs
# ---------------------------------------------------------------------------
log_step "1/7 — Rendering configuration files"

RENDER_CMD="python3 ${SCRIPT_DIR}/render_configs.py --scenario ${SCENARIO_ID}"
[[ -n "$PSK_ARG" ]] && RENDER_CMD="$RENDER_CMD $PSK_ARG"
$DRY_RUN && RENDER_CMD="$RENDER_CMD --dry-run"

log_info "Running: $RENDER_CMD"
eval "$RENDER_CMD" || {
    log_error "Config rendering failed"
    exit 2
}
log_info "Config rendering: OK"

if $DRY_RUN; then
    log_info "Dry-run mode — stopping after config validation"
    exit 0
fi

# ---------------------------------------------------------------------------
# STEP 2: Setup namespaces
# ---------------------------------------------------------------------------
log_step "2/7 — Setting up network namespaces"

bash "${SCRIPT_DIR}/setup_namespaces.sh" || {
    log_error "Namespace setup failed"
    exit 3
}
log_info "Namespace setup: OK"

# ---------------------------------------------------------------------------
# STEP 3: Deploy scenario
# ---------------------------------------------------------------------------
log_step "3/7 — Deploying scenario to namespaces"

DEPLOY_CMD="bash ${SCRIPT_DIR}/deploy_scenario.sh ${SCENARIO_ID} --timeout ${SA_TIMEOUT}"
[[ -n "$LEGACY_ARG" ]] && DEPLOY_CMD="$DEPLOY_CMD $LEGACY_ARG"

eval "$DEPLOY_CMD" || {
    log_error "Scenario deployment failed"
    exit 4
}
log_info "Scenario deployment: OK"

# ---------------------------------------------------------------------------
# STEP 4: Start capture (background)
# ---------------------------------------------------------------------------
if $DO_CAPTURE; then
    log_step "4/7 — Starting PCAP capture (background)"

    CAPTURE_ARGS=("${SCENARIO_ID}" --background)
    [[ -n "$TRAFFIC_TYPE" ]] && CAPTURE_ARGS+=(--traffic-type "$TRAFFIC_TYPE")
    CAPTURE_PID=$(bash "${SCRIPT_DIR}/capture.sh" "${CAPTURE_ARGS[@]}")
    log_info "Capture started (PID: $CAPTURE_PID)"
else
    log_step "4/7 — Skipping PCAP capture (--no-capture)"
fi

# ---------------------------------------------------------------------------
# STEP 5: Generate traffic
# ---------------------------------------------------------------------------
if $DO_TRAFFIC; then
    log_step "5/7 — Generating traffic"

    TRAFFIC_ARGS=("${SCENARIO_ID}")
    [[ -n "$TRAFFIC_TYPE" ]] && TRAFFIC_ARGS+=(--types "$TRAFFIC_TYPE")
    bash "${SCRIPT_DIR}/generate_traffic.sh" "${TRAFFIC_ARGS[@]}" || {
        log_warn "Traffic generation had issues (non-fatal)"
    }
    log_info "Traffic generation: OK"
else
    log_step "5/7 — Skipping traffic generation (--no-traffic)"
fi

# ---------------------------------------------------------------------------
# STEP 6: Validate tunnel
# ---------------------------------------------------------------------------
log_step "6/7 — Validating tunnel"

bash "${VALIDATE_DIR}/validate_tunnel.sh" "${SCENARIO_ID}" || {
    log_error "Tunnel validation failed"
    exit 7
}
log_info "Tunnel validation: OK"

# ---------------------------------------------------------------------------
# STEP 7: Stop capture and validate PCAP
# ---------------------------------------------------------------------------
if $DO_CAPTURE && [[ -n "$CAPTURE_PID" ]]; then
    log_step "7/7 — Stopping capture and validating PCAP"

    # Wait for capture to finish (it runs for the scenario's capture_duration)
    log_info "Waiting for capture to complete (PID: $CAPTURE_PID)..."
    wait "$CAPTURE_PID" 2>/dev/null || true
    CAPTURE_PID=""

    # Find the most recent PCAP for this scenario
    REPO_DIR="$(dirname "$TESTBED_DIR")"
    LATEST_PCAP=$(ls -t "${REPO_DIR}/dataset/raw/${SCENARIO_ID}_"*.pcap 2>/dev/null | head -1 || true)

    if [[ -n "$LATEST_PCAP" ]]; then
        log_info "Validating PCAP: $LATEST_PCAP"
        python3 "${VALIDATE_DIR}/check_pcap.py" "$LATEST_PCAP" || {
            log_warn "PCAP validation had issues (non-fatal)"
        }
    else
        log_warn "No PCAP file found for scenario $SCENARIO_ID"
    fi
else
    log_step "7/7 — Skipping PCAP validation"
fi

# ---------------------------------------------------------------------------
# Success banner
# ---------------------------------------------------------------------------
SCENARIO_END=$(date +%s)
ELAPSED=$(( SCENARIO_END - SCENARIO_START ))

echo ""
log_banner "Scenario COMPLETED: $SCENARIO_ID"
echo "  Duration:  ${ELAPSED}s"
echo "  Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
if $DO_CAPTURE; then
    REPO_DIR="$(dirname "$TESTBED_DIR")"
    echo "  PCAP dir:  ${REPO_DIR}/dataset/raw/"
fi
echo ""
