#!/usr/bin/env bash
# =============================================================================
# deploy_scenario.sh — PS 26160 IPSecAI Testbed
# =============================================================================
# Deploys a rendered scenario configuration into the network namespaces and
# starts strongSwan on both peers. Waits for the IKE SA to be established
# before returning.
#
# Usage:
#   sudo ./deploy_scenario.sh <scenario_id> [--timeout <seconds>] [--legacy]
#
# Arguments:
#   scenario_id   — ID from scenarios.yaml (e.g. scen_01_tunnel_aes128cbc_...)
#   --timeout N   — seconds to wait for SA establishment (default: 30)
#   --legacy      — use ipsec.conf instead of swanctl.conf (IKEv1 or old distros)
#
# Prerequisites:
#   - setup_namespaces.sh must have been run first
#   - render_configs.py must have been run for this scenario_id
#   - strongSwan must be installed (charon, swanctl or ipsec)
#
# Exit codes:
#   0  — SA established successfully
#   1  — argument / prerequisite error
#   2  — config deployment error
#   3  — SA establishment timeout
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTBED_DIR="$(dirname "$SCRIPT_DIR")"
GENERATED_DIR="${TESTBED_DIR}/configs/generated"

NS_LEFT="peer_left"
NS_RIGHT="peer_right"

# strongSwan config paths (inside each namespace's filesystem view)
# We use /tmp/ipsecai/<ns>/ as the config root to avoid touching system paths
CONFIG_ROOT_LEFT="/tmp/ipsecai/${NS_LEFT}"
CONFIG_ROOT_RIGHT="/tmp/ipsecai/${NS_RIGHT}"

CHARON_BIN="$(command -v charon 2>/dev/null || true)"
if [[ -z "$CHARON_BIN" && -x "/usr/lib/ipsec/charon" ]]; then
    CHARON_BIN="/usr/lib/ipsec/charon"
fi

SWANCTL_DIR="swanctl"          # relative to config root
IPSEC_CONF="ipsec.conf"
IPSEC_SECRETS="ipsec.secrets"
STRONGSWAN_CONF="strongswan.conf"

SA_WAIT_TIMEOUT=30
USE_LEGACY=false

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log_info()  { echo "[INFO]  $(date -u +%H:%M:%S) $*"; }
log_warn()  { echo "[WARN]  $(date -u +%H:%M:%S) $*" >&2; }
log_error() { echo "[ERROR] $(date -u +%H:%M:%S) $*" >&2; }
log_step()  { echo ""; echo "==> $*"; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <scenario_id> [--timeout <seconds>] [--legacy]" >&2
    exit 1
fi

SCENARIO_ID="$1"
shift

while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout)
            SA_WAIT_TIMEOUT="$2"
            shift 2
            ;;
        --legacy)
            USE_LEGACY=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 <scenario_id> [--timeout <seconds>] [--legacy]"
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

if [[ -z "$CHARON_BIN" || ! -x "$CHARON_BIN" ]]; then
    log_error "charon daemon not found. Install strongswan-charon or set a valid charon path."
    exit 2
fi
log_info "  charon binary: $CHARON_BIN"

# ---------------------------------------------------------------------------
# Validate scenario directory exists
# ---------------------------------------------------------------------------
log_step "Validating scenario: $SCENARIO_ID"
SCENARIO_DIR="${GENERATED_DIR}/${SCENARIO_ID}"

if [[ ! -d "$SCENARIO_DIR" ]]; then
    log_error "Generated config directory not found: $SCENARIO_DIR"
    log_error "Run render_configs.py first:"
    log_error "  python3 ${SCRIPT_DIR}/render_configs.py --scenario $SCENARIO_ID"
    exit 1
fi

for required_file in swanctl.conf ipsec.conf ipsec.secrets strongswan.conf labels.json; do
    if [[ ! -f "${SCENARIO_DIR}/${required_file}" ]]; then
        log_error "Missing required file: ${SCENARIO_DIR}/${required_file}"
        exit 2
    fi
done
log_info "  All required config files present"

# ---------------------------------------------------------------------------
# Validate namespaces exist
# ---------------------------------------------------------------------------
log_step "Checking network namespaces"
for ns in "$NS_LEFT" "$NS_RIGHT"; do
    if ! ip netns list | grep -q "^${ns}"; then
        log_error "Namespace '$ns' does not exist."
        log_error "Run setup_namespaces.sh first."
        exit 1
    fi
    log_info "  Namespace exists: $ns"
done

# ---------------------------------------------------------------------------
# Read scenario metadata from labels.json
# ---------------------------------------------------------------------------
log_step "Reading scenario metadata"
IKE_VERSION=$(python3 -c "import json,sys; d=json.load(open('${SCENARIO_DIR}/labels.json')); print(d['labels']['ike_version'])")
log_info "  IKE version: $IKE_VERSION"

# Use legacy ipsec.conf for IKEv1 scenarios
if [[ "$IKE_VERSION" == "1" ]]; then
    log_info "  IKEv1 scenario detected — using legacy ipsec.conf"
    USE_LEGACY=true
fi

# ---------------------------------------------------------------------------
# Deploy configs to each namespace
# ---------------------------------------------------------------------------
log_step "Deploying configs to namespaces"

deploy_to_namespace() {
    local ns="$1"
    local config_root="$2"

    # Create config directories
    mkdir -p "${config_root}/${SWANCTL_DIR}/conf.d"
    mkdir -p "${config_root}/ipsec.d/"{private,certs,cacerts,crls}

    # Copy configs
    # Network namespaces share the host filesystem, so each daemon needs a unique VICI socket.
    sed "s#socket = /var/run/charon.vici#socket = ${config_root}/charon.vici#" \
        "${SCENARIO_DIR}/strongswan.conf" > "${config_root}/${STRONGSWAN_CONF}"
    # ip netns exec bind-mounts /etc/netns/<name>/strongswan.conf as /etc/strongswan.conf.
    # Standalone charon reads /etc/strongswan.conf and does not honor STRONGSWAN_CONF.
    mkdir -p "/etc/netns/${ns}"
    cp "${config_root}/${STRONGSWAN_CONF}" "/etc/netns/${ns}/${STRONGSWAN_CONF}"
    cp "${SCENARIO_DIR}/ipsec.secrets"   "${config_root}/${IPSEC_SECRETS}"
    chmod 600 "${config_root}/${IPSEC_SECRETS}"

    if $USE_LEGACY; then
        cp "${SCENARIO_DIR}/ipsec.conf" "${config_root}/${IPSEC_CONF}"
        log_info "  [$ns] Deployed ipsec.conf (legacy mode)"
    else
        cp "${SCENARIO_DIR}/swanctl.conf" "${config_root}/${SWANCTL_DIR}/conf.d/${SCENARIO_ID}.conf"
        log_info "  [$ns] Deployed swanctl.conf"
    fi

    log_info "  [$ns] Config root: $config_root"
}

deploy_to_namespace "$NS_LEFT"  "$CONFIG_ROOT_LEFT"
deploy_to_namespace "$NS_RIGHT" "$CONFIG_ROOT_RIGHT"

# ---------------------------------------------------------------------------
# Start strongSwan in each namespace
# ---------------------------------------------------------------------------
log_step "Starting strongSwan"

start_strongswan() {
    local ns="$1"
    local config_root="$2"
    local role="$3"   # "left" or "right"

    # Kill any existing charon in this namespace
    local pids
    pids=$(ip netns pids "$ns" 2>/dev/null || true)
    for pid in $pids; do
        local comm
        comm=$(cat /proc/"$pid"/comm 2>/dev/null || echo "")
        if [[ "$comm" == "charon" || "$comm" == "charon-systemd" ]]; then
            log_info "  [$ns] Stopping existing charon (PID $pid)"
            kill -TERM "$pid" 2>/dev/null || true
            sleep 1
        fi
    done

    if $USE_LEGACY; then
        # Legacy mode: use ipsec start with custom config path
        ip netns exec "$ns" \
            ipsec start \
                --conf "${config_root}/${IPSEC_CONF}" \
                --strongswan-conf "${config_root}/${STRONGSWAN_CONF}" \
            2>&1 | sed "s/^/  [$ns] /" &
    else
        # Modern mode: start charon directly, then load config via swanctl
        local vici_socket="${config_root}/charon.vici"
        ip netns exec "$ns" \
            "$CHARON_BIN" \
            &>/var/log/charon_${SCENARIO_ID}_${ns}.log &
        local charon_pid=$!
        log_info "  [$ns] charon started (PID $charon_pid)"

        # Wait for VICI socket to appear
        local wait_count=0
        while [[ ! -S "$vici_socket" ]] && [[ $wait_count -lt 10 ]]; do
            sleep 1
            wait_count=$((wait_count + 1))
        done

        if [[ ! -S "$vici_socket" ]]; then
            log_error "  [$ns] VICI socket not found at $vici_socket"
            log_error "  [$ns] charon startup log: /var/log/charon_${SCENARIO_ID}_${ns}.log"
            if ! kill -0 "$charon_pid" 2>/dev/null; then
                log_error "  [$ns] charon exited during startup"
            fi
            sed 's/^/    /' "/var/log/charon_${SCENARIO_ID}_${ns}.log" >&2 || true
            return 3
        fi

        # Load configuration via swanctl
        ip netns exec "$ns" \
            swanctl \
                --load-all \
                --file "${config_root}/${SWANCTL_DIR}/conf.d/${SCENARIO_ID}.conf" \
                --uri "unix://${vici_socket}" \
            2>&1 | sed "s/^/  [$ns] /" || true
    fi

    log_info "  [$ns] strongSwan started"
}

start_strongswan "$NS_RIGHT" "$CONFIG_ROOT_RIGHT" "right"
sleep 2   # Give responder time to initialize before initiator connects
start_strongswan "$NS_LEFT"  "$CONFIG_ROOT_LEFT"  "left"

# ---------------------------------------------------------------------------
# Wait for SA establishment
# ---------------------------------------------------------------------------
log_step "Waiting for SA establishment (timeout: ${SA_WAIT_TIMEOUT}s)"

wait_for_sa() {
    local ns="$1"
    local timeout="$2"
    local elapsed=0

    while [[ $elapsed -lt $timeout ]]; do
        # Check for established ESP SA via ip xfrm state
        local sa_count
        sa_count=$(ip netns exec "$ns" ip xfrm state list 2>/dev/null | grep -c "proto esp" || true)
        if [[ $sa_count -gt 0 ]]; then
            log_info "  [$ns] Found $sa_count ESP SA(s) — ESTABLISHED"
            return 0
        fi
        sleep 2
        ((elapsed += 2))
        log_info "  [$ns] Waiting for SA... (${elapsed}s / ${timeout}s)"
    done

    log_error "  [$ns] SA establishment timeout after ${timeout}s"
    return 1
}

SA_OK=true
if ! wait_for_sa "$NS_LEFT" "$SA_WAIT_TIMEOUT"; then
    SA_OK=false
fi

if ! wait_for_sa "$NS_RIGHT" "$SA_WAIT_TIMEOUT"; then
    SA_OK=false
fi

if ! $SA_OK; then
    log_error "SA establishment failed. Check charon logs:"
    log_error "  /var/log/charon_${SCENARIO_ID}_${NS_LEFT}.log"
    log_error "  /var/log/charon_${SCENARIO_ID}_${NS_RIGHT}.log"
    exit 3
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log_step "Deployment successful"
echo ""
echo "  Scenario:  $SCENARIO_ID"
echo "  Mode:      $(if $USE_LEGACY; then echo 'legacy (ipsec.conf)'; else echo 'modern (swanctl)'; fi)"
echo "  SA status: ESTABLISHED"
echo ""
echo "  To validate:"
echo "    sudo ip netns exec $NS_LEFT  ip xfrm state"
echo "    sudo ip netns exec $NS_RIGHT ip xfrm state"
echo ""
echo "  To capture traffic:"
echo "    sudo ./capture.sh $SCENARIO_ID"
echo ""
