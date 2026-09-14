#!/usr/bin/env bash
# =============================================================================
# entrypoint.sh — PS 26160 IPSecAI Testbed Docker Entrypoint
# =============================================================================
# Container startup script for IPsec peer nodes.
#
# Responsibilities:
#   1. Load required kernel modules (if available)
#   2. Configure sysctl for IPsec
#   3. Start strongSwan (charon)
#   4. If SCENARIO_ID is set, auto-deploy the scenario
#   5. Tail logs or exec the CMD
#
# Environment variables:
#   PEER_ROLE       — "left" (initiator) or "right" (responder)
#   SCENARIO_ID     — scenario to auto-deploy (optional)
#   PEER_IP         — IP address of this peer
#   REMOTE_IP       — IP address of the remote peer
#   CHARON_LOG_LEVEL — charon log verbosity (default: 2)
#
# Exit codes:
#   0  — normal exit
#   1  — startup failure
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TESTBED_DIR="/opt/ipsecai/testbed"
GENERATED_DIR="${TESTBED_DIR}/configs/generated"
LOG_DIR="/var/log/ipsecai"
CHARON_LOG="${LOG_DIR}/charon.log"
VICI_SOCKET="/var/run/charon.vici"

PEER_ROLE="${PEER_ROLE:-left}"
SCENARIO_ID="${SCENARIO_ID:-}"
PEER_IP="${PEER_IP:-172.20.0.10}"
REMOTE_IP="${REMOTE_IP:-172.20.0.20}"
CHARON_LOG_LEVEL="${CHARON_LOG_LEVEL:-2}"

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log_info()  { echo "[ENTRYPOINT] [INFO]  $(date -u +%H:%M:%S) $*"; }
log_warn()  { echo "[ENTRYPOINT] [WARN]  $(date -u +%H:%M:%S) $*" >&2; }
log_error() { echo "[ENTRYPOINT] [ERROR] $(date -u +%H:%M:%S) $*" >&2; }
log_step()  { echo ""; echo "[ENTRYPOINT] ==> $*"; }

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
echo ""
echo "================================================================"
echo "  PS 26160 IPSecAI Testbed — Peer Container"
echo "  Role:      $PEER_ROLE"
echo "  Peer IP:   $PEER_IP"
echo "  Remote IP: $REMOTE_IP"
echo "  Scenario:  ${SCENARIO_ID:-<none>}"
echo "================================================================"
echo ""

# ---------------------------------------------------------------------------
# Create log directory
# ---------------------------------------------------------------------------
mkdir -p "$LOG_DIR"

# ---------------------------------------------------------------------------
# Load kernel modules
# ---------------------------------------------------------------------------
log_step "Loading kernel modules"

MODULES=(xfrm_user xfrm_algo esp4 esp6 ah4 ah6 af_key)
for mod in "${MODULES[@]}"; do
    if modprobe "$mod" 2>/dev/null; then
        log_info "  Loaded: $mod"
    else
        log_warn "  Could not load: $mod (may be built-in or unavailable in container)"
    fi
done

# ---------------------------------------------------------------------------
# Configure sysctl
# ---------------------------------------------------------------------------
log_step "Configuring sysctl"

sysctl -qw net.ipv4.ip_forward=1              2>/dev/null || log_warn "  Could not set net.ipv4.ip_forward"
sysctl -qw net.ipv6.conf.all.forwarding=1     2>/dev/null || log_warn "  Could not set net.ipv6.conf.all.forwarding"
sysctl -qw net.ipv6.conf.all.disable_ipv6=0   2>/dev/null || log_warn "  Could not set net.ipv6.conf.all.disable_ipv6"
sysctl -qw net.ipv4.conf.all.rp_filter=0      2>/dev/null || log_warn "  Could not set net.ipv4.conf.all.rp_filter"
sysctl -qw net.ipv4.conf.default.rp_filter=0  2>/dev/null || log_warn "  Could not set net.ipv4.conf.default.rp_filter"

log_info "  sysctl configured"

# ---------------------------------------------------------------------------
# Start strongSwan
# ---------------------------------------------------------------------------
log_step "Starting strongSwan"

# Determine which strongSwan binary is available
if command -v charon-systemd &>/dev/null; then
    CHARON_BIN="charon-systemd"
elif command -v charon &>/dev/null; then
    CHARON_BIN="charon"
else
    log_error "No strongSwan daemon found (charon or charon-systemd)"
    exit 1
fi

log_info "  Using: $CHARON_BIN"

# Write a minimal strongswan.conf for the container
cat > /etc/strongswan.conf <<SWANCONF
charon {
    filelog {
        ${CHARON_LOG} {
            default = ${CHARON_LOG_LEVEL}
            time_format = %Y-%m-%dT%H:%M:%S
            flush_line = yes
            append = no
        }
    }
    plugins {
        vici {
            socket = ${VICI_SOCKET}
        }
    }
    threads = 4
    install_virtual_ip = no
}
SWANCONF

# Start charon in background
"$CHARON_BIN" &>/dev/null &
CHARON_PID=$!
log_info "  $CHARON_BIN started (PID: $CHARON_PID)"

# Wait for VICI socket
log_info "  Waiting for VICI socket..."
WAIT_COUNT=0
while [[ ! -S "$VICI_SOCKET" ]] && [[ $WAIT_COUNT -lt 15 ]]; do
    sleep 1
    ((WAIT_COUNT++))
done

if [[ -S "$VICI_SOCKET" ]]; then
    log_info "  VICI socket ready: $VICI_SOCKET"
else
    log_warn "  VICI socket not found after 15s — continuing anyway"
fi

# ---------------------------------------------------------------------------
# Auto-deploy scenario (if SCENARIO_ID is set)
# ---------------------------------------------------------------------------
if [[ -n "$SCENARIO_ID" ]]; then
    log_step "Auto-deploying scenario: $SCENARIO_ID"

    SCENARIO_DIR="${GENERATED_DIR}/${SCENARIO_ID}"

    if [[ ! -d "$SCENARIO_DIR" ]]; then
        log_warn "  Scenario directory not found: $SCENARIO_DIR"
        log_warn "  Run render_configs.py on the host first, then mount the generated/ directory"
    else
        # Load swanctl config
        SWANCTL_CONF="${SCENARIO_DIR}/swanctl.conf"
        if [[ -f "$SWANCTL_CONF" ]]; then
            log_info "  Loading swanctl config: $SWANCTL_CONF"
            swanctl --load-all --file "$SWANCTL_CONF" 2>&1 | sed 's/^/  [swanctl] /' || {
                log_warn "  swanctl load failed — trying ipsec.conf"
                IPSEC_CONF="${SCENARIO_DIR}/ipsec.conf"
                if [[ -f "$IPSEC_CONF" ]]; then
                    ipsec start --conf "$IPSEC_CONF" 2>&1 | sed 's/^/  [ipsec] /' || true
                fi
            }

            # Initiator: trigger SA establishment
            if [[ "$PEER_ROLE" == "left" ]]; then
                sleep 3
                log_info "  Initiating IKE SA..."
                swanctl --initiate --child "${SCENARIO_ID}_child" 2>&1 | sed 's/^/  [swanctl] /' || {
                    log_warn "  SA initiation failed — responder may not be ready yet"
                }
            fi
        else
            log_warn "  swanctl.conf not found: $SWANCTL_CONF"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------
cleanup() {
    log_info "Shutting down..."
    swanctl --terminate --ike-id 0 2>/dev/null || true
    kill "$CHARON_PID" 2>/dev/null || true
    wait "$CHARON_PID" 2>/dev/null || true
    log_info "Shutdown complete"
}
trap cleanup SIGTERM SIGINT

# ---------------------------------------------------------------------------
# Execute CMD or tail logs
# ---------------------------------------------------------------------------
log_step "Container ready"
log_info "  Peer role:  $PEER_ROLE"
log_info "  Peer IP:    $PEER_IP"
log_info "  Remote IP:  $REMOTE_IP"
log_info "  Charon log: $CHARON_LOG"
echo ""

# Execute the CMD passed to the container (default: tail -f charon.log)
exec "$@"
