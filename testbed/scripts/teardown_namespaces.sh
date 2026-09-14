#!/usr/bin/env bash
# =============================================================================
# teardown_namespaces.sh — PS 26160 IPSecAI Testbed
# =============================================================================
# Cleanly removes the peer_left and peer_right network namespaces, the veth
# pair, and flushes all XFRM (IPsec) state and policy from the kernel.
#
# Usage:
#   sudo ./teardown_namespaces.sh
#
# This script is idempotent — it is safe to run even if the namespaces do
# not exist (e.g., after a failed setup).
#
# Exit codes:
#   0  — success (or nothing to clean up)
#   1  — insufficient privileges
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (must match setup_namespaces.sh)
# ---------------------------------------------------------------------------
NS_LEFT="peer_left"
NS_RIGHT="peer_right"
VETH_LEFT="veth-left"
VETH_RIGHT="veth-right"

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log_info()  { echo "[INFO]  $(date -u +%H:%M:%S) $*"; }
log_warn()  { echo "[WARN]  $(date -u +%H:%M:%S) $*" >&2; }
log_step()  { echo ""; echo "==> $*"; }

# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (or with sudo)." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Stop any running strongSwan instances inside the namespaces
# ---------------------------------------------------------------------------
log_step "Stopping strongSwan instances"
for ns in "$NS_LEFT" "$NS_RIGHT"; do
    if ip netns list 2>/dev/null | grep -q "^${ns}"; then
        # Try swanctl first (IKEv2), then ipsec (legacy)
        ip netns exec "$ns" swanctl --terminate --ike-id 0 2>/dev/null || true
        ip netns exec "$ns" ipsec stop 2>/dev/null || true
        # Kill any remaining charon processes in the namespace
        # (use nsenter to find PIDs in the namespace)
        local_pids=$(ip netns pids "$ns" 2>/dev/null || true)
        if [[ -n "$local_pids" ]]; then
            for pid in $local_pids; do
                comm=$(cat /proc/"$pid"/comm 2>/dev/null || echo "")
                if [[ "$comm" == "charon" || "$comm" == "charon-systemd" ]]; then
                    log_info "  Killing charon PID $pid in $ns"
                    kill -TERM "$pid" 2>/dev/null || true
                fi
            done
            sleep 1
        fi
        log_info "  strongSwan stopped in $ns"
    fi
done

# ---------------------------------------------------------------------------
# Flush XFRM state and policy from both namespaces
# ---------------------------------------------------------------------------
log_step "Flushing XFRM state and policy"
for ns in "$NS_LEFT" "$NS_RIGHT"; do
    if ip netns list 2>/dev/null | grep -q "^${ns}"; then
        ip netns exec "$ns" ip xfrm state  flush 2>/dev/null || true
        ip netns exec "$ns" ip xfrm policy flush 2>/dev/null || true
        log_info "  XFRM flushed in $ns"
    fi
done

# Also flush the host namespace (in case any state leaked)
ip xfrm state  flush 2>/dev/null || true
ip xfrm policy flush 2>/dev/null || true
log_info "  XFRM flushed in host namespace"

# ---------------------------------------------------------------------------
# Remove network namespaces
# ---------------------------------------------------------------------------
log_step "Removing network namespaces"
for ns in "$NS_LEFT" "$NS_RIGHT"; do
    if ip netns list 2>/dev/null | grep -q "^${ns}"; then
        ip netns del "$ns"
        log_info "  Removed namespace: $ns"
    else
        log_info "  Namespace not found (already removed): $ns"
    fi
done

# ---------------------------------------------------------------------------
# Remove veth pair (should be gone with namespaces, but clean up just in case)
# ---------------------------------------------------------------------------
log_step "Cleaning up veth interfaces"
for iface in "$VETH_LEFT" "$VETH_RIGHT"; do
    if ip link show "$iface" &>/dev/null 2>&1; then
        ip link del "$iface" 2>/dev/null || true
        log_info "  Removed interface: $iface"
    else
        log_info "  Interface already gone: $iface"
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log_step "Teardown complete"
echo ""
echo "  Removed namespaces: $NS_LEFT, $NS_RIGHT"
echo "  Flushed XFRM state and policy"
echo "  Removed veth pair: $VETH_LEFT <-> $VETH_RIGHT"
echo ""
