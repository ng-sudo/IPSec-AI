#!/usr/bin/env bash
# =============================================================================
# setup_namespaces.sh — PS 26160 IPSecAI Testbed
# =============================================================================
# Creates two Linux network namespaces (peer_left, peer_right) connected by a
# veth pair, assigns IPv4 and IPv6 addresses, and loads required kernel modules.
#
# Topology:
#
#   peer_left ns                    peer_right ns
#   ┌──────────────┐                ┌──────────────┐
#   │  veth-left   │◄──────────────►│  veth-right  │
#   │  10.0.0.1/24 │                │  10.0.0.2/24 │
#   │  fd00::1/64  │                │  fd00::2/64  │
#   └──────────────┘                └──────────────┘
#
# Usage:
#   sudo ./setup_namespaces.sh [--ipv6-only | --ipv4-only]
#
# Requirements:
#   - Linux kernel >= 4.19
#   - iproute2 (ip command)
#   - Root / CAP_NET_ADMIN
#
# Exit codes:
#   0  — success
#   1  — missing dependency or insufficient privileges
#   2  — namespace/interface creation failed
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
NS_LEFT="peer_left"
NS_RIGHT="peer_right"
VETH_LEFT="veth-left"
VETH_RIGHT="veth-right"

IPV4_LEFT="10.0.0.1"
IPV4_RIGHT="10.0.0.2"
IPV4_PREFIX="24"

IPV6_LEFT="fd00::1"
IPV6_RIGHT="fd00::2"
IPV6_PREFIX="64"

# Kernel modules required for IPsec
REQUIRED_MODULES=(
    xfrm_user   # XFRM netlink interface
    xfrm_algo   # XFRM algorithm support
    esp4        # ESP over IPv4
    esp6        # ESP over IPv6
    ah4         # AH over IPv4 (optional but loaded for completeness)
    ah6         # AH over IPv6
    af_key      # PF_KEY socket (used by some IKE daemons)
)

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
ENABLE_IPV4=true
ENABLE_IPV6=true

for arg in "$@"; do
    case "$arg" in
        --ipv4-only) ENABLE_IPV6=false ;;
        --ipv6-only) ENABLE_IPV4=false ;;
        --help|-h)
            echo "Usage: $0 [--ipv4-only | --ipv6-only]"
            exit 0
            ;;
        *)
            log_error "Unknown argument: $arg"
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------
log_step "Checking privileges"
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (or with sudo)."
    log_error "Network namespace creation requires CAP_NET_ADMIN."
    exit 1
fi
log_info "Running as root — OK"

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
log_step "Checking dependencies"
for cmd in ip modprobe sysctl; do
    if ! command -v "$cmd" &>/dev/null; then
        log_error "Required command not found: $cmd"
        log_error "Install iproute2 and kmod packages."
        exit 1
    fi
    log_info "  Found: $cmd"
done

# ---------------------------------------------------------------------------
# Load kernel modules
# ---------------------------------------------------------------------------
log_step "Loading kernel modules"
for mod in "${REQUIRED_MODULES[@]}"; do
    if modprobe "$mod" 2>/dev/null; then
        log_info "  Loaded: $mod"
    else
        log_warn "  Could not load: $mod (may already be built-in or unavailable)"
    fi
done

# ---------------------------------------------------------------------------
# Clean up any existing namespaces / interfaces from a previous run
# ---------------------------------------------------------------------------
log_step "Cleaning up any pre-existing namespaces"
for ns in "$NS_LEFT" "$NS_RIGHT"; do
    if ip netns list | grep -q "^${ns}"; then
        log_info "  Removing existing namespace: $ns"
        ip netns del "$ns" 2>/dev/null || true
    fi
done

# The veth pair is deleted automatically when the namespace is deleted,
# but clean up the host-side interface just in case.
if ip link show "$VETH_LEFT" &>/dev/null 2>&1; then
    log_info "  Removing existing interface: $VETH_LEFT"
    ip link del "$VETH_LEFT" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Create network namespaces
# ---------------------------------------------------------------------------
log_step "Creating network namespaces"
ip netns add "$NS_LEFT"
log_info "  Created namespace: $NS_LEFT"
ip netns add "$NS_RIGHT"
log_info "  Created namespace: $NS_RIGHT"

# ---------------------------------------------------------------------------
# Create veth pair
# ---------------------------------------------------------------------------
log_step "Creating veth pair: $VETH_LEFT <-> $VETH_RIGHT"
ip link add "$VETH_LEFT" type veth peer name "$VETH_RIGHT"
log_info "  Created veth pair"

# Move each end into its namespace
ip link set "$VETH_LEFT"  netns "$NS_LEFT"
ip link set "$VETH_RIGHT" netns "$NS_RIGHT"
log_info "  Moved $VETH_LEFT  -> namespace $NS_LEFT"
log_info "  Moved $VETH_RIGHT -> namespace $NS_RIGHT"

# ---------------------------------------------------------------------------
# Configure loopback in each namespace
# ---------------------------------------------------------------------------
log_step "Bringing up loopback interfaces"
ip netns exec "$NS_LEFT"  ip link set lo up
ip netns exec "$NS_RIGHT" ip link set lo up
log_info "  Loopback up in both namespaces"

# ---------------------------------------------------------------------------
# Bring up veth interfaces
# ---------------------------------------------------------------------------
log_step "Bringing up veth interfaces"
ip netns exec "$NS_LEFT"  ip link set "$VETH_LEFT"  up
ip netns exec "$NS_RIGHT" ip link set "$VETH_RIGHT" up
log_info "  $VETH_LEFT  up in $NS_LEFT"
log_info "  $VETH_RIGHT up in $NS_RIGHT"

# ---------------------------------------------------------------------------
# Assign IPv4 addresses
# ---------------------------------------------------------------------------
if $ENABLE_IPV4; then
    log_step "Assigning IPv4 addresses"
    ip netns exec "$NS_LEFT"  ip addr add "${IPV4_LEFT}/${IPV4_PREFIX}"  dev "$VETH_LEFT"
    ip netns exec "$NS_RIGHT" ip addr add "${IPV4_RIGHT}/${IPV4_PREFIX}" dev "$VETH_RIGHT"
    log_info "  $NS_LEFT:  $IPV4_LEFT/$IPV4_PREFIX on $VETH_LEFT"
    log_info "  $NS_RIGHT: $IPV4_RIGHT/$IPV4_PREFIX on $VETH_RIGHT"

    # Enable IPv4 forwarding in each namespace
    ip netns exec "$NS_LEFT"  sysctl -qw net.ipv4.ip_forward=1
    ip netns exec "$NS_RIGHT" sysctl -qw net.ipv4.ip_forward=1
    log_info "  IPv4 forwarding enabled in both namespaces"
fi

# ---------------------------------------------------------------------------
# Assign IPv6 addresses
# ---------------------------------------------------------------------------
if $ENABLE_IPV6; then
    log_step "Assigning IPv6 addresses"

    # Ensure IPv6 is not disabled
    ip netns exec "$NS_LEFT"  sysctl -qw net.ipv6.conf.all.disable_ipv6=0
    ip netns exec "$NS_RIGHT" sysctl -qw net.ipv6.conf.all.disable_ipv6=0
    ip netns exec "$NS_LEFT"  sysctl -qw net.ipv6.conf."${VETH_LEFT}".disable_ipv6=0
    ip netns exec "$NS_RIGHT" sysctl -qw net.ipv6.conf."${VETH_RIGHT}".disable_ipv6=0

    ip netns exec "$NS_LEFT"  ip addr add "${IPV6_LEFT}/${IPV6_PREFIX}"  dev "$VETH_LEFT"
    ip netns exec "$NS_RIGHT" ip addr add "${IPV6_RIGHT}/${IPV6_PREFIX}" dev "$VETH_RIGHT"
    log_info "  $NS_LEFT:  $IPV6_LEFT/$IPV6_PREFIX on $VETH_LEFT"
    log_info "  $NS_RIGHT: $IPV6_RIGHT/$IPV6_PREFIX on $VETH_RIGHT"

    # Enable IPv6 forwarding
    ip netns exec "$NS_LEFT"  sysctl -qw net.ipv6.conf.all.forwarding=1
    ip netns exec "$NS_RIGHT" sysctl -qw net.ipv6.conf.all.forwarding=1
    log_info "  IPv6 forwarding enabled in both namespaces"
fi

# ---------------------------------------------------------------------------
# Verify connectivity
# ---------------------------------------------------------------------------
log_step "Verifying connectivity"

if $ENABLE_IPV4; then
    if ip netns exec "$NS_LEFT" ping -c 2 -W 2 "$IPV4_RIGHT" &>/dev/null; then
        log_info "  IPv4 ping $NS_LEFT -> $NS_RIGHT: OK"
    else
        log_warn "  IPv4 ping $NS_LEFT -> $NS_RIGHT: FAILED (may be transient)"
    fi
fi

if $ENABLE_IPV6; then
    # Give IPv6 a moment for DAD (Duplicate Address Detection)
    sleep 1
    if ip netns exec "$NS_LEFT" ping6 -c 2 -W 2 "$IPV6_RIGHT" &>/dev/null; then
        log_info "  IPv6 ping $NS_LEFT -> $NS_RIGHT: OK"
    else
        log_warn "  IPv6 ping $NS_LEFT -> $NS_RIGHT: FAILED (may need more time for DAD)"
    fi
fi

# ---------------------------------------------------------------------------
# Print summary
# ---------------------------------------------------------------------------
log_step "Namespace setup complete"
echo ""
echo "  Namespaces created:"
echo "    $NS_LEFT  — left peer (initiator)"
echo "    $NS_RIGHT — right peer (responder)"
echo ""
echo "  Network topology:"
if $ENABLE_IPV4; then
    echo "    IPv4: $IPV4_LEFT <-> $IPV4_RIGHT (/$IPV4_PREFIX)"
fi
if $ENABLE_IPV6; then
    echo "    IPv6: $IPV6_LEFT <-> $IPV6_RIGHT (/$IPV6_PREFIX)"
fi
echo ""
echo "  To run a command in a namespace:"
echo "    ip netns exec $NS_LEFT  <command>"
echo "    ip netns exec $NS_RIGHT <command>"
echo ""
echo "  To tear down:"
echo "    sudo ./teardown_namespaces.sh"
echo ""
