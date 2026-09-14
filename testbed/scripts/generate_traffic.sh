#!/usr/bin/env bash
# =============================================================================
# generate_traffic.sh — PS 26160 IPSecAI Testbed
# =============================================================================
# Generates traffic inside the peer_left namespace toward peer_right.
# Reads traffic_types from the scenario's labels.json and runs the appropriate
# traffic generators.
#
# Supported traffic types:
#   icmp   — ping / ping6 (ICMP echo request/reply)
#   tcp    — netcat TCP connection (simulates HTTP-like traffic)
#   udp    — netcat UDP datagrams
#   iperf  — iperf3 bulk throughput test
#
# Usage:
#   sudo ./generate_traffic.sh <scenario_id> [--types icmp,tcp,udp,iperf]
#
# Arguments:
#   scenario_id       — ID from scenarios.yaml
#   --types LIST      — comma-separated list of traffic types to generate
#                       (overrides scenario definition)
#   --count N         — number of ICMP packets to send (default: 20)
#   --tcp-duration N  — seconds for TCP traffic (default: 10)
#   --udp-duration N  — seconds for UDP traffic (default: 10)
#   --iperf-duration N — seconds for iperf3 test (default: 30)
#
# Exit codes:
#   0  — all traffic generators completed
#   1  — argument / prerequisite error
#   2  — traffic generation error (partial failure)
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

# Default traffic parameters
ICMP_COUNT=20
TCP_DURATION=10
UDP_DURATION=10
IPERF_DURATION=30
TCP_PORT=8080
UDP_PORT=9090
IPERF_PORT=5201

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
    echo "Usage: $0 <scenario_id> [--types icmp,tcp,udp,iperf] [--count N] [--tcp-duration N] [--udp-duration N] [--iperf-duration N]" >&2
    exit 1
fi

SCENARIO_ID="$1"
shift

TRAFFIC_TYPES_OVERRIDE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --types)
            TRAFFIC_TYPES_OVERRIDE="$2"
            shift 2
            ;;
        --count)
            ICMP_COUNT="$2"
            shift 2
            ;;
        --tcp-duration)
            TCP_DURATION="$2"
            shift 2
            ;;
        --udp-duration)
            UDP_DURATION="$2"
            shift 2
            ;;
        --iperf-duration)
            IPERF_DURATION="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 <scenario_id> [--types icmp,tcp,udp,iperf] [--count N]"
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
# Validate scenario
# ---------------------------------------------------------------------------
log_step "Loading scenario: $SCENARIO_ID"
SCENARIO_DIR="${GENERATED_DIR}/${SCENARIO_ID}"

if [[ ! -f "${SCENARIO_DIR}/labels.json" ]]; then
    log_error "labels.json not found: ${SCENARIO_DIR}/labels.json"
    exit 1
fi

# Read scenario parameters from labels.json
RIGHT_IP=$(python3 -c "import json; d=json.load(open('${SCENARIO_DIR}/labels.json')); print(d['labels'].get('ip_version', 4))")
IP_VERSION="$RIGHT_IP"

# Get peer IPs from labels.json (stored in scenario section)
# We need to re-read from scenarios.yaml for the actual IPs
SCENARIOS_FILE="${TESTBED_DIR}/scenarios/scenarios.yaml"
PEER_IPS=$(python3 - <<PYEOF
import yaml, json, sys

with open("${SCENARIOS_FILE}") as f:
    data = yaml.safe_load(f)

for s in data.get("scenarios", []):
    if s["id"] == "${SCENARIO_ID}":
        print(s["right_ip"])
        print(s["left_ip"])
        print(s["ip_version"])
        print(",".join(s.get("traffic_types", ["icmp"])))
        sys.exit(0)

print("NOT_FOUND")
sys.exit(1)
PYEOF
)

RIGHT_IP=$(echo "$PEER_IPS" | sed -n '1p')
LEFT_IP=$(echo "$PEER_IPS"  | sed -n '2p')
IP_VERSION=$(echo "$PEER_IPS" | sed -n '3p')
TRAFFIC_TYPES_FROM_SCENARIO=$(echo "$PEER_IPS" | sed -n '4p')

log_info "  Left IP:     $LEFT_IP"
log_info "  Right IP:    $RIGHT_IP"
log_info "  IP version:  $IP_VERSION"
log_info "  Traffic types (scenario): $TRAFFIC_TYPES_FROM_SCENARIO"

# Use override if provided, otherwise use scenario definition
if [[ -n "$TRAFFIC_TYPES_OVERRIDE" ]]; then
    TRAFFIC_TYPES="$TRAFFIC_TYPES_OVERRIDE"
    log_info "  Traffic types (override): $TRAFFIC_TYPES"
else
    TRAFFIC_TYPES="$TRAFFIC_TYPES_FROM_SCENARIO"
fi

# ---------------------------------------------------------------------------
# Validate namespaces
# ---------------------------------------------------------------------------
for ns in "$NS_LEFT" "$NS_RIGHT"; do
    if ! ip netns list | grep -q "^${ns}"; then
        log_error "Namespace '$ns' does not exist. Run setup_namespaces.sh first."
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# Traffic generation functions
# ---------------------------------------------------------------------------

generate_icmp() {
    log_step "Generating ICMP traffic ($ICMP_COUNT packets)"

    if [[ "$IP_VERSION" == "6" ]]; then
        PING_CMD="ping6"
    else
        PING_CMD="ping"
    fi

    if command -v "$PING_CMD" &>/dev/null || ip netns exec "$NS_LEFT" which "$PING_CMD" &>/dev/null 2>&1; then
        log_info "  Running: $PING_CMD -c $ICMP_COUNT $RIGHT_IP"
        ip netns exec "$NS_LEFT" \
            "$PING_CMD" -c "$ICMP_COUNT" -i 0.5 -W 2 "$RIGHT_IP" \
            2>&1 | sed 's/^/  [icmp] /' || {
            log_warn "  ICMP traffic generation failed (SA may not be established yet)"
            return 1
        }
        log_info "  ICMP traffic: OK"
    else
        log_warn "  $PING_CMD not available — skipping ICMP"
    fi
}

generate_tcp() {
    log_step "Generating TCP traffic (${TCP_DURATION}s on port $TCP_PORT)"

    # Start a simple TCP server on the right peer
    if command -v nc &>/dev/null || ip netns exec "$NS_RIGHT" which nc &>/dev/null 2>&1; then
        # Start server in background
        ip netns exec "$NS_RIGHT" \
            nc -l -p "$TCP_PORT" -k \
            2>/dev/null &
        SERVER_PID=$!
        sleep 1

        # Send data from left peer
        local end_time=$(( $(date +%s) + TCP_DURATION ))
        local seq=0
        while [[ $(date +%s) -lt $end_time ]]; do
            echo "IPSecAI TCP test packet seq=$seq ts=$(date -u +%s)" | \
                ip netns exec "$NS_LEFT" \
                    nc -w 1 "$RIGHT_IP" "$TCP_PORT" \
                2>/dev/null || true
            ((seq++))
            sleep 0.5
        done

        kill "$SERVER_PID" 2>/dev/null || true
        log_info "  TCP traffic: OK ($seq packets sent)"
    else
        log_warn "  nc (netcat) not available — skipping TCP"
    fi
}

generate_udp() {
    log_step "Generating UDP traffic (${UDP_DURATION}s on port $UDP_PORT)"

    if command -v nc &>/dev/null || ip netns exec "$NS_RIGHT" which nc &>/dev/null 2>&1; then
        # Start UDP server in background
        ip netns exec "$NS_RIGHT" \
            nc -u -l -p "$UDP_PORT" \
            2>/dev/null &
        SERVER_PID=$!
        sleep 1

        # Send UDP datagrams from left peer
        local end_time=$(( $(date +%s) + UDP_DURATION ))
        local seq=0
        while [[ $(date +%s) -lt $end_time ]]; do
            echo "IPSecAI UDP test datagram seq=$seq ts=$(date -u +%s)" | \
                ip netns exec "$NS_LEFT" \
                    nc -u -w 1 "$RIGHT_IP" "$UDP_PORT" \
                2>/dev/null || true
            ((seq++))
            sleep 0.5
        done

        kill "$SERVER_PID" 2>/dev/null || true
        log_info "  UDP traffic: OK ($seq datagrams sent)"
    else
        log_warn "  nc (netcat) not available — skipping UDP"
    fi
}

generate_iperf() {
    log_step "Generating iperf3 bulk traffic (${IPERF_DURATION}s)"

    if command -v iperf3 &>/dev/null || ip netns exec "$NS_RIGHT" which iperf3 &>/dev/null 2>&1; then
        # Start iperf3 server on right peer
        ip netns exec "$NS_RIGHT" \
            iperf3 -s -p "$IPERF_PORT" -D \
            2>/dev/null || true
        sleep 1

        # Run iperf3 client from left peer
        ip netns exec "$NS_LEFT" \
            iperf3 \
                -c "$RIGHT_IP" \
                -p "$IPERF_PORT" \
                -t "$IPERF_DURATION" \
                -i 5 \
                --json \
            2>&1 | sed 's/^/  [iperf] /' || {
            log_warn "  iperf3 test failed"
        }

        # Stop iperf3 server
        ip netns exec "$NS_RIGHT" \
            pkill -f "iperf3 -s" 2>/dev/null || true

        log_info "  iperf3 traffic: OK"
    else
        log_warn "  iperf3 not available — skipping bulk traffic"
    fi
}

# ---------------------------------------------------------------------------
# Run traffic generators based on traffic_types
# ---------------------------------------------------------------------------
log_step "Starting traffic generation for scenario: $SCENARIO_ID"
log_info "  Traffic types: $TRAFFIC_TYPES"

ERRORS=0

IFS=',' read -ra TYPES <<< "$TRAFFIC_TYPES"
for type in "${TYPES[@]}"; do
    type=$(echo "$type" | tr -d ' ')
    case "$type" in
        icmp)
            generate_icmp || ((ERRORS++)) || true
            ;;
        tcp)
            generate_tcp || ((ERRORS++)) || true
            ;;
        udp)
            generate_udp || ((ERRORS++)) || true
            ;;
        iperf)
            generate_iperf || ((ERRORS++)) || true
            ;;
        *)
            log_warn "  Unknown traffic type: $type (skipping)"
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log_step "Traffic generation complete"
echo ""
echo "  Scenario:      $SCENARIO_ID"
echo "  Traffic types: $TRAFFIC_TYPES"
if [[ $ERRORS -gt 0 ]]; then
    echo "  Warnings:      $ERRORS generator(s) had issues (see above)"
    exit 2
else
    echo "  Status:        All generators completed successfully"
fi
echo ""
