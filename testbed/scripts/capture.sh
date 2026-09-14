#!/usr/bin/env bash
# =============================================================================
# capture.sh — PS 26160 IPSecAI Testbed
# =============================================================================
# Starts a tcpdump/tshark packet capture on the veth interface for a given
# scenario. Writes the PCAP to dataset/raw/<scenario_id>_<timestamp>.pcap
# and records capture metadata to a JSON sidecar file.
#
# Usage:
#   sudo ./capture.sh <scenario_id> [--duration <seconds>] [--tool tcpdump|tshark]
#
# Arguments:
#   scenario_id       — ID from scenarios.yaml
#   --duration N      — capture duration in seconds (default: from labels.json)
#   --tool tcpdump    — capture tool to use (default: tcpdump; fallback: tshark)
#   --interface IFACE — interface to capture on (default: veth-left)
#   --background      — run capture in background and print PID
#
# Output:
#   dataset/raw/<scenario_id>_<timestamp>.pcap
#   dataset/raw/<scenario_id>_<timestamp>.pcap.meta.json
#
# Exit codes:
#   0  — capture completed successfully
#   1  — argument / prerequisite error
#   2  — capture tool not found
#   3  — capture failed
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTBED_DIR="$(dirname "$SCRIPT_DIR")"
REPO_DIR="$(dirname "$TESTBED_DIR")"
GENERATED_DIR="${TESTBED_DIR}/configs/generated"
RAW_DIR="${REPO_DIR}/dataset/raw"

NS_LEFT="peer_left"
CAPTURE_IFACE="veth-left"
CAPTURE_TOOL="tcpdump"
DURATION=""
RUN_BACKGROUND=false
TRAFFIC_TYPE=""

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
    echo "Usage: $0 <scenario_id> [--duration <seconds>] [--tool tcpdump|tshark] [--interface IFACE] [--background]" >&2
    exit 1
fi

SCENARIO_ID="$1"
shift

while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --tool)
            CAPTURE_TOOL="$2"
            shift 2
            ;;
        --interface)
            CAPTURE_IFACE="$2"
            shift 2
            ;;
        --background)
            RUN_BACKGROUND=true
            shift
            ;;
        --traffic-type)
            TRAFFIC_TYPE="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 <scenario_id> [--duration <seconds>] [--tool tcpdump|tshark] [--interface IFACE] [--traffic-type TYPE] [--background]"
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
    log_error "Packet capture requires root (or CAP_NET_RAW)."
    exit 1
fi

# ---------------------------------------------------------------------------
# Validate scenario
# ---------------------------------------------------------------------------
log_step "Validating scenario: $SCENARIO_ID"
SCENARIO_DIR="${GENERATED_DIR}/${SCENARIO_ID}"

if [[ ! -f "${SCENARIO_DIR}/labels.json" ]]; then
    log_error "labels.json not found: ${SCENARIO_DIR}/labels.json"
    log_error "Run render_configs.py first."
    exit 1
fi

# Read duration from labels.json if not provided on command line
if [[ -z "$DURATION" ]]; then
    DURATION=$(python3 -c "import json; d=json.load(open('${SCENARIO_DIR}/labels.json')); print(d['capture']['duration_seconds'])")
    log_info "  Duration from labels.json: ${DURATION}s"
else
    log_info "  Duration (override): ${DURATION}s"
fi

# ---------------------------------------------------------------------------
# Check capture tool availability
# ---------------------------------------------------------------------------
log_step "Checking capture tool: $CAPTURE_TOOL"
if ! command -v "$CAPTURE_TOOL" &>/dev/null; then
    log_warn "  $CAPTURE_TOOL not found, trying fallback"
    if [[ "$CAPTURE_TOOL" == "tcpdump" ]] && command -v tshark &>/dev/null; then
        CAPTURE_TOOL="tshark"
        log_info "  Using tshark as fallback"
    elif [[ "$CAPTURE_TOOL" == "tshark" ]] && command -v tcpdump &>/dev/null; then
        CAPTURE_TOOL="tcpdump"
        log_info "  Using tcpdump as fallback"
    else
        log_error "Neither tcpdump nor tshark found. Install one of them."
        exit 2
    fi
fi
log_info "  Using: $CAPTURE_TOOL"

# ---------------------------------------------------------------------------
# Prepare output paths
# ---------------------------------------------------------------------------
log_step "Preparing output paths"
mkdir -p "$RAW_DIR"

TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
PCAP_BASENAME="${SCENARIO_ID}"
if [[ -n "$TRAFFIC_TYPE" ]]; then
    PCAP_BASENAME="${PCAP_BASENAME}_${TRAFFIC_TYPE}"
fi
PCAP_FILE="${RAW_DIR}/${PCAP_BASENAME}_${TIMESTAMP}.pcap"
META_FILE="${PCAP_FILE}.meta.json"

log_info "  PCAP output: $PCAP_FILE"
log_info "  Meta output: $META_FILE"

# ---------------------------------------------------------------------------
# Build capture command
# ---------------------------------------------------------------------------
# Capture filter: IKE (UDP 500, UDP 4500) + ESP (proto 50) + AH (proto 51)
CAPTURE_FILTER="udp port 500 or udp port 4500 or proto 50 or proto 51"

build_tcpdump_cmd() {
    echo "ip netns exec ${NS_LEFT} tcpdump \
        -i ${CAPTURE_IFACE} \
        -w ${PCAP_FILE} \
        -G ${DURATION} \
        -W 1 \
        -s 0 \
        '${CAPTURE_FILTER}'"
}

build_tshark_cmd() {
    echo "ip netns exec ${NS_LEFT} tshark \
        -i ${CAPTURE_IFACE} \
        -w ${PCAP_FILE} \
        -a duration:${DURATION} \
        -f '${CAPTURE_FILTER}'"
}

if [[ "$CAPTURE_TOOL" == "tcpdump" ]]; then
    CAPTURE_CMD=$(build_tcpdump_cmd)
else
    CAPTURE_CMD=$(build_tshark_cmd)
fi

# ---------------------------------------------------------------------------
# Write initial metadata sidecar
# ---------------------------------------------------------------------------
TIMESTAMP_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)

python3 - <<PYEOF
import json, os

labels_path = "${SCENARIO_DIR}/labels.json"
meta_path   = "${META_FILE}"

with open(labels_path) as f:
    labels = json.load(f)

meta = {
    "schema_version": "1.0",
    "scenario_id":    "${SCENARIO_ID}",
    "pcap_file":      "${PCAP_FILE}",
    "capture_tool":   "${CAPTURE_TOOL}",
    "interface":      "${CAPTURE_IFACE}",
    "namespace":      "${NS_LEFT}",
    "filter":         "${CAPTURE_FILTER}",
    "duration_seconds": int("${DURATION}"),
    "timestamp_start":  "${TIMESTAMP_START}",
    "timestamp_end":    None,
    "packet_count":     None,
    "file_size_bytes":  None,
    "traffic_type":     "${TRAFFIC_TYPE:-}",
    "labels":           labels["labels"],
    "tags":             labels.get("tags", []),
}

with open(meta_path, "w") as f:
    json.dump(meta, f, indent=2)

print(f"  Metadata written: {meta_path}")
PYEOF

# ---------------------------------------------------------------------------
# Start capture
# ---------------------------------------------------------------------------
log_step "Starting capture (${DURATION}s on ${CAPTURE_IFACE} in ${NS_LEFT})"
log_info "  Command: $CAPTURE_CMD"

if $RUN_BACKGROUND; then
    eval "$CAPTURE_CMD" &
    CAPTURE_PID=$!
    log_info "  Capture running in background (PID: $CAPTURE_PID)"
    echo "$CAPTURE_PID" > "${PCAP_FILE}.pid"
    log_info "  PID file: ${PCAP_FILE}.pid"
    echo "$CAPTURE_PID"
else
    eval "$CAPTURE_CMD"
    CAPTURE_EXIT=$?

    if [[ $CAPTURE_EXIT -ne 0 ]]; then
        log_error "Capture failed with exit code $CAPTURE_EXIT"
        exit 3
    fi

    # ---------------------------------------------------------------------------
    # Update metadata with final stats
    # ---------------------------------------------------------------------------
    TIMESTAMP_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    FILE_SIZE=$(stat -c%s "$PCAP_FILE" 2>/dev/null || echo 0)

    python3 - <<PYEOF2
import json

meta_path = "${META_FILE}"
with open(meta_path) as f:
    meta = json.load(f)

meta["timestamp_end"]   = "${TIMESTAMP_END}"
meta["file_size_bytes"] = ${FILE_SIZE}

with open(meta_path, "w") as f:
    json.dump(meta, f, indent=2)

print(f"  Metadata updated: {meta_path}")
PYEOF2

    log_step "Capture complete"
    echo ""
    echo "  PCAP file: $PCAP_FILE"
    echo "  Metadata:  $META_FILE"
    echo "  Duration:  ${DURATION}s"
    echo "  Size:      ${FILE_SIZE} bytes"
    echo ""
    echo "  To validate PCAP:"
    echo "    python3 ${TESTBED_DIR}/validate/check_pcap.py $PCAP_FILE"
    echo ""
fi
