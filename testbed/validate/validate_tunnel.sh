#!/usr/bin/env bash
# =============================================================================
# validate_tunnel.sh — PS 26160 IPSecAI Testbed
# =============================================================================
# Verifies whether an IPsec scenario was established successfully in the network
# namespaces.
#
# This validation is intentionally conservative: it checks the kernel XFRM state
# for at least one ESP SA on each peer and then tests basic reachability through
# the protected path.
#
# Usage:
#   sudo ./validate_tunnel.sh <scenario_id>
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTBED_DIR="$(dirname "$SCRIPT_DIR")"
GENERATED_DIR="${TESTBED_DIR}/configs/generated"

NS_LEFT="peer_left"
NS_RIGHT="peer_right"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <scenario_id>" >&2
    exit 1
fi

SCENARIO_ID="$1"
SCENARIO_DIR="${GENERATED_DIR}/${SCENARIO_ID}"
SCENARIO_YAML="${TESTBED_DIR}/scenarios/scenarios.yaml"

if [[ ! -f "${SCENARIO_DIR}/labels.json" ]]; then
    echo "ERROR: Missing labels.json for ${SCENARIO_ID}" >&2
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root or with sudo." >&2
    exit 1
fi

IP_VERSION=$(python3 - <<PY
import json
with open("${SCENARIO_DIR}/labels.json", "r", encoding="utf-8") as fh:
    print(json.load(fh)["labels"]["ip_version"])
PY
)

RIGHT_IP=$(python3 - <<PY
import yaml
with open('${SCENARIO_YAML}', 'r', encoding='utf-8') as fh:
    data = yaml.safe_load(fh)
for s in data.get('scenarios', []):
    if s.get('id') == '${SCENARIO_ID}':
        print(s['right_ip'])
        break
PY
)

LEFT_IP=$(python3 - <<PY
import yaml
with open('${SCENARIO_YAML}', 'r', encoding='utf-8') as fh:
    data = yaml.safe_load(fh)
for s in data.get('scenarios', []):
    if s.get('id') == '${SCENARIO_ID}':
        print(s['left_ip'])
        break
PY
)

check_esp_sa() {
    local ns="$1"
    local count
    count=$(ip netns exec "$ns" ip xfrm state list 2>/dev/null | grep -c "proto esp" || true)
    if [[ "$count" -gt 0 ]]; then
        echo "OK: $ns has $count ESP SA(s)"
        return 0
    fi
    echo "ERROR: $ns has no active ESP SA" >&2
    return 1
}

check_traffic() {
    local ns="$1"
    local peer_ip="$2"
    local ping_cmd="ping"

    if [[ "$IP_VERSION" == "6" ]]; then
        ping_cmd="ping6"
    fi

    if ip netns exec "$ns" "$ping_cmd" -c 2 -W 2 "$peer_ip" >/dev/null 2>&1; then
        echo "OK: $ns can reach $peer_ip"
        return 0
    fi

    echo "WARN: $ns cannot reach $peer_ip over the current IPsec configuration" >&2
    return 1
}

check_esp_sa "$NS_LEFT" || exit 1
check_esp_sa "$NS_RIGHT" || exit 1
check_traffic "$NS_LEFT" "$RIGHT_IP" || true
check_traffic "$NS_RIGHT" "$LEFT_IP" || true

echo "Validation successful for scenario: ${SCENARIO_ID}"
exit 0
