#!/bin/bash
# Generates fresh sandbox_n2.pcap / sandbox_n4.pcap fixtures for 5gcap:
# brings up an ephemeral UERANSIM RAN against the (already-running,
# persistent) Open5GS core, captures N2 (NGAP/SCTP) and N4 (PFCP) on the
# shared core bridge with port filters, waits for all UEs to complete
# Registration + PDU session establishment, then tears the RAN back down.
# See docs/adr/0002-open5gs-ueransim-sandbox.md.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$SCRIPT_DIR/core"
RAN_DIR="$SCRIPT_DIR/ran"
FIXTURES_DIR="$SCRIPT_DIR/../5gcap/tests/fixtures"
NETWORK_NAME=sandbox_core
UE_SERVICES=(ue1 ue2 ue3)
TIMEOUT_SECS=60

cleanup() {
  set +e
  [[ -n "${N2_PID:-}" ]] && kill "$N2_PID" 2>/dev/null
  [[ -n "${N4_PID:-}" ]] && kill "$N4_PID" 2>/dev/null
  wait "${N2_PID:-}" "${N4_PID:-}" 2>/dev/null
  (cd "$RAN_DIR" && docker compose down)
}
trap cleanup EXIT

if ! docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
  echo "Error: $NETWORK_NAME network not found. Start the core first: (cd core && docker compose up -d)" >&2
  exit 1
fi

NET_ID=$(docker network inspect "$NETWORK_NAME" --format '{{.Id}}')
BRIDGE="br-${NET_ID:0:12}"

echo "Capturing N2 (SCTP/38412) and N4 (PFCP/8805) on $BRIDGE..."
tcpdump -i "$BRIDGE" -w "$FIXTURES_DIR/sandbox_n2.pcap" 'sctp port 38412' &
N2_PID=$!
tcpdump -i "$BRIDGE" -w "$FIXTURES_DIR/sandbox_n4.pcap" 'udp port 8805' &
N4_PID=$!
sleep 3  # let both tcpdump processes attach to the bridge before any RAN traffic starts

echo "Starting ephemeral RAN (gNB + ${#UE_SERVICES[@]} UEs)..."
(cd "$RAN_DIR" && docker compose up -d --force-recreate)

echo "Waiting for Registration + PDU session establishment on all UEs (timeout ${TIMEOUT_SECS}s)..."
deadline=$(( $(date +%s) + TIMEOUT_SECS ))
pending=("${UE_SERVICES[@]}")
while [[ ${#pending[@]} -gt 0 ]]; do
  if (( $(date +%s) > deadline )); then
    echo "Error: timed out waiting for UE(s) to complete: ${pending[*]}" >&2
    exit 1
  fi
  still_pending=()
  for svc in "${pending[@]}"; do
    if ! (cd "$RAN_DIR" && docker compose logs "$svc" 2>/dev/null) | grep -q "PDU Session establishment is successful"; then
      still_pending+=("$svc")
    fi
  done
  pending=("${still_pending[@]}")
  [[ ${#pending[@]} -gt 0 ]] && sleep 1
done
echo "All UEs completed Registration + PDU session establishment."

sleep 1  # drain any trailing capture-complete signaling before we stop tcpdump
kill "$N2_PID" "$N4_PID" 2>/dev/null
wait "$N2_PID" "$N4_PID" 2>/dev/null
unset N2_PID N4_PID

echo "Wrote:"
echo "  $FIXTURES_DIR/sandbox_n2.pcap"
echo "  $FIXTURES_DIR/sandbox_n4.pcap"
