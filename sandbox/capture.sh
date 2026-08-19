#!/bin/bash
# Generates fresh fixture captures for 5gcap from the Open5GS + UERANSIM
# sandbox: brings up an ephemeral UERANSIM RAN against the (already-running,
# persistent) Open5GS core, captures N2 (NGAP/SCTP), N4 (PFCP), and SBI
# (HTTP/2, tcp/7777) on the shared core bridge, waits for all UEs to
# complete Registration + PDU session establishment, then tears the RAN
# back down.
#
# Without --scenario (golden path) this writes the fixed-named
# sandbox_n2.pcap / sandbox_n4.pcap / sandbox_sbi.pcap used by 5gcap's
# test suite.
#
# With --scenario <name>, a failure-injection scenario is applied to UE1
# only (UE2/UE3 stay untouched as golden flows in the same capture) and the
# output is <name>.pcap plus <name>_n4.pcap and <name>_sbi.pcap (every
# scenario captures N4 and SBI) and a sibling <name>.label.json =
# {incident_type, scenario}, supplying ground truth for the triage eval
# harness. A scenario is a UE1-config override plus optional UDM seed
# variant (pre-hook) and optional docker pause (timeout shapes), or a
# core-side injection (the sbi_* pair and n4_upf_timeout), and maps
# one-to-one onto the nine incident_types in ../triage/CONTEXT.md:
#
#   auth_failure              wrong Ki on UE1      -> SYNCH FAILURE #21, then
#                                                    REGISTRATION REJECT #111
#   registration_reject       unprovisioned IMSI   -> REGISTRATION REJECT #7
#   registration_timeout      pause sandbox_amf    -> registration left open,
#                                                    UE retries (2 flows)
#   pdu_session_reject_slice  UE1 second session   -> 5GMM STATUS #91 on the
#                             on SST 2             SST 2 request, retried
#   pdu_session_reject_other  UE1 APN "otherdnn"   -> 5GSM REJECT #67
#                             (DNN seeded in UDM only, absent from SMF)
#   pdu_session_timeout       blackhole SMF SBI    -> sm-context creates hang
#                                                    ~11s then 5GMM #90
#   sbi_udm_timeout           blackhole UDM SBI    -> Nudm_* requests left
#                                                    unanswered (SBI timeout)
#   sbi_nssf_reject           SMF profile dropped  -> Nnssf_NSSelection 403,
#                             + SMF paused + NSI   then 5GMM STATUS #147
#                             retargeted (sst 1->2)
#   n4_upf_timeout            blackhole UPF PFCP   -> session establishment
#                             port (udp/8805)      requests left unanswered,
#                                                  then 5GSM REJECT #38
#
# See ../docs/adr/0002-open5gs-ueransim-sandbox.md and
# ../triage/docs/adr/0002-triage-v1-implementation-choices.md.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$SCRIPT_DIR/core"
RAN_DIR="$SCRIPT_DIR/ran"
FIXTURES_DIR="$SCRIPT_DIR/../5gcap/tests/fixtures"
NETWORK_NAME=sandbox_core
UE_SERVICES=(ue1 ue2 ue3)
UE1_IMSI=999700000000001
UE1_WRONG_KI=565B5CE8B199B49FAA5F0A2EE238A6BC  # real Ki starts 465B..., flipped
UE1_WRONG_IMSI=999700000000099                # absent from the UDM
TIMEOUT_SECS=60
TIMEOUT_SCENARIO_SECS=45

SCENARIO=""
if [[ $# -eq 2 && "$1" == "--scenario" ]]; then
  SCENARIO="$2"
elif [[ $# -gt 0 ]]; then
  echo "Usage: $0 [--scenario auth_failure|registration_reject|registration_timeout|pdu_session_reject_slice|pdu_session_reject_other|pdu_session_timeout|sbi_udm_timeout|sbi_nssf_reject|n4_upf_timeout]" >&2
  exit 2
fi
case "$SCENARIO" in
  ""|auth_failure|registration_reject|registration_timeout|pdu_session_reject_slice|pdu_session_reject_other|pdu_session_timeout|sbi_udm_timeout|sbi_nssf_reject|n4_upf_timeout) ;;
  *)
    echo "Error: unknown scenario '$SCENARIO'" >&2
    exit 2 ;;
esac

UE1_YAML="$RAN_DIR/ueransim/ueransim-ue1.yaml"
UE1_YAML_BAK="$RAN_DIR/ueransim/ueransim-ue1.yaml.scenario-bak"
NSSF_YAML="$CORE_DIR/nssf/nssf.yaml"
NSSF_YAML_BAK="$CORE_DIR/nssf/nssf.yaml.scenario-bak"
DB_URI="mongodb://$(grep ^MONGO_IP= "$CORE_DIR/.env" | cut -d= -f2)/open5gs"
PAUSED=""
UDM_SEEDED=""
SMF_BLACKHOLED=""
SMF_PAUSED=""
UDM_BLACKHOLED=""
UPF_BLACKHOLED=""
NSSF_MODIFIED=""

cleanup() {
  set +e
  [[ -n "${N2_PID:-}" ]] && kill "$N2_PID" 2>/dev/null
  [[ -n "${N4_PID:-}" ]] && kill "$N4_PID" 2>/dev/null
  [[ -n "${SBI_PID:-}" ]] && kill "$SBI_PID" 2>/dev/null
  wait "${N2_PID:-}" "${N4_PID:-}" "${SBI_PID:-}" 2>/dev/null
  [[ -n "$PAUSED" ]] && docker unpause "$PAUSED" 2>/dev/null
  if [[ -n "$SMF_BLACKHOLED" ]]; then
    docker exec sandbox_smf iptables -D INPUT -p tcp --dport 7777 -j DROP \
      2>/dev/null
  fi
  if [[ -n "$UDM_BLACKHOLED" ]]; then
    docker exec sandbox_udm iptables -D INPUT -p tcp --dport 7777 -j DROP \
      2>/dev/null
  fi
  if [[ -n "$UPF_BLACKHOLED" ]]; then
    docker exec sandbox_upf iptables -D INPUT -p udp --dport 8805 -j DROP \
      2>/dev/null
  fi
  if [[ -n "$SMF_PAUSED" ]]; then
    # The SMF was paused while its NF profile was dropped from the NRF:
    # a restart re-registers the profile, restoring the golden state.
    docker restart sandbox_smf 2>/dev/null
  fi
  if [[ -n "$UDM_SEEDED" ]]; then
    # Remove the otherdnn seed variant so the golden state is restored.
    (cd "$CORE_DIR" && docker compose exec -T nrf mongosh "$DB_URI" --quiet \
      --eval 'db.subscribers.updateOne({imsi:"'"$UE1_IMSI"'"},{$pull:{"slice.0.session":{name:"otherdnn"}}})' \
      >/dev/null 2>&1)
  fi
  if [[ -n "$NSSF_MODIFIED" ]]; then
    [[ -f "$NSSF_YAML_BAK" ]] && mv -f "$NSSF_YAML_BAK" "$NSSF_YAML"
    docker restart sandbox_nssf 2>/dev/null
  fi
  [[ -f "$UE1_YAML_BAK" ]] && mv -f "$UE1_YAML_BAK" "$UE1_YAML"
  (cd "$RAN_DIR" && docker compose down)
}
trap cleanup EXIT

if ! docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
  echo "Error: $NETWORK_NAME network not found. Start the core first: (cd core && docker compose up -d)" >&2
  exit 1
fi

sed_ue1() {
  # sed the ueransim-ue1.yaml template (restored in cleanup); the init
  # script's env substitution only fills placeholders, so replaced literals
  # survive into the running config.
  cp "$UE1_YAML" "$UE1_YAML_BAK"
  sed -i "$@" "$UE1_YAML"
}

restart_amf_fresh() {
  # Restart the AMF so its UE/SM context is fresh: otherwise the first
  # registration can stall on stale state from previous captures. Wait for
  # the NEW process and for it to have associated the SMF (both checks
  # only look at log lines added after the restart, hence the line-count
  # marker -- --since would match stale lines).
  local mark amf_ready smf_known
  mark=$(docker compose --project-directory "$CORE_DIR" logs --no-color amf \
    2>/dev/null | wc -l)
  docker restart sandbox_amf
  amf_ready=0
  for _ in $(seq 1 60); do
    # NOTE: grep without -q: -q exits at the first match, which SIGPIPEs the
    # upstream tail and, under `set -o pipefail`, makes the pipeline report
    # failure even when the pattern WAS found.
    if docker compose --project-directory "$CORE_DIR" logs --no-color amf \
        2>/dev/null | tail -n +$((mark + 1)) \
        | grep "AMF initialize...done" >/dev/null
    then amf_ready=1; break; fi
    sleep 1
  done
  [[ "$amf_ready" = 1 ]] || { echo "Error: AMF did not become ready" >&2; exit 1; }
  smf_known=0
  for _ in $(seq 1 20); do
    if docker compose --project-directory "$CORE_DIR" logs --no-color amf \
        2>/dev/null | tail -n +$((mark + 1)) \
        | grep "\[SMF\] NFInstance associated" >/dev/null
    then smf_known=1; break; fi
    sleep 1
  done
  [[ "$smf_known" = 1 ]] || { echo "Error: AMF did not associate the SMF" >&2; exit 1; }
}

restart_nssf_fresh() {
  # Restart the NSSF so it picks up the modified nssf.yaml, and wait for
  # the NEW process (same line-count marker trick as restart_amf_fresh).
  local mark nssf_ready
  mark=$(docker compose --project-directory "$CORE_DIR" logs --no-color nssf \
    2>/dev/null | wc -l)
  docker restart sandbox_nssf
  nssf_ready=0
  for _ in $(seq 1 60); do
    if docker compose --project-directory "$CORE_DIR" logs --no-color nssf \
        2>/dev/null | tail -n +$((mark + 1)) \
        | grep "NSSF initialize...done" >/dev/null
    then nssf_ready=1; break; fi
    sleep 1
  done
  [[ "$nssf_ready" = 1 ]] || { echo "Error: NSSF did not become ready" >&2; exit 1; }
}

apply_scenario() {
  case "$SCENARIO" in
    auth_failure)
      # Wrong Ki: the UE's RES no longer matches the core's XRES. On the
      # wire this shows as 5GMMAuthenticationFailure (SYNCH failure #21)
      # followed by REGISTRATION REJECT #111 (protocol error), not the
      # textbook AUTHENTICATION REJECT #20 -- Open5GS answers the RES
      # mismatch this way.
      sed_ue1 "s|UE_KI|$UE1_WRONG_KI|"
      ;;
    registration_reject)
      # IMSI absent from UDM -> REGISTRATION REJECT (cause #7).
      sed_ue1 "s|UE_IMSI|$UE1_WRONG_IMSI|"
      ;;
    pdu_session_reject_slice)
      # UE1 asks for two PDU sessions: SST 1 (golden, succeeds) and SST 2,
      # which the core has no slice for -> 5GMM STATUS #91 on the SST 2
      # request (the AMF never forwards it to an SMF); the UE retries it a
      # couple of times. A single-session SST 2 config would fail the same
      # way but with no golden PDU accept in the flow.
      cp "$UE1_YAML" "$UE1_YAML_BAK"
      python3 - "$UE1_YAML" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("""sessions:
  - type: 'IPv4'
    apn: 'internet'
    slice:
      sst: 1
""", """sessions:
  - type: 'IPv4'
    apn: 'internet'
    slice:
      sst: 1
  - type: 'IPv4'
    apn: 'internet'
    slice:
      sst: 2
""")
open(p, "w").write(s)
PY
      ;;
    pdu_session_reject_other)
      # Seed variant: "otherdnn" is subscribed in UDM for UE1 but the SMF
      # has no such DNN -> the AMF forwards the request and the SMF answers
      # 5GSM REJECT #67 (insufficient resources for specific slice and DNN);
      # the UE retries the rejected request once.
      sed_ue1 "s|apn: 'internet'|apn: 'otherdnn'|"
      (cd "$CORE_DIR" && docker compose exec -T nrf mongosh "$DB_URI" --quiet \
        --eval 'db.subscribers.updateOne({imsi:"'"$UE1_IMSI"'"},{$pull:{"slice.0.session":{name:"otherdnn"}}})' \
        >/dev/null)
      (cd "$CORE_DIR" && docker compose exec -T nrf /open5gs/misc/db/open5gs-dbctl \
        --db_uri="$DB_URI" update_apn "$UE1_IMSI" otherdnn 0 >/dev/null)
      UDM_SEEDED=1
      ;;
  esac
}

if [[ -n "$SCENARIO" ]]; then
  N2_OUT="$FIXTURES_DIR/$SCENARIO.pcap"
  N4_OUT="$FIXTURES_DIR/${SCENARIO}_n4.pcap"
  SBI_OUT="$FIXTURES_DIR/${SCENARIO}_sbi.pcap"
else
  N2_OUT="$FIXTURES_DIR/sandbox_n2.pcap"
  N4_OUT="$FIXTURES_DIR/sandbox_n4.pcap"
  SBI_OUT="$FIXTURES_DIR/sandbox_sbi.pcap"
fi

NET_ID=$(docker network inspect "$NETWORK_NAME" --format '{{.Id}}')
BRIDGE="br-${NET_ID:0:12}"

echo "Capturing N2 (SCTP/38412) on $BRIDGE..."
tcpdump -i "$BRIDGE" -w "$N2_OUT" 'sctp port 38412' &
N2_PID=$!
# N4 and SBI are captured on every run: scenario labels live on the N2
# plane today, but the 8805/7777 traffic is the ground-truth evidence the
# n4_*/sbi_* fixtures are judged against (and a visibility bonus on the N2
# scenarios).
tcpdump -i "$BRIDGE" -w "$N4_OUT" 'udp port 8805' &
N4_PID=$!
tcpdump -i "$BRIDGE" -w "$SBI_OUT" 'tcp port 7777' &
SBI_PID=$!
sleep 3  # let tcpdump attach to the bridge before any RAN traffic starts

# Fresh AMF state so the first registration does not stall on stale UE
# context left over from earlier captures (every scenario run and the
# golden run get this).
restart_amf_fresh

apply_scenario

if [[ "$SCENARIO" == "registration_timeout" ]]; then
  # The gNB must complete NGSetup first so the capture contains a live SCTP
  # association carrying the UE's RegistrationRequest; only then is the AMF
  # frozen, leaving every request unanswered. The UE re-attempts
  # registration on its own timers, so the capture holds two flows (one per
  # attempt) -- the expected "left open" signature.
  echo "Starting gNB..."
  (cd "$RAN_DIR" && docker compose up -d --force-recreate gnb)
  sleep 8
  echo "Pausing sandbox_amf (registration will never complete)..."
  docker pause sandbox_amf
  PAUSED=sandbox_amf
  (cd "$RAN_DIR" && docker compose up -d --force-recreate ue1)
  sleep "$TIMEOUT_SCENARIO_SECS"
  echo "Capture window done (registration timeout is the expected outcome)."
elif [[ "$SCENARIO" == "pdu_session_timeout" ]]; then
  # Registration does not involve the SMF, so it completes normally. The
  # injection blackholes the SMF's SBI port from inside the SMF netns (the
  # smf service runs with cap_add NET_ADMIN, see core/docker-compose.yml):
  # the SMF keeps heartbeating to the NRF so the AMF still discovers it,
  # but every sm-context create hangs until the AMF's SBI deadline and then
  # fails with 5GMM #90 (~11s: Open5GS hardcodes time.message.duration to
  # 10s for the AMF, and the deadline is duration + 1s; no amf.yaml key
  # overrides it). Pausing the SMF container does NOT work: the NRF purges
  # a heartbeat-less NF within ~10s and the AMF drops it from its cache,
  # which turns the failure into an instant #90 instead of a timeout.
  echo "Blackholing the SMF SBI port (PDU session requests will time out)..."
  docker exec sandbox_smf iptables -A INPUT -p tcp --dport 7777 -j DROP
  SMF_BLACKHOLED=1
  (cd "$RAN_DIR" && docker compose up -d --force-recreate gnb ue1)
  sleep "$TIMEOUT_SCENARIO_SECS"
  echo "Capture window done (PDU session timeout is the expected outcome)."
elif [[ "$SCENARIO" == "sbi_udm_timeout" ]]; then
  # Registration reaches the UDM through the AUSF (Nudm_UEAuthentication);
  # blackholing the UDM's SBI port from inside its netns (the same trick as
  # the SMF blackhole above, NET_ADMIN on the udm service) leaves every
  # Nudm_* request unanswered until the AMF's SBI deadline, then
  # registration fails -- the SBI plane's "left open" signature. Pausing
  # the UDM container does NOT work: the AUSF fails fast on the broken
  # connection and the AMF rejects instantly (2-3 ms), no hang. (The gNB
  # comes up first so the capture holds its SCTP association carrying the
  # registration traffic.)
  echo "Starting gNB..."
  (cd "$RAN_DIR" && docker compose up -d --force-recreate gnb)
  sleep 8
  echo "Blackholing the UDM's SBI port (Nudm_* requests will hang)..."
  docker exec sandbox_udm iptables -A INPUT -p tcp --dport 7777 -j DROP
  UDM_BLACKHOLED=1
  (cd "$RAN_DIR" && docker compose up -d --force-recreate ue1)
  sleep "$TIMEOUT_SCENARIO_SECS"
  echo "Capture window done (SBI timeout is the expected outcome)."
elif [[ "$SCENARIO" == "sbi_nssf_reject" ]]; then
  # The compound injection (source-verified against Open5GS v2.8.0): the
  # AMF only consults the NSSF when its SMF cache is empty -- a cache fed
  # by NRF nf-status-notify subscriptions, not by /nnrf-disc/ discovery
  # calls (none appear on the wire). Deleting the SMF's NF profile empties
  # it; pausing the SMF keeps it from heartbeat-re-registering; and with
  # the only NSI retargeted to SST 2 the NSSF can answer NSSelection only
  # with 403 "Cannot find NSI by S-NSSAI[SST:1 SD:0xffffff]". (Removing
  # the nsi: entry does not work: the NSSF aborts at boot with
  # "No nssf.nsi", and it needs at least one NSI entry to initialize --
  # so the entry stays, pointed at a slice nobody requests.)
  # The AMF turns the 403 into 5GMM STATUS carrying cause 147, not 403:
  # nnssf-handler.c passes the raw HTTP status through
  # nas_5gs_send_gmm_status(), whose parameter is
  # uint8_t ogs_nas_5gmm_cause_t, truncating 0x0193 to 0x93 on the wire.
  # Registration itself never touches the SMF or NSSF, so it completes
  # normally before the PDU session request fails.
  echo "Dropping the SMF NF profile and pausing the SMF..."
  (cd "$CORE_DIR" && docker compose exec -T nrf mongosh "$DB_URI" --quiet \
    --eval 'db.nf_profiles.deleteMany({nfType:"SMF"})' >/dev/null)
  docker pause sandbox_smf
  PAUSED=sandbox_smf
  SMF_PAUSED=1
  echo "Retargeting the NSI to SST 2 in nssf.yaml and restarting the NSSF..."
  cp "$NSSF_YAML" "$NSSF_YAML_BAK"
  sed -i 's/^              sst: 1$/              sst: 2/' "$NSSF_YAML"
  NSSF_MODIFIED=1
  restart_nssf_fresh
  (cd "$RAN_DIR" && docker compose up -d --force-recreate gnb ue1)
  sleep "$TIMEOUT_SCENARIO_SECS"
  echo "Capture window done (NSSF 403 -> 5GMM STATUS #147 is the expected outcome)."
elif [[ "$SCENARIO" == "n4_upf_timeout" ]]; then
  # Blackholing the UPF's PFCP port (8805/udp) from inside its netns (the
  # upf service already runs privileged with NET_ADMIN -- see
  # core/docker-compose.yml) leaves every SMF Session Establishment Request
  # unanswered: Open5GS retransmits at 2.5 s intervals but gives up ~7.5 s
  # after the first send (live-verified: 3 sends per attempt -- the give-up
  # pre-empts the 3rd retransmit), then the AMF answers the UE with
  # PDU SESSION ESTABLISHMENT REJECT, 5GSM cause #38 (Network failure) --
  # NOT 5GMM #90, which is pdu_session_timeout's AMF SBI deadline
  # signature. The UPF's SBI heartbeats keep flowing, so the NRF never
  # purges it; only the PFCP data path is dead (association setup retries
  # start after the first missed heartbeat at ~11 s).
  echo "Blackholing the UPF PFCP port (session establishment will time out)..."
  docker exec sandbox_upf iptables -A INPUT -p udp --dport 8805 -j DROP
  UPF_BLACKHOLED=1
  (cd "$RAN_DIR" && docker compose up -d --force-recreate gnb ue1)
  sleep "$TIMEOUT_SCENARIO_SECS"
  echo "Capture window done (N4 timeout is the expected outcome)."
else
  echo "Starting ephemeral RAN (gNB + ${#UE_SERVICES[@]} UEs)..."
  (cd "$RAN_DIR" && docker compose up -d --force-recreate)

  if [[ -n "$SCENARIO" ]]; then
    # UE1 is the injected failure; wait for the two golden UEs instead.
    wait_ues=(ue2 ue3)
  else
    wait_ues=("${UE_SERVICES[@]}")
  fi
  echo "Waiting for Registration + PDU session establishment (timeout ${TIMEOUT_SECS}s)..."
  deadline=$(( $(date +%s) + TIMEOUT_SECS ))
  pending=("${wait_ues[@]}")
  while [[ ${#pending[@]} -gt 0 ]]; do
    if (( $(date +%s) > deadline )); then
      echo "Error: timed out waiting for UE(s) to complete: ${pending[*]}" >&2
      exit 1
    fi
    still_pending=()
    for svc in "${pending[@]}"; do
      # grep without -q (see restart_amf_fresh: -q's early exit SIGPIPEs the
      # upstream command and pipefail turns a match into a failure).
      if ! (cd "$RAN_DIR" && docker compose logs "$svc" 2>/dev/null) | grep "PDU Session establishment is successful" >/dev/null; then
        still_pending+=("$svc")
      fi
    done
    pending=("${still_pending[@]}")
    [[ ${#pending[@]} -gt 0 ]] && sleep 1
  done
  echo "All golden UEs completed Registration + PDU session establishment."

  sleep 1  # drain any trailing capture-complete signaling before we stop tcpdump
fi

# Teardown must never abort the script: `wait` returns 143 for a SIGTERMed
# tcpdump, and an empty argument to kill/wait fails under `set -e` before
# the label block can run.
kill "$N2_PID" 2>/dev/null || true
[[ -n "${N4_PID:-}" ]] && kill "$N4_PID" 2>/dev/null || true
[[ -n "${SBI_PID:-}" ]] && kill "$SBI_PID" 2>/dev/null || true
wait "$N2_PID" 2>/dev/null || true
[[ -n "${N4_PID:-}" ]] && wait "$N4_PID" 2>/dev/null || true
[[ -n "${SBI_PID:-}" ]] && wait "$SBI_PID" 2>/dev/null || true
unset N2_PID N4_PID SBI_PID

if [[ -n "$SCENARIO" ]]; then
  printf '{"incident_type": "%s", "scenario": "%s"}\n' "$SCENARIO" "$SCENARIO" \
    > "$FIXTURES_DIR/$SCENARIO.label.json"
fi

echo "Wrote:"
echo "  $N2_OUT"
[[ -n "${N4_OUT:-}" ]] && echo "  $N4_OUT"
[[ -n "$SCENARIO" ]] && echo "  $FIXTURES_DIR/$SCENARIO.label.json"
echo "  $SBI_OUT"
