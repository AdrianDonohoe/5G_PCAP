# sandbox

A local Open5GS + UERANSIM lab used to generate real Registration + PDU
session establishment captures for `5gcap`, and to poke around a live 5G
core interactively. Design rationale: [`../docs/adr/0002-open5gs-ueransim-sandbox.md`](../docs/adr/0002-open5gs-ueransim-sandbox.md).

## Layout

- `core/` — Open5GS (AMF, SMF, UPF, NRF, SCP, AUSF, UDM, UDR, PCF, BSF, NSSF)
  + Mongo, long-lived, persistent volume. Its own Docker Compose project.
- `ran/` — UERANSIM gNB + 3 UEs, ephemeral, recreated on every capture.
  Joins `core`'s network (`sandbox_core`) as an external network.
- `capture.sh` — brings the RAN up, captures N2/N4/SBI, waits for all UEs to
  finish, tears the RAN back down, writes fixtures.

Per-NF config/init scripts and the UERANSIM Dockerfile are vendored (and
trimmed to only what this sandbox needs — no IMS/4G/VoLTE/metrics) from
[herlesupreeth/docker_open5gs](https://github.com/herlesupreeth/docker_open5gs)
(BSD-2-Clause). Images are pulled prebuilt from that project's GHCR registry
rather than built locally.

## One-time setup

Requires Docker with a working `docker compose`, and `tcpdump` capturing
without `sudo`:

```
sudo apt-get install -y docker.io docker-compose-v2
sudo usermod -aG docker $USER   # then re-login, or `newgrp docker`
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)
```

## Usage

```
cd core && docker compose up -d      # start the core (leave it running)
./seed/seed_subscribers.sh           # one-time (or after the volume is wiped):
                                      # provisions 3 test subscribers
cd ../
./capture.sh                         # brings up RAN, captures, tears RAN down
```

Output: `../5gcap/tests/fixtures/sandbox_n2.pcap` (NGAP/SCTP),
`sandbox_n4.pcap` (PFCP), and `sandbox_sbi.pcap` (HTTP/2 SBI on TCP 7777) —
fixed filenames, overwritten each run. Review with
`git diff`/`git status` before committing; re-run `capture.sh` if a run comes
back with a `[PARTIAL]` flow (rare capture-start race).

### Failure-injection scenarios

`./capture.sh --scenario <name>` applies a failure to UE1 only (UE2/UE3 stay
golden in the same capture) and writes `<name>.pcap` and `<name>_sbi.pcap`
plus a sibling `<name>.label.json` ground-truth label for the triage eval
harness:

| scenario | injection | expected wire shape |
|---|---|---|
| `auth_failure` | wrong Ki on UE1 | SYNCH FAILURE #21, then REGISTRATION REJECT #111 (protocol error) |
| `registration_reject` | unprovisioned IMSI on UE1 | REGISTRATION REJECT, cause #7 |
| `registration_timeout` | `docker pause sandbox_amf` | RegistrationRequest left open, UE retries (2 flows) |
| `pdu_session_reject_slice` | UE1 second session on SST 2 | SST 1 session accepts; 5GMM STATUS #91 on SST 2 |
| `pdu_session_reject_other` | UE1 APN `otherdnn` (UDM-only DNN) | 5GSM REJECT, cause #67 |
| `pdu_session_timeout` | blackhole SMF SBI port (in-netns iptables) | sm-context create hangs ~11 s, then 5GMM #90, UE retries |
| `sbi_udm_timeout` | `docker pause sandbox_udm` | ≥1 unanswered Nudm_* request (AUSF→UDM auth hangs first); N2 registration never completes |
| `sbi_nssf_reject` | SMF profile deleted from NRF + SMF paused + `nsi:` stripped from NSSF config | Nnssf_NSSelection 403, then 5GMM STATUS #403 to the UE |

Two shapes differ from the 3GPP textbook on purpose, because they are what
Open5GS actually emits (verified in the generated fixtures): `auth_failure`
ends in REGISTRATION REJECT #111, not AUTHENTICATION REJECT #20, and
`pdu_session_reject_other` yields 5GSM REJECT #67, not #27. The
`pdu_session_timeout` hang is bounded by Open5GS's hardcoded 11 s AMF SBI
deadline (`time.message.duration` + 1 s — no amf.yaml key overrides it for
the AMF); pausing the SMF container does not produce a hang at all (the NRF
purges a heartbeat-less NF within ~10 s and the AMF answers instantly), which
is why the scenario blackholes the SMF's SBI port from inside its own netns
instead — heartbeats keep flowing, data-path requests time out. The
`sbi_nssf_reject` injection is compound for the same reason: deleting the SMF
NF profile alone fails (its heartbeats re-register it), so the SMF is paused
too, and the NSSF's `nsi:` block is stripped — with no SMF discoverable and no
NSI mapping S-NSSAI 1, the NSSF answers Nnssf_NSSelection 403 and the AMF
relays it as 5GMM STATUS #403.

Timeout scenarios start only `gnb`+`ue1`, capture a fixed ~45 s window, and
exit 0 — the missing terminal message *is* the expected outcome. All scenario
mutations (UE1 config, UDM seed variant, container pauses, SMF blackhole
rule, NRF profile delete, NSSF config edit) are reverted on exit.

For interactive poking: `docker compose logs -f <service>` in `core/`, or
`docker compose exec <service> bash`.

To tear the core down entirely (wipes the subscriber DB, requires re-seeding):
`cd core && docker compose down -v`.

## Test subscribers

IMSIs `999700000000001`–`999700000000003`, PLMN 999/70 (Open5GS's canonical
test PLMN), shared K/OPc (`465B5CE8B199B49FAA5F0A2EE238A6BC` /
`E8ED289DEBA952E4283B54E88E6183CA` — the standard Open5GS test credentials,
not secret).
