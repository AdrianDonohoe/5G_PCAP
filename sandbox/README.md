# sandbox

A local Open5GS + UERANSIM lab used to generate real Registration + PDU
session establishment captures for `5gcap`, and to poke around a live 5G
core interactively. Design rationale: [`../docs/adr/0002-open5gs-ueransim-sandbox.md`](../docs/adr/0002-open5gs-ueransim-sandbox.md).

## Layout

- `core/` — Open5GS (AMF, SMF, UPF, NRF, SCP, AUSF, UDM, UDR, PCF, BSF, NSSF)
  + Mongo, long-lived, persistent volume. Its own Docker Compose project.
- `ran/` — UERANSIM gNB + 3 UEs, ephemeral, recreated on every capture.
  Joins `core`'s network (`sandbox_core`) as an external network.
- `capture.sh` — brings the RAN up, captures N2/N4, waits for all UEs to
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

Output: `../5gcap/tests/fixtures/sandbox_n2.pcap` (NGAP/SCTP) and
`sandbox_n4.pcap` (PFCP) — fixed filenames, overwritten each run. Review with
`git diff`/`git status` before committing; re-run `capture.sh` if a run comes
back with a `[PARTIAL]` flow (rare capture-start race).

For interactive poking: `docker compose logs -f <service>` in `core/`, or
`docker compose exec <service> bash`.

To tear the core down entirely (wipes the subscriber DB, requires re-seeding):
`cd core && docker compose down -v`.

## Test subscribers

IMSIs `999700000000001`–`999700000000003`, PLMN 999/70 (Open5GS's canonical
test PLMN), shared K/OPc (`465B5CE8B199B49FAA5F0A2EE238A6BC` /
`E8ED289DEBA952E4283B54E88E6183CA` — the standard Open5GS test credentials,
not secret).
