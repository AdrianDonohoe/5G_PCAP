"""Self-generated Open5GS+UERANSIM captures from sandbox/capture.sh.

Unlike the other fixtures, these are regenerated locally on demand (see
docs/adr/0002-open5gs-ueransim-sandbox.md), so assertions check structure and
outcomes rather than exact latencies, which vary between runs.
"""

from pathlib import Path

from fivegcap.capture import read_capture, read_pfcp_capture
from fivegcap.correlate import correlate
from fivegcap.flow import build_flows
from fivegcap.kpi import compute
from fivegcap.ngap import decode as ngap_decode
from fivegcap.pfcp import decode as pfcp_decode, pair_procedures
from fivegcap.sbi import read_sbi_capture

N2_FIXTURE = Path(__file__).parent / "fixtures" / "sandbox_n2.pcap"
N4_FIXTURE = Path(__file__).parent / "fixtures" / "sandbox_n4.pcap"
SBI_FIXTURE = Path(__file__).parent / "fixtures" / "sandbox_sbi.pcap"

# The one declared non-decodable class, tolerated only on the SBI golden:
# capture.sh attaches tcpdump after the persistent core has booted, so
# core-internal SBI sessions start before the capture and h2 cannot sync
# HPACK state without the client preface. Any other unparsed note is a
# decoder regression.
MIDSTREAM_SBI_NOTE = "h2 decode failed: no HTTP/2 client preface"


def test_n2_decodes_and_computes_kpis():
    raw = read_capture(str(N2_FIXTURE))
    assert raw, "no NGAP messages decoded from sandbox_n2.pcap"
    msgs = [ngap_decode(m.ts, m.assoc, m.stream, m.data, m.src_ip, m.dst_ip)
            for m in raw]
    flows, unassociated = build_flows(msgs)

    # N2 endpoint IPs: gNB 10.53.0.20 <-> AMF 10.53.0.11
    n2_ips = {"10.53.0.20", "10.53.0.11"}
    for m in msgs:
        assert m.src_ip in n2_ips and m.dst_ip in n2_ips

    assert len(flows) == 3
    for f in flows:
        assert not f.partial, f"flow {f.flow_id} missing its start message"
        kinds = [p.kind for p in f.procedures]
        assert kinds == ["registration", "pdu_session_est"]
        assert all(p.outcome == "accept" for p in f.procedures)
        # Post-SMC NAS is integrity-protected but not encrypted (the AMF
        # selected 5G-EA0), so every protected payload must expose its
        # plaintext inner, including the RegistrationAccept terminal outcome.
        inner_names = {nas.inner for _, nas in f.messages if nas and nas.inner}
        assert {"5GMMSecurityModeCommand", "5GMMSecurityModeComplete",
                "5GMMRegistrationAccept"} <= inner_names
        assert any(nas.ciph_algo == 0 for _, nas in f.messages if nas)
        for _, nas in f.messages:
            if nas and nas.protected:
                assert nas.inner is not None and nas.unparsed is None, \
                    f"protected payload undecoded in flow {f.flow_id}: {nas}"

    kpi = compute(flows)
    assert kpi.success_rate == 1.0
    assert (kpi.successes, kpi.failures) == (6, 0)
    assert len(kpi.attach_times_ms) == 3
    assert len(kpi.pdu_session_times_ms) == 3
    assert all(ms > 0 for ms in kpi.attach_times_ms + kpi.pdu_session_times_ms)


def test_n4_decodes_and_pairs_procedures():
    raw = read_pfcp_capture(str(N4_FIXTURE))
    assert raw, "no PFCP messages decoded from sandbox_n4.pcap"
    msgs = [pfcp_decode(m.ts, m.data, m.src_ip, m.dst_ip, m.src_port, m.dst_port)
            for m in raw]

    assert all(m.unparsed is None for m in msgs)

    # N4 endpoint IPs: SMF 10.53.0.12 <-> UPF 10.53.0.13
    n4_ips = {"10.53.0.12", "10.53.0.13"}
    for m in msgs:
        assert m.src_ip in n4_ips and m.dst_ip in n4_ips
        assert m.src_port == 8805 and m.dst_port == 8805

    procedures, unpaired = pair_procedures(msgs)
    assert unpaired == []
    session_est = [p for p in procedures if p.kind == "session_establishment"]
    assert len(session_est) == 3
    assert all(p.outcome == "accept" for p in procedures if p.kind != "heartbeat")


def test_golden_captures_have_zero_unparsed():
    """Zero-unparsed bar: every message in the golden captures must decode
    fully, or (SBI only) carry the declared midstream-preface note. Any
    other unparsed message fails CI as a decoder regression."""
    # N2: NGAP level on every message (flow and unassociated), NAS level
    # on every flow message.
    msgs = [ngap_decode(m.ts, m.assoc, m.stream, m.data, m.src_ip, m.dst_ip)
            for m in read_capture(str(N2_FIXTURE))]
    flows, _ = build_flows(msgs)
    for m in msgs:
        assert m.unparsed is None, f"NGAP undecoded in sandbox_n2.pcap: {m}"
    for f in flows:
        for _, nas in f.messages:
            if nas is not None:
                assert nas.unparsed is None, \
                    f"NAS undecoded in sandbox_n2.pcap flow {f.flow_id}: {nas}"

    # N4
    msgs = [pfcp_decode(m.ts, m.data, m.src_ip, m.dst_ip, m.src_port, m.dst_port)
            for m in read_pfcp_capture(str(N4_FIXTURE))]
    for m in msgs:
        assert m.unparsed is None, f"PFCP undecoded in sandbox_n4.pcap: {m}"

    # SBI: only the midstream class is tolerated (see MIDSTREAM_SBI_NOTE).
    for m in read_sbi_capture(str(SBI_FIXTURE)):
        assert m.unparsed is None or m.unparsed.startswith(MIDSTREAM_SBI_NOTE), \
            f"SBI undecoded in sandbox_sbi.pcap: {m}"


def test_sbi_correlates_by_supi():
    """Golden merged run: the three UEs' IMSIs form a bijection with the
    three flows, the body-only sm-contexts creates join, and unparsed
    (midstream) SBI messages never link."""
    msgs = [ngap_decode(m.ts, m.assoc, m.stream, m.data, m.src_ip, m.dst_ip)
            for m in read_capture(str(N2_FIXTURE))]
    flows, _ = build_flows(msgs)
    sbi_msgs = read_sbi_capture(str(SBI_FIXTURE))
    corr = correlate(flows, sbi_msgs=sbi_msgs)

    # Unparsed (midstream) SBI messages never join.
    for i, m in enumerate(sbi_msgs):
        if m.unparsed is not None:
            assert corr.sbi_flow[i] is None, f"unparsed message joined: {m}"

    # Every IMSI joins exactly one flow, and every flow is claimed by one
    # IMSI (the sandbox has three UEs, one flow each — a bijection).
    imsi_set = {"999700000000001", "999700000000002", "999700000000003"}
    imsi_flows: dict[str, set[int]] = {}
    for i, m in enumerate(sbi_msgs):
        fid = corr.sbi_flow[i]
        if fid is None:
            continue
        assert m.unparsed is None, "refused message linked"
        for imsi in imsi_set:
            if m.path and f"imsi-{imsi}" in m.path:
                imsi_flows.setdefault(imsi, set()).add(fid)
    assert set(imsi_flows) == imsi_set
    assert {fid for fids in imsi_flows.values() for fid in fids} == \
        {f.flow_id for f in flows}
    for imsi, fids in imsi_flows.items():
        assert len(fids) == 1, f"{imsi} claimed by flows {fids}"

    # Each flow's refs include its sm-contexts create — the create whose
    # identity lives only in the request body — and are sorted by index.
    for f in flows:
        refs = corr.flow_sbi_refs.get(f.flow_id, [])
        assert refs, f"flow {f.flow_id} has no SBI links"
        assert refs == sorted(refs)
        paths = {sbi_msgs[i].path for i in refs
                 if sbi_msgs[i].direction == "request"}
        assert "/nsmf-pdusession/v1/sm-contexts" in paths, \
            f"flow {f.flow_id} missing its session create: {paths}"

    # The null-scheme suci- requests link and normalize, one flow each.
    suci_links = [(m.path, corr.sbi_flow[i])
                  for i, m in enumerate(sbi_msgs)
                  if m.path and "/suci-" in m.path]
    assert len(suci_links) == 3
    assert len({fid for _, fid in suci_links}) == 3
