"""SBI decoder tests over synthetic cleartext HTTP/2 (h2c) pcaps.

Offline by construction: the pcaps are built in tmp_path with the h2 library
itself (the decoder under test is a passive reader of its wire bytes) and
wrpcap'd as Ethernet/IP/TCP packets on port 7777.
"""

from h2.config import H2Configuration
from h2.connection import H2Connection
from scapy.all import Ether, IP, Raw, TCP, wrpcap

from fivegcap.sbi import (read_sbi_capture, pair_procedures, service_name,
                          SBI_PORT)

CLIENT = "10.0.0.1"
CLIENT2 = "10.0.0.3"
SERVER = "10.0.0.2"


def _exchange(request_headers, request_body=b"", status=200,
              response_headers=None, response_body=b""):
    """One HTTP/2 request/response exchange on stream 1.

    Returns (client_bytes, server_bytes): the wire bytes each side sent, in
    order, exactly as a tcpdump of the connection would contain them.
    """
    client = H2Connection(H2Configuration(client_side=True))
    server = H2Connection(H2Configuration(client_side=False))
    client.initiate_connection()
    c2s = client.data_to_send()          # client preface + SETTINGS
    server.receive_data(c2s)
    s2c = server.data_to_send()          # server preface (SETTINGS)
    client.send_headers(1, request_headers, end_stream=not request_body)
    if request_body:
        client.send_data(1, request_body, end_stream=True)
    new = client.data_to_send()          # HEADERS (+ DATA)
    c2s += new
    server.receive_data(new)
    server.send_headers(1, [(":status", str(status))] + (response_headers or []),
                        end_stream=not response_body)
    if response_body:
        server.send_data(1, response_body, end_stream=True)
    new = server.data_to_send()          # HEADERS (+ DATA)
    s2c += new
    client.receive_data(new)             # keep the client endpoint's state sane
    return c2s, s2c


def _segment(src, sport, dst, dport, payload, seq=1):
    return Ether() / IP(src=src, dst=dst) / \
        TCP(sport=sport, dport=dport, seq=seq, flags="PA") / Raw(load=payload)


def _headers(path, method="POST"):
    return [(":method", method), (":scheme", "http"),
            (":authority", f"{SERVER}:7777"), (":path", path)]


def test_request_response_accept(tmp_path):
    body = b'{"supi": "999700000000001"}'
    c2s, s2c = _exchange(_headers("/nudm-ueau/v1/auth-vectors"),
                         request_body=body, status=200)
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(CLIENT, 40000, SERVER, SBI_PORT, c2s),
            _segment(SERVER, SBI_PORT, CLIENT, 40000, s2c)])
    msgs = read_sbi_capture(str(tmp_path / "x.pcap"))
    assert len(msgs) == 2
    req = next(m for m in msgs if m.direction == "request")
    rsp = next(m for m in msgs if m.direction == "response")
    assert req.method == "POST" and req.path == "/nudm-ueau/v1/auth-vectors"
    assert req.name == "Nudm_UEAuthentication"
    assert req.body_len == len(body)
    assert rsp.status == 200 and rsp.name == "Nudm_UEAuthentication"
    assert rsp.src_ip == SERVER and rsp.dst_ip == CLIENT
    procedures, unpaired = pair_procedures(msgs)
    assert unpaired == 0
    assert len(procedures) == 1
    p = procedures[0]
    assert p.kind == "Nudm_UEAuthentication"
    assert p.outcome == "accept" and p.status == 200
    assert p.start_msg == "POST /nudm-ueau/v1/auth-vectors"
    assert p.end_msg == "200"


def test_unanswered_request_is_timeout(tmp_path):
    c2s, _ = _exchange(_headers("/nudm-uecm/v1/registrations"), status=200)
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(CLIENT, 40000, SERVER, SBI_PORT, c2s)])
    msgs = read_sbi_capture(str(tmp_path / "x.pcap"))
    assert len(msgs) == 1
    assert msgs[0].name == "Nudm_UECM"
    procedures, unpaired = pair_procedures(msgs)
    assert unpaired == 1
    p = procedures[0]
    assert p.kind == "Nudm_UECM"
    assert p.outcome == "timeout" and p.status is None
    assert p.end_msg is None and p.end_ts == p.start_ts


def test_403_reject_with_problem_details(tmp_path):
    body = b'{"title": "Cannot find NSI", "cause": "SNSSAI_NOT_SUPPORTED"}'
    c2s, s2c = _exchange(
        _headers("/nnssf-nsselection/v1/network-slice-information",
                 method="GET"),
        status=403, response_body=body)
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(CLIENT, 40000, SERVER, SBI_PORT, c2s),
            _segment(SERVER, SBI_PORT, CLIENT, 40000, s2c)])
    msgs = read_sbi_capture(str(tmp_path / "x.pcap"))
    rsp = next(m for m in msgs if m.direction == "response")
    assert rsp.status == 403
    assert rsp.name == "Nnssf_NSSelection"
    assert rsp.problem_title == "Cannot find NSI"
    assert rsp.problem_cause == "SNSSAI_NOT_SUPPORTED"
    assert rsp.body_len == len(body)
    p = pair_procedures(msgs)[0][0]
    assert p.outcome == "reject" and p.status == 403


def test_garbage_tcp_degrades(tmp_path):
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(CLIENT, 40000, SERVER, SBI_PORT, b"not http/2 at all")])
    msgs = read_sbi_capture(str(tmp_path / "x.pcap"))
    assert len(msgs) == 1
    assert msgs[0].unparsed and "preface" in msgs[0].unparsed
    procedures, unpaired = pair_procedures(msgs)
    assert procedures == [] and unpaired == 0


def test_midstream_connection_degrades(tmp_path):
    # Only the server direction is captured: no client preface anywhere.
    _, s2c = _exchange(_headers("/nudm-sdm/v1/x"), status=200)
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(SERVER, SBI_PORT, CLIENT, 40000, s2c)])
    msgs = read_sbi_capture(str(tmp_path / "x.pcap"))
    assert len(msgs) == 1
    assert msgs[0].unparsed and "preface" in msgs[0].unparsed


def test_pairing_scoped_to_connection(tmp_path):
    a_c2s, a_s2c = _exchange(_headers("/nudm-sdm/v1/a"), status=200)
    b_c2s, _ = _exchange(_headers("/nudm-sdm/v1/b"), status=200)
    # Interleaved: A request, B request (both stream 1), A response; B is
    # never answered. Pairing must not marry B's request to A's response.
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(CLIENT, 40001, SERVER, SBI_PORT, a_c2s),
            _segment(CLIENT2, 40002, SERVER, SBI_PORT, b_c2s),
            _segment(SERVER, SBI_PORT, CLIENT, 40001, a_s2c)])
    msgs = read_sbi_capture(str(tmp_path / "x.pcap"))
    procedures, unpaired = pair_procedures(msgs)
    assert unpaired == 1
    assert [(p.outcome, p.status, p.kind) for p in procedures] == [
        ("accept", 200, "Nudm_SDM"), ("timeout", None, "Nudm_SDM")]


def test_retransmission_dropped(tmp_path):
    c2s, s2c = _exchange(_headers("/nudm-sdm/v1/x"), status=200)
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(CLIENT, 40000, SERVER, SBI_PORT, c2s, seq=1),
            _segment(CLIENT, 40000, SERVER, SBI_PORT, c2s, seq=1),  # retransmit
            _segment(SERVER, SBI_PORT, CLIENT, 40000, s2c, seq=1)])
    msgs = read_sbi_capture(str(tmp_path / "x.pcap"))
    # The duplicate segment is dropped before h2 sees it twice; a second
    # feed would corrupt the HPACK/stream state and produce no clean pair.
    assert len(msgs) == 2
    assert pair_procedures(msgs)[0][0].outcome == "accept"


def test_server_first_packet_order_decodes(tmp_path):
    # The bridge can deliver the server's SETTINGS before the client's
    # preface segment (tcpdump packet order, not wire causality); decode
    # must not depend on it. Feeding the server bytes to a client-side conn
    # whose streams were never replayed used to raise "Invalid stream ID".
    c2s, s2c = _exchange(_headers("/nudm-sdm/v1/x"), status=200)
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(SERVER, SBI_PORT, CLIENT, 40000, s2c),
            _segment(CLIENT, 40000, SERVER, SBI_PORT, c2s)])
    msgs = read_sbi_capture(str(tmp_path / "x.pcap"))
    rsp = next(m for m in msgs if m.direction == "response")
    assert rsp.status == 200 and rsp.name == "Nudm_SDM"
    assert pair_procedures(msgs)[0][0].outcome == "accept"


def test_non_7777_tcp_ignored(tmp_path):
    c2s, s2c = _exchange(_headers("/nudm-sdm/v1/x"), status=200)
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(CLIENT, 40000, SERVER, 8080, c2s),
            _segment(SERVER, 8080, CLIENT, 40000, s2c)])
    assert read_sbi_capture(str(tmp_path / "x.pcap")) == []


def test_response_after_client_reset_degrades(tmp_path):
    # Client sends its request, then resets stream 1 while the server's
    # response is in flight (the server answered before seeing the RST).
    # The request is refused as "stream reset"; a response to a refused
    # request must degrade to an unparsed note too — copying the cleared
    # name would leave it neither decoded nor refused.
    client = H2Connection(H2Configuration(client_side=True))
    client.initiate_connection()
    preface = client.data_to_send()         # client preface + SETTINGS
    client.send_headers(1, _headers("/nudm-ueau/v1/auth-vectors"),
                        end_stream=False)
    headers_wire = client.data_to_send()
    client.reset_stream(1)
    reset_wire = client.data_to_send()
    c2s = preface + headers_wire + reset_wire
    server = H2Connection(H2Configuration(client_side=False))
    server.receive_data(preface + headers_wire)
    server.send_headers(1, [(":status", "200")], end_stream=True)
    s2c = server.data_to_send()
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(CLIENT, 40000, SERVER, SBI_PORT, c2s),
            _segment(SERVER, SBI_PORT, CLIENT, 40000, s2c)])
    msgs = read_sbi_capture(str(tmp_path / "x.pcap"))
    req = next(m for m in msgs if m.direction == "request")
    rsp = next(m for m in msgs if m.direction == "response")
    assert req.name is None and req.unparsed == "stream reset"
    assert rsp.name is None and rsp.unparsed


def test_supi_from_imsi_path(tmp_path):
    c2s, s2c = _exchange(
        _headers("/nudm-sdm/v2/imsi-999700000000001/sdm-subscriptions"),
        status=200)
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(CLIENT, 40000, SERVER, SBI_PORT, c2s),
            _segment(SERVER, SBI_PORT, CLIENT, 40000, s2c)])
    msgs = read_sbi_capture(str(tmp_path / "x.pcap"))
    req = next(m for m in msgs if m.direction == "request")
    rsp = next(m for m in msgs if m.direction == "response")
    assert req.supi == "999700000000001"
    assert rsp.supi is None


def test_supi_from_null_scheme_suci_path(tmp_path):
    c2s, s2c = _exchange(
        _headers("/nudm-ueau/v1/suci-0-999-70-0000-0-0-0000000001/"
                 "security-information/generate-auth-data"), status=200)
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(CLIENT, 40000, SERVER, SBI_PORT, c2s),
            _segment(SERVER, SBI_PORT, CLIENT, 40000, s2c)])
    req = next(m for m in read_sbi_capture(str(tmp_path / "x.pcap"))
               if m.direction == "request")
    assert req.supi == "999700000000001"
    assert req.name is not None


def test_protected_suci_path_yields_no_supi(tmp_path):
    c2s, s2c = _exchange(
        _headers("/nudm-ueau/v1/suci-0-999-70-0000-1-0-abc123def/"
                 "security-information/generate-auth-data"), status=200)
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(CLIENT, 40000, SERVER, SBI_PORT, c2s),
            _segment(SERVER, SBI_PORT, CLIENT, 40000, s2c)])
    req = next(m for m in read_sbi_capture(str(tmp_path / "x.pcap"))
               if m.direction == "request")
    assert req.supi is None
    assert req.name is not None  # decoded, not refused


def test_supi_from_request_body(tmp_path):
    # The sm-contexts create has no identity in its path: the JSON body's
    # "supi" is the only exact signal.
    body = b'{"supi": "imsi-999700000000001", "dnn": "internet"}'
    c2s, s2c = _exchange(_headers("/nsmf-pdusession/v1/sm-contexts"),
                         request_body=body, status=201)
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(CLIENT, 40000, SERVER, SBI_PORT, c2s),
            _segment(SERVER, SBI_PORT, CLIENT, 40000, s2c)])
    req = next(m for m in read_sbi_capture(str(tmp_path / "x.pcap"))
               if m.direction == "request")
    assert req.supi == "999700000000001"


def test_pdu_session_id_from_request_body(tmp_path):
    # The sm-contexts create's JSON body declares the session it anchors:
    # "pduSessionId" as an int. Absent or non-int yields nothing.
    body = b'{"supi": "imsi-999700000000001", "pduSessionId": 1}'
    c2s, s2c = _exchange(_headers("/nsmf-pdusession/v1/sm-contexts"),
                         request_body=body, status=201)
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(CLIENT, 40000, SERVER, SBI_PORT, c2s),
            _segment(SERVER, SBI_PORT, CLIENT, 40000, s2c)])
    req = next(m for m in read_sbi_capture(str(tmp_path / "x.pcap"))
               if m.direction == "request")
    assert req.pdu_session_id == 1

    body = b'{"supi": "imsi-999700000000001", "dnn": "internet"}'
    c2s, s2c = _exchange(_headers("/nsmf-pdusession/v1/sm-contexts"),
                         request_body=body, status=201)
    wrpcap(str(tmp_path / "y.pcap"),
           [_segment(CLIENT, 40000, SERVER, SBI_PORT, c2s),
            _segment(SERVER, SBI_PORT, CLIENT, 40000, s2c)])
    req = next(m for m in read_sbi_capture(str(tmp_path / "y.pcap"))
               if m.direction == "request")
    assert req.pdu_session_id is None


def test_conflicting_identities_yield_no_supi(tmp_path):
    # Path and body declare different identities: the message is not
    # trustworthy as a join key — no link.
    c2s, s2c = _exchange(
        _headers("/nudm-sdm/v2/imsi-999700000000001/x"),
        request_body=b'{"supi": "imsi-999700000000002"}', status=200)
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(CLIENT, 40000, SERVER, SBI_PORT, c2s),
            _segment(SERVER, SBI_PORT, CLIENT, 40000, s2c)])
    req = next(m for m in read_sbi_capture(str(tmp_path / "x.pcap"))
               if m.direction == "request")
    assert req.supi is None


def test_reset_request_yields_no_supi(tmp_path):
    client = H2Connection(H2Configuration(client_side=True))
    client.initiate_connection()
    preface = client.data_to_send()
    client.send_headers(1, _headers("/nudm-sdm/v2/imsi-999700000000001/x"),
                        end_stream=False)
    headers_wire = client.data_to_send()
    client.reset_stream(1)
    reset_wire = client.data_to_send()
    c2s = preface + headers_wire + reset_wire
    server = H2Connection(H2Configuration(client_side=False))
    server.receive_data(preface + headers_wire)
    server.send_headers(1, [(":status", "200")], end_stream=True)
    s2c = server.data_to_send()
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(CLIENT, 40000, SERVER, SBI_PORT, c2s),
            _segment(SERVER, SBI_PORT, CLIENT, 40000, s2c)])
    req = next(m for m in read_sbi_capture(str(tmp_path / "x.pcap"))
               if m.direction == "request")
    assert req.unparsed == "stream reset"
    assert req.supi is None


def test_service_name_prefixes_and_fallback():
    assert service_name("/nudm-ueau/v1/x") == "Nudm_UEAuthentication"
    assert service_name("/nudm-uecm/v1/x") == "Nudm_UECM"
    assert service_name("/nnssf-nsselection/v1/x") == "Nnssf_NSSelection"
    assert service_name("/nsmf-pdusession/v1/x") == "Nsmf_PDUSession"
    assert service_name("/nnrf-nfm/v1/x") == "Nnrf_NFM"
    assert service_name("/nnrf-disc/v1/x") == "Nnrf_NFDiscovery"
    assert service_name("/nausf-auth/v1/x") == "Nausf_UEAuthentication"
    # The fallback can't recover spec capitalization from a lowercase prefix;
    # it capitalizes each hyphen/underscore segment deterministically.
    assert service_name("/nfoo-bar/v1/x") == "NfooBar"
