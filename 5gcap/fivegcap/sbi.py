"""SBI decoding: cleartext HTTP/2 (h2c) between the sandbox core's NFs.

The Open5GS core runs every NF's SBI server on TCP 7777 with no_tls, so the
SBI plane is HTTP/2 over plain TCP (h2c prior knowledge). Decoding is lenient
like the rest of 5gcap: failures become unparsed notes, never fatal.

Request/response pairing uses the HTTP/2 stream id within one TCP
connection, matching Open5GS's own request-response correlation. Like the
PFCP module, this is a standalone plane view: SBI messages carry no NGAP UE
IDs, so nothing is correlated against N2 flows (the Flow/KPI vocabulary in
CONTEXT.md is defined over the NGAP carrier).

Two passive h2 connections per TCP connection decode the traffic: the
request side (built server-side, fed the client's bytes including the HTTP/2
client preface) and the response side (built client-side, with each observed
request replayed through send_headers/send_data so the streams it answers
exist -- a client-side conn otherwise rejects responses on streams it never
opened). HPACK state is per-direction, so the response decoder stays in sync.
A capture that starts mid-connection (no client preface on either direction)
degrades to a single unparsed message.
"""

import json
import re
from dataclasses import dataclass

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import (DataReceived, RequestReceived, ResponseReceived,
                       StreamEnded, StreamReset)
from scapy.all import IP, TCP, rdpcap

SBI_PORT = 7777
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# SBI service name per resource path prefix (TS 29.5xx); unknown prefixes
# fall back to a camelized form of the first path segment.
SERVICE_PREFIXES = [
    ("/nudm-ueau/", "Nudm_UEAuthentication"),
    ("/nudm-uecm/", "Nudm_UECM"),
    ("/nudm-sdm/", "Nudm_SDM"),
    ("/nnssf-nsselection/", "Nnssf_NSSelection"),
    ("/nsmf-pdusession/", "Nsmf_PDUSession"),
    ("/nnrf-nfm/", "Nnrf_NFM"),
    ("/nnrf-disc/", "Nnrf_NFDiscovery"),
    ("/nausf-auth/", "Nausf_UEAuthentication"),
]


def service_name(path: str) -> str:
    """The spec service name for a resource path."""
    for prefix, name in SERVICE_PREFIXES:
        if path.startswith(prefix):
            return name
    segment = path.lstrip("/").split("/", 1)[0]
    return ("".join(part.capitalize() for part in re.split(r"[-_]", segment))
            if segment else "unknown")


@dataclass
class SbiMsg:
    ts: float
    stream_id: int
    direction: str  # "request" / "response"
    method: str | None = None
    path: str | None = None
    status: int | None = None
    body_len: int = 0
    name: str | None = None      # SBI service name, e.g. "Nudm_UEAuthentication"
    problem_title: str | None = None
    problem_cause: str | None = None
    unparsed: str | None = None
    conn: frozenset | None = None  # internal: TCP endpoints (pairing key)
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None


def _parse_problem_details(body: bytes, msg: SbiMsg) -> None:
    """Extract ProblemDetails title/cause from a JSON response body."""
    if not body:
        return
    try:
        data = json.loads(body)
    except Exception:
        return
    if isinstance(data, dict):
        if data.get("title"):
            msg.problem_title = str(data["title"])
        if data.get("cause"):
            msg.problem_cause = str(data["cause"])


def _decode_connection(conn: frozenset,
                       directions: dict[tuple, list[tuple[float, bytes]]],
                       ) -> list[SbiMsg]:
    """Decode one TCP connection's two directions into SBI messages."""
    client = next((ep for ep, entries in directions.items()
                   if entries and entries[0][1].startswith(PREFACE)), None)
    if client is None:
        # No HTTP/2 client preface anywhere: the capture started midstream
        # (or the traffic is not h2c at all) and h2 cannot sync its state.
        first = min(directions.items(), key=lambda kv: kv[1][0][0])
        ep, entries = first
        return [SbiMsg(ts=entries[0][0], stream_id=0, direction="request",
                       unparsed="h2 decode failed: no HTTP/2 client preface "
                                "(capture started midstream?)",
                       conn=conn, src_ip=ep[0], dst_ip=ep[2],
                       src_port=ep[1], dst_port=ep[3])]
    # One passive connection per direction: the request side decodes the
    # client's frames (it must receive the client preface, so it is built
    # server-side); the response side is client-side, and each request the
    # other side observes is replayed onto it so its streams exist.
    req_conn = H2Connection(H2Configuration(client_side=False,
                                            header_encoding="utf-8"))
    rsp_conn = H2Connection(H2Configuration(client_side=True,
                                            header_encoding="utf-8"))
    rsp_conn.initiate_connection()  # mark the local preface sent
    requests: dict[int, SbiMsg] = {}
    responses: dict[int, SbiMsg] = {}
    bodies: dict[tuple[int, str], bytearray] = {}
    msgs: list[SbiMsg] = []
    for ep, entries in directions.items():
        is_request = ep == client
        conn_obj = req_conn if is_request else rsp_conn
        for ts, payload in entries:
            try:
                events = conn_obj.receive_data(payload)
            except Exception as e:  # lenient: never fatal
                msgs.append(SbiMsg(
                    ts=ts, stream_id=0,
                    direction="request" if is_request else "response",
                    unparsed=f"h2 decode failed: {e!r}",
                    conn=conn, src_ip=ep[0], dst_ip=ep[2],
                    src_port=ep[1], dst_port=ep[3]))
                break
            for e in events:
                if isinstance(e, RequestReceived):
                    headers = dict(e.headers)
                    rec = SbiMsg(
                        ts=ts, stream_id=e.stream_id, direction="request",
                        method=headers.get(":method"),
                        path=headers.get(":path"),
                        name=service_name(headers.get(":path") or ""),
                        conn=conn, src_ip=ep[0], dst_ip=ep[2],
                        src_port=ep[1], dst_port=ep[3])
                    requests[e.stream_id] = rec
                    msgs.append(rec)
                    try:
                        # Replay the request onto the response-side conn so
                        # the stream it answers exists there.
                        rsp_conn.send_headers(e.stream_id, list(e.headers),
                                              end_stream=e.stream_ended)
                        rsp_conn.data_to_send()  # drain the replay's output
                    except Exception:
                        pass  # a stream that can't open fails leniently
                elif isinstance(e, ResponseReceived):
                    headers = dict(e.headers)
                    req = requests.get(e.stream_id)
                    rec = SbiMsg(
                        ts=ts, stream_id=e.stream_id, direction="response",
                        status=int(headers.get(":status", "0")),
                        name=req.name if req else None,
                        conn=conn, src_ip=ep[0], dst_ip=ep[2],
                        src_port=ep[1], dst_port=ep[3])
                    responses[e.stream_id] = rec
                    msgs.append(rec)
                elif isinstance(e, DataReceived):
                    rec = (requests if is_request else responses).get(e.stream_id)
                    if rec is not None:
                        rec.body_len += e.flow_controlled_length
                    bodies.setdefault(
                        (e.stream_id, "request" if is_request else "response"),
                        bytearray()).extend(e.data)
                    if is_request:
                        try:
                            rsp_conn.send_data(e.stream_id, e.data,
                                               end_stream=e.stream_ended)
                            rsp_conn.data_to_send()
                        except Exception:
                            pass
                elif isinstance(e, StreamEnded):
                    if not is_request and e.stream_id in responses:
                        _parse_problem_details(
                            bytes(bodies.get((e.stream_id, "response"), b"")),
                            responses[e.stream_id])
                elif isinstance(e, StreamReset):
                    rec = (requests if is_request else responses).get(e.stream_id)
                    if rec is not None and rec.unparsed is None:
                        rec.unparsed = "stream reset"
    return msgs


def read_sbi_capture(path: str) -> list[SbiMsg]:
    """Read a capture file and return SBI (HTTP/2) messages.

    TCP retransmissions are dropped (same direction + sequence number + size
    seen twice) so h2 state never sees duplicate bytes.
    """
    pkts = rdpcap(path)
    conns: dict[frozenset, dict[tuple, list[tuple[float, bytes]]]] = {}
    seen: dict[frozenset, set] = {}
    for pk in pkts:
        if not pk.haslayer(TCP):
            continue
        tcp = pk[TCP]
        if tcp.sport != SBI_PORT and tcp.dport != SBI_PORT:
            continue
        payload = bytes(tcp.payload)
        if not payload:
            continue
        if pk.haslayer(IP):
            # Trim to the IP-declared length so TCP padding never reaches h2.
            expected = pk[IP].len - (pk[IP].ihl + tcp.dataofs) * 4
            if 0 <= expected < len(payload):
                payload = payload[:expected]
        endpoint = (pk[IP].src if pk.haslayer(IP) else None, tcp.sport,
                    pk[IP].dst if pk.haslayer(IP) else None, tcp.dport)
        key = frozenset(((endpoint[0], endpoint[1]),
                         (endpoint[2], endpoint[3])))
        sig = (endpoint, tcp.seq, len(payload))
        if sig in seen.setdefault(key, set()):
            continue
        seen[key].add(sig)
        conns.setdefault(key, {}).setdefault(endpoint, []).append(
            (float(pk.time), payload))
    msgs: list[SbiMsg] = []
    for key, directions in conns.items():
        msgs.extend(_decode_connection(key, directions))
    msgs.sort(key=lambda m: m.ts)
    return msgs


@dataclass
class SbiProcedure:
    kind: str
    start_ts: float
    end_ts: float
    start_msg: str
    end_msg: str | None
    outcome: str  # "accept" / "reject" / "timeout"
    status: int | None


def pair_procedures(msgs: list[SbiMsg]) -> tuple[list[SbiProcedure], int]:
    """Pairs request/response messages by (connection, stream id). Returns
    (procedures, unpaired request count). A request never answered by
    capture end is a timeout procedure and counts toward the unpaired
    total."""
    reqs: dict[frozenset, dict[int, SbiMsg]] = {}
    rsps: dict[frozenset, dict[int, SbiMsg]] = {}
    for m in msgs:
        if m.unparsed or m.conn is None:
            continue
        bucket = reqs if m.direction == "request" else rsps
        bucket.setdefault(m.conn, {})[m.stream_id] = m
    procedures: list[SbiProcedure] = []
    unpaired = 0
    for conn, conn_reqs in reqs.items():
        conn_rsps = rsps.get(conn, {})
        for sid, req in conn_reqs.items():
            rsp = conn_rsps.get(sid)
            start_msg = (f"{req.method} {req.path}"
                         if req.method else (req.path or "?"))
            if rsp is None:
                procedures.append(SbiProcedure(
                    kind=req.name or "unknown", start_ts=req.ts, end_ts=req.ts,
                    start_msg=start_msg, end_msg=None,
                    outcome="timeout", status=None))
                unpaired += 1
            else:
                outcome = ("accept"
                           if 200 <= (rsp.status or 0) < 300 else "reject")
                procedures.append(SbiProcedure(
                    kind=req.name or "unknown", start_ts=req.ts, end_ts=rsp.ts,
                    start_msg=start_msg, end_msg=str(rsp.status),
                    outcome=outcome, status=rsp.status))
    procedures.sort(key=lambda p: p.start_ts)
    return procedures, unpaired
