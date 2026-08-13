"""PCAP reading and SCTP/NGAP reassembly.

v1 assumption (CONTEXT.md): one Capture = one interface. Non-SCTP traffic is
ignored. NGAP messages are reassembled from SCTP DATA chunks (PPID 60) per
association and stream.
"""

from dataclasses import dataclass

from scapy.all import rdpcap, SCTPChunkData, UDP

NGAP_PPID = 60
PFCP_PORT = 8805


@dataclass
class N2Message:
    ts: float
    assoc: tuple  # (src_port, dst_port)
    stream: int
    data: bytes


def read_capture(path: str) -> list[N2Message]:
    """Read a capture file and return reassembled N2/NGAP messages.

    SCTP retransmissions are dropped (same association + TSN seen twice).
    """
    pkts = rdpcap(path)
    buffers: dict[tuple, bytearray] = {}
    seen_tsns: set[tuple] = set()
    msgs: list[N2Message] = []
    for pk in pkts:
        if not pk.haslayer(SCTPChunkData):
            continue
        ch = pk[SCTPChunkData]
        if ch.proto_id != NGAP_PPID or not ch.data:
            continue
        assoc = (pk["SCTP"].sport, pk["SCTP"].dport)
        tsn_key = (assoc, ch.tsn)
        if tsn_key in seen_tsns:
            continue  # retransmission
        seen_tsns.add(tsn_key)
        key = (assoc, ch.stream_id)
        buf = buffers.setdefault(key, bytearray())
        buf += ch.data
        if ch.ending:
            msgs.append(
                N2Message(
                    ts=float(pk.time),
                    assoc=assoc,
                    stream=key[1],
                    data=bytes(buf),
                )
            )
            del buffers[key]
    return msgs


@dataclass
class N4Message:
    ts: float
    data: bytes


def read_pfcp_capture(path: str) -> list[N4Message]:
    """Read a capture file and return PFCP (N4) message payloads."""
    pkts = rdpcap(path)
    msgs: list[N4Message] = []
    for pk in pkts:
        if not pk.haslayer(UDP):
            continue
        udp = pk[UDP]
        if udp.sport != PFCP_PORT and udp.dport != PFCP_PORT:
            continue
        payload = bytes(udp.payload)
        if payload:
            msgs.append(N4Message(ts=float(pk.time), data=payload))
    return msgs
