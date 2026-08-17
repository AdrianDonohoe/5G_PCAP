"""PCAP reading and SCTP/NGAP reassembly.

v1 assumption (CONTEXT.md): one Capture = one interface. Non-SCTP traffic is
ignored. NGAP messages are reassembled from SCTP DATA chunks (PPID 60) per
association and stream.
"""

from dataclasses import dataclass

from scapy.all import rdpcap, NoPayload, SCTP, SCTPChunkData, UDP

NGAP_PPID = 60
PFCP_PORT = 8805


@dataclass
class N2Message:
    ts: float
    assoc: tuple  # (src_port, dst_port)
    stream: int
    data: bytes
    src_ip: str | None = None
    dst_ip: str | None = None


def read_capture(path: str) -> list[N2Message]:
    """Read a capture file and return reassembled N2/NGAP messages.

    SCTP retransmissions are dropped (same association + TSN seen twice).
    """
    pkts = rdpcap(path)
    buffers: dict[tuple, bytearray] = {}
    seen_tsns: set[tuple] = set()
    msgs: list[N2Message] = []
    for pk in pkts:
        sctp = pk.getlayer(SCTP)
        if sctp is None:
            continue
        # One packet may bundle several DATA chunks (e.g. the gNB piggybacks
        # two InitialUEMessages); each is its own NGAP message. Chunks are
        # stacked as payload layers under the SCTP header.
        chunk = sctp.payload
        while chunk is not None and not isinstance(chunk, NoPayload):
            if isinstance(chunk, SCTPChunkData) \
                    and chunk.proto_id == NGAP_PPID and chunk.data:
                assoc = (sctp.sport, sctp.dport)
                tsn_key = (assoc, chunk.tsn)
                if tsn_key not in seen_tsns:
                    seen_tsns.add(tsn_key)
                    key = (assoc, chunk.stream_id)
                    buf = buffers.setdefault(key, bytearray())
                    buf += chunk.data
                    if chunk.ending:
                        msgs.append(
                            N2Message(
                                ts=float(pk.time),
                                assoc=assoc,
                                stream=key[1],
                                data=bytes(buf),
                                src_ip=pk["IP"].src if pk.haslayer("IP") else None,
                                dst_ip=pk["IP"].dst if pk.haslayer("IP") else None,
                            )
                        )
                        del buffers[key]
            chunk = chunk.payload
    return msgs


@dataclass
class N4Message:
    ts: float
    data: bytes
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None


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
            msgs.append(
                N4Message(
                    ts=float(pk.time),
                    data=payload,
                    src_ip=pk["IP"].src if pk.haslayer("IP") else None,
                    dst_ip=pk["IP"].dst if pk.haslayer("IP") else None,
                    src_port=udp.sport,
                    dst_port=udp.dport,
                )
            )
    return msgs
