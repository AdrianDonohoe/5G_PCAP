"""Fuzz smoke: the decoders must never crash, and every input must come
back either decoded (a name) or honestly refused (an unparsed note) —
exactly one of the two, never a half-decoded mix.

Seeded stdlib random keeps the sweep deterministic in CI and adds no
dependencies. Two input classes: pure noise (catches crash-on-parse) and
mutations of valid encodings (bit flips, truncation, junk insertion —
catches off-by-one and length bugs noise never reaches).
"""

import random

import pytest
from pycrate_mobile.TS24501_FGMM import FGMMRegistrationRequest
from pycrate_mobile.TS29244_PFCP import PFCPSessionEstablishmentReq

from fivegcap.nas import decode as nas_decode
from fivegcap.ngap import decode as ngap_decode
from fivegcap.pfcp import decode as pfcp_decode
from synth import initial_ue_message

SEED = 0
RANDOM_PER_DECODER = 200
MUTATED_PER_DECODER = 50

SRC_IP = "10.0.0.1"
DST_IP = "10.0.0.2"


def _mutate(rng: random.Random, data: bytes) -> bytes:
    if not data:
        return b"\x00"
    kind = rng.randrange(3)
    if kind == 0:  # bit flips
        b = bytearray(data)
        for _ in range(rng.randint(1, 4)):
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
        return bytes(b)
    if kind == 1:  # truncate
        return data[: rng.randrange(len(data))]
    # junk insertion mid-buffer (a trailing suffix mostly re-validates:
    # from_aper tolerates extra bytes after the PDU)
    pos = rng.randrange(len(data))
    return data[:pos] + rng.randbytes(rng.randint(1, 32)) + data[pos:]


def _assert_honest(msg, label: str) -> None:
    """The lenient contract: decoded XOR refused. A message with both a
    name and an unparsed note is a half-decode — the decoder's own bug."""
    assert (msg.name is not None) != (msg.unparsed is not None), \
        f"{label}: neither decoded nor refused (or half-decoded): {msg}"


def _decode_or_fail(fn, data: bytes, label: str):
    try:
        return fn(data)
    except Exception as e:  # the smoke's whole point: nothing must raise
        pytest.fail(f"{label} raised on {data.hex()}: {e!r}")


def test_ngap_fuzz_smoke():
    decode = lambda d: ngap_decode(0.0, (38412, 38412), 0, d, SRC_IP, DST_IP)
    rng = random.Random(SEED)
    for i in range(RANDOM_PER_DECODER):
        data = rng.randbytes(rng.randrange(0, 257))
        _assert_honest(_decode_or_fail(decode, data, f"ngap noise {i}"),
                       f"ngap noise {i}")
    # Built lazily (the template loads a fixture pcap — that cost and a
    # missing-template failure belong to this test, not to collection).
    valid = initial_ue_message(FGMMRegistrationRequest().to_bytes(), 1)
    for i in range(MUTATED_PER_DECODER):
        data = _mutate(rng, valid)
        _assert_honest(_decode_or_fail(decode, data, f"ngap mutated {i}"),
                       f"ngap mutated {i}")


def test_nas_fuzz_smoke():
    rng = random.Random(SEED)
    for i in range(RANDOM_PER_DECODER):
        data = rng.randbytes(rng.randrange(0, 257))
        _assert_honest(_decode_or_fail(nas_decode, data, f"nas noise {i}"),
                       f"nas noise {i}")
    plain = FGMMRegistrationRequest().to_bytes()
    # Protected wire forms (EPB, sec hdr, 4-byte MAC, seq — the layout
    # test_nas.py's _wrap builds) so the decoder's security-header handling
    # is exercised alongside plaintext parsing: shdr 2 is the ciphered
    # form (ciph_algo None/0/2 cover the three cipher branches), shdr 3
    # the integrity-only form (always-plaintext inner branch).
    shdr2 = b"\x7e\x02\x01\x02\x03\x04\x00" + plain
    shdr3 = b"\x7e\x03\x01\x02\x03\x04\x00" + plain
    combos = ((plain, None), (shdr2, None), (plain, 0), (shdr2, 0),
              (shdr2, 2), (shdr3, None))  # every security-header branch
    for i in range(MUTATED_PER_DECODER):
        base, ciph = combos[i % len(combos)]
        data = _mutate(rng, base)
        decode = lambda d: nas_decode(d, ciph_algo=ciph)
        _assert_honest(_decode_or_fail(decode, data, f"nas mutated {i}"),
                       f"nas mutated {i}")


def test_pfcp_fuzz_smoke():
    decode = lambda d: pfcp_decode(0.0, d, SRC_IP, DST_IP, 8805, 8805)
    rng = random.Random(SEED)
    for i in range(RANDOM_PER_DECODER):
        data = rng.randbytes(rng.randrange(0, 257))
        _assert_honest(_decode_or_fail(decode, data, f"pfcp noise {i}"),
                       f"pfcp noise {i}")
    # Valid baseline: a pycrate-encoded session establishment request, the
    # same construction the offline PFCP tests use.
    valid = PFCPSessionEstablishmentReq()
    valid[0]["S"].set_val(0)
    valid[0]["SeqNum"].set_val(1)
    valid = valid.to_bytes()
    for i in range(MUTATED_PER_DECODER):
        data = _mutate(rng, valid)
        _assert_honest(_decode_or_fail(decode, data, f"pfcp mutated {i}"),
                       f"pfcp mutated {i}")
