"""NAS-5G decoding via pycrate_mobile (lenient).

The sandbox AMF selects 5G-EA0 (null cipher), so "ciphered" payloads are
actually plaintext: integrity-protected messages carry the inner NAS after a
7-byte header (EPD, security header, 4-byte MAC, sequence number). `decode`
strips that header and parses the inner message directly. The ciphering
algorithm is taken from the flow's SecurityModeCommand rather than assumed,
so a real cipher degrades to an honest unparsed note instead of a bogus parse.
"""

from dataclasses import dataclass

from pycrate_mobile import NAS5G
from pycrate_mobile.TS24501_IE import _FGMMCause_dict, _FGSMCause_dict

# Cause IE names -> value dictionaries (5GMM cause / 5GSM cause).
CAUSE_DICTS = {"5GMMCause": _FGMMCause_dict, "5GSMCause": _FGSMCause_dict}


@dataclass
class NasMsg:
    name: str | None          # e.g. "5GMMRegistrationRequest"
    protected: bool = False   # security-protected payload (MAC-stripped)
    inner: str | None = None  # inner message name when decodable
    cause: int | None = None       # e.g. 7 in a RegistrationReject
    cause_name: str | None = None  # e.g. "5GS services not allowed"
    ciph_algo: int | None = None   # selected by the SMC (0 = 5G-EA0 null)
    integ_algo: int | None = None
    unparsed: str | None = None


def decode(data: bytes, ciph_algo: int | None = None) -> NasMsg:
    """Parse a 5G NAS PDU. `ciph_algo` is the ciphering algorithm the flow's
    SecurityModeCommand selected; it decides whether shdr 2/4 (integrity +
    ciphering) payloads are plaintext (5G-EA0) or opaque."""
    msg = NasMsg(name=None)
    try:
        parsed, err = NAS5G.parse_NAS5G(data, inner=True, sec_hdr=True)
    except Exception as e:  # lenient
        msg.unparsed = f"NAS parse failed: {e!r}"
        return msg
    if parsed is None:
        msg.unparsed = f"NAS parse failed (pycrate err {err})"
        return msg
    name = getattr(parsed, "_name", None) or type(parsed).__name__
    msg.protected = "SecProt" in name
    msg.name = name
    _fill_from(msg, parsed)
    if msg.protected and len(data) > 7 and data[0] == 0x7E:
        shdr = data[1] & 0x0F
        if shdr in (1, 3):
            # Integrity-protected only: payload is always plaintext.
            _decode_inner(msg, data[7:])
        elif ciph_algo == 0:
            # 5G-EA0 null cipher: "ciphered" payload is plaintext.
            _decode_inner(msg, data[7:])
        elif ciph_algo is None:
            msg.unparsed = "security-protected (ciphering unknown: no SMC in capture)"
        else:
            msg.unparsed = f"security-protected (ciphering 5G-EA{ciph_algo} not supported)"
    return msg


def _decode_inner(msg: NasMsg, inner_data: bytes) -> None:
    try:
        inner, err = NAS5G.parse_NAS5G(inner_data, inner=True, sec_hdr=True)
    except Exception as e:  # lenient
        msg.unparsed = f"inner NAS parse failed: {e!r}"
        return
    if inner is None:
        msg.unparsed = f"inner NAS parse failed (pycrate err {err})"
        return
    msg.inner = getattr(inner, "_name", None) or type(inner).__name__
    _fill_from(msg, inner)


def _fill_from(msg: NasMsg, parsed) -> None:
    """Extract cause IEs and the SMC's selected algorithms, leniently."""
    try:
        ies = parsed._content
    except Exception:
        return
    container = None
    for ie in ies:
        ie_name = getattr(ie, "_name", None)
        if ie_name == "NASSecAlgo":
            val = ie.get_val()
            if val and isinstance(val[0], list) and len(val[0]) == 2:
                msg.ciph_algo, msg.integ_algo = val[0]
        elif ie_name in CAUSE_DICTS:
            # Type3V values come back as [value], Type3TV as [tag, value].
            val = ie.get_val()
            if isinstance(val, list) and val:
                v = val[-1]
                if isinstance(v, bytes) and v:
                    v = int.from_bytes(v, "big")
                if isinstance(v, int):
                    msg.cause = v
                    msg.cause_name = CAUSE_DICTS[ie_name].get(v)
        elif ie_name == "PayloadContainer":
            # 5GMM UL/DL NAS transport: pycrate (inner=True) already parsed
            # the container into a nested 5GSM message, replacing the raw 'V'
            # element with it (ie._content == [L, <5GSM message>]). Defer to
            # after the outer loop so the 5GSM cause (the specific one) wins
            # over a 5GMM cause on the transport itself.
            try:
                cont = ie._content[1]
            except (IndexError, AttributeError):
                continue
            cont_name = getattr(cont, "_name", None)
            if cont_name and cont_name.startswith("5GSM"):
                container = cont
    if container is not None:
        msg.inner = container._name
        _fill_from(msg, container)
