"""NAS-5G decoding via pycrate_mobile (lenient)."""

from dataclasses import dataclass

from pycrate_mobile import NAS5G


@dataclass
class NasMsg:
    name: str | None          # e.g. "5GMMRegistrationRequest"
    protected: bool = False   # security-protected payload (no CryptoMobile)
    inner: str | None = None  # inner message name when decodable
    unparsed: str | None = None


def decode(data: bytes) -> NasMsg:
    msg = NasMsg(name=None)
    try:
        parsed, err = NAS5G.parse_NAS5G(data, inner=True, sec_hdr=True)
    except Exception as e:  # lenient
        msg.unparsed = f"NAS parse failed: {e!r}"
        return msg
    if parsed is None:
        msg.unparsed = f"NAS parse failed (pycrate err {err})"
        return msg
    # Security-protected messages surface the container, not the plaintext.
    name = getattr(parsed, "_name", None) or type(parsed).__name__
    msg.protected = name == "FGMMSecProtNASMessage" or "SecProt" in name
    msg.name = name
    inner_obj = getattr(parsed, "NASMessage", None) if msg.protected else None
    if inner_obj is not None and inner_obj:
        msg.inner = getattr(inner_obj, "_name", None) or type(inner_obj).__name__
    return msg
