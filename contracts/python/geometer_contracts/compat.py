"""Readers for earlier protocol versions; mirrors
crates/geo-contracts/src/compat.rs. A geo/1 record migrates only to a
test-trial context; generation is inherited only from an envelope naming the
same trial. Migration rewrites the JSON tree before strict decoding."""

from .canon import DecodeError, parse, to_canonical
from .generated import PROTOCOL, roundtrip_named

LEGACY_PROTOCOLS = ("geo/1",)


def _contextualize(o, generation, path):
    if "context" in o:
        raise DecodeError("unknown_field", path, "geo/1 record cannot also carry a context")
    if "trial" not in o:
        raise DecodeError("missing_field", path, "geo/1 record without trial")
    c = {"kind": "test_trial", "trial": o.pop("trial")}
    if generation is not None:
        c["generation"] = generation
    o["context"] = c


def _migrate_fact(j, inherited, path):
    if not isinstance(j, dict) or "trial" not in j or "context" in j:
        return
    t = j["trial"]
    g = inherited[1] if inherited and isinstance(t, str) and t == inherited[0] else None
    _contextualize(j, g, path)


def _migrate_envelope(j):
    if not isinstance(j, dict) or not isinstance(j.get("protocol"), str) or j["protocol"] not in LEGACY_PROTOCOLS:
        return
    if "generation" not in j:
        raise DecodeError("missing_field", "$", "geo/1 envelope without generation")
    if "trial" not in j:
        raise DecodeError("missing_field", "$", "geo/1 envelope without trial")
    generation = j.pop("generation")
    trial = j["trial"]
    _contextualize(j, generation, "$")
    j["protocol"] = PROTOCOL
    body = j.get("body")
    if isinstance(body, dict):
        for key in ("observation", "decision"):
            _migrate_fact(body.get(key), (trial, generation), f"$.body.{key}")


def migrate(type_name, j):
    if type_name == "Envelope":
        _migrate_envelope(j)
    elif type_name in ("Observation", "Decision"):
        _migrate_fact(j, None, "$")
    elif type_name == "EnvironmentSpec" and isinstance(j, dict):
        # Plans recorded before later list fields existed: absent means none.
        for k in ("secrets", "tools", "models"):
            j.setdefault(k, [])


def migrate_named(type_name: str, data: bytes) -> bytes:
    """Migrate then round-trip (shared migration vectors)."""
    j = parse(data)
    migrate(type_name, j)
    return roundtrip_named(type_name, to_canonical(j))
