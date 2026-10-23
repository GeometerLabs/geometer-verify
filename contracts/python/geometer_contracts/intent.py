"""Logical action identity; mirrors
crates/geo-contracts/src/intent.rs. Only a ToolContract's declared intent key
identifies an intent; argument equality never merges two calls."""

import hashlib

from .canon import to_canonical
from .generated import IntentKeyFields, IntentKeyMaterial, encode_intent_key_material


class IntentError(Exception):
    def __init__(self, code: str, msg: str):
        super().__init__(msg)
        self.code = code  # unsupported | missing_key | inexact_key


def _exact(v) -> bool:
    if v.t == "f64":
        return False
    if v.t == "list":
        return all(_exact(e) for e in v.v)
    if v.t == "map":
        return all(_exact(e) for e in v.v.values())
    return True


def material(contract, tenant, provider_account, args) -> IntentKeyMaterial:
    k = contract.intent_key
    if not isinstance(k, IntentKeyFields):
        raise IntentError("unsupported", k.reason)
    if not k.names:
        raise IntentError("unsupported", "intent key declares no fields")
    key = {}
    for n in k.names:
        v = args.get(n)
        if v is None or v.t in ("absent", "null"):
            raise IntentError("missing_key", n)
        if not _exact(v):
            raise IntentError("inexact_key", n)
        key[n] = v
    return IntentKeyMaterial(tool=contract.tool, operation=contract.operation, semantics=contract.semantics,
                             tenant=tenant, provider_account=provider_account, key=key)


def intent_id(m: IntentKeyMaterial) -> str:
    return "intent:" + hashlib.sha256(to_canonical(encode_intent_key_material(m))).hexdigest()


def attempt_id(lineage: str, ordinal: int) -> str:
    return f"{lineage}/attempt-{ordinal}"
