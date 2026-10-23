"""Assessment certificates; mirrors the identity
and schema-version parts of crates/geo-contracts/src/assessment.rs.

A SystemAssessment is {id, manifest, signatures}. Its id is
"assessment:" + hex(sha256("geo-assessment/1\\n" || canonical manifest bytes)),
so the signatures are not part of it and the verification policy is. Full
validation (proof gating, the conservative summary, references and identity
bindings) is implemented in Rust only."""

import hashlib

from .canon import parse, to_canonical
from .generated import SystemAssessment, decode_system_assessment, encode_assessment_manifest

ASSESSMENT_SCHEMA = "geo_assessment_v1"
ASSESSMENT_ID_PREFIX = "assessment:"
_ID_DOMAIN = b"geo-assessment/1\n"


class AssessmentRefusal(Exception):
    def __init__(self, code: str, msg: str):
        super().__init__(f"{code}: {msg}")
        self.code = code  # unsupported_schema_version | id_mismatch


def assessment_id(manifest) -> str:
    """The content-derived id of a manifest."""
    data = to_canonical(encode_assessment_manifest(manifest))
    return ASSESSMENT_ID_PREFIX + hashlib.sha256(_ID_DOMAIN + data).hexdigest()


def check_schema(data: bytes) -> None:
    """Refuse a schema version this reader does not know, before strict decoding."""
    j = parse(data)
    if isinstance(j, dict) and isinstance(j.get("manifest"), dict):
        s = j["manifest"].get("schema")
        if isinstance(s, str) and s != ASSESSMENT_SCHEMA:
            raise AssessmentRefusal("unsupported_schema_version", f"{s!r} is not {ASSESSMENT_SCHEMA}; this reader does not read it")


def decode_assessment(data: bytes) -> SystemAssessment:
    """Refuse an unknown schema version, decode strictly (DecodeError) and
    refuse an id that is not the manifest's content id."""
    check_schema(data)
    a = decode_system_assessment(parse(data), "$")
    want = assessment_id(a.manifest)
    if a.id != want:
        raise AssessmentRefusal("id_mismatch", f"id is {a.id} but the manifest's content id is {want}")
    return a
