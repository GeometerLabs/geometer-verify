"""Assessment certificate vectors, shared with Rust and
TypeScript: canonical bytes, content ids, codec rejections and schema-version
refusal. Validation and binding checks are Rust only; their vectors must still
decode here once the id is re-derived."""

import copy
import hashlib
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from geometer_contracts import DecodeError  # noqa: E402
from geometer_contracts.assessment import AssessmentRefusal, assessment_id, decode_assessment  # noqa: E402
from geometer_contracts.canon import parse, to_canonical  # noqa: E402
from geometer_contracts.generated import (  # noqa: E402
    decode_assessment_manifest,
    decode_system_assessment,
    encode_system_assessment,
    roundtrip_named,
)

DIR = pathlib.Path(__file__).resolve().parents[2] / "fixtures/assessment"
VECTORS = json.loads((DIR / "vectors.json").read_text(encoding="utf-8"))


def _read(name):
    return (DIR / name).read_bytes()


def _mutate(base, ops):
    v = copy.deepcopy(base)
    for op in ops:
        parts = op[1].split("/")[1:]
        key = parts.pop()
        p = v
        for k in parts:
            p = p[int(k)] if isinstance(p, list) else p[k]
        if op[0] == "append":
            p[key].append(op[2])
        elif op[0] == "set":
            p[int(key) if isinstance(p, list) else key] = op[2]
        elif isinstance(p, list):
            del p[int(key)]
        else:
            del p[key]
    return v


def _base(c):
    return json.loads(_read(c["base"]))


def _input(c):
    if "base" in c:
        return json.dumps(_mutate(_base(c), c["ops"])).encode()
    return c["input"].encode("utf-8")


class Assessments(unittest.TestCase):
    def test_manifests(self):
        for c in VECTORS["manifests"]:
            with self.subTest(c["file"]):
                a = decode_assessment(_read(c["file"]))
                canonical = to_canonical(encode_system_assessment(a))
                self.assertEqual("sha256:" + hashlib.sha256(canonical).hexdigest(), c["canonical_sha256"])
                self.assertEqual(to_canonical(encode_system_assessment(decode_system_assessment(parse(canonical), "$"))), canonical)
                self.assertEqual(a.id, c["assessment_id"])
                self.assertEqual(assessment_id(a.manifest), c["assessment_id"])
                self.assertEqual(a.manifest.summary.outcome, c["summary"])
                self.assertEqual(a.manifest.artifact, c["artifact"])
                self.assertEqual(len(a.signatures), c["signatures"])
        self.assertGreaterEqual(len(VECTORS["manifests"]), 5)

    def test_codec_vectors(self):
        for c in VECTORS["codec_positive"]:
            with self.subTest(c["id"]):
                self.assertEqual(roundtrip_named(c["type"], _input(c)).decode("utf-8"), c["canonical"])
        for c in VECTORS["codec_negative"]:
            with self.subTest(c["id"]):
                with self.assertRaises(DecodeError) as cm:
                    roundtrip_named(c["type"], _input(c))
                self.assertEqual(cm.exception.cls, c["error"], str(cm.exception))

    def test_schema_and_id_refusals(self):
        for c in VECTORS["schema"]:
            with self.subTest(c["id"]):
                with self.assertRaises(AssessmentRefusal) as cm:
                    decode_assessment(_input(c))
                self.assertEqual(cm.exception.code, c["refusal"])

    def test_validation_only_vectors_decode_here(self):
        for c in VECTORS["refusals"]:
            with self.subTest(c["id"]):
                v = _mutate(_base(c), c["ops"])
                if c["reid"]:
                    v["id"] = assessment_id(decode_assessment_manifest(parse(json.dumps(v["manifest"]).encode()), "$"))
                data = json.dumps(v).encode()
                if "id_mismatch" in c["codes"]:
                    with self.assertRaises(AssessmentRefusal):
                        decode_assessment(data)
                else:
                    decode_assessment(data)


if __name__ == "__main__":
    unittest.main()
