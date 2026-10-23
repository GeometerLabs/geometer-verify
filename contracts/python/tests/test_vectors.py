"""Cross-language codec vectors, shared with Rust/TypeScript."""

import base64
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from geometer_contracts import DecodeError  # noqa: E402
from geometer_contracts.generated import roundtrip_named  # noqa: E402

VECTORS = json.loads((pathlib.Path(__file__).resolve().parents[2] / "fixtures/vectors.json").read_text(encoding="utf-8"))


def _input(c):
    return base64.b64decode(c["input_b64"]) if "input_b64" in c else c["input"].encode("utf-8")


class Vectors(unittest.TestCase):
    def test_positive_roundtrip(self):
        for c in VECTORS["positive"]:
            with self.subTest(c["id"]):
                self.assertEqual(roundtrip_named(c["type"], _input(c)).decode("utf-8"), c["canonical"])
                self.assertEqual(roundtrip_named(c["type"], c["canonical"].encode("utf-8")).decode("utf-8"), c["canonical"])

    def test_negative_rejected_with_class(self):
        for c in VECTORS["negative"]:
            with self.subTest(c["id"]):
                with self.assertRaises(DecodeError) as cm:
                    roundtrip_named(c["type"], _input(c))
                self.assertEqual(cm.exception.cls, c["error"], str(cm.exception))

    def test_geo1_migration(self):
        from geometer_contracts.compat import migrate_named

        for c in VECTORS["migrations"]:
            with self.subTest(c["id"]):
                self.assertEqual(migrate_named(c["type"], _input(c)).decode("utf-8"), c["canonical"])
        for c in VECTORS["migration_negative"]:
            with self.subTest(c["id"]):
                with self.assertRaises(DecodeError) as cm:
                    migrate_named(c["type"], _input(c))
                self.assertEqual(cm.exception.cls, c["error"], str(cm.exception))


if __name__ == "__main__":
    unittest.main()
