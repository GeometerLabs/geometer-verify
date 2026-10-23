"""Intent identity vectors, shared with Rust/TypeScript."""

import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from geometer_contracts.canon import decode_value, parse  # noqa: E402
from geometer_contracts.generated import decode_tool_contract  # noqa: E402
from geometer_contracts.intent import IntentError, intent_id, material  # noqa: E402

VECTORS = json.loads((pathlib.Path(__file__).resolve().parents[2] / "fixtures/vectors.json").read_text(encoding="utf-8"))


class Intents(unittest.TestCase):
    def test_vectors(self):
        got = {}
        for c in VECTORS["intents"]:
            with self.subTest(c["id"]):
                contract = decode_tool_contract(parse(c["contract"].encode()), "$")
                args = {k: decode_value(j, "$") for k, j in parse(c["arguments"].encode()).items()}
                try:
                    got[c["id"]] = intent_id(material(contract, c.get("tenant"), c["provider_account"], args))
                    self.assertEqual(got[c["id"]], c["intent"])
                except IntentError as e:
                    self.assertEqual(e.code, c["error"])
        for a, b in VECTORS["intent_relations"]["same_intent"]:
            self.assertEqual(got[a], got[b])
        for g in VECTORS["intent_relations"]["distinct_intents"]:
            self.assertEqual(len({got[x] for x in g}), len(g))


if __name__ == "__main__":
    unittest.main()
