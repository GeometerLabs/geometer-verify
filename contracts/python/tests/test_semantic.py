"""The semantic fixtures decode with the generated Python codecs and
re-encode to the same canonical bytes."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from geometer_contracts.canon import parse, to_canonical  # noqa: E402
from geometer_contracts.generated import (  # noqa: E402
    decode_action_graph, decode_entity_ref, decode_observation, encode_action_graph, encode_observation,
)

DIR = pathlib.Path(__file__).resolve().parents[2] / "fixtures/semantic"


class Semantic(unittest.TestCase):
    def test_fixtures_roundtrip(self):
        files = sorted(DIR.glob("*.json"))
        self.assertEqual(len(files), 3)
        for f in files:
            doc = parse(f.read_bytes())
            g = decode_action_graph(doc["graph"], "$.graph")
            self.assertEqual(to_canonical(encode_action_graph(g)), to_canonical(doc["graph"]), f.name)
            for o in doc["observations"]:
                ob = decode_observation(o, "$")
                self.assertIsInstance(ob.seq, int)
                self.assertEqual(to_canonical(encode_observation(ob)), to_canonical(o), f"{f.name} {ob.id}")
            for e in doc["expectations"]:
                if e["scope"] is not None:
                    decode_entity_ref(e["scope"], "$")


if __name__ == "__main__":
    unittest.main()
