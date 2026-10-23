// The semantic fixtures decode with the generated TypeScript codecs and
// re-encode to the same canonical bytes as the Rust codecs produce.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { parse, toCanonical, JObj, decodeActionGraph, encodeActionGraph, decodeObservation, encodeObservation, decodeEntityRef } from "../src/index.ts";

const dir = new URL("../../fixtures/semantic/", import.meta.url);

test("semantic fixtures decode and round-trip", () => {
  const files = readdirSync(dir).filter((f) => f.endsWith(".json"));
  assert.equal(files.length, 3);
  for (const f of files) {
    const doc = parse(readFileSync(new URL(f, dir))) as JObj;
    const g = decodeActionGraph(doc.m.get("graph")!, "$.graph");
    assert.deepEqual(toCanonical(encodeActionGraph(g)), toCanonical(doc.m.get("graph")!), f);
    for (const o of doc.m.get("observations") as JObj[]) {
      const ob = decodeObservation(o, "$");
      assert.equal(typeof ob.seq, "bigint");
      assert.deepEqual(toCanonical(encodeObservation(ob)), toCanonical(o), `${f} ${ob.id}`);
    }
    for (const e of doc.m.get("expectations") as JObj[]) {
      const sc = e.m.get("scope");
      if (sc !== null && sc !== undefined) decodeEntityRef(sc, "$");
    }
  }
});
