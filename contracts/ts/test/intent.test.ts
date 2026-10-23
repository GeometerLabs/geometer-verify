// Intent identity vectors, shared with Rust/Python.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parse, JObj, decodeValue, decodeToolContract, material, intentId, IntentError, type Value } from "../src/index.ts";

const vectors = JSON.parse(readFileSync(new URL("../../fixtures/vectors.json", import.meta.url), "utf8"));
const enc = new TextEncoder();

test("intent vectors derive the same ids", () => {
  const got: Record<string, string | undefined> = {};
  for (const c of vectors.intents) {
    const contract = decodeToolContract(parse(enc.encode(c.contract)), "$");
    const a = parse(enc.encode(c.arguments)) as JObj;
    const args = new Map<string, Value>([...a.m].map(([k, j]) => [k, decodeValue(j, "$")]));
    try {
      const id = intentId(material(contract, c.tenant, c.provider_account, args));
      assert.equal(id, c.intent, c.id);
      got[c.id] = id;
    } catch (e) {
      if (!(e instanceof IntentError)) throw e;
      assert.equal(e.code, c.error, c.id);
    }
  }
  for (const [a, b] of vectors.intent_relations.same_intent) assert.equal(got[a], got[b]);
  for (const g of vectors.intent_relations.distinct_intents) assert.equal(new Set(g.map((x: string) => got[x])).size, g.length);
});
