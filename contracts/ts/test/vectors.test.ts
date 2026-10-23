// Cross-language codec vectors, shared with Rust/Python.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { roundtripNamed, DecodeError } from "../src/index.ts";

const vectors = JSON.parse(readFileSync(new URL("../../fixtures/vectors.json", import.meta.url), "utf8"));
const enc = new TextEncoder();
const dec = new TextDecoder();
const input = (c: any): Uint8Array => (c.input_b64 !== undefined ? Uint8Array.from(atob(c.input_b64), (x) => x.charCodeAt(0)) : enc.encode(c.input));

test("positive vectors round-trip to canonical bytes", () => {
  for (const c of vectors.positive) {
    const out = dec.decode(roundtripNamed(c.type, input(c)));
    assert.equal(out, c.canonical, c.id);
    assert.equal(dec.decode(roundtripNamed(c.type, enc.encode(c.canonical))), c.canonical, `${c.id} fixed point`);
  }
});

test("negative vectors reject with the declared class", () => {
  for (const c of vectors.negative) {
    assert.throws(() => roundtripNamed(c.type, input(c)), (e: unknown) => {
      assert.ok(e instanceof DecodeError, `${c.id}: ${e}`);
      assert.equal(e.cls, c.error, `${c.id}: ${e.message}`);
      return true;
    }, c.id);
  }
});

test("geo/1 migration vectors", async () => {
  const { migrateNamed } = await import("../src/index.ts");
  for (const c of vectors.migrations) assert.equal(dec.decode(migrateNamed(c.type, input(c))), c.canonical, c.id);
  for (const c of vectors.migration_negative) {
    assert.throws(() => migrateNamed(c.type, input(c)), (e: unknown) => {
      assert.ok(e instanceof DecodeError, `${c.id}: ${e}`);
      assert.equal(e.cls, c.error, `${c.id}: ${e.message}`);
      return true;
    }, c.id);
  }
});
