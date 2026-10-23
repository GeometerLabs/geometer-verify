// Assessment certificate vectors, shared with Rust and
// Python: canonical bytes, content ids, codec rejections and schema-version
// refusal. Validation and binding checks are Rust only; their vectors must
// still decode here once the id is re-derived.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  AssessmentRefusal, DecodeError, assessmentId, decodeAssessment, decodeAssessmentManifest, decodeSystemAssessment,
  encodeSystemAssessment, parse, roundtripNamed, toCanonical,
} from "../src/index.ts";

const dir = new URL("../../fixtures/assessment/", import.meta.url);
const enc = new TextEncoder();
const dec = new TextDecoder();
const read = (name: string): Uint8Array => readFileSync(new URL(name, dir));
const vectors = JSON.parse(dec.decode(read("vectors.json")));

function mutate(base: any, ops: any[]): any {
  const v = structuredClone(base);
  for (const [op, ptr, value] of ops) {
    const parts = ptr.split("/").slice(1);
    const key = parts.pop();
    let p = v;
    for (const k of parts) p = p[Array.isArray(p) ? Number(k) : k];
    if (op === "append") p[key].push(value);
    else if (op === "set") p[Array.isArray(p) ? Number(key) : key] = value;
    else if (Array.isArray(p)) p.splice(Number(key), 1);
    else delete p[key];
  }
  return v;
}

const baseOf = (c: any) => JSON.parse(dec.decode(read(c.base)));
const inputOf = (c: any): Uint8Array => (c.base !== undefined ? enc.encode(JSON.stringify(mutate(baseOf(c), c.ops))) : enc.encode(c.input));

test("manifests re-encode to the shared canonical bytes and derive the same ids", () => {
  for (const c of vectors.manifests) {
    const a = decodeAssessment(read(c.file));
    const canonical = toCanonical(encodeSystemAssessment(a));
    assert.equal("sha256:" + createHash("sha256").update(canonical).digest("hex"), c.canonical_sha256, c.file);
    assert.deepEqual(toCanonical(encodeSystemAssessment(decodeSystemAssessment(parse(canonical), "$"))), canonical, `${c.file} fixed point`);
    assert.equal(a.id, c.assessment_id, c.file);
    assert.equal(assessmentId(a.manifest), c.assessment_id, c.file);
    assert.equal(a.manifest.summary.outcome, c.summary, c.file);
    assert.equal(a.manifest.artifact, c.artifact, c.file);
    assert.equal(a.signatures.length, c.signatures, c.file);
  }
  assert.ok(vectors.manifests.length >= 5);
});

test("codec vectors round-trip or reject with the declared class", () => {
  for (const c of vectors.codec_positive) assert.equal(dec.decode(roundtripNamed(c.type, inputOf(c))), c.canonical, c.id);
  for (const c of vectors.codec_negative) {
    assert.throws(() => roundtripNamed(c.type, inputOf(c)), (e: unknown) => {
      assert.ok(e instanceof DecodeError, `${c.id}: ${e}`);
      assert.equal(e.cls, c.error, `${c.id}: ${e.message}`);
      return true;
    }, c.id);
  }
});

test("unknown schema versions and wrong ids are refused", () => {
  for (const c of vectors.schema) {
    assert.throws(() => decodeAssessment(inputOf(c)), (e: unknown) => {
      assert.ok(e instanceof AssessmentRefusal, `${c.id}: ${e}`);
      assert.equal(e.code, c.refusal, c.id);
      return true;
    }, c.id);
  }
});

test("validation-only vectors decode here once the id is re-derived (Rust refuses them)", () => {
  for (const c of vectors.refusals) {
    const v = mutate(baseOf(c), c.ops);
    if (c.reid) v.id = assessmentId(decodeAssessmentManifest(parse(enc.encode(JSON.stringify(v.manifest))), "$"));
    const bytes = enc.encode(JSON.stringify(v));
    if (c.codes.includes("id_mismatch")) assert.throws(() => decodeAssessment(bytes), AssessmentRefusal, c.id);
    else decodeAssessment(bytes);
  }
});
