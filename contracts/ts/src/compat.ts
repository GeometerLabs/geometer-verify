// Readers for earlier protocol versions; mirrors
// crates/geo-contracts/src/compat.rs. A geo/1 record migrates only to a
// test-trial context; generation is inherited only from an envelope naming
// the same trial. Migration rewrites the JSON tree before strict decoding.

import { DecodeError, JObj, parse, toCanonical, type Json } from "./canon.ts";
import { PROTOCOL, roundtripNamed } from "./generated.ts";

export const LEGACY_PROTOCOLS = ["geo/1"];

function contextualize(o: JObj, generation: Json | undefined, path: string): void {
  if (o.m.has("context")) throw new DecodeError("unknown_field", path, "geo/1 record cannot also carry a context");
  if (!o.m.has("trial")) throw new DecodeError("missing_field", path, "geo/1 record without trial");
  const c = new Map<string, Json>([["kind", "test_trial"], ["trial", o.m.get("trial")!]]);
  if (generation !== undefined) c.set("generation", generation);
  o.m.delete("trial");
  o.m.set("context", new JObj(c));
}

function migrateFact(j: Json | undefined, inherited: [Json, Json] | undefined, path: string): void {
  if (!(j instanceof JObj) || !j.m.has("trial") || j.m.has("context")) return;
  const t = j.m.get("trial");
  const g = inherited && typeof t === "string" && t === inherited[0] ? inherited[1] : undefined;
  contextualize(j, g, path);
}

function migrateEnvelope(j: Json): void {
  if (!(j instanceof JObj)) return;
  const p = j.m.get("protocol");
  if (typeof p !== "string" || !LEGACY_PROTOCOLS.includes(p)) return;
  const generation = j.m.get("generation");
  if (generation === undefined) throw new DecodeError("missing_field", "$", "geo/1 envelope without generation");
  const trial = j.m.get("trial");
  if (trial === undefined) throw new DecodeError("missing_field", "$", "geo/1 envelope without trial");
  j.m.delete("generation");
  contextualize(j, generation, "$");
  j.m.set("protocol", PROTOCOL);
  const body = j.m.get("body");
  if (body instanceof JObj) {
    for (const key of ["observation", "decision"]) migrateFact(body.m.get(key), [trial, generation], `$.body.${key}`);
  }
}

export function migrate(typeName: string, j: Json): void {
  if (typeName === "Envelope") migrateEnvelope(j);
  else if (typeName === "Observation" || typeName === "Decision") migrateFact(j, undefined, "$");
  else if (typeName === "EnvironmentSpec" && j instanceof JObj) {
    // Plans recorded before later list fields existed: absent means none.
    for (const k of ["secrets", "tools", "models"]) if (!j.m.has(k)) j.m.set(k, []);
  }
}

/** Migrate then round-trip (shared migration vectors). */
export function migrateNamed(typeName: string, bytes: Uint8Array): Uint8Array {
  const j = parse(bytes);
  migrate(typeName, j);
  return roundtripNamed(typeName, toCanonical(j));
}
