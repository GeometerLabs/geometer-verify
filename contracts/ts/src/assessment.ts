// Assessment certificates; mirrors the identity
// and schema-version parts of crates/geo-contracts/src/assessment.rs.
//
// A SystemAssessment is { id, manifest, signatures }. Its id is
//   "assessment:" + hex(sha256("geo-assessment/1\n" || canonical manifest bytes))
// so the signatures are not part of it and the verification policy is.
// Three axes stay separate and are never combined into one badge:
//   AssessmentOutcome (per rule, in the manifest), AssessmentIntegrity and
//   AssessmentApplicability (judged by a verifier, see AssessmentStanding).
// Full validation (proof gating, the conservative summary, references and
// identity bindings) is implemented in Rust only; a viewer must not present a
// manifest as checked because decodeAssessment accepted it. Times and other
// u64 fields are bigint.

import { createHash } from "node:crypto";
import { JObj, parse, toCanonical } from "./canon.ts";
import { decodeSystemAssessment, encodeAssessmentManifest, type AssessmentManifest, type SystemAssessment } from "./generated.ts";

/** The only schema version this reader knows. */
export const ASSESSMENT_SCHEMA = "geo_assessment_v1";
/** Prefix of every assessment id. */
export const ASSESSMENT_ID_PREFIX = "assessment:";
const ID_DOMAIN = new TextEncoder().encode("geo-assessment/1\n");

/** Why an assessment was refused after it decoded (or before, for a newer schema). */
export class AssessmentRefusal extends Error {
  code: "unsupported_schema_version" | "id_mismatch";
  constructor(code: AssessmentRefusal["code"], msg: string) {
    super(`${code}: ${msg}`);
    this.code = code;
  }
}

/** The content-derived id of a manifest. */
export function assessmentId(m: AssessmentManifest): string {
  const bytes = toCanonical(encodeAssessmentManifest(m));
  const h = createHash("sha256").update(ID_DOMAIN).update(bytes).digest("hex");
  return ASSESSMENT_ID_PREFIX + h;
}

/** Refuse a schema version this reader does not know, before strict decoding. */
export function checkSchema(bytes: Uint8Array): void {
  const j = parse(bytes);
  if (!(j instanceof JObj)) return;
  const m = j.m.get("manifest");
  if (!(m instanceof JObj)) return;
  const s = m.m.get("schema");
  if (typeof s === "string" && s !== ASSESSMENT_SCHEMA) {
    throw new AssessmentRefusal("unsupported_schema_version", `${JSON.stringify(s)} is not ${ASSESSMENT_SCHEMA}; this reader does not read it`);
  }
}

/**
 * Read an assessment: refuse an unknown schema version (AssessmentRefusal),
 * decode strictly (DecodeError with the shared error classes) and refuse an id
 * that is not the manifest's content id. It does not run the Rust validation.
 */
export function decodeAssessment(bytes: Uint8Array): SystemAssessment {
  checkSchema(bytes);
  const a = decodeSystemAssessment(parse(bytes), "$");
  const want = assessmentId(a.manifest);
  if (a.id !== want) throw new AssessmentRefusal("id_mismatch", `id is ${a.id} but the manifest's content id is ${want}`);
  return a;
}

