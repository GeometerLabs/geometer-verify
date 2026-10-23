// Logical action identity; mirrors
// crates/geo-contracts/src/intent.rs. Only a ToolContract's declared intent
// key identifies an intent; argument equality never merges two calls.

import { createHash } from "node:crypto";
import { toCanonical, type Value } from "./canon.ts";
import { encodeIntentKeyMaterial, type IntentKeyMaterial, type ToolContract } from "./generated.ts";

export class IntentError extends Error {
  code: "unsupported" | "missing_key" | "inexact_key";
  constructor(code: IntentError["code"], msg: string) {
    super(msg);
    this.code = code;
  }
}

function exact(v: Value): boolean {
  if (v.t === "f64") return false;
  if (v.t === "list") return v.v.every(exact);
  if (v.t === "map") return [...v.v.values()].every(exact);
  return true;
}

export function material(contract: ToolContract, tenant: string | undefined, providerAccount: string, args: Map<string, Value>): IntentKeyMaterial {
  const k = contract.intent_key;
  if (k.kind === "unsupported") throw new IntentError("unsupported", k.reason);
  if (k.names.length === 0) throw new IntentError("unsupported", "intent key declares no fields");
  const key = new Map<string, Value>();
  for (const n of k.names) {
    const v = args.get(n);
    if (v === undefined || v.t === "absent" || v.t === "null") throw new IntentError("missing_key", n);
    if (!exact(v)) throw new IntentError("inexact_key", n);
    key.set(n, v);
  }
  const m: IntentKeyMaterial = { tool: contract.tool, operation: contract.operation, semantics: contract.semantics, provider_account: providerAccount, key };
  if (tenant !== undefined) m.tenant = tenant;
  return m;
}

export function intentId(m: IntentKeyMaterial): string {
  return "intent:" + createHash("sha256").update(toCanonical(encodeIntentKeyMaterial(m))).digest("hex");
}

export function attemptId(lineage: string, ordinal: bigint): string {
  return `${lineage}/attempt-${ordinal}`;
}
