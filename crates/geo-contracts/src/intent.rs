//! Logical action identity.
//!
//! An intent id is derived only from a ToolContract's declared intent key,
//! scoped by tenant, provider account, tool, operation and semantics version.
//! Argument equality never merges two calls: without a declared key there is
//! no intent (deduplication unsupported), and a key field that is missing,
//! absent, null or floating-point is refused rather than guessed. The same
//! derivation is implemented in TypeScript and Python and checked against the
//! shared vectors.

use crate::codec::{Canon, Digest, Id};
use crate::generated::{IntentKey, IntentKeyMaterial, ToolContract};
use crate::value::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentError {
    /// The contract declares no intent identity.
    Unsupported(String),
    /// A declared key field is missing, absent or null in this call.
    MissingKey(String),
    /// A key field is not exact (binary floating point).
    InexactKey(String),
}

impl std::fmt::Display for IntentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntentError::Unsupported(r) => write!(f, "intent deduplication unsupported: {r}"),
            IntentError::MissingKey(k) => write!(f, "intent key field {k} missing"),
            IntentError::InexactKey(k) => write!(f, "intent key field {k} is floating point"),
        }
    }
}

fn exact(v: &Value) -> bool {
    match v {
        Value::F64(_) => false,
        Value::List(xs) => xs.iter().all(exact),
        Value::Map(m) => m.values().all(exact),
        _ => true,
    }
}

/// The canonical key material of one call.
pub fn material(
    contract: &ToolContract,
    tenant: Option<&Id>,
    provider_account: &Id,
    arguments: &BTreeMap<String, Value>,
) -> Result<IntentKeyMaterial, IntentError> {
    let names = match &contract.intent_key {
        IntentKey::Unsupported { reason } => return Err(IntentError::Unsupported(reason.clone())),
        IntentKey::Fields { names } if names.is_empty() => {
            return Err(IntentError::Unsupported("intent key declares no fields".into()));
        }
        IntentKey::Fields { names } => names,
    };
    let mut key = BTreeMap::new();
    for n in names {
        match arguments.get(n) {
            None | Some(Value::Absent) | Some(Value::Null) => return Err(IntentError::MissingKey(n.clone())),
            Some(v) if !exact(v) => return Err(IntentError::InexactKey(n.clone())),
            Some(v) => {
                key.insert(n.clone(), v.clone());
            }
        }
    }
    Ok(IntentKeyMaterial {
        tool: contract.tool.clone(),
        operation: contract.operation.clone(),
        semantics: contract.semantics.clone(),
        tenant: tenant.cloned(),
        provider_account: provider_account.clone(),
        key,
    })
}

/// `intent:<sha256 hex of the material's canonical bytes>`.
pub fn intent_id(m: &IntentKeyMaterial) -> Id {
    Id::new(format!("intent:{}", Digest::of(&m.encode()).hex())).expect("hex id is valid")
}

/// Attempt identity from logical lineage and occurrence, never wall-clock
/// time: the n-th dispatch (from 1) of an intent, or of an action lineage
/// when the contract has no intent key.
pub fn attempt_id(lineage: &Id, ordinal: u64) -> Id {
    Id::new(format!("{lineage}/attempt-{ordinal}")).expect("attempt id within id limits")
}

/// Digest of the exact arguments of one attempt.
pub fn arguments_digest(arguments: &BTreeMap<String, Value>) -> Digest {
    Digest::of(&Value::Map(arguments.clone()).encode())
}

/// The strongest evidence a receipt may claim under a tool contract:
/// without an independent receipt lookup, a tool's own reply is at most
/// inferred evidence of a committed effect.
pub fn max_receipt_strength(contract: &ToolContract) -> crate::generated::EvidenceStrength {
    if contract.receipt_lookup {
        crate::generated::EvidenceStrength::Proven
    } else {
        crate::generated::EvidenceStrength::Inferred
    }
}

/// Refuse a receipt that claims more than its contract can establish.
pub fn admit_receipt(contract: &ToolContract, r: &crate::generated::EffectReceipt) -> Result<(), String> {
    use crate::generated::EvidenceStrength::*;
    let rank = |s| match s {
        Proven => 2,
        Inferred => 1,
        Correlated => 0,
    };
    let max = max_receipt_strength(contract);
    if rank(r.strength) > rank(max) {
        return Err(format!(
            "receipt {} claims {} but {}.{} has no independent receipt lookup (at most {})",
            r.id,
            r.strength.as_str(),
            contract.tool,
            contract.operation,
            max.as_str()
        ));
    }
    Ok(())
}
