//! Signature suites and profiles. Verification side only.
//!
//! A **suite** fixes an algorithm, its parameters and how a signature input is
//! encoded; a new choice (a new parameter set, a FIPS 204 context string) is a
//! new suite version, never a reinterpretation of old bytes:
//!
//! - `geo-ed25519/1`: ed25519 (`ed25519-dalek`), 32-byte public keys and
//!   64-byte signatures. The classical checkpoint and key-event formats keep
//!   their own messages (`geo-checkpoint/1`, `geo-keyevent/1`) unchanged.
//! - `geo-ml-dsa-65/1`: ML-DSA-65 of FIPS 204 (final), RustCrypto `ml-dsa`,
//!   the pure (not pre-hash) interface with an empty context string; 1952-byte
//!   public keys and 3309-byte signatures.
//!
//! A **profile** names the suites a signed record must carry, every one of
//! them: `geo-profile/classical/1` (ed25519), `geo-profile/pq/1` (ML-DSA-65)
//! and `geo-profile/hybrid/1` (both). A hybrid record with one valid signature
//! is not accepted as the other profile: the profile is inside the signed
//! input, so a stripped or relabelled signature fails.
//!
//! Every suite signature covers `geo-suite-signature/1\n` and the canonical
//! [`SuiteSignatureInput`] (record type, record digest, profile, suite,
//! algorithm, key). A record type defines its own signature-free digest.
//!
//! What a signature does not do: it does not make an assessment correct, an
//! observation complete or a record true, and its security rests on the
//! algorithm, the implementation (not independently audited) and key custody.

use crate::{Finding, KeyLog, KeyState, checkpoint_message, verify_sig};
use geo_contracts::{Anchor, Canon, Checkpoint, Digest, Id, SuiteSignatureInput};
use std::collections::BTreeSet;

pub const ED25519: &str = "geo-ed25519/1";
pub const ML_DSA_65: &str = "geo-ml-dsa-65/1";

pub const CLASSICAL: &str = "geo-profile/classical/1";
pub const PQ: &str = "geo-profile/pq/1";
pub const HYBRID: &str = "geo-profile/hybrid/1";

/// The profile marker key-event signatures of non-classical suites bind (the
/// key log's own rules decide which signatures an event needs).
pub const KEYLOG: &str = "geo-keylog/1";

pub const SIG_DOMAIN: &[u8] = b"geo-suite-signature/1\n";
/// The FIPS 204 context string of `geo-ml-dsa-65/1` (fixed by the suite).
pub const ML_DSA_CONTEXT: &[u8] = b"";

/// A supported suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suite {
    pub id: &'static str,
    pub algorithm: &'static str,
    pub public_key_len: usize,
    pub signature_len: usize,
}

pub const SUITES: &[Suite] = &[
    Suite { id: ED25519, algorithm: "ed25519", public_key_len: 32, signature_len: 64 },
    Suite { id: ML_DSA_65, algorithm: "ml-dsa-65", public_key_len: 1952, signature_len: 3309 },
];

pub fn suite(id: &str) -> Option<&'static Suite> {
    SUITES.iter().find(|s| s.id == id)
}

/// The suites a profile requires, all of them.
pub fn profile_suites(profile: &str) -> Option<&'static [&'static str]> {
    match profile {
        CLASSICAL => Some(&[ED25519]),
        PQ => Some(&[ML_DSA_65]),
        HYBRID => Some(&[ED25519, ML_DSA_65]),
        _ => None,
    }
}

/// A profile by its short name (`classical`, `pq`, `hybrid`) or its id.
pub fn profile_named(name: &str) -> Option<&'static str> {
    match name {
        "classical" | CLASSICAL => Some(CLASSICAL),
        "pq" | PQ => Some(PQ),
        "hybrid" | HYBRID => Some(HYBRID),
        _ => None,
    }
}

/// A key's identity: `key:` and the sha256 of its public key bytes. The suite
/// is recorded with the key (key log, anchor), never inferred from the id.
pub fn key_id(suite_id: &str, public_key: &[u8]) -> Result<Id, String> {
    use sha2::Digest as _;
    let s = suite(suite_id).ok_or_else(|| format!("unsupported signature suite {suite_id}"))?;
    if public_key.len() != s.public_key_len {
        return Err(format!("a {} public key is {} bytes, not {}", s.algorithm, s.public_key_len, public_key.len()));
    }
    Id::new(format!("key:{}", hex::encode(sha2::Sha256::digest(public_key)))).map_err(|e| e.to_string())
}

/// The result of checking one signature.
#[derive(Debug, Clone, PartialEq)]
pub enum SigCheck {
    Valid,
    Invalid(String),
    /// This verifier does not implement the suite: neither valid nor invalid.
    Unsupported(String),
}

/// Verify raw signature bytes under a suite.
pub fn verify(suite_id: &str, public_key: &[u8], message: &[u8], signature: &[u8]) -> SigCheck {
    let Some(s) = suite(suite_id) else { return SigCheck::Unsupported(format!("suite {suite_id}")) };
    if public_key.len() != s.public_key_len {
        return SigCheck::Invalid(format!("the public key is not a {} key", s.algorithm));
    }
    if signature.len() != s.signature_len {
        return SigCheck::Invalid(format!(
            "the signature is not a {} signature ({} bytes)",
            s.algorithm,
            signature.len()
        ));
    }
    let ok = match s.id {
        ED25519 => verify_sig(&hex::encode(public_key), message, &hex::encode(signature)),
        ML_DSA_65 => ml_dsa_65_verify_with_context(public_key, message, ML_DSA_CONTEXT, signature),
        _ => return SigCheck::Unsupported(format!("suite {suite_id}")),
    };
    if ok { SigCheck::Valid } else { SigCheck::Invalid("the signature does not verify".into()) }
}

/// ML-DSA-65 verification (FIPS 204 ML-DSA.Verify, pure interface) with an
/// explicit context string. The suite always uses [`ML_DSA_CONTEXT`]; this is
/// public so standardized test vectors (which vary the context) exercise the
/// same code the verifier uses.
pub fn ml_dsa_65_verify_with_context(public_key: &[u8], message: &[u8], context: &[u8], signature: &[u8]) -> bool {
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
    let (Ok(pk), Ok(sig)) =
        (EncodedVerifyingKey::<MlDsa65>::try_from(public_key), EncodedSignature::<MlDsa65>::try_from(signature))
    else {
        return false;
    };
    let Some(sig) = Signature::<MlDsa65>::decode(&sig) else { return false };
    VerifyingKey::<MlDsa65>::decode(&pk).verify_with_context(message, context, &sig)
}

/// The bytes one suite signature covers.
pub fn signature_input(record_type: &str, record: &Digest, profile: &str, suite_id: &str, key: &Id) -> Vec<u8> {
    let alg = suite(suite_id).map_or("unknown", |s| s.algorithm);
    let input = SuiteSignatureInput {
        record_type: Id::new(record_type).expect("record type id"),
        record: record.clone(),
        profile: Id::new(profile).unwrap_or_else(|_| Id::new("invalid-profile").expect("id")),
        suite: Id::new(suite_id).unwrap_or_else(|_| Id::new("invalid-suite").expect("id")),
        algorithm: Id::new(alg).expect("algorithm id"),
        key: key.clone(),
    };
    [SIG_DOMAIN, &input.encode()].concat()
}

/// The signature-free digest of a version 2 checkpoint.
pub fn checkpoint_digest(c: &Checkpoint) -> Digest {
    let mut c = c.clone();
    c.sig = String::new();
    c.sigs = None;
    Digest::of(&[b"geo-checkpoint/2\n".as_slice(), &c.encode()].concat())
}

pub const CHECKPOINT_V2: &str = "geo.checkpoint/2";
pub const KEY_EVENT: &str = "geo.key-event/1";

/// What a verifier itself requires, independent of what a record claims:
/// suites every trusted checkpoint must carry valid signatures for.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Policy {
    pub name: String,
    pub require_suites: Vec<String>,
}

impl Policy {
    /// Accept what the key log requires (the default).
    pub fn any() -> Policy {
        Policy { name: "as recorded".into(), require_suites: vec![] }
    }
    /// Require a profile's suites (`classical`, `pq`, `hybrid`).
    pub fn profile(name: &str) -> Option<Policy> {
        let p = profile_named(name)?;
        Some(Policy { name: p.into(), require_suites: profile_suites(p)?.iter().map(|s| s.to_string()).collect() })
    }
}

/// The profile the key log required for checkpoints signed under `key_log_seq`.
pub fn profile_at(kl: &KeyLog, key_log_seq: u64) -> &str {
    kl.profiles.iter().rev().find(|(seq, _)| *seq <= key_log_seq).map_or(CLASSICAL, |(_, p)| p.as_str())
}

/// Why a checkpoint cannot be trusted: `invalid` (a forgery, a stripped or
/// relabelled signature, a downgrade) or not usable (an unsupported suite or
/// profile, a policy the record does not meet), which is unknown, not invalid.
#[derive(Debug, Clone)]
pub struct Refusal {
    pub invalid: bool,
    pub finding: Finding,
}

fn bad(code: &str, seq: u64, detail: impl Into<String>) -> Refusal {
    Refusal { invalid: true, finding: Finding::new(code, Some(seq), detail) }
}

fn unusable(code: &str, seq: u64, detail: impl Into<String>) -> Refusal {
    Refusal { invalid: false, finding: Finding::new(code, Some(seq), detail) }
}

/// The keys whose valid signatures make a checkpoint what it claims, checked
/// against the key log (and, for an anchor, the anchor's own copy of each key).
/// A classical (version 1) checkpoint goes through the old message and the old
/// checks, plus one: the key log must not have required a stronger profile.
pub fn checkpoint_signers(
    kl: &KeyLog,
    c: &Checkpoint,
    anchor: Option<&Anchor>,
    policy: &Policy,
) -> Result<Vec<String>, Refusal> {
    if let Some(u) = kl.unsupported_from
        && c.key_log_seq >= u
    {
        return Err(unusable(
            "unsupported_suite",
            c.seq,
            "the key log uses a signature suite this verifier does not support, so this checkpoint cannot be checked",
        ));
    }
    let required = profile_at(kl, c.key_log_seq).to_string();
    let covered: BTreeSet<String>;
    let signers: Vec<String>;
    match &c.profile {
        None => {
            if required != CLASSICAL {
                return Err(bad(
                    "downgrade",
                    c.seq,
                    format!("a classical checkpoint was signed after the key log required {required}: a downgrade"),
                ));
            }
            let Some(k) = kl.keys.get(c.key.as_str()) else {
                return Err(bad("key", c.seq, "a checkpoint is signed by a key the key log does not know"));
            };
            if k.suite != ED25519 {
                return Err(bad("suite_mismatch", c.seq, format!("a classical checkpoint names a {} key", k.suite)));
            }
            let pk = anchor.map_or(k.public_key.as_str(), |a| a.public_key.as_str());
            if !verify_sig(pk, &checkpoint_message(c), &c.sig) {
                return Err(bad("signature", c.seq, "a checkpoint's signature does not verify"));
            }
            covered = [ED25519.to_string()].into();
            signers = vec![c.key.to_string()];
        }
        Some(p) => {
            if !c.sig.is_empty() || c.v < 2 {
                return Err(bad("format", c.seq, "a version 2 checkpoint carries its signatures in sigs only"));
            }
            let Some(need) = profile_suites(p.as_str()) else {
                return Err(unusable(
                    "unsupported_profile",
                    c.seq,
                    format!("profile {p} is not supported by this verifier"),
                ));
            };
            if p.as_str() != required {
                return Err(bad(
                    "profile_mismatch",
                    c.seq,
                    format!("the checkpoint claims profile {p} but the key log required {required}"),
                ));
            }
            if let Some(a) = anchor
                && a.key_log_head.is_none()
            {
                return Err(bad("key_log", c.seq, "an anchor of a version 2 checkpoint must name the key log head"));
            }
            let digest = checkpoint_digest(c);
            let mut cov = BTreeSet::new();
            let mut who = vec![];
            for s in c.sigs.iter().flatten() {
                let Some(k) = kl.keys.get(s.key.as_str()) else {
                    return Err(bad(
                        "key",
                        c.seq,
                        format!("a checkpoint signature names {}, which the key log does not know", s.key),
                    ));
                };
                if k.suite != s.suite.as_str() {
                    return Err(bad(
                        "suite_mismatch",
                        c.seq,
                        format!("a signature claims suite {} but its key is registered as {}", s.suite, k.suite),
                    ));
                }
                let Some(st) = suite(s.suite.as_str()) else {
                    if need.contains(&s.suite.as_str()) {
                        return Err(unusable(
                            "unsupported_suite",
                            c.seq,
                            format!("required suite {} is not supported here", s.suite),
                        ));
                    }
                    continue;
                };
                if st.algorithm != s.algorithm.as_str() {
                    return Err(bad(
                        "algorithm_mismatch",
                        c.seq,
                        format!("suite {} is {}, but the signature says {}", st.id, st.algorithm, s.algorithm),
                    ));
                }
                let pk_hex = match anchor {
                    Some(a) => {
                        let Some(ak) = a.keys.iter().flatten().find(|x| x.key == s.key) else {
                            return Err(bad(
                                "wrong_key",
                                c.seq,
                                "the anchor does not carry the key of one of its signatures",
                            ));
                        };
                        if ak.suite != s.suite || ak.public_key != k.public_key {
                            return Err(bad(
                                "wrong_key",
                                c.seq,
                                "the key log holds a different key than the anchor under the same id",
                            ));
                        }
                        ak.public_key.as_str()
                    }
                    None => k.public_key.as_str(),
                };
                let pk = hex::decode(pk_hex).unwrap_or_default();
                match verify(
                    st.id,
                    &pk,
                    &signature_input(CHECKPOINT_V2, &digest, p.as_str(), st.id, &s.key),
                    &s.signature.0,
                ) {
                    SigCheck::Valid => {
                        cov.insert(st.id.to_string());
                        who.push(s.key.to_string());
                    }
                    SigCheck::Invalid(why) => {
                        return Err(bad(
                            "signature",
                            c.seq,
                            format!("a {} signature on the checkpoint is invalid: {why}", st.algorithm),
                        ));
                    }
                    SigCheck::Unsupported(why) => return Err(unusable("unsupported_suite", c.seq, why)),
                }
            }
            for n in need {
                if !cov.contains(*n) {
                    return Err(bad(
                        "missing_signature",
                        c.seq,
                        format!(
                            "profile {p} requires a {n} signature and the checkpoint has none that verifies: one signature is never enough"
                        ),
                    ));
                }
            }
            covered = cov;
            signers = who;
        }
    }
    for s in &policy.require_suites {
        if !covered.contains(s) {
            return Err(unusable(
                "profile_below_policy",
                c.seq,
                format!(
                    "the verification policy ({}) requires a {s} signature, which this checkpoint does not carry",
                    policy.name
                ),
            ));
        }
    }
    Ok(signers)
}

/// A key event's signature by `signer`, checked under the signer's suite.
pub fn key_event_sig_ok(signer: &KeyState, signer_id: &str, e: &geo_contracts::KeyEvent, sig_hex: &str) -> SigCheck {
    if signer.suite == ED25519 {
        return if verify_sig(&signer.public_key, &crate::key_event_message(e), sig_hex) {
            SigCheck::Valid
        } else {
            SigCheck::Invalid("the signature does not verify".into())
        };
    }
    let (Ok(pk), Ok(sig), Ok(id)) = (hex::decode(&signer.public_key), hex::decode(sig_hex), Id::new(signer_id)) else {
        return SigCheck::Invalid("not hex".into());
    };
    verify(&signer.suite, &pk, &signature_input(KEY_EVENT, &crate::key_event_hash(e), KEYLOG, &signer.suite, &id), &sig)
}
