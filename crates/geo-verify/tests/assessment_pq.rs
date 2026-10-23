//! C4 wired into assessment verification: an assessment
//! can carry an ed25519 and an ML-DSA-65 signature, and `verify` checks each
//! under its suite. Hybrid and PQ-only policies verify; a missing second
//! signature, a downgrade of the required suites and a mislabelled signature
//! do not. Built from the approved refund-agent example like
//! tests/assessment.rs; implementer-written tests, not an external review.

use ed25519_dalek::{Signer, SigningKey};
use geo_contracts::assessment as a;
use geo_contracts::*;
use geo_verify::assessment::{Inputs, key_id_of_bytes, verify};
use geo_verify::suite::ML_DSA_65;
use std::collections::BTreeMap;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/fixtures/assessment/");
const NOW: u64 = 1_792_300_000_000;
const ML_ALG: &str = "ml-dsa-65";

fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}

struct Keys {
    ed: SigningKey,
    ml: ml_dsa::SigningKey<ml_dsa::MlDsa65>,
}

fn keys() -> Keys {
    Keys { ed: SigningKey::from_bytes(&[1; 32]), ml: ml_dsa::SigningKey::from_seed(&[2u8; 32].into()) }
}

fn ml_pk(k: &Keys) -> Vec<u8> {
    use ml_dsa::signature::Keypair;
    k.ml.verifying_key().encode().to_vec()
}

fn trusted(k: &Keys) -> Vec<AssessmentTrustedKey> {
    let ed = k.ed.verifying_key().to_bytes().to_vec();
    let ml = ml_pk(k);
    vec![
        AssessmentTrustedKey {
            key: key_id_of_bytes(&ed),
            suite: id(a::SUITE_ED25519),
            algorithm: id(a::ALG_ED25519),
            public_key: Bytes(ed),
            label: "issuer ed25519".into(),
        },
        AssessmentTrustedKey {
            key: key_id_of_bytes(&ml),
            suite: id(ML_DSA_65),
            algorithm: id(ML_ALG),
            public_key: Bytes(ml),
            label: "issuer ML-DSA-65".into(),
        },
    ]
}

fn policy(k: &Keys) -> AssessmentTrustPolicy {
    AssessmentTrustPolicy {
        id: id("test-policy"),
        keys: trusted(k),
        key_log: vec![],
        key_log_as_of_ms: None,
        max_status_age_ms: None,
    }
}

fn manifest(suites: &[&str]) -> AssessmentManifest {
    let ex = SystemAssessment::decode(&std::fs::read(format!("{DIR}example-refund-agent.json")).unwrap()).unwrap();
    let mut m = ex.manifest;
    m.issued_ms = NOW - 3_600_000;
    m.verification.required_suites = suites.iter().map(|s| id(s)).collect();
    m
}

fn sign(k: &Keys, suite: &str, aid: &Id) -> AssessmentSignature {
    let (alg, key) = if suite == ML_DSA_65 {
        (ML_ALG, key_id_of_bytes(&ml_pk(k)))
    } else {
        (a::ALG_ED25519, key_id_of_bytes(&k.ed.verifying_key().to_bytes()))
    };
    let mut s = AssessmentSignature { suite: id(suite), algorithm: id(alg), key, signature: Bytes(vec![]) };
    let msg = a::signature_message(aid, &s);
    s.signature = Bytes(if suite == ML_DSA_65 {
        k.ml.expanded_key().sign_deterministic(&msg, b"").unwrap().encode().to_vec()
    } else {
        k.ed.sign(&msg).to_bytes().to_vec()
    });
    s
}

fn bundle(
    m: AssessmentManifest,
    aid: Id,
    sigs: Vec<AssessmentSignature>,
) -> (AssessmentBundle, BTreeMap<String, Option<Vec<u8>>>) {
    let sa = SystemAssessment { id: aid, signatures: sigs, manifest: m };
    let mut files = BTreeMap::new();
    let mut entries = vec![];
    for e in &sa.manifest.evidence {
        let name = e.location.clone().unwrap().rsplit('/').next().unwrap().to_string();
        let bytes = std::fs::read(format!("{DIR}evidence/{name}")).unwrap();
        let path = format!("evidence/{}", e.id);
        entries.push(AssessmentBundleFile {
            evidence: e.id.clone(),
            availability: AssessmentPayloadAvailability::Included,
            path: Some(path.clone()),
            digest: Some(Digest::of(&bytes)),
            size: Some(bytes.len() as u64),
            reason: String::new(),
        });
        files.insert(path, Some(bytes));
    }
    let b = AssessmentBundle {
        format: a::BUNDLE_FORMAT.into(),
        v: a::BUNDLE_VERSION,
        assessment: sa,
        files: entries,
        status: None,
        statement: None,
        renewals: vec![],
        key_hints: vec![],
        key_log: vec![],
        provenance: None,
        exported_ms: NOW,
        notes: vec![],
    };
    (b, files)
}

fn integrity(k: &Keys, b: &AssessmentBundle, files: &BTreeMap<String, Option<Vec<u8>>>) -> AssessmentIntegrity {
    let p = policy(k);
    verify(&Inputs {
        bundle: b,
        files,
        policy: &p,
        status: None,
        anchors: &[],
        packs: &[],
        expected: None,
        now_ms: NOW,
    })
    .standing
    .integrity
}

fn signed(k: &Keys, required: &[&str], with: &[&str]) -> (AssessmentBundle, BTreeMap<String, Option<Vec<u8>>>) {
    let m = manifest(required);
    let aid = a::assessment_id(&m);
    let sigs = with.iter().map(|s| sign(k, s, &aid)).collect();
    bundle(m, aid, sigs)
}

#[test]
fn a_hybrid_assessment_with_both_signatures_verifies() {
    let k = keys();
    let (b, f) = signed(&k, &[a::SUITE_ED25519, ML_DSA_65], &[a::SUITE_ED25519, ML_DSA_65]);
    assert_eq!(integrity(&k, &b, &f), AssessmentIntegrity::VerifiedAgainstTrustedInputs);
}

#[test]
fn a_pq_only_assessment_verifies_with_the_ml_dsa_signature() {
    let k = keys();
    let (b, f) = signed(&k, &[ML_DSA_65], &[ML_DSA_65]);
    assert_eq!(integrity(&k, &b, &f), AssessmentIntegrity::VerifiedAgainstTrustedInputs);
}

#[test]
fn a_hybrid_assessment_missing_its_second_signature_is_invalid() {
    let k = keys();
    for only in [a::SUITE_ED25519, ML_DSA_65] {
        let (b, f) = signed(&k, &[a::SUITE_ED25519, ML_DSA_65], &[only]);
        assert_eq!(integrity(&k, &b, &f), AssessmentIntegrity::Invalid, "only {only}");
    }
}

#[test]
fn lowering_the_required_suites_is_a_different_assessment_and_its_signatures_fail() {
    let k = keys();
    let (mut b, f) = signed(&k, &[a::SUITE_ED25519, ML_DSA_65], &[a::SUITE_ED25519, ML_DSA_65]);
    // Downgrade: require ed25519 only and drop the ML-DSA signature, keeping the id.
    b.assessment.manifest.verification.required_suites = vec![id(a::SUITE_ED25519)];
    b.assessment.signatures.retain(|s| s.suite.as_str() == a::SUITE_ED25519);
    assert_eq!(integrity(&k, &b, &f), AssessmentIntegrity::Invalid, "the id no longer matches the manifest");
    // The same with the id re-derived: the ed25519 signature was made over the hybrid assessment's id.
    b.assessment.id = a::assessment_id(&b.assessment.manifest);
    assert_eq!(integrity(&k, &b, &f), AssessmentIntegrity::Invalid);
}

#[test]
fn an_ml_dsa_signature_relabelled_or_damaged_is_refused() {
    let k = keys();
    let (mut b, f) = signed(&k, &[a::SUITE_ED25519, ML_DSA_65], &[a::SUITE_ED25519, ML_DSA_65]);
    let good = b.clone();
    b.assessment.signatures[1].suite = id(a::SUITE_ED25519);
    b.assessment.signatures[1].algorithm = id(a::ALG_ED25519);
    assert_ne!(integrity(&k, &b, &f), AssessmentIntegrity::VerifiedAgainstTrustedInputs);
    let mut b = good;
    b.assessment.signatures[1].signature.0[10] ^= 1;
    assert_eq!(integrity(&k, &b, &f), AssessmentIntegrity::Invalid);
}
