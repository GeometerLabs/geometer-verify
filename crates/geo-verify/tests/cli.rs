//! The standalone `geo-verify` binary's `--require-profile`:
//! the reader's own signature policy, apart from what a record says it needs.
//!
//! - Packs: the fixtures in `tests/fixtures/profile/` (written by
//!   Geometer's ledger writer) are a ledger signed classically
//!   for five entries, then under the hybrid profile for five more, with the
//!   classical anchor saved before the switch and the hybrid one at the end.
//! - Assessments: the approved refund-agent example, signed with ed25519 only
//!   (classical) or with ed25519 and ML-DSA-65 (hybrid), written as a bundle
//!   directory with its evidence files.
//!
//! Implementer-written tests, not an external review.

use ed25519_dalek::{Signer, SigningKey};
use geo_contracts::assessment as a;
use geo_contracts::*;
use geo_verify::assessment::key_id_of_bytes;
use geo_verify::suite::ML_DSA_65;
use std::path::{Path, PathBuf};
use std::process::Command;

const ASSESSMENT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/fixtures/assessment/");
const ML_ALG: &str = "ml-dsa-65";

fn profile_fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/profile")
}

/// Run the binary: (exit code, stdout, stderr).
fn geo_verify(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_geo-verify")).args(args).output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A fresh directory under the system's temporary folder (this crate keeps no test dependencies).
fn tempdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("geo-verify-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn p(name: &str) -> String {
    profile_fixtures().join(name).to_string_lossy().into_owned()
}

// ------------------------------------------------------------ packs

#[test]
fn a_pack_verifies_as_recorded_without_the_flag() {
    let (code, out, err) = geo_verify(&[&p("pack.json"), "--anchor", &p("anchor-classical.json")]);
    assert_eq!(code, 0, "{out}{err}");
    let (code, out, err) =
        geo_verify(&[&p("pack.json"), "--anchor", &p("anchor-classical.json"), "--anchor", &p("anchor-hybrid.json")]);
    assert_eq!(code, 0, "{out}{err}");
}

#[test]
fn requiring_hybrid_refuses_a_classical_anchor_and_accepts_a_hybrid_one() {
    // The classical anchor alone: nothing carries the signatures hybrid needs, so nothing is trusted.
    let (code, out, err) =
        geo_verify(&[&p("pack.json"), "--anchor", &p("anchor-classical.json"), "--require-profile", "hybrid"]);
    assert_eq!(code, 3, "unverifiable, not invalid: {out}{err}");
    let (_, json, _) = geo_verify(&[
        &p("pack.json"),
        "--anchor",
        &p("anchor-classical.json"),
        "--require-profile",
        "hybrid",
        "--json",
    ]);
    let j: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(j["state"], "unverifiable", "{j}");
    assert!(json.contains("profile_below_policy"), "{json}");
    // With the hybrid anchor too, the whole history verifies under the hybrid requirement.
    let (code, out, err) = geo_verify(&[
        &p("pack.json"),
        "--anchor",
        &p("anchor-classical.json"),
        "--anchor",
        &p("anchor-hybrid.json"),
        "--require-profile",
        "hybrid",
    ]);
    assert_eq!(code, 0, "{out}{err}");
    // Requiring classical accepts the classical anchor.
    let (code, out, err) =
        geo_verify(&[&p("pack.json"), "--anchor", &p("anchor-classical.json"), "--require-profile", "classical"]);
    assert_eq!(code, 0, "{out}{err}");
}

#[test]
fn an_unknown_or_missing_profile_is_bad_usage() {
    let (code, _, err) =
        geo_verify(&[&p("pack.json"), "--anchor", &p("anchor-hybrid.json"), "--require-profile", "quantum"]);
    assert_eq!(code, 64);
    assert!(err.contains("unknown profile quantum: use classical, pq or hybrid"), "{err}");
    let (code, _, err) = geo_verify(&[&p("pack.json"), "--require-profile"]);
    assert_eq!(code, 64);
    assert!(err.contains("--require-profile needs"), "{err}");
    let (code, _, err) = geo_verify(&["assessment", "x", "--require-profile", "quantum"]);
    assert_eq!(code, 64);
    assert!(err.contains("unknown profile quantum"), "{err}");
}

// ------------------------------------------------------------ assessments

fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}

struct Issuer {
    ed: SigningKey,
    ml: ml_dsa::SigningKey<ml_dsa::MlDsa65>,
}

fn issuer() -> Issuer {
    Issuer { ed: SigningKey::from_bytes(&[7; 32]), ml: ml_dsa::SigningKey::from_seed(&[8u8; 32].into()) }
}

fn ed_pk(k: &Issuer) -> Vec<u8> {
    k.ed.verifying_key().to_bytes().to_vec()
}

fn ml_pk(k: &Issuer) -> Vec<u8> {
    use ml_dsa::signature::Keypair;
    k.ml.verifying_key().encode().to_vec()
}

fn sign(k: &Issuer, suite: &str, aid: &Id) -> AssessmentSignature {
    let (alg, key) = if suite == ML_DSA_65 {
        (ML_ALG, key_id_of_bytes(&ml_pk(k)))
    } else {
        (a::ALG_ED25519, key_id_of_bytes(&ed_pk(k)))
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

/// Write the example assessment signed under `suites` as a bundle directory with its evidence.
fn write_bundle(dir: &Path, k: &Issuer, suites: &[&str]) {
    let ex =
        SystemAssessment::decode(&std::fs::read(format!("{ASSESSMENT}example-refund-agent.json")).unwrap()).unwrap();
    let mut m = ex.manifest;
    m.verification.required_suites = suites.iter().map(|s| id(s)).collect();
    let aid = a::assessment_id(&m);
    let sa = SystemAssessment {
        id: aid.clone(),
        signatures: suites.iter().map(|s| sign(k, s, &aid)).collect(),
        manifest: m,
    };
    std::fs::create_dir_all(dir.join("evidence")).unwrap();
    let mut files = vec![];
    for e in &sa.manifest.evidence {
        let name = e.location.clone().unwrap().rsplit('/').next().unwrap().to_string();
        let bytes = std::fs::read(format!("{ASSESSMENT}evidence/{name}")).unwrap();
        let path = format!("evidence/{}", e.id);
        std::fs::write(dir.join(&path), &bytes).unwrap();
        files.push(AssessmentBundleFile {
            evidence: e.id.clone(),
            availability: AssessmentPayloadAvailability::Included,
            path: Some(path),
            digest: Some(Digest::of(&bytes)),
            size: Some(bytes.len() as u64),
            reason: String::new(),
        });
    }
    let bundle = AssessmentBundle {
        format: a::BUNDLE_FORMAT.into(),
        v: a::BUNDLE_VERSION,
        exported_ms: sa.manifest.issued_ms,
        assessment: sa,
        files,
        status: None,
        statement: None,
        renewals: vec![],
        key_hints: vec![],
        key_log: vec![],
        provenance: None,
        notes: vec![],
    };
    std::fs::write(dir.join("bundle.json"), bundle.encode()).unwrap();
}

/// Key files for the issuer's ed25519 and ML-DSA-65 keys.
fn write_keys(dir: &Path, k: &Issuer) -> (String, String) {
    let ed = AssessmentTrustedKey {
        key: key_id_of_bytes(&ed_pk(k)),
        suite: id(a::SUITE_ED25519),
        algorithm: id(a::ALG_ED25519),
        public_key: Bytes(ed_pk(k)),
        label: "issuer ed25519".into(),
    };
    let ml = AssessmentTrustedKey {
        key: key_id_of_bytes(&ml_pk(k)),
        suite: id(ML_DSA_65),
        algorithm: id(ML_ALG),
        public_key: Bytes(ml_pk(k)),
        label: "issuer ML-DSA-65".into(),
    };
    let (e, m) = (dir.join("ed.json"), dir.join("ml.json"));
    std::fs::write(&e, ed.encode()).unwrap();
    std::fs::write(&m, ml.encode()).unwrap();
    (e.to_string_lossy().into_owned(), m.to_string_lossy().into_owned())
}

#[test]
fn requiring_hybrid_refuses_a_classical_assessment() {
    let d = tempdir("classical");
    let k = issuer();
    let bundle = d.join("classical");
    write_bundle(&bundle, &k, &[a::SUITE_ED25519]);
    let (ed, ml) = write_keys(&d, &k);
    let b = bundle.to_string_lossy().into_owned();
    // As recorded, and under the classical profile: unchanged and signed with a key you trust.
    let (code, out, err) = geo_verify(&["assessment", &b, "--trust-key", &ed]);
    assert_eq!(code, 0, "{out}{err}");
    let (code, out, err) = geo_verify(&["assessment", &b, "--trust-key", &ed, "--require-profile", "classical"]);
    assert_eq!(code, 0, "{out}{err}");
    // Requiring hybrid: not trusted (exit 3), and said in words; never reported as changed.
    let (code, out, err) =
        geo_verify(&["assessment", &b, "--trust-key", &ed, "--trust-key", &ml, "--require-profile", "hybrid"]);
    assert_eq!(code, 3, "{out}{err}");
    assert!(out.contains("You require the geo-profile/hybrid/1 signature profile"), "{out}");
    assert!(!out.contains("Changed or wrongly signed"), "{out}");
    let (_, json, _) = geo_verify(&["assessment", &b, "--trust-key", &ed, "--require-profile", "hybrid", "--json"]);
    let j: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(j["standing"]["integrity"], "unverifiable", "{j}");
}

#[test]
fn requiring_hybrid_accepts_a_hybrid_assessment_with_both_keys_trusted() {
    let d = tempdir("hybrid");
    let k = issuer();
    let bundle = d.join("hybrid");
    write_bundle(&bundle, &k, &[a::SUITE_ED25519, ML_DSA_65]);
    let (ed, ml) = write_keys(&d, &k);
    let b = bundle.to_string_lossy().into_owned();
    let (code, out, err) =
        geo_verify(&["assessment", &b, "--trust-key", &ed, "--trust-key", &ml, "--require-profile", "hybrid"]);
    assert_eq!(code, 0, "{out}{err}");
    // Trusting only the ed25519 key is not enough for a reader who requires hybrid.
    let (code, out, err) = geo_verify(&["assessment", &b, "--trust-key", &ed, "--require-profile", "hybrid"]);
    assert_eq!(code, 3, "{out}{err}");
    // A pq-only reader is satisfied by the ML-DSA-65 signature alone.
    let (code, out, err) =
        geo_verify(&["assessment", &b, "--trust-key", &ed, "--trust-key", &ml, "--require-profile", "pq"]);
    assert_eq!(code, 0, "{out}{err}");
}
