//! The verifier's signature-suite primitives against standardized vectors
//! (a NIST ACVP ML-DSA-65 subset, tests/fixtures/acvp, NIST notice in
//! LICENSE-NIST.txt) and malformed inputs. The vectors go through the same
//! functions the verifier calls, not the library directly.

use geo_verify::suite::{self, SigCheck};

fn vectors() -> serde_json::Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/acvp/ml-dsa-65.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn h(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

#[test]
fn acvp_ml_dsa_65_signature_verification_vectors_agree() {
    let v = vectors();
    let cases = v["sigVer"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    let (mut pass, mut fail) = (0, 0);
    for c in cases {
        let ok = suite::ml_dsa_65_verify_with_context(
            &h(&c["pk"]),
            &h(&c["message"]),
            &h(&c["context"]),
            &h(&c["signature"]),
        );
        assert_eq!(ok, c["testPassed"].as_bool().unwrap(), "tcId {} ({})", c["tcId"], c["reason"]);
        if ok { pass += 1 } else { fail += 1 }
    }
    assert_eq!((pass, fail), (3, 4));
}

#[test]
fn the_suite_fixes_its_context_so_a_vector_with_another_context_does_not_verify_under_it() {
    let v = vectors();
    let c = v["sigVer"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["testPassed"] == true && !c["context"].as_str().unwrap().is_empty())
        .unwrap();
    // The vector verifies with its own context, and not under the suite (whose context is empty).
    assert!(suite::ml_dsa_65_verify_with_context(
        &h(&c["pk"]),
        &h(&c["message"]),
        &h(&c["context"]),
        &h(&c["signature"])
    ));
    assert!(matches!(
        suite::verify(suite::ML_DSA_65, &h(&c["pk"]), &h(&c["message"]), &h(&c["signature"])),
        SigCheck::Invalid(_)
    ));
}

#[test]
fn malformed_keys_and_signatures_are_invalid_and_unknown_suites_are_unsupported() {
    let v = vectors();
    let c = &v["sigVer"][0];
    let (pk, sig, msg) = (h(&c["pk"]), h(&c["signature"]), h(&c["message"]));
    // Wrong lengths under each suite.
    assert!(matches!(suite::verify(suite::ML_DSA_65, &pk[..100], &msg, &sig), SigCheck::Invalid(_)));
    assert!(matches!(suite::verify(suite::ML_DSA_65, &pk, &msg, &sig[..sig.len() - 1]), SigCheck::Invalid(_)));
    assert!(
        matches!(suite::verify(suite::ED25519, &pk, &msg, &sig), SigCheck::Invalid(_)),
        "an ML-DSA key is not an ed25519 key"
    );
    assert!(matches!(suite::verify(suite::ED25519, &[0u8; 32], &msg, &[0u8; 64]), SigCheck::Invalid(_)));
    // A suite this verifier does not know is neither valid nor invalid.
    assert!(matches!(suite::verify("geo-falcon-512/1", &pk, &msg, &sig), SigCheck::Unsupported(_)));
    // Key ids bind the suite's key length.
    assert!(suite::key_id(suite::ML_DSA_65, &pk).is_ok());
    assert!(suite::key_id(suite::ED25519, &pk).is_err());
    assert!(suite::key_id(suite::ML_DSA_65, &[0u8; 32]).is_err());
}

#[test]
fn profiles_require_every_suite_they_name() {
    assert_eq!(suite::profile_suites(suite::CLASSICAL), Some(&[suite::ED25519][..]));
    assert_eq!(suite::profile_suites(suite::PQ), Some(&[suite::ML_DSA_65][..]));
    assert_eq!(suite::profile_suites(suite::HYBRID), Some(&[suite::ED25519, suite::ML_DSA_65][..]));
    assert_eq!(suite::profile_suites("geo-profile/future/1"), None);
    assert_eq!(suite::Policy::profile("hybrid").unwrap().require_suites, vec![suite::ED25519, suite::ML_DSA_65]);
    assert!(suite::Policy::profile("quantum-safe").is_none());
    // A signature input binds record type, record, profile, suite, algorithm and key.
    let d = geo_contracts::Digest::of(b"x");
    let k = geo_contracts::Id::new("key:abc").unwrap();
    let a = suite::signature_input(suite::CHECKPOINT_V2, &d, suite::HYBRID, suite::ML_DSA_65, &k);
    for other in [
        suite::signature_input(suite::KEY_EVENT, &d, suite::HYBRID, suite::ML_DSA_65, &k),
        suite::signature_input(
            suite::CHECKPOINT_V2,
            &geo_contracts::Digest::of(b"y"),
            suite::HYBRID,
            suite::ML_DSA_65,
            &k,
        ),
        suite::signature_input(suite::CHECKPOINT_V2, &d, suite::PQ, suite::ML_DSA_65, &k),
        suite::signature_input(suite::CHECKPOINT_V2, &d, suite::HYBRID, suite::ED25519, &k),
        suite::signature_input(
            suite::CHECKPOINT_V2,
            &d,
            suite::HYBRID,
            suite::ML_DSA_65,
            &geo_contracts::Id::new("key:abd").unwrap(),
        ),
    ] {
        assert_ne!(a, other);
    }
    assert!(a.starts_with(b"geo-suite-signature/1\n"));
}
