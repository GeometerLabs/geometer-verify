//! Cross-language codec vectors: the same file is run by
//! the TypeScript and Python contract tests.

use base64::Engine;
use geo_contracts::generated::roundtrip_named;

fn vectors() -> serde_json::Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/fixtures/vectors.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn input(v: &serde_json::Value) -> Vec<u8> {
    match v.get("input_b64") {
        Some(b) => base64::engine::general_purpose::STANDARD.decode(b.as_str().unwrap()).unwrap(),
        None => v["input"].as_str().unwrap().as_bytes().to_vec(),
    }
}

#[test]
fn positive_vectors_roundtrip_to_canonical_bytes() {
    let v = vectors();
    let mut n = 0;
    for c in v["positive"].as_array().unwrap() {
        let out =
            roundtrip_named(c["type"].as_str().unwrap(), &input(c)).unwrap_or_else(|e| panic!("{}: {e}", c["id"]));
        assert_eq!(String::from_utf8(out).unwrap(), c["canonical"].as_str().unwrap(), "{}", c["id"]);
        // Canonical output is a fixed point.
        let again = roundtrip_named(c["type"].as_str().unwrap(), c["canonical"].as_str().unwrap().as_bytes()).unwrap();
        assert_eq!(String::from_utf8(again).unwrap(), c["canonical"].as_str().unwrap(), "{} fixed point", c["id"]);
        n += 1;
    }
    assert!(n >= 20);
}

#[test]
fn negative_vectors_reject_with_the_declared_class() {
    let v = vectors();
    for c in v["negative"].as_array().unwrap() {
        match roundtrip_named(c["type"].as_str().unwrap(), &input(c)) {
            Ok(out) => panic!("{} accepted: {}", c["id"], String::from_utf8_lossy(&out)),
            Err(e) => assert_eq!(e.class.as_str(), c["error"].as_str().unwrap(), "{}: {e}", c["id"]),
        }
    }
}

#[test]
fn legacy_migration_vectors() {
    let v = vectors();
    let mut n = 0;
    for c in v["migrations"].as_array().unwrap() {
        let out = geo_contracts::compat::migrate_named(c["type"].as_str().unwrap(), &input(c))
            .unwrap_or_else(|e| panic!("{}: {e}", c["id"]));
        assert_eq!(String::from_utf8(out).unwrap(), c["canonical"].as_str().unwrap(), "{}", c["id"]);
        n += 1;
    }
    assert!(n >= 5);
    for c in v["migration_negative"].as_array().unwrap() {
        match geo_contracts::compat::migrate_named(c["type"].as_str().unwrap(), &input(c)) {
            Ok(out) => panic!("{} accepted: {}", c["id"], String::from_utf8_lossy(&out)),
            Err(e) => assert_eq!(e.class.as_str(), c["error"].as_str().unwrap(), "{}: {e}", c["id"]),
        }
    }
}
