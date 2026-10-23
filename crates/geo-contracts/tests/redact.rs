//! Secret references and redaction.

use geo_contracts::Id;
use geo_contracts::redact::*;
use std::collections::BTreeMap;

#[test]
fn classification_is_broad() {
    for k in [
        "POSTGRES_PASSWORD",
        "RABBITMQ_DEFAULT_PASS",
        "db.pwd",
        "STRIPE_SECRET",
        "api-key",
        "GITHUB_TOKEN",
        "SENTRY_DSN",
    ] {
        assert!(is_secret_key(k), "{k}");
    }
    for k in ["POSTGRES_USER", "PORT", "LOG_LEVEL"] {
        assert!(!is_secret_key(k), "{k}");
    }
    for v in [
        "sk_live_abc123",
        "AKIAABCDEFGHIJKLMNOP",
        "Bearer abc.def",
        "eyJhbGciOi.eyJzdWIi.sig",
        "-----BEGIN PRIVATE KEY-----",
    ] {
        assert!(looks_like_credential(v), "{v}");
    }
    assert!(!looks_like_credential("redis://cache:6379"));
}

#[test]
fn url_passwords_are_split_and_references_resolve_only_when_known() {
    let id = Id::new("api.DB_URL.password").unwrap();
    let (red, pw) = split_url_password("postgres://shop:s3cr@t@db:5432/shop?x=1", &placeholder(&id)).unwrap();
    assert_eq!(pw, "s3cr@t");
    assert_eq!(red, "postgres://shop:${geo-secret:api.DB_URL.password}@db:5432/shop?x=1");
    assert!(split_url_password("redis://cache:6379", "x").is_none());
    assert!(split_url_password("amqp://user@broker", "x").is_none());
    // An already-redacted URL is not redacted twice.
    assert!(split_url_password(&red, "x").is_none());

    let mut vault = BTreeMap::new();
    vault.insert(id.to_string(), pw.clone());
    assert_eq!(resolve(&red, &vault).unwrap(), "postgres://shop:s3cr@t@db:5432/shop?x=1");
    // Unknown references are refused, never passed on as the value.
    assert!(resolve(&red, &BTreeMap::new()).unwrap_err().contains("not available"));
    assert!(resolve("${geo-secret:open", &vault).is_err());
}

#[test]
fn known_values_are_hidden_in_free_text() {
    let mut vault = BTreeMap::new();
    vault.insert("a".to_string(), "hunter2".to_string());
    vault.insert("b".to_string(), "hunter2-long".to_string());
    let t = redact_text("login hunter2-long then hunter2", &vault);
    assert_eq!(t, "login ${geo-secret:b} then ${geo-secret:a}");
}
