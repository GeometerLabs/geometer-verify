//! Intent identity vectors, shared with TypeScript/Python.

use geo_contracts::intent::{IntentError, attempt_id, intent_id, material};
use geo_contracts::json::{Json, parse};
use geo_contracts::*;
use std::collections::BTreeMap;

fn vectors() -> serde_json::Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/fixtures/vectors.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn intent_vectors_derive_the_same_ids() {
    let v = vectors();
    let mut got = BTreeMap::new();
    for c in v["intents"].as_array().unwrap() {
        let contract = ToolContract::decode(c["contract"].as_str().unwrap().as_bytes()).unwrap();
        let Json::Obj(args) = parse(c["arguments"].as_str().unwrap().as_bytes()).unwrap() else { panic!() };
        let args: BTreeMap<String, Value> =
            args.iter().map(|(k, j)| (k.clone(), Value::from_json(j, "$").unwrap())).collect();
        let tenant = c.get("tenant").map(|t| Id::new(t.as_str().unwrap()).unwrap());
        let account = Id::new(c["provider_account"].as_str().unwrap()).unwrap();
        let r = material(&contract, tenant.as_ref(), &account, &args).map(|m| intent_id(&m));
        match (&r, c.get("intent"), c.get("error")) {
            (Ok(id), Some(want), None) => assert_eq!(id.as_str(), want.as_str().unwrap(), "{}", c["id"]),
            (Err(e), None, Some(want)) => {
                let code = match e {
                    IntentError::Unsupported(_) => "unsupported",
                    IntentError::MissingKey(_) => "missing_key",
                    IntentError::InexactKey(_) => "inexact_key",
                };
                assert_eq!(code, want.as_str().unwrap(), "{}", c["id"]);
            }
            other => panic!("{}: {other:?}", c["id"]),
        }
        got.insert(c["id"].as_str().unwrap().to_string(), r.ok());
    }
    for pair in v["intent_relations"]["same_intent"].as_array().unwrap() {
        let ids: Vec<_> = pair.as_array().unwrap().iter().map(|x| got[x.as_str().unwrap()].clone().unwrap()).collect();
        assert!(ids.windows(2).all(|w| w[0] == w[1]), "{pair}");
    }
    for group in v["intent_relations"]["distinct_intents"].as_array().unwrap() {
        let ids: std::collections::BTreeSet<_> =
            group.as_array().unwrap().iter().map(|x| got[x.as_str().unwrap()].clone().unwrap()).collect();
        assert_eq!(ids.len(), group.as_array().unwrap().len(), "{group}");
    }
}

#[test]
fn attempts_are_lineage_and_occurrence_not_time() {
    let i = Id::new("intent:abc").unwrap();
    assert_eq!(attempt_id(&i, 1).as_str(), "intent:abc/attempt-1");
    assert_ne!(attempt_id(&i, 1), attempt_id(&i, 2));
}
