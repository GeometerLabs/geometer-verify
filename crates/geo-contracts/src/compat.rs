//! Readers for earlier protocol versions.
//!
//! geo/1 carried a bare `trial` id (plus `generation` on envelopes). geo/2
//! replaces both with a tagged [`ExecutionContext`]. A geo/1 record migrates
//! only to a test-trial context: no production context is ever fabricated,
//! and a geo/1 observation read outside an envelope keeps its generation
//! absent rather than guessing one. Current decoders stay strict; migration
//! happens on the JSON tree before strict decoding, so TypeScript and Python
//! implement the same rules and are checked against the shared vectors.

use crate::codec::Canon;
use crate::error::{DecodeError, ErrorClass};
use crate::generated::{Decision, Envelope, Observation, PROTOCOL};
use crate::json::{Json, parse, to_canonical};
use std::collections::BTreeMap;

pub const LEGACY_PROTOCOLS: &[&str] = &["geo/1"];

fn err(class: ErrorClass, path: &str, msg: &str) -> DecodeError {
    DecodeError::new(class, path, msg)
}

/// Move a legacy `trial` (and optional generation) into a test-trial context.
fn contextualize(m: &mut BTreeMap<String, Json>, generation: Option<Json>, path: &str) -> Result<(), DecodeError> {
    if m.contains_key("context") {
        return Err(err(ErrorClass::UnknownField, path, "geo/1 record cannot also carry a context"));
    }
    let trial = m.remove("trial").ok_or_else(|| err(ErrorClass::MissingField, path, "geo/1 record without trial"))?;
    let mut c = BTreeMap::new();
    c.insert("kind".to_string(), Json::Str("test_trial".into()));
    c.insert("trial".to_string(), trial);
    if let Some(g) = generation {
        c.insert("generation".to_string(), g);
    }
    m.insert("context".into(), Json::Obj(c));
    Ok(())
}

/// A standalone geo/1 Observation or Decision: detected by `trial` without
/// `context`. Anything else is passed through for strict decoding.
fn migrate_fact(j: &mut Json, inherited: Option<(&Json, &Json)>, path: &str) -> Result<(), DecodeError> {
    let Json::Obj(m) = j else { return Ok(()) };
    if !m.contains_key("trial") || m.contains_key("context") {
        return Ok(());
    }
    // A fact inside a geo/1 envelope inherits the envelope's generation only
    // when it names the same trial.
    let g = match inherited {
        Some((trial, g)) if m.get("trial") == Some(trial) => Some(g.clone()),
        _ => None,
    };
    contextualize(m, g, path)
}

fn migrate_envelope(j: &mut Json) -> Result<(), DecodeError> {
    let Json::Obj(m) = j else { return Ok(()) };
    let legacy = matches!(m.get("protocol"), Some(Json::Str(p)) if LEGACY_PROTOCOLS.contains(&p.as_str()));
    if !legacy {
        return Ok(());
    }
    let generation = m
        .remove("generation")
        .ok_or_else(|| err(ErrorClass::MissingField, "$", "geo/1 envelope without generation"))?;
    let trial =
        m.get("trial").cloned().ok_or_else(|| err(ErrorClass::MissingField, "$", "geo/1 envelope without trial"))?;
    contextualize(m, Some(generation.clone()), "$")?;
    m.insert("protocol".into(), Json::Str(PROTOCOL.into()));
    if let Some(Json::Obj(body)) = m.get_mut("body") {
        for key in ["observation", "decision"] {
            if let Some(f) = body.get_mut(key) {
                migrate_fact(f, Some((&trial, &generation)), &format!("$.body.{key}"))?;
            }
        }
    }
    Ok(())
}

/// Migrate a JSON tree of the named type to the current protocol.
pub fn migrate(type_name: &str, j: &mut Json) -> Result<(), DecodeError> {
    match type_name {
        "Envelope" => migrate_envelope(j),
        "Observation" | "Decision" => migrate_fact(j, None, "$"),
        "EnvironmentSpec" => {
            default_lists(j);
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Decode an envelope of any supported protocol version.
pub fn decode_envelope(bytes: &[u8]) -> Result<Envelope, DecodeError> {
    let mut j = parse(bytes)?;
    migrate_envelope(&mut j)?;
    Envelope::from_json(&j, "$")
}

pub fn decode_observation(bytes: &[u8]) -> Result<Observation, DecodeError> {
    let mut j = parse(bytes)?;
    migrate_fact(&mut j, None, "$")?;
    Observation::from_json(&j, "$")
}

pub fn decode_decision(bytes: &[u8]) -> Result<Decision, DecodeError> {
    let mut j = parse(bytes)?;
    migrate_fact(&mut j, None, "$")?;
    Decision::from_json(&j, "$")
}

/// An EnvironmentSpec recorded before a list field existed: absent lists
/// (secrets, tools, models) mean none. Other missing fields stay errors.
pub fn decode_environment_spec(bytes: &[u8]) -> Result<crate::generated::EnvironmentSpec, DecodeError> {
    let mut j = parse(bytes)?;
    default_lists(&mut j);
    crate::generated::EnvironmentSpec::from_json(&j, "$")
}

fn default_lists(j: &mut Json) {
    if let Json::Obj(m) = j {
        for k in ["secrets", "tools", "models"] {
            m.entry(k.to_string()).or_insert_with(|| Json::Arr(vec![]));
        }
    }
}

/// Migrate then round-trip (shared migration vectors).
pub fn migrate_named(type_name: &str, bytes: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let mut j = parse(bytes)?;
    migrate(type_name, &mut j)?;
    crate::generated::roundtrip_named(type_name, &to_canonical(&j))
}
