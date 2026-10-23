//! Codec trait and primitive encodings used by the generated records.

use crate::error::{DecodeError, ErrorClass};
use crate::json::{Json, parse, to_canonical};
use crate::value::Value;
use base64::Engine;
use std::collections::BTreeMap;

pub trait Canon: Sized {
    fn to_json(&self) -> Json;
    fn from_json(j: &Json, path: &str) -> Result<Self, DecodeError>;

    /// Canonical bytes.
    fn encode(&self) -> Vec<u8> {
        to_canonical(&self.to_json())
    }
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::from_json(&parse(bytes)?, "$")
    }
}

fn type_err(path: &str, want: &str, got: &Json) -> DecodeError {
    DecodeError::new(ErrorClass::Type, path, format!("expected {want}, got {}", got.kind()))
}

impl Canon for String {
    fn to_json(&self) -> Json {
        Json::Str(self.clone())
    }
    fn from_json(j: &Json, path: &str) -> Result<Self, DecodeError> {
        match j {
            Json::Str(s) => Ok(s.clone()),
            _ => Err(type_err(path, "string", j)),
        }
    }
}

impl Canon for bool {
    fn to_json(&self) -> Json {
        Json::Bool(*self)
    }
    fn from_json(j: &Json, path: &str) -> Result<Self, DecodeError> {
        match j {
            Json::Bool(b) => Ok(*b),
            _ => Err(type_err(path, "boolean", j)),
        }
    }
}

/// u32 is the only integer carried as a JSON number: every language
/// represents it exactly.
impl Canon for u32 {
    fn to_json(&self) -> Json {
        Json::Num(self.to_string())
    }
    fn from_json(j: &Json, path: &str) -> Result<Self, DecodeError> {
        let Json::Num(n) = j else { return Err(type_err(path, "u32 number", j)) };
        if !n.bytes().all(|c| c.is_ascii_digit()) || (n.len() > 1 && n.starts_with('0')) {
            return Err(DecodeError::new(
                ErrorClass::Type,
                path,
                format!("u32 must be a plain non-negative integer, got {n}"),
            ));
        }
        n.parse().map_err(|_| DecodeError::new(ErrorClass::Range, path, format!("{n} exceeds u32")))
    }
}

fn int_text(j: &Json, path: &str, what: &str) -> Result<String, DecodeError> {
    let Json::Str(s) = j else { return Err(type_err(path, &format!("{what} decimal string"), j)) };
    if !crate::value::valid_int_text(s) {
        return Err(DecodeError::new(ErrorClass::NonCanonical, path, format!("non-canonical {what} {s:?}")));
    }
    Ok(s.clone())
}

impl Canon for u64 {
    fn to_json(&self) -> Json {
        Json::Str(self.to_string())
    }
    fn from_json(j: &Json, path: &str) -> Result<Self, DecodeError> {
        let s = int_text(j, path, "u64")?;
        s.parse().map_err(|_| DecodeError::new(ErrorClass::Range, path, format!("{s} out of u64 range")))
    }
}

impl Canon for i64 {
    fn to_json(&self) -> Json {
        Json::Str(self.to_string())
    }
    fn from_json(j: &Json, path: &str) -> Result<Self, DecodeError> {
        let s = int_text(j, path, "i64")?;
        s.parse().map_err(|_| DecodeError::new(ErrorClass::Range, path, format!("{s} out of i64 range")))
    }
}

impl Canon for Value {
    fn to_json(&self) -> Json {
        Value::to_json(self)
    }
    fn from_json(j: &Json, path: &str) -> Result<Self, DecodeError> {
        Value::from_json(j, path)
    }
}

impl<T: Canon> Canon for Vec<T> {
    fn to_json(&self) -> Json {
        Json::Arr(self.iter().map(Canon::to_json).collect())
    }
    fn from_json(j: &Json, path: &str) -> Result<Self, DecodeError> {
        let Json::Arr(v) = j else { return Err(type_err(path, "array", j)) };
        v.iter().enumerate().map(|(i, x)| T::from_json(x, &format!("{path}[{i}]"))).collect()
    }
}

impl<T: Canon> Canon for BTreeMap<String, T> {
    fn to_json(&self) -> Json {
        Json::Obj(self.iter().map(|(k, v)| (k.clone(), v.to_json())).collect())
    }
    fn from_json(j: &Json, path: &str) -> Result<Self, DecodeError> {
        let Json::Obj(m) = j else { return Err(type_err(path, "object", j)) };
        m.iter().map(|(k, v)| Ok((k.clone(), T::from_json(v, &format!("{path}.{k}"))?))).collect()
    }
}

/// Identifier: `[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id(String);

impl Id {
    pub fn new(s: impl Into<String>) -> Result<Id, DecodeError> {
        let s = s.into();
        if Self::valid(&s) {
            Ok(Id(s))
        } else {
            Err(DecodeError::new(ErrorClass::InvalidId, "$", format!("invalid id {s:?}")))
        }
    }
    pub fn valid(s: &str) -> bool {
        let b = s.as_bytes();
        !b.is_empty()
            && b.len() <= 200
            && b[0].is_ascii_alphanumeric()
            && b.iter().all(|c| c.is_ascii_alphanumeric() || b"._:/@+-".contains(c))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Canon for Id {
    fn to_json(&self) -> Json {
        Json::Str(self.0.clone())
    }
    fn from_json(j: &Json, path: &str) -> Result<Self, DecodeError> {
        let Json::Str(s) = j else { return Err(type_err(path, "id string", j)) };
        if !Id::valid(s) {
            return Err(DecodeError::new(ErrorClass::InvalidId, path, format!("invalid id {s:?}")));
        }
        Ok(Id(s.clone()))
    }
}

/// Content digest: `sha256:` + 64 lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest(String);

impl Digest {
    pub fn of(bytes: &[u8]) -> Digest {
        use sha2::Digest as _;
        Digest(format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes))))
    }
    pub fn parse(s: &str) -> Option<Digest> {
        let h = s.strip_prefix("sha256:")?;
        (h.len() == 64 && h.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))).then(|| Digest(s.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn hex(&self) -> &str {
        &self.0[7..]
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Canon for Digest {
    fn to_json(&self) -> Json {
        Json::Str(self.0.clone())
    }
    fn from_json(j: &Json, path: &str) -> Result<Self, DecodeError> {
        let Json::Str(s) = j else { return Err(type_err(path, "digest string", j)) };
        Digest::parse(s)
            .ok_or_else(|| DecodeError::new(ErrorClass::InvalidDigest, path, format!("invalid digest {s:?}")))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bytes(pub Vec<u8>);

impl Canon for Bytes {
    fn to_json(&self) -> Json {
        Json::Str(base64::engine::general_purpose::STANDARD.encode(&self.0))
    }
    fn from_json(j: &Json, path: &str) -> Result<Self, DecodeError> {
        let Json::Str(s) = j else { return Err(type_err(path, "base64 string", j)) };
        let e = &base64::engine::general_purpose::STANDARD;
        let b = e.decode(s).map_err(|_| DecodeError::new(ErrorClass::NonCanonical, path, "invalid base64"))?;
        if e.encode(&b) != *s {
            return Err(DecodeError::new(ErrorClass::NonCanonical, path, "non-canonical base64"));
        }
        Ok(Bytes(b))
    }
}

// ---- helpers for generated code

pub fn obj<'a>(j: &'a Json, path: &str) -> Result<&'a BTreeMap<String, Json>, DecodeError> {
    match j {
        Json::Obj(m) => Ok(m),
        _ => Err(type_err(path, "object", j)),
    }
}

pub fn only_fields(m: &BTreeMap<String, Json>, allowed: &[&str], path: &str) -> Result<(), DecodeError> {
    for k in m.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(DecodeError::new(ErrorClass::UnknownField, path, format!("unknown field {k:?}")));
        }
    }
    Ok(())
}

pub fn req<T: Canon>(m: &BTreeMap<String, Json>, k: &str, path: &str) -> Result<T, DecodeError> {
    match m.get(k) {
        Some(v) => T::from_json(v, &format!("{path}.{k}")),
        None => Err(DecodeError::new(ErrorClass::MissingField, path, format!("missing field {k:?}"))),
    }
}

/// Optional field: omitted when absent. An explicit JSON null is a type error,
/// so "absent" never has two encodings.
pub fn opt<T: Canon>(m: &BTreeMap<String, Json>, k: &str, path: &str) -> Result<Option<T>, DecodeError> {
    match m.get(k) {
        None => Ok(None),
        Some(Json::Null) => {
            Err(DecodeError::new(ErrorClass::Type, path, format!("optional field {k:?} must be omitted, not null")))
        }
        Some(v) => T::from_json(v, &format!("{path}.{k}")).map(Some),
    }
}

pub fn put<T: Canon>(m: &mut BTreeMap<String, Json>, k: &str, v: &T) {
    m.insert(k.to_owned(), v.to_json());
}

pub fn put_opt<T: Canon>(m: &mut BTreeMap<String, Json>, k: &str, v: &Option<T>) {
    if let Some(v) = v {
        m.insert(k.to_owned(), v.to_json());
    }
}

pub fn enum_str<'a>(j: &'a Json, path: &str) -> Result<&'a str, DecodeError> {
    match j {
        Json::Str(s) => Ok(s),
        _ => Err(type_err(path, "enum string", j)),
    }
}

pub fn unknown_variant(path: &str, what: &str, v: &str) -> DecodeError {
    DecodeError::new(ErrorClass::UnknownVariant, path, format!("unknown {what} {v:?}"))
}
