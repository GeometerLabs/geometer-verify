//! Portable typed values.
//!
//! Wire form is a tagged array: `["null"]`, `["absent"]`, `["bool",b]`,
//! `["int","-12"]` (arbitrary precision), `["dec","-1.50"]` (exact decimal,
//! scale preserved), `["f64","3ff8000000000000"]` (IEEE-754 bits, NaN
//! rejected), `["str",s]`, `["bytes","<base64>"]`, `["list",[..]]`,
//! `["map",{..}]`, `["ref",{"key":[..],"kind":k,"ns":n}]`.
//! Null and absent are different values. Integers and decimals never pass
//! through a binary float.

use crate::error::{DecodeError, ErrorClass};
use crate::json::Json;
use base64::Engine;
use std::cmp::Ordering;
use std::collections::BTreeMap;

pub const MAX_NUMERIC_CHARS: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Absent,
    Bool(bool),
    /// Canonical decimal integer text.
    Int(String),
    /// Canonical decimal text with at least one fraction digit.
    Dec(String),
    /// IEEE-754 binary64 bits.
    F64(u64),
    Str(String),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Map(BTreeMap<String, Value>),
    Ref {
        ns: String,
        kind: String,
        key: Vec<Value>,
    },
}

fn err(class: ErrorClass, path: &str, msg: impl Into<String>) -> DecodeError {
    DecodeError::new(class, path, msg)
}

pub fn valid_int_text(s: &str) -> bool {
    let d = s.strip_prefix('-').unwrap_or(s);
    !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit()) && (d == "0" || !d.starts_with('0')) && s != "-0"
}

pub fn valid_dec_text(s: &str) -> bool {
    let Some((i, f)) = s.split_once('.') else { return false };
    let id = i.strip_prefix('-').unwrap_or(i);
    let int_ok = !id.is_empty() && id.bytes().all(|c| c.is_ascii_digit()) && (id == "0" || !id.starts_with('0'));
    let frac_ok = !f.is_empty() && f.bytes().all(|c| c.is_ascii_digit());
    // Negative zero at any scale is non-canonical.
    let neg_zero = i.starts_with('-') && id.bytes().all(|c| c == b'0') && f.bytes().all(|c| c == b'0');
    int_ok && frac_ok && !neg_zero
}

impl Value {
    pub fn int(n: i128) -> Value {
        Value::Int(n.to_string())
    }
    pub fn str(s: impl Into<String>) -> Value {
        Value::Str(s.into())
    }
    pub fn as_i128(&self) -> Option<i128> {
        match self {
            Value::Int(s) => s.parse().ok(),
            _ => None,
        }
    }

    pub fn to_json(&self) -> Json {
        let tag = |t: &str, rest: Option<Json>| {
            let mut v = vec![Json::Str(t.into())];
            v.extend(rest);
            Json::Arr(v)
        };
        match self {
            Value::Null => tag("null", None),
            Value::Absent => tag("absent", None),
            Value::Bool(b) => tag("bool", Some(Json::Bool(*b))),
            Value::Int(s) => tag("int", Some(Json::Str(s.clone()))),
            Value::Dec(s) => tag("dec", Some(Json::Str(s.clone()))),
            Value::F64(bits) => tag("f64", Some(Json::Str(format!("{bits:016x}")))),
            Value::Str(s) => tag("str", Some(Json::Str(s.clone()))),
            Value::Bytes(b) => tag("bytes", Some(Json::Str(base64::engine::general_purpose::STANDARD.encode(b)))),
            Value::List(v) => tag("list", Some(Json::Arr(v.iter().map(Value::to_json).collect()))),
            Value::Map(m) => tag("map", Some(Json::Obj(m.iter().map(|(k, v)| (k.clone(), v.to_json())).collect()))),
            Value::Ref { ns, kind, key } => {
                let mut m = BTreeMap::new();
                m.insert("key".into(), Json::Arr(key.iter().map(Value::to_json).collect()));
                m.insert("kind".into(), Json::Str(kind.clone()));
                m.insert("ns".into(), Json::Str(ns.clone()));
                tag("ref", Some(Json::Obj(m)))
            }
        }
    }

    pub fn from_json(j: &Json, path: &str) -> Result<Value, DecodeError> {
        let Json::Arr(a) = j else { return Err(err(ErrorClass::Type, path, "value must be a tagged array")) };
        let Some(Json::Str(tag)) = a.first() else {
            return Err(err(ErrorClass::Type, path, "value tag must be a string"));
        };
        let arity = |n: usize| -> Result<(), DecodeError> {
            if a.len() == n {
                Ok(())
            } else {
                Err(err(ErrorClass::Type, path, format!("{tag} takes {} element(s)", n - 1)))
            }
        };
        let text = || -> Result<&String, DecodeError> {
            match a.get(1) {
                Some(Json::Str(s)) => Ok(s),
                _ => Err(err(ErrorClass::Type, path, format!("{tag} payload must be a string"))),
            }
        };
        match tag.as_str() {
            "null" => arity(1).map(|_| Value::Null),
            "absent" => arity(1).map(|_| Value::Absent),
            "bool" => {
                arity(2)?;
                match &a[1] {
                    Json::Bool(b) => Ok(Value::Bool(*b)),
                    _ => Err(err(ErrorClass::Type, path, "bool payload must be a boolean")),
                }
            }
            "int" => {
                arity(2)?;
                let s = text()?;
                if s.len() > MAX_NUMERIC_CHARS {
                    return Err(err(ErrorClass::Range, path, "integer too long"));
                }
                if !valid_int_text(s) {
                    return Err(err(ErrorClass::NonCanonical, path, format!("non-canonical integer {s:?}")));
                }
                Ok(Value::Int(s.clone()))
            }
            "dec" => {
                arity(2)?;
                let s = text()?;
                if s.len() > MAX_NUMERIC_CHARS {
                    return Err(err(ErrorClass::Range, path, "decimal too long"));
                }
                if !valid_dec_text(s) {
                    return Err(err(ErrorClass::NonCanonical, path, format!("non-canonical decimal {s:?}")));
                }
                Ok(Value::Dec(s.clone()))
            }
            "f64" => {
                arity(2)?;
                let s = text()?;
                if s.len() != 16 || !s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
                    return Err(err(ErrorClass::NonCanonical, path, "f64 must be 16 lowercase hex digits"));
                }
                let bits = u64::from_str_radix(s, 16).unwrap();
                if f64::from_bits(bits).is_nan() {
                    return Err(err(ErrorClass::Nan, path, "NaN is not a portable value"));
                }
                Ok(Value::F64(bits))
            }
            "str" => {
                arity(2)?;
                Ok(Value::Str(text()?.clone()))
            }
            "bytes" => {
                arity(2)?;
                let s = text()?;
                let e = &base64::engine::general_purpose::STANDARD;
                let b = e.decode(s).map_err(|_| err(ErrorClass::NonCanonical, path, "invalid base64"))?;
                if e.encode(&b) != *s {
                    return Err(err(ErrorClass::NonCanonical, path, "non-canonical base64"));
                }
                Ok(Value::Bytes(b))
            }
            "list" => {
                arity(2)?;
                let Json::Arr(v) = &a[1] else {
                    return Err(err(ErrorClass::Type, path, "list payload must be an array"));
                };
                v.iter()
                    .enumerate()
                    .map(|(i, x)| Value::from_json(x, &format!("{path}[{i}]")))
                    .collect::<Result<_, _>>()
                    .map(Value::List)
            }
            "map" => {
                arity(2)?;
                let Json::Obj(m) = &a[1] else {
                    return Err(err(ErrorClass::Type, path, "map payload must be an object"));
                };
                m.iter()
                    .map(|(k, v)| Ok((k.clone(), Value::from_json(v, &format!("{path}.{k}"))?)))
                    .collect::<Result<_, _>>()
                    .map(Value::Map)
            }
            "ref" => {
                arity(2)?;
                let Json::Obj(m) = &a[1] else {
                    return Err(err(ErrorClass::Type, path, "ref payload must be an object"));
                };
                for k in m.keys() {
                    if !matches!(k.as_str(), "key" | "kind" | "ns") {
                        return Err(err(ErrorClass::UnknownField, path, format!("unknown ref field {k}")));
                    }
                }
                let s = |k: &str| match m.get(k) {
                    Some(Json::Str(s)) => Ok(s.clone()),
                    None => Err(err(ErrorClass::MissingField, path, format!("ref.{k} missing"))),
                    _ => Err(err(ErrorClass::Type, path, format!("ref.{k} must be a string"))),
                };
                let key = match m.get("key") {
                    Some(Json::Arr(v)) => v
                        .iter()
                        .enumerate()
                        .map(|(i, x)| Value::from_json(x, &format!("{path}.key[{i}]")))
                        .collect::<Result<_, _>>()?,
                    None => return Err(err(ErrorClass::MissingField, path, "ref.key missing")),
                    _ => return Err(err(ErrorClass::Type, path, "ref.key must be an array")),
                };
                Ok(Value::Ref { ns: s("ns")?, kind: s("kind")?, key })
            }
            other => Err(err(ErrorClass::UnknownVariant, path, format!("unknown value tag {other:?}"))),
        }
    }
}

/// Exact numeric comparison of int/dec text (no binary floats). Returns None
/// if either value is not an int or dec.
pub fn compare_numeric(a: &Value, b: &Value) -> Option<Ordering> {
    let text = |v: &Value| match v {
        Value::Int(s) | Value::Dec(s) => Some(s.clone()),
        _ => None,
    };
    let (x, y) = (text(a)?, text(b)?);
    Some(cmp_decimal_text(&x, &y))
}

fn split(s: &str) -> (bool, String, String) {
    let (neg, body) = match s.strip_prefix('-') {
        Some(b) => (true, b),
        None => (false, s),
    };
    let (i, f) = body.split_once('.').unwrap_or((body, ""));
    let i = i.trim_start_matches('0').to_string();
    let f = f.trim_end_matches('0').to_string();
    let zero = i.is_empty() && f.is_empty();
    (neg && !zero, i, f)
}

fn cmp_mag(ai: &str, af: &str, bi: &str, bf: &str) -> Ordering {
    ai.len().cmp(&bi.len()).then_with(|| ai.cmp(bi)).then_with(|| {
        let n = af.len().max(bf.len());
        let pa = format!("{af:0<n$}");
        let pb = format!("{bf:0<n$}");
        pa.cmp(&pb)
    })
}

pub fn cmp_decimal_text(a: &str, b: &str) -> Ordering {
    let (an, ai, af) = split(a);
    let (bn, bi, bf) = split(b);
    match (an, bn) {
        (false, true) => Ordering::Greater,
        (true, false) => Ordering::Less,
        (false, false) => cmp_mag(&ai, &af, &bi, &bf),
        (true, true) => cmp_mag(&bi, &bf, &ai, &af),
    }
}

impl Value {
    /// Plain JSON (e.g. an HTTP payload or observer row) to a portable value
    /// without passing through binary floating point: integers become Int,
    /// plain decimals Dec (scale kept), exponent forms stay lexical Str.
    pub fn from_plain_json(j: &crate::json::Json) -> Value {
        use crate::json::Json;
        match j {
            Json::Null => Value::Null,
            Json::Bool(b) => Value::Bool(*b),
            Json::Num(n) if !n.contains(['.', 'e', 'E']) => {
                n.parse::<i128>().map(Value::int).unwrap_or_else(|_| Value::Str(n.clone()))
            }
            Json::Num(n) if !n.contains(['e', 'E']) && valid_dec_text(n) => Value::Dec(n.clone()),
            Json::Num(n) => Value::Str(n.clone()),
            Json::Str(s) => Value::Str(s.clone()),
            Json::Arr(a) => Value::List(a.iter().map(Value::from_plain_json).collect()),
            Json::Obj(m) => Value::Map(m.iter().map(|(k, v)| (k.clone(), Value::from_plain_json(v))).collect()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_compare_exact() {
        let d = |s: &str| Value::Dec(s.into());
        assert_eq!(compare_numeric(&d("1.50"), &d("1.5")), Some(Ordering::Equal));
        assert_eq!(compare_numeric(&Value::int(-2), &d("-1.99")), Some(Ordering::Less));
        assert_eq!(
            compare_numeric(
                &Value::Int("123456789012345678901234567890".into()),
                &Value::Int("123456789012345678901234567889".into())
            ),
            Some(Ordering::Greater)
        );
        assert_eq!(compare_numeric(&d("0.0"), &Value::int(0)), Some(Ordering::Equal));
        assert_eq!(compare_numeric(&Value::Str("1".into()), &Value::int(1)), None);
    }

    #[test]
    fn canonical_text_rules() {
        assert!(
            valid_int_text("0")
                && valid_int_text("-7")
                && !valid_int_text("-0")
                && !valid_int_text("007")
                && !valid_int_text("+1")
        );
        assert!(
            valid_dec_text("0.0")
                && valid_dec_text("-1.50")
                && !valid_dec_text("-0.00")
                && !valid_dec_text("1.")
                && !valid_dec_text("01.5")
        );
    }
}
