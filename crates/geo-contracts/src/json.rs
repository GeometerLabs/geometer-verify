//! Strict JSON tree, parser and canonical writer.
//!
//! The parser keeps numbers lexical (so precision is never lost), rejects
//! duplicate object keys, lone surrogates and nesting deeper than
//! [`MAX_DEPTH`]. The canonical writer sorts object keys by UTF-8 bytes, emits
//! no whitespace and uses the minimal escape set defined in docs/contracts.md.
//! TypeScript and Python implement the same rules and are checked against the
//! shared vectors.

use crate::error::{DecodeError, ErrorClass};
use std::collections::BTreeMap;

pub const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    /// Lexical JSON number, validated against the JSON grammar.
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn kind(&self) -> &'static str {
        match self {
            Json::Null => "null",
            Json::Bool(_) => "bool",
            Json::Num(_) => "number",
            Json::Str(_) => "string",
            Json::Arr(_) => "array",
            Json::Obj(_) => "object",
        }
    }
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

fn syntax(msg: impl Into<String>, at: usize) -> DecodeError {
    DecodeError::new(ErrorClass::Syntax, "$", format!("{} at byte {at}", msg.into()))
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, DecodeError> {
        if depth > MAX_DEPTH {
            return Err(DecodeError::new(ErrorClass::Depth, "$", format!("nesting deeper than {MAX_DEPTH}")));
        }
        self.ws();
        let Some(&c) = self.b.get(self.i) else { return Err(syntax("unexpected end", self.i)) };
        match c {
            b'n' => self.lit("null", Json::Null),
            b't' => self.lit("true", Json::Bool(true)),
            b'f' => self.lit("false", Json::Bool(false)),
            b'"' => Ok(Json::Str(self.string()?)),
            b'[' => {
                self.i += 1;
                let mut v = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(Json::Arr(v));
                }
                loop {
                    v.push(self.value(depth + 1)?);
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Json::Arr(v));
                        }
                        _ => return Err(syntax("expected , or ]", self.i)),
                    }
                }
            }
            b'{' => {
                self.i += 1;
                let mut m = BTreeMap::new();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(Json::Obj(m));
                }
                loop {
                    self.ws();
                    if self.b.get(self.i) != Some(&b'"') {
                        return Err(syntax("expected object key", self.i));
                    }
                    let k = self.string()?;
                    self.ws();
                    if self.b.get(self.i) != Some(&b':') {
                        return Err(syntax("expected :", self.i));
                    }
                    self.i += 1;
                    let v = self.value(depth + 1)?;
                    if m.contains_key(&k) {
                        return Err(DecodeError::new(ErrorClass::DuplicateKey, "$", format!("duplicate key {k:?}")));
                    }
                    m.insert(k, v);
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Json::Obj(m));
                        }
                        _ => return Err(syntax("expected , or }", self.i)),
                    }
                }
            }
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(syntax(format!("unexpected byte 0x{c:02x}"), self.i)),
        }
    }

    fn lit(&mut self, word: &str, v: Json) -> Result<Json, DecodeError> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(syntax("invalid literal", self.i))
        }
    }

    fn number(&mut self) -> Result<Json, DecodeError> {
        let s = self.i;
        if self.b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        match self.b.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return Err(syntax("invalid number", self.i)),
        }
        if self.b.get(self.i) == Some(&b'.') {
            self.i += 1;
            let d = self.i;
            while matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
                self.i += 1;
            }
            if d == self.i {
                return Err(syntax("invalid fraction", self.i));
            }
        }
        if matches!(self.b.get(self.i), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.b.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            let d = self.i;
            while matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
                self.i += 1;
            }
            if d == self.i {
                return Err(syntax("invalid exponent", self.i));
            }
        }
        Ok(Json::Num(String::from_utf8(self.b[s..self.i].to_vec()).unwrap()))
    }

    fn hex4(&mut self) -> Result<u32, DecodeError> {
        let h = self.b.get(self.i..self.i + 4).ok_or_else(|| syntax("short \\u escape", self.i))?;
        let s = std::str::from_utf8(h).map_err(|_| syntax("bad \\u escape", self.i))?;
        if !s.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(syntax("bad \\u escape", self.i));
        }
        self.i += 4;
        Ok(u32::from_str_radix(s, 16).unwrap())
    }

    fn string(&mut self) -> Result<String, DecodeError> {
        self.i += 1; // opening quote
        let mut out = Vec::new();
        loop {
            let Some(&c) = self.b.get(self.i) else { return Err(syntax("unterminated string", self.i)) };
            match c {
                b'"' => {
                    self.i += 1;
                    return String::from_utf8(out).map_err(|_| syntax("invalid UTF-8", self.i));
                }
                b'\\' => {
                    self.i += 1;
                    let Some(&e) = self.b.get(self.i) else { return Err(syntax("bad escape", self.i)) };
                    self.i += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if self.b.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return Err(syntax("lone high surrogate", self.i));
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(syntax("invalid low surrogate", self.i));
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(syntax("lone low surrogate", self.i));
                            } else {
                                hi
                            };
                            char::from_u32(cp).ok_or_else(|| syntax("invalid code point", self.i))?
                        }
                        _ => return Err(syntax("bad escape", self.i)),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                0..=0x1f => return Err(syntax("control character in string", self.i)),
                _ => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
    }
}

/// Parse one JSON document; trailing non-whitespace is a syntax error.
pub fn parse(bytes: &[u8]) -> Result<Json, DecodeError> {
    let mut p = Parser { b: bytes, i: 0 };
    let v = p.value(0)?;
    p.ws();
    if p.i != bytes.len() {
        return Err(syntax("trailing data", p.i));
    }
    Ok(v)
}

fn write_str(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for &c in s.as_bytes() {
        match c {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0..=0x1f => out.extend_from_slice(format!("\\u{:04x}", c).as_bytes()),
            _ => out.push(c),
        }
    }
    out.push(b'"');
}

fn write(out: &mut Vec<u8>, j: &Json) {
    match j {
        Json::Null => out.extend_from_slice(b"null"),
        Json::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Json::Num(n) => out.extend_from_slice(n.as_bytes()),
        Json::Str(s) => write_str(out, s),
        Json::Arr(v) => {
            out.push(b'[');
            for (i, x) in v.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write(out, x);
            }
            out.push(b']');
        }
        Json::Obj(m) => {
            // BTreeMap<String> iterates in byte order of UTF-8, the canonical order.
            out.push(b'{');
            for (i, (k, v)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_str(out, k);
                out.push(b':');
                write(out, v);
            }
            out.push(b'}');
        }
    }
}

pub fn to_canonical(j: &Json) -> Vec<u8> {
    let mut out = Vec::new();
    write(&mut out, j);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sorts_and_strips_whitespace() {
        let j = parse(br#" { "b" : [1, 2.50, -0e3], "a":"x\u00e9\ud83d\ude00\n" } "#).unwrap();
        assert_eq!(to_canonical(&j), "{\"a\":\"xé😀\\n\",\"b\":[1,2.50,-0e3]}".as_bytes());
    }

    #[test]
    fn rejects_duplicates_surrogates_depth() {
        assert_eq!(parse(br#"{"a":1,"a":2}"#).unwrap_err().class, ErrorClass::DuplicateKey);
        assert_eq!(parse(br#""\ud800""#).unwrap_err().class, ErrorClass::Syntax);
        let deep = "[".repeat(MAX_DEPTH + 2) + &"]".repeat(MAX_DEPTH + 2);
        assert_eq!(parse(deep.as_bytes()).unwrap_err().class, ErrorClass::Depth);
        assert_eq!(parse(b"01").unwrap_err().class, ErrorClass::Syntax);
        assert_eq!(parse(b"1 2").unwrap_err().class, ErrorClass::Syntax);
    }

    #[test]
    fn key_order_is_utf8_byte_order() {
        // U+FF5E (3 UTF-8 bytes EF BD 9E) sorts before U+1F600 (F0 ...) in
        // UTF-8 byte order, but after it in UTF-16 code-unit order.
        let j = parse("{\"😀\":1,\"～\":2}".as_bytes()).unwrap();
        assert_eq!(to_canonical(&j), "{\"～\":2,\"😀\":1}".as_bytes());
    }
}
