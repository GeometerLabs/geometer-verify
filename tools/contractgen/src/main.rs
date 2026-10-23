//! Contract code generator.
//!
//!   contractgen            regenerate all bindings
//!   contractgen --check    fail if any committed binding differs from generation
//!
//! Source: contracts/schemas/*.toml. Outputs:
//!   crates/geo-contracts/src/generated.rs
//!   contracts/ts/src/generated.ts
//!   contracts/python/geometer_contracts/generated.py

use anyhow::{Context, Result, bail};
use std::fmt::Write as _;
use std::path::Path;

#[derive(Debug, Clone)]
enum Ty {
    String,
    Bool,
    U32,
    U64,
    I64,
    Bytes,
    Value,
    Digest,
    Id,
    List(Box<Ty>),
    Map(Box<Ty>),
    Option(Box<Ty>),
    Named(String),
}

fn parse_ty(s: &str) -> Result<Ty> {
    let s = s.trim();
    let inner = |p: &str| s.strip_prefix(p).and_then(|r| r.strip_suffix('>'));
    Ok(match s {
        "string" => Ty::String,
        "bool" => Ty::Bool,
        "u32" => Ty::U32,
        "u64" => Ty::U64,
        "i64" => Ty::I64,
        "bytes" => Ty::Bytes,
        "value" => Ty::Value,
        "digest" => Ty::Digest,
        "id" => Ty::Id,
        _ if s.starts_with("list<") => Ty::List(Box::new(parse_ty(inner("list<").context("bad list")?)?)),
        _ if s.starts_with("map<") => Ty::Map(Box::new(parse_ty(inner("map<").context("bad map")?)?)),
        _ if s.starts_with("option<") => Ty::Option(Box::new(parse_ty(inner("option<").context("bad option")?)?)),
        _ if s.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && s.chars().all(|c| c.is_ascii_alphanumeric()) =>
        {
            Ty::Named(s.to_owned())
        }
        _ => bail!("unknown type {s}"),
    })
}

#[derive(Debug)]
struct Field {
    name: String,
    ty: Ty,
}

#[derive(Debug)]
enum Def {
    Enum { name: String, doc: String, values: Vec<String> },
    Record { name: String, doc: String, fields: Vec<Field> },
    Union { name: String, doc: String, variants: Vec<(String, Vec<Field>)> },
}

impl Def {
    fn name(&self) -> &str {
        match self {
            Def::Enum { name, .. } | Def::Record { name, .. } | Def::Union { name, .. } => name,
        }
    }
}

fn fields(v: &toml::Value) -> Result<Vec<Field>> {
    let mut out = Vec::new();
    for f in v.as_array().context("fields must be an array")? {
        let name = f.get("name").and_then(|x| x.as_str()).context("field name")?.to_owned();
        let ty = parse_ty(f.get("type").and_then(|x| x.as_str()).context("field type")?)?;
        if let Ty::List(i) | Ty::Map(i) | Ty::Option(i) = &ty
            && matches!(**i, Ty::Option(_))
        {
            bail!("field {name}: option may only appear at field level");
        }
        out.push(Field { name, ty });
    }
    Ok(out)
}

fn load(root: &Path) -> Result<(String, Vec<Def>)> {
    let mut defs = Vec::new();
    let mut protocol = String::new();
    let mut files: Vec<_> = std::fs::read_dir(root.join("contracts/schemas"))?.collect::<std::io::Result<_>>()?;
    files.sort_by_key(|e| e.path());
    for f in files {
        let text = std::fs::read_to_string(f.path())?;
        // Definitions are emitted in source order: toml tables are ordered by
        // key, so recover declaration order from the text.
        let doc: toml::Table = text.parse()?;
        if let Some(p) = doc.get("meta").and_then(|m| m.get("protocol")).and_then(|p| p.as_str()) {
            protocol = p.to_owned();
        }
        let mut order: Vec<(String, String)> = Vec::new();
        for line in text.lines() {
            let l = line.trim();
            for kind in ["enum", "record", "union"] {
                if let Some(rest) = l.strip_prefix(&format!("[{kind}.")) {
                    let name = rest.trim_end_matches(']');
                    if !name.contains('.') {
                        order.push((kind.to_owned(), name.to_owned()));
                    }
                }
            }
        }
        for (kind, name) in order {
            let t = doc.get(&kind).and_then(|k| k.get(&name)).context("definition")?;
            let docstr = t.get("doc").and_then(|d| d.as_str()).unwrap_or("").to_owned();
            defs.push(match kind.as_str() {
                "enum" => Def::Enum {
                    name,
                    doc: docstr,
                    values: t
                        .get("values")
                        .and_then(|v| v.as_array())
                        .context("enum values")?
                        .iter()
                        .map(|v| v.as_str().unwrap().to_owned())
                        .collect(),
                },
                "record" => {
                    Def::Record { name, doc: docstr, fields: fields(t.get("fields").context("record fields")?)? }
                }
                _ => {
                    let vs = t.get("variants").and_then(|v| v.as_table()).context("union variants")?;
                    // Variant order: order of appearance in the source text.
                    let mut names: Vec<&String> = vs.keys().collect();
                    let pos = |n: &str| text.find(&format!("\n{n} = ")).unwrap_or(usize::MAX);
                    names.sort_by_key(|n| pos(n));
                    let mut variants = Vec::new();
                    for n in names {
                        let fs = fields(&vs[n])?;
                        if fs.iter().any(|f| f.name == "kind") {
                            bail!("union {name} variant {n}: field name 'kind' is reserved for the discriminator");
                        }
                        variants.push((n.clone(), fs));
                    }
                    Def::Union { name, doc: docstr, variants }
                }
            });
        }
    }
    // Every named type must resolve.
    let names: Vec<String> = defs.iter().map(|d| d.name().to_owned()).collect();
    fn check(t: &Ty, names: &[String]) -> Result<()> {
        match t {
            Ty::Named(n) if !names.contains(n) => bail!("unresolved type {n}"),
            Ty::List(i) | Ty::Map(i) | Ty::Option(i) => check(i, names),
            _ => Ok(()),
        }
    }
    for d in &defs {
        match d {
            Def::Record { fields, .. } => fields.iter().try_for_each(|f| check(&f.ty, &names))?,
            Def::Union { variants, .. } => variants.iter().flat_map(|v| &v.1).try_for_each(|f| check(&f.ty, &names))?,
            Def::Enum { .. } => {}
        }
    }
    Ok((protocol, defs))
}

fn pascal(s: &str) -> String {
    s.split('_').map(|p| p[..1].to_uppercase() + &p[1..]).collect()
}

const HEADER: &str = "Generated by tools/contractgen from contracts/schemas. Do not edit.";

// ------------------------------------------------------------------ Rust

fn rust_ty(t: &Ty) -> String {
    match t {
        Ty::String => "String".into(),
        Ty::Bool => "bool".into(),
        Ty::U32 => "u32".into(),
        Ty::U64 => "u64".into(),
        Ty::I64 => "i64".into(),
        Ty::Bytes => "Bytes".into(),
        Ty::Value => "Value".into(),
        Ty::Digest => "Digest".into(),
        Ty::Id => "Id".into(),
        Ty::List(i) => format!("Vec<{}>", rust_ty(i)),
        Ty::Map(i) => format!("BTreeMap<String, {}>", rust_ty(i)),
        Ty::Option(i) => format!("Option<{}>", rust_ty(i)),
        Ty::Named(n) => n.clone(),
    }
}

fn rust_ident(n: &str) -> String {
    if matches!(n, "type" | "ref" | "in" | "fn" | "match" | "mod" | "use" | "self" | "struct" | "enum") {
        format!("r#{n}")
    } else {
        n.to_owned()
    }
}

fn rust_fields_encode(out: &mut String, fields: &[Field], access: &dyn Fn(&str) -> String) {
    for f in fields {
        let a = access(&rust_ident(&f.name));
        if matches!(f.ty, Ty::Option(_)) {
            writeln!(out, "        put_opt(&mut m, {:?}, {a});", f.name).unwrap();
        } else {
            writeln!(out, "        put(&mut m, {:?}, {a});", f.name).unwrap();
        }
    }
}

fn rust_fields_decode(fields: &[Field]) -> String {
    fields
        .iter()
        .map(|f| {
            let fun = if matches!(f.ty, Ty::Option(_)) { "opt" } else { "req" };
            format!("{}: {fun}(m, {:?}, path)?", rust_ident(&f.name), f.name)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn allowed(fields: &[Field], extra: &[&str]) -> String {
    let mut names: Vec<String> = fields.iter().map(|f| format!("{:?}", f.name)).collect();
    names.extend(extra.iter().map(|e| format!("{e:?}")));
    names.join(", ")
}

fn gen_rust(protocol: &str, defs: &[Def]) -> String {
    let mut o = String::new();
    writeln!(o, "// {HEADER}\n#![allow(clippy::all)]\n").unwrap();
    writeln!(o, "use crate::codec::*;\nuse crate::json::Json;\nuse crate::value::Value;\nuse crate::error::DecodeError;\nuse std::collections::BTreeMap;\n").unwrap();
    writeln!(o, "pub const PROTOCOL: &str = {protocol:?};\n").unwrap();
    for d in defs {
        match d {
            Def::Enum { name, doc, values } => {
                if !doc.is_empty() {
                    writeln!(o, "/// {doc}").unwrap();
                }
                writeln!(o, "#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]\npub enum {name} {{")
                    .unwrap();
                for v in values {
                    writeln!(o, "    {},", pascal(v)).unwrap();
                }
                writeln!(
                    o,
                    "}}\n\nimpl {name} {{\n    pub const ALL: &'static [{name}] = &[{}];",
                    values.iter().map(|v| format!("{name}::{}", pascal(v))).collect::<Vec<_>>().join(", ")
                )
                .unwrap();
                writeln!(o, "    pub fn as_str(self) -> &'static str {{\n        match self {{").unwrap();
                for v in values {
                    writeln!(o, "            {name}::{} => {v:?},", pascal(v)).unwrap();
                }
                writeln!(o, "        }}\n    }}\n    pub fn parse(s: &str) -> Option<{name}> {{\n        match s {{")
                    .unwrap();
                for v in values {
                    writeln!(o, "            {v:?} => Some({name}::{}),", pascal(v)).unwrap();
                }
                writeln!(o, "            _ => None,\n        }}\n    }}\n}}\n").unwrap();
                writeln!(o, "impl Canon for {name} {{\n    fn to_json(&self) -> Json {{\n        Json::Str(self.as_str().to_owned())\n    }}\n    fn from_json(j: &Json, path: &str) -> Result<Self, DecodeError> {{\n        let s = enum_str(j, path)?;\n        {name}::parse(s).ok_or_else(|| unknown_variant(path, {name:?}, s))\n    }}\n}}\n").unwrap();
            }
            Def::Record { name, doc, fields } => {
                if !doc.is_empty() {
                    writeln!(o, "/// {doc}").unwrap();
                }
                writeln!(o, "#[derive(Debug, Clone, PartialEq)]\npub struct {name} {{").unwrap();
                for f in fields {
                    writeln!(o, "    pub {}: {},", rust_ident(&f.name), rust_ty(&f.ty)).unwrap();
                }
                writeln!(o, "}}\n\nimpl Canon for {name} {{\n    fn to_json(&self) -> Json {{\n        let mut m = BTreeMap::new();").unwrap();
                rust_fields_encode(&mut o, fields, &|n| format!("&self.{n}"));
                writeln!(o, "        Json::Obj(m)\n    }}\n    fn from_json(j: &Json, path: &str) -> Result<Self, DecodeError> {{\n        let m = obj(j, path)?;\n        only_fields(m, &[{}], path)?;\n        Ok({name} {{ {} }})\n    }}\n}}\n", allowed(fields, &[]), rust_fields_decode(fields)).unwrap();
            }
            Def::Union { name, doc, variants } => {
                if !doc.is_empty() {
                    writeln!(o, "/// {doc}").unwrap();
                }
                writeln!(o, "#[derive(Debug, Clone, PartialEq)]\npub enum {name} {{").unwrap();
                for (v, fs) in variants {
                    if fs.is_empty() {
                        writeln!(o, "    {},", pascal(v)).unwrap();
                    } else {
                        writeln!(
                            o,
                            "    {} {{ {} }},",
                            pascal(v),
                            fs.iter()
                                .map(|f| format!("{}: {}", rust_ident(&f.name), rust_ty(&f.ty)))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                        .unwrap();
                    }
                }
                writeln!(o, "}}\n\nimpl {name} {{\n    pub fn kind(&self) -> &'static str {{\n        match self {{")
                    .unwrap();
                for (v, fs) in variants {
                    let pat = if fs.is_empty() { String::new() } else { " { .. }".into() };
                    writeln!(o, "            {name}::{}{pat} => {v:?},", pascal(v)).unwrap();
                }
                writeln!(o, "        }}\n    }}\n}}\n\nimpl Canon for {name} {{\n    fn to_json(&self) -> Json {{\n        let mut m = BTreeMap::new();\n        m.insert(\"kind\".to_owned(), Json::Str(self.kind().to_owned()));\n        match self {{").unwrap();
                for (v, fs) in variants {
                    if fs.is_empty() {
                        writeln!(o, "            {name}::{} => {{}}", pascal(v)).unwrap();
                    } else {
                        writeln!(
                            o,
                            "            {name}::{} {{ {} }} => {{",
                            pascal(v),
                            fs.iter().map(|f| rust_ident(&f.name)).collect::<Vec<_>>().join(", ")
                        )
                        .unwrap();
                        let mut inner = String::new();
                        rust_fields_encode(&mut inner, fs, &|n| n.to_owned());
                        for l in inner.lines() {
                            writeln!(o, "        {l}").unwrap();
                        }
                        writeln!(o, "            }}").unwrap();
                    }
                }
                writeln!(o, "        }}\n        Json::Obj(m)\n    }}\n    fn from_json(j: &Json, path: &str) -> Result<Self, DecodeError> {{\n        let m = obj(j, path)?;\n        let kind: String = req(m, \"kind\", path)?;\n        match kind.as_str() {{").unwrap();
                for (v, fs) in variants {
                    let ctor = if fs.is_empty() {
                        format!("{name}::{}", pascal(v))
                    } else {
                        format!("{name}::{} {{ {} }}", pascal(v), rust_fields_decode(fs))
                    };
                    writeln!(o, "            {v:?} => {{\n                only_fields(m, &[{}], path)?;\n                Ok({ctor})\n            }}", allowed(fs, &["kind"])).unwrap();
                }
                writeln!(
                    o,
                    "            other => Err(unknown_variant(path, {name:?}, other)),\n        }}\n    }}\n}}\n"
                )
                .unwrap();
            }
        }
    }
    // Registry used by the cross-language vector tests.
    writeln!(o, "/// Decode `bytes` as the named contract type and re-encode canonically.\npub fn roundtrip_named(type_name: &str, bytes: &[u8]) -> Result<Vec<u8>, DecodeError> {{\n    match type_name {{").unwrap();
    for d in defs {
        writeln!(o, "        {:?} => {}::decode(bytes).map(|v| v.encode()),", d.name(), d.name()).unwrap();
    }
    writeln!(o, "        \"Value\" => Value::decode(bytes).map(|v| v.encode()),\n        other => panic!(\"unknown contract type {{other}}\"),\n    }}\n}}").unwrap();
    o
}

// ------------------------------------------------------------ TypeScript

fn ts_ty(t: &Ty) -> String {
    match t {
        Ty::String | Ty::Digest | Ty::Id => "string".into(),
        Ty::Bool => "boolean".into(),
        Ty::U32 => "number".into(),
        Ty::U64 | Ty::I64 => "bigint".into(),
        Ty::Bytes => "Uint8Array".into(),
        Ty::Value => "Value".into(),
        Ty::List(i) => format!("{}[]", ts_ty(i)),
        Ty::Map(i) => format!("Map<string, {}>", ts_ty(i)),
        Ty::Option(i) => ts_ty(i),
        Ty::Named(n) => n.clone(),
    }
}

fn ts_enc(t: &Ty, x: &str) -> String {
    match t {
        Ty::String | Ty::Digest | Ty::Id => format!("encString({x})"),
        Ty::Bool => format!("encBool({x})"),
        Ty::U32 => format!("encU32({x})"),
        Ty::U64 | Ty::I64 => format!("encBig({x})"),
        Ty::Bytes => format!("encBytes({x})"),
        Ty::Value => format!("encodeValue({x})"),
        Ty::List(i) => format!("{x}.map((e) => {})", ts_enc(i, "e")),
        Ty::Map(i) => format!("encMap({x}, (e) => {})", ts_enc(i, "e")),
        Ty::Option(i) => ts_enc(i, x),
        Ty::Named(n) => format!("encode{n}({x})"),
    }
}

fn ts_dec(t: &Ty) -> String {
    match t {
        Ty::String => "decString".into(),
        Ty::Digest => "decDigest".into(),
        Ty::Id => "decId".into(),
        Ty::Bool => "decBool".into(),
        Ty::U32 => "decU32".into(),
        Ty::U64 => "decU64".into(),
        Ty::I64 => "decI64".into(),
        Ty::Bytes => "decBytes".into(),
        Ty::Value => "decodeValue".into(),
        Ty::List(i) => format!("decList({})", ts_dec(i)),
        Ty::Map(i) => format!("decMap({})", ts_dec(i)),
        Ty::Option(i) => ts_dec(i),
        Ty::Named(n) => format!("decode{n}"),
    }
}

fn ts_fields_decl(fs: &[Field]) -> String {
    fs.iter()
        .map(|f| format!("{}{}: {}", f.name, if matches!(f.ty, Ty::Option(_)) { "?" } else { "" }, ts_ty(&f.ty)))
        .collect::<Vec<_>>()
        .join("; ")
}

fn ts_fields_enc(o: &mut String, fs: &[Field], src: &str) {
    for f in fs {
        let acc = format!("{src}.{}", f.name);
        if matches!(f.ty, Ty::Option(_)) {
            writeln!(o, "  if ({acc} !== undefined) m.set({:?}, {});", f.name, ts_enc(&f.ty, &acc)).unwrap();
        } else {
            writeln!(o, "  m.set({:?}, {});", f.name, ts_enc(&f.ty, &acc)).unwrap();
        }
    }
}

fn ts_fields_dec(fs: &[Field]) -> String {
    fs.iter()
        .map(|f| {
            let fun = if matches!(f.ty, Ty::Option(_)) { "opt" } else { "req" };
            format!("{}: {fun}(m, {:?}, path, {})", f.name, f.name, ts_dec(&f.ty))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn ts_allowed(fs: &[Field], extra: &[&str]) -> String {
    let mut v: Vec<String> = fs.iter().map(|f| format!("{:?}", f.name)).collect();
    v.extend(extra.iter().map(|e| format!("{e:?}")));
    format!("[{}]", v.join(", "))
}

fn gen_ts(protocol: &str, defs: &[Def]) -> String {
    let mut o = String::new();
    writeln!(o, "// {HEADER}\n").unwrap();
    writeln!(o, "import {{ type Json, JObj, type Value, DecodeError, encodeValue, decodeValue, encString, decString, encBool, decBool, encU32, decU32, encBig, decU64, decI64, encBytes, decBytes, decId, decDigest, encMap, decMap, decList, obj, onlyFields, req, opt, decEnum, toCanonical, parse }} from \"./canon.ts\";\n").unwrap();
    writeln!(o, "export const PROTOCOL = {protocol:?};\n").unwrap();
    for d in defs {
        match d {
            Def::Enum { name, doc, values } => {
                if !doc.is_empty() {
                    writeln!(o, "/** {doc} */").unwrap();
                }
                writeln!(
                    o,
                    "export const {name}Values = [{}] as const;",
                    values.iter().map(|v| format!("{v:?}")).collect::<Vec<_>>().join(", ")
                )
                .unwrap();
                writeln!(o, "export type {name} = (typeof {name}Values)[number];").unwrap();
                writeln!(o, "export function encode{name}(v: {name}): Json {{\n  return v;\n}}").unwrap();
                writeln!(o, "export function decode{name}(j: Json, path: string): {name} {{\n  return decEnum(j, path, {name}Values, {name:?});\n}}\n").unwrap();
            }
            Def::Record { name, doc, fields } => {
                if !doc.is_empty() {
                    writeln!(o, "/** {doc} */").unwrap();
                }
                writeln!(o, "export interface {name} {{ {} }}", ts_fields_decl(fields)).unwrap();
                writeln!(o, "export function encode{name}(v: {name}): Json {{\n  const m = new Map<string, Json>();")
                    .unwrap();
                ts_fields_enc(&mut o, fields, "v");
                writeln!(o, "  return new JObj(m);\n}}").unwrap();
                writeln!(o, "export function decode{name}(j: Json, path: string): {name} {{\n  const m = obj(j, path);\n  onlyFields(m, {}, path);\n  return {{ {} }};\n}}\n", ts_allowed(fields, &[]), ts_fields_dec(fields)).unwrap();
            }
            Def::Union { name, doc, variants } => {
                if !doc.is_empty() {
                    writeln!(o, "/** {doc} */").unwrap();
                }
                let alts: Vec<String> = variants
                    .iter()
                    .map(|(v, fs)| {
                        if fs.is_empty() {
                            format!("{{ kind: {v:?} }}")
                        } else {
                            format!("{{ kind: {v:?}; {} }}", ts_fields_decl(fs))
                        }
                    })
                    .collect();
                writeln!(o, "export type {name} = {};", alts.join(" | ")).unwrap();
                writeln!(o, "export function encode{name}(v: {name}): Json {{\n  const m = new Map<string, Json>();\n  m.set(\"kind\", v.kind);\n  switch (v.kind) {{").unwrap();
                for (v, fs) in variants {
                    writeln!(o, "    case {v:?}: {{").unwrap();
                    let mut inner = String::new();
                    ts_fields_enc(&mut inner, fs, "v");
                    for l in inner.lines() {
                        writeln!(o, "    {l}").unwrap();
                    }
                    writeln!(o, "      break;\n    }}").unwrap();
                }
                writeln!(o, "  }}\n  return new JObj(m);\n}}").unwrap();
                writeln!(o, "export function decode{name}(j: Json, path: string): {name} {{\n  const m = obj(j, path);\n  const kind = req(m, \"kind\", path, decString);\n  switch (kind) {{").unwrap();
                for (v, fs) in variants {
                    let body = if fs.is_empty() {
                        format!("{{ kind: {v:?} }}")
                    } else {
                        format!("{{ kind: {v:?}, {} }}", ts_fields_dec(fs))
                    };
                    writeln!(
                        o,
                        "    case {v:?}:\n      onlyFields(m, {}, path);\n      return {body};",
                        ts_allowed(fs, &["kind"])
                    )
                    .unwrap();
                }
                writeln!(o, "    default:\n      throw new DecodeError(\"unknown_variant\", path, `unknown {name} ${{kind}}`);\n  }}\n}}\n").unwrap();
            }
        }
    }
    writeln!(o, "const REGISTRY: Record<string, [(v: any) => Json, (j: Json, path: string) => any]> = {{").unwrap();
    for d in defs {
        writeln!(o, "  {}: [encode{}, decode{}],", d.name(), d.name(), d.name()).unwrap();
    }
    writeln!(o, "  Value: [encodeValue, decodeValue],\n}};\n").unwrap();
    writeln!(o, "/** Decode `bytes` as the named contract type and re-encode canonically. */\nexport function roundtripNamed(typeName: string, bytes: Uint8Array): Uint8Array {{\n  const codec = REGISTRY[typeName];\n  if (!codec) throw new Error(`unknown contract type ${{typeName}}`);\n  return toCanonical(codec[0](codec[1](parse(bytes), \"$\")));\n}}").unwrap();
    o
}

// ---------------------------------------------------------------- Python

fn py_ty(t: &Ty) -> String {
    match t {
        Ty::String | Ty::Digest | Ty::Id => "str".into(),
        Ty::Bool => "bool".into(),
        Ty::U32 | Ty::U64 | Ty::I64 => "int".into(),
        Ty::Bytes => "bytes".into(),
        Ty::Value => "Value".into(),
        Ty::List(i) => format!("list[{}]", py_ty(i)),
        Ty::Map(i) => format!("dict[str, {}]", py_ty(i)),
        Ty::Option(i) => format!("{} | None", py_ty(i)),
        Ty::Named(n) => format!("\"{n}\""),
    }
}

fn py_enc(t: &Ty, x: &str) -> String {
    match t {
        Ty::String | Ty::Digest | Ty::Id => format!("enc_string({x})"),
        Ty::Bool => format!("enc_bool({x})"),
        Ty::U32 => format!("enc_u32({x})"),
        Ty::U64 => format!("enc_u64({x})"),
        Ty::I64 => format!("enc_i64({x})"),
        Ty::Bytes => format!("enc_bytes({x})"),
        Ty::Value => format!("encode_value({x})"),
        Ty::List(i) => format!("[{} for e in {x}]", py_enc(i, "e")),
        Ty::Map(i) => format!("{{k: {} for k, e in {x}.items()}}", py_enc(i, "e")),
        Ty::Option(i) => py_enc(i, x),
        Ty::Named(n) => format!("encode_{}({x})", snake(n)),
    }
}

fn py_dec(t: &Ty) -> String {
    match t {
        Ty::String => "dec_string".into(),
        Ty::Digest => "dec_digest".into(),
        Ty::Id => "dec_id".into(),
        Ty::Bool => "dec_bool".into(),
        Ty::U32 => "dec_u32".into(),
        Ty::U64 => "dec_u64".into(),
        Ty::I64 => "dec_i64".into(),
        Ty::Bytes => "dec_bytes".into(),
        Ty::Value => "decode_value".into(),
        Ty::List(i) => format!("dec_list({})", py_dec(i)),
        Ty::Map(i) => format!("dec_map({})", py_dec(i)),
        Ty::Option(i) => py_dec(i),
        Ty::Named(n) => format!("decode_{}", snake(n)),
    }
}

fn snake(s: &str) -> String {
    let mut o = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                o.push('_');
            }
            o.push(c.to_ascii_lowercase());
        } else {
            o.push(c);
        }
    }
    o
}

const PY_KEYWORDS: &[&str] = &[
    "from", "in", "is", "not", "and", "or", "if", "else", "for", "while", "with", "as", "def", "class", "return",
    "import", "pass", "lambda", "global", "del", "try", "except", "raise", "yield", "assert", "break", "continue",
    "None", "True", "False", "async", "await", "nonlocal", "finally", "elif",
];

/// Python attribute for a contract field; keywords get a trailing underscore
/// (the wire key is unchanged).
fn py_ident(n: &str) -> String {
    if PY_KEYWORDS.contains(&n) { format!("{n}_") } else { n.to_owned() }
}

fn py_fields_enc(o: &mut String, fs: &[Field], src: &str, indent: &str) {
    for f in fs {
        let acc = format!("{src}.{}", py_ident(&f.name));
        if matches!(f.ty, Ty::Option(_)) {
            writeln!(o, "{indent}if {acc} is not None:\n{indent}    m[{:?}] = {}", f.name, py_enc(&f.ty, &acc))
                .unwrap();
        } else {
            writeln!(o, "{indent}m[{:?}] = {}", f.name, py_enc(&f.ty, &acc)).unwrap();
        }
    }
}

fn py_fields_dec(fs: &[Field]) -> String {
    fs.iter()
        .map(|f| {
            let fun = if matches!(f.ty, Ty::Option(_)) { "opt" } else { "req" };
            format!("{}={fun}(m, {:?}, path, {})", py_ident(&f.name), f.name, py_dec(&f.ty))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn py_allowed(fs: &[Field], extra: &[&str]) -> String {
    let mut v: Vec<String> = fs.iter().map(|f| format!("{:?}", f.name)).collect();
    v.extend(extra.iter().map(|e| format!("{e:?}")));
    format!("({}{})", v.join(", "), if v.len() == 1 { "," } else { "" })
}

fn gen_py(protocol: &str, defs: &[Def]) -> String {
    let mut o = String::new();
    writeln!(o, "# {HEADER}\n# ruff: noqa\nfrom __future__ import annotations\n\nfrom dataclasses import dataclass, field\nfrom typing import ClassVar, Union\n\nfrom .canon import (\n    DecodeError, Value, decode_value, encode_value, enc_string, dec_string, enc_bool, dec_bool, enc_u32, dec_u32,\n    enc_u64, dec_u64, enc_i64, dec_i64, enc_bytes, dec_bytes, dec_id, dec_digest, dec_list, dec_map, obj, only_fields,\n    req, opt, dec_enum, to_canonical, parse,\n)\n\nPROTOCOL = {protocol:?}\n").unwrap();
    for d in defs {
        match d {
            Def::Enum { name, doc, values } => {
                if !doc.is_empty() {
                    writeln!(o, "# {doc}").unwrap();
                }
                writeln!(
                    o,
                    "{}_VALUES = ({}{})\n",
                    snake(name).to_uppercase(),
                    values.iter().map(|v| format!("{v:?}")).collect::<Vec<_>>().join(", "),
                    if values.len() == 1 { "," } else { "" }
                )
                .unwrap();
                writeln!(o, "\ndef encode_{}(v: str):\n    return enc_string(v)\n\n", snake(name)).unwrap();
                writeln!(
                    o,
                    "def decode_{}(j, path: str) -> str:\n    return dec_enum(j, path, {}_VALUES, {name:?})\n\n",
                    snake(name),
                    snake(name).to_uppercase()
                )
                .unwrap();
            }
            Def::Record { name, doc, fields } => {
                writeln!(o, "@dataclass\nclass {name}:").unwrap();
                if !doc.is_empty() {
                    writeln!(o, "    \"\"\"{doc}\"\"\"\n").unwrap();
                }
                for f in fields {
                    if matches!(f.ty, Ty::Option(_)) {
                        writeln!(o, "    {}: {} = None", py_ident(&f.name), py_ty(&f.ty)).unwrap();
                    } else {
                        writeln!(o, "    {}: {}", py_ident(&f.name), py_ty(&f.ty)).unwrap();
                    }
                }
                // Required fields must precede defaulted ones in a dataclass.
                let mut sorted: Vec<&Field> = fields.iter().collect();
                sorted.sort_by_key(|f| matches!(f.ty, Ty::Option(_)));
                if sorted.iter().map(|f| &f.name).ne(fields.iter().map(|f| &f.name)) {
                    // Re-emit with required-first ordering.
                    let start = o.rfind(&format!("@dataclass\nclass {name}:")).unwrap();
                    o.truncate(start);
                    writeln!(o, "@dataclass\nclass {name}:").unwrap();
                    if !doc.is_empty() {
                        writeln!(o, "    \"\"\"{doc}\"\"\"\n").unwrap();
                    }
                    for f in &sorted {
                        if matches!(f.ty, Ty::Option(_)) {
                            writeln!(o, "    {}: {} = None", py_ident(&f.name), py_ty(&f.ty)).unwrap();
                        } else {
                            writeln!(o, "    {}: {}", py_ident(&f.name), py_ty(&f.ty)).unwrap();
                        }
                    }
                }
                writeln!(o, "\n\ndef encode_{}(v: {name}):\n    m = {{}}", snake(name)).unwrap();
                py_fields_enc(&mut o, fields, "v", "    ");
                writeln!(o, "    return m\n\n\ndef decode_{}(j, path: str) -> {name}:\n    m = obj(j, path)\n    only_fields(m, {}, path)\n    return {name}({})\n\n", snake(name), py_allowed(fields, &[]), py_fields_dec(fields)).unwrap();
            }
            Def::Union { name, doc, variants } => {
                if !doc.is_empty() {
                    writeln!(o, "# {doc}").unwrap();
                }
                let mut classes = Vec::new();
                for (v, fs) in variants {
                    let cls = format!("{name}{}", pascal(v));
                    classes.push(cls.clone());
                    writeln!(o, "@dataclass\nclass {cls}:\n    KIND: ClassVar[str] = {v:?}").unwrap();
                    let mut sorted: Vec<&Field> = fs.iter().collect();
                    sorted.sort_by_key(|f| matches!(f.ty, Ty::Option(_)));
                    for f in sorted {
                        if matches!(f.ty, Ty::Option(_)) {
                            writeln!(o, "    {}: {} = None", py_ident(&f.name), py_ty(&f.ty)).unwrap();
                        } else {
                            writeln!(o, "    {}: {}", py_ident(&f.name), py_ty(&f.ty)).unwrap();
                        }
                    }
                    writeln!(o, "\n").unwrap();
                }
                writeln!(o, "{name} = Union[{}]\n\n", classes.join(", ")).unwrap();
                writeln!(o, "def encode_{}(v):\n    m = {{\"kind\": v.KIND}}", snake(name)).unwrap();
                for ((_, fs), cls) in variants.iter().zip(&classes) {
                    writeln!(o, "    if isinstance(v, {cls}):").unwrap();
                    let mut inner = String::new();
                    py_fields_enc(&mut inner, fs, "v", "        ");
                    if inner.is_empty() {
                        inner = "        pass\n".into();
                    }
                    o.push_str(&inner);
                }
                writeln!(o, "    return m\n\n\ndef decode_{}(j, path: str):\n    m = obj(j, path)\n    kind = req(m, \"kind\", path, dec_string)", snake(name)).unwrap();
                for ((v, fs), cls) in variants.iter().zip(&classes) {
                    writeln!(
                        o,
                        "    if kind == {v:?}:\n        only_fields(m, {}, path)\n        return {cls}({})",
                        py_allowed(fs, &["kind"]),
                        py_fields_dec(fs)
                    )
                    .unwrap();
                }
                writeln!(o, "    raise DecodeError(\"unknown_variant\", path, f\"unknown {name} {{kind}}\")\n\n")
                    .unwrap();
            }
        }
    }
    writeln!(o, "REGISTRY = {{").unwrap();
    for d in defs {
        writeln!(o, "    {:?}: (encode_{}, decode_{}),", d.name(), snake(d.name()), snake(d.name())).unwrap();
    }
    writeln!(o, "    \"Value\": (encode_value, decode_value),\n}}\n\n\ndef roundtrip_named(type_name: str, data: bytes) -> bytes:\n    \"\"\"Decode `data` as the named contract type and re-encode canonically.\"\"\"\n    enc, dec = REGISTRY[type_name]\n    return to_canonical(enc(dec(parse(data), \"$\")))").unwrap();
    o
}

fn main() -> Result<()> {
    let check = std::env::args().any(|a| a == "--check");
    let root = std::env::current_dir()?;
    let (protocol, defs) = load(&root)?;
    let outputs = [
        ("crates/geo-contracts/src/generated.rs", gen_rust(&protocol, &defs)),
        ("contracts/ts/src/generated.ts", gen_ts(&protocol, &defs)),
        ("contracts/python/geometer_contracts/generated.py", gen_py(&protocol, &defs)),
    ];
    let mut stale = Vec::new();
    for (path, content) in &outputs {
        let p = root.join(path);
        let current = std::fs::read_to_string(&p).unwrap_or_default();
        if check {
            if current != *content {
                stale.push(*path);
            }
        } else if current != *content {
            std::fs::create_dir_all(p.parent().unwrap())?;
            std::fs::write(&p, content)?;
            println!("wrote {path}");
        }
    }
    if !stale.is_empty() {
        bail!("generated bindings are stale (run `cargo run -p contractgen`): {}", stale.join(", "));
    }
    if check {
        println!("generated bindings match {} definitions", defs.len());
    }
    Ok(())
}
