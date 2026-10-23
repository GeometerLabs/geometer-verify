// Canonical encoding runtime for TypeScript (hand-written; mirrors
// crates/geo-contracts/src/{json,value,codec}.rs). Numbers stay lexical,
// 64-bit and arbitrary-precision integers are bigint or decimal strings,
// object keys sort by UTF-8 bytes (not UTF-16 code units), duplicate keys and
// lone surrogates are rejected. Shared vectors check parity with Rust/Python.

export const MAX_DEPTH = 64;
export const MAX_NUMERIC_CHARS = 1000;

export type ErrorClass =
  | "syntax" | "duplicate_key" | "depth" | "unknown_field" | "missing_field" | "type" | "range"
  | "non_canonical" | "invalid_id" | "invalid_digest" | "unknown_variant" | "nan" | "frame_too_large";

export class DecodeError extends Error {
  cls: ErrorClass;
  path: string;
  constructor(cls: ErrorClass, path: string, msg: string) {
    super(`${cls} at ${path}: ${msg}`);
    this.cls = cls;
    this.path = path;
  }
}

export class JNum {
  lex: string;
  constructor(lex: string) {
    this.lex = lex;
  }
}

export class JObj {
  m: Map<string, Json>;
  constructor(m: Map<string, Json>) {
    this.m = m;
  }
}

export type Json = null | boolean | JNum | string | Json[] | JObj;

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

function kindOf(j: Json): string {
  if (j === null) return "null";
  if (typeof j === "boolean") return "bool";
  if (typeof j === "string") return "string";
  if (j instanceof JNum) return "number";
  if (Array.isArray(j)) return "array";
  return "object";
}

// ------------------------------------------------------------ parser

export function parse(bytes: Uint8Array): Json {
  let i = 0;
  const b = bytes;
  const syntax = (msg: string) => new DecodeError("syntax", "$", `${msg} at byte ${i}`);
  const ws = () => {
    while (i < b.length && (b[i] === 0x20 || b[i] === 0x09 || b[i] === 0x0a || b[i] === 0x0d)) i++;
  };
  const hex4 = (): number => {
    if (i + 4 > b.length) throw syntax("short \\u escape");
    let n = 0;
    for (let k = 0; k < 4; k++) {
      const c = b[i + k];
      const d = c >= 0x30 && c <= 0x39 ? c - 0x30 : c >= 0x61 && c <= 0x66 ? c - 87 : c >= 0x41 && c <= 0x46 ? c - 55 : -1;
      if (d < 0) throw syntax("bad \\u escape");
      n = n * 16 + d;
    }
    i += 4;
    return n;
  };
  const str = (): string => {
    i++;
    const out: number[] = [];
    for (;;) {
      if (i >= b.length) throw syntax("unterminated string");
      const c = b[i];
      if (c === 0x22) {
        i++;
        try {
          return dec.decode(new Uint8Array(out));
        } catch {
          throw syntax("invalid UTF-8");
        }
      }
      if (c === 0x5c) {
        i++;
        if (i >= b.length) throw syntax("bad escape");
        const e = b[i++];
        let cp: number;
        switch (e) {
          case 0x22: cp = 0x22; break;
          case 0x5c: cp = 0x5c; break;
          case 0x2f: cp = 0x2f; break;
          case 0x62: cp = 8; break;
          case 0x66: cp = 12; break;
          case 0x6e: cp = 10; break;
          case 0x72: cp = 13; break;
          case 0x74: cp = 9; break;
          case 0x75: {
            const hi = hex4();
            if (hi >= 0xd800 && hi < 0xdc00) {
              if (b[i] !== 0x5c || b[i + 1] !== 0x75) throw syntax("lone high surrogate");
              i += 2;
              const lo = hex4();
              if (lo < 0xdc00 || lo >= 0xe000) throw syntax("invalid low surrogate");
              cp = 0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00);
            } else if (hi >= 0xdc00 && hi < 0xe000) {
              throw syntax("lone low surrogate");
            } else cp = hi;
            break;
          }
          default:
            throw syntax("bad escape");
        }
        out.push(...enc.encode(String.fromCodePoint(cp)));
        continue;
      }
      if (c < 0x20) throw syntax("control character in string");
      out.push(c);
      i++;
    }
  };
  const num = (): JNum => {
    const s = i;
    if (b[i] === 0x2d) i++;
    if (b[i] === 0x30) i++;
    else if (b[i] >= 0x31 && b[i] <= 0x39) while (b[i] >= 0x30 && b[i] <= 0x39) i++;
    else throw syntax("invalid number");
    if (b[i] === 0x2e) {
      i++;
      const d = i;
      while (b[i] >= 0x30 && b[i] <= 0x39) i++;
      if (d === i) throw syntax("invalid fraction");
    }
    if (b[i] === 0x65 || b[i] === 0x45) {
      i++;
      if (b[i] === 0x2b || b[i] === 0x2d) i++;
      const d = i;
      while (b[i] >= 0x30 && b[i] <= 0x39) i++;
      if (d === i) throw syntax("invalid exponent");
    }
    return new JNum(dec.decode(b.subarray(s, i)));
  };
  const lit = (w: string, v: Json): Json => {
    for (let k = 0; k < w.length; k++) if (b[i + k] !== w.charCodeAt(k)) throw syntax("invalid literal");
    i += w.length;
    return v;
  };
  const value = (depth: number): Json => {
    if (depth > MAX_DEPTH) throw new DecodeError("depth", "$", `nesting deeper than ${MAX_DEPTH}`);
    ws();
    if (i >= b.length) throw syntax("unexpected end");
    const c = b[i];
    if (c === 0x6e) return lit("null", null);
    if (c === 0x74) return lit("true", true);
    if (c === 0x66) return lit("false", false);
    if (c === 0x22) return str();
    if (c === 0x5b) {
      i++;
      const v: Json[] = [];
      ws();
      if (b[i] === 0x5d) {
        i++;
        return v;
      }
      for (;;) {
        v.push(value(depth + 1));
        ws();
        if (b[i] === 0x2c) i++;
        else if (b[i] === 0x5d) {
          i++;
          return v;
        } else throw syntax("expected , or ]");
      }
    }
    if (c === 0x7b) {
      i++;
      const m = new Map<string, Json>();
      ws();
      if (b[i] === 0x7d) {
        i++;
        return new JObj(m);
      }
      for (;;) {
        ws();
        if (b[i] !== 0x22) throw syntax("expected object key");
        const k = str();
        ws();
        if (b[i] !== 0x3a) throw syntax("expected :");
        i++;
        const v = value(depth + 1);
        if (m.has(k)) throw new DecodeError("duplicate_key", "$", `duplicate key ${JSON.stringify(k)}`);
        m.set(k, v);
        ws();
        if (b[i] === 0x2c) i++;
        else if (b[i] === 0x7d) {
          i++;
          return new JObj(m);
        } else throw syntax("expected , or }");
      }
    }
    if (c === 0x2d || (c >= 0x30 && c <= 0x39)) return num();
    throw syntax(`unexpected byte 0x${c.toString(16).padStart(2, "0")}`);
  };
  const v = value(0);
  ws();
  if (i !== b.length) throw syntax("trailing data");
  return v;
}

// ---------------------------------------------------- canonical writer

function cmpUtf8(a: string, b: string): number {
  const x = enc.encode(a);
  const y = enc.encode(b);
  const n = Math.min(x.length, y.length);
  for (let k = 0; k < n; k++) if (x[k] !== y[k]) return x[k] - y[k];
  return x.length - y.length;
}

function writeStr(s: string): string {
  let o = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (ch === '"') o += '\\"';
    else if (ch === "\\") o += "\\\\";
    else if (c === 8) o += "\\b";
    else if (c === 12) o += "\\f";
    else if (c === 10) o += "\\n";
    else if (c === 13) o += "\\r";
    else if (c === 9) o += "\\t";
    else if (c < 0x20) o += "\\u" + c.toString(16).padStart(4, "0");
    else o += ch;
  }
  return o + '"';
}

function write(j: Json): string {
  if (j === null) return "null";
  if (j === true) return "true";
  if (j === false) return "false";
  if (typeof j === "string") return writeStr(j);
  if (j instanceof JNum) return j.lex;
  if (Array.isArray(j)) return "[" + j.map(write).join(",") + "]";
  const keys = [...j.m.keys()].sort(cmpUtf8);
  return "{" + keys.map((k) => writeStr(k) + ":" + write(j.m.get(k)!)).join(",") + "}";
}

export function toCanonical(j: Json): Uint8Array {
  return enc.encode(write(j));
}

// ------------------------------------------------------------- values

export type Value =
  | { t: "null" }
  | { t: "absent" }
  | { t: "bool"; v: boolean }
  | { t: "int"; v: bigint }
  | { t: "dec"; v: string }
  | { t: "f64"; bits: bigint }
  | { t: "str"; v: string }
  | { t: "bytes"; v: Uint8Array }
  | { t: "list"; v: Value[] }
  | { t: "map"; v: Map<string, Value> }
  | { t: "ref"; ns: string; kind: string; key: Value[] };

export function validIntText(s: string): boolean {
  return /^-?(0|[1-9][0-9]*)$/.test(s) && s !== "-0";
}

export function validDecText(s: string): boolean {
  if (!/^-?(0|[1-9][0-9]*)\.[0-9]+$/.test(s)) return false;
  return !(s.startsWith("-") && /^-0\.0+$/.test(s));
}

function b64(bytes: Uint8Array): string {
  let s = "";
  for (const x of bytes) s += String.fromCharCode(x);
  return btoa(s);
}

function unb64(s: string, path: string): Uint8Array {
  let raw: string;
  try {
    raw = atob(s);
  } catch {
    throw new DecodeError("non_canonical", path, "invalid base64");
  }
  const out = Uint8Array.from(raw, (c) => c.charCodeAt(0));
  if (b64(out) !== s) throw new DecodeError("non_canonical", path, "non-canonical base64");
  return out;
}

export function encodeValue(v: Value): Json {
  switch (v.t) {
    case "null":
    case "absent":
      return [v.t];
    case "bool":
      return ["bool", v.v];
    case "int":
      return ["int", v.v.toString()];
    case "dec":
      return ["dec", v.v];
    case "f64":
      return ["f64", v.bits.toString(16).padStart(16, "0")];
    case "str":
      return ["str", v.v];
    case "bytes":
      return ["bytes", b64(v.v)];
    case "list":
      return ["list", v.v.map(encodeValue)];
    case "map":
      return ["map", new JObj(new Map([...v.v].map(([k, x]) => [k, encodeValue(x)])))];
    case "ref":
      return ["ref", new JObj(new Map<string, Json>([["key", v.key.map(encodeValue)], ["kind", v.kind], ["ns", v.ns]]))];
  }
}

export function decodeValue(j: Json, path: string): Value {
  if (!Array.isArray(j)) throw new DecodeError("type", path, "value must be a tagged array");
  const tag = j[0];
  if (typeof tag !== "string") throw new DecodeError("type", path, "value tag must be a string");
  const arity = (n: number) => {
    if (j.length !== n) throw new DecodeError("type", path, `${tag} takes ${n - 1} element(s)`);
  };
  const text = (): string => {
    if (typeof j[1] !== "string") throw new DecodeError("type", path, `${tag} payload must be a string`);
    return j[1];
  };
  switch (tag) {
    case "null":
    case "absent":
      arity(1);
      return { t: tag };
    case "bool":
      arity(2);
      if (typeof j[1] !== "boolean") throw new DecodeError("type", path, "bool payload must be a boolean");
      return { t: "bool", v: j[1] };
    case "int": {
      arity(2);
      const s = text();
      if (s.length > MAX_NUMERIC_CHARS) throw new DecodeError("range", path, "integer too long");
      if (!validIntText(s)) throw new DecodeError("non_canonical", path, `non-canonical integer ${JSON.stringify(s)}`);
      return { t: "int", v: BigInt(s) };
    }
    case "dec": {
      arity(2);
      const s = text();
      if (s.length > MAX_NUMERIC_CHARS) throw new DecodeError("range", path, "decimal too long");
      if (!validDecText(s)) throw new DecodeError("non_canonical", path, `non-canonical decimal ${JSON.stringify(s)}`);
      return { t: "dec", v: s };
    }
    case "f64": {
      arity(2);
      const s = text();
      if (!/^[0-9a-f]{16}$/.test(s)) throw new DecodeError("non_canonical", path, "f64 must be 16 lowercase hex digits");
      const bits = BigInt("0x" + s);
      const exp = (bits >> 52n) & 0x7ffn;
      const mant = bits & ((1n << 52n) - 1n);
      if (exp === 0x7ffn && mant !== 0n) throw new DecodeError("nan", path, "NaN is not a portable value");
      return { t: "f64", bits };
    }
    case "str":
      arity(2);
      return { t: "str", v: text() };
    case "bytes":
      arity(2);
      return { t: "bytes", v: unb64(text(), path) };
    case "list": {
      arity(2);
      const a = j[1];
      if (!Array.isArray(a)) throw new DecodeError("type", path, "list payload must be an array");
      return { t: "list", v: a.map((x, k) => decodeValue(x, `${path}[${k}]`)) };
    }
    case "map": {
      arity(2);
      const o = j[1];
      if (!(o instanceof JObj)) throw new DecodeError("type", path, "map payload must be an object");
      return { t: "map", v: new Map([...o.m].map(([k, x]) => [k, decodeValue(x, `${path}.${k}`)])) };
    }
    case "ref": {
      arity(2);
      const o = j[1];
      if (!(o instanceof JObj)) throw new DecodeError("type", path, "ref payload must be an object");
      for (const k of o.m.keys()) if (!["key", "kind", "ns"].includes(k)) throw new DecodeError("unknown_field", path, `unknown ref field ${k}`);
      const s = (k: string): string => {
        const x = o.m.get(k);
        if (x === undefined) throw new DecodeError("missing_field", path, `ref.${k} missing`);
        if (typeof x !== "string") throw new DecodeError("type", path, `ref.${k} must be a string`);
        return x;
      };
      const key = o.m.get("key");
      if (key === undefined) throw new DecodeError("missing_field", path, "ref.key missing");
      if (!Array.isArray(key)) throw new DecodeError("type", path, "ref.key must be an array");
      const k = key.map((x, n) => decodeValue(x, `${path}.key[${n}]`));
      return { t: "ref", ns: s("ns"), kind: s("kind"), key: k };
    }
    default:
      throw new DecodeError("unknown_variant", path, `unknown value tag ${JSON.stringify(tag)}`);
  }
}

// --------------------------------------------------------- primitives

function typeErr(path: string, want: string, j: Json): DecodeError {
  return new DecodeError("type", path, `expected ${want}, got ${kindOf(j)}`);
}

export const encString = (s: string): Json => s;
export function decString(j: Json, path: string): string {
  if (typeof j !== "string") throw typeErr(path, "string", j);
  return j;
}
export const encBool = (b: boolean): Json => b;
export function decBool(j: Json, path: string): boolean {
  if (typeof j !== "boolean") throw typeErr(path, "boolean", j);
  return j;
}
export function encU32(n: number): Json {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new RangeError(`${n} is not a u32`);
  return new JNum(String(n));
}
export function decU32(j: Json, path: string): number {
  if (!(j instanceof JNum)) throw typeErr(path, "u32 number", j);
  if (!/^(0|[1-9][0-9]*)$/.test(j.lex)) throw new DecodeError("type", path, `u32 must be a plain non-negative integer, got ${j.lex}`);
  const n = BigInt(j.lex);
  if (n > 0xffffffffn) throw new DecodeError("range", path, `${j.lex} exceeds u32`);
  return Number(n);
}
export const encBig = (n: bigint): Json => n.toString();
function bigText(j: Json, path: string, what: string): bigint {
  if (typeof j !== "string") throw typeErr(path, `${what} decimal string`, j);
  if (!validIntText(j)) throw new DecodeError("non_canonical", path, `non-canonical ${what} ${JSON.stringify(j)}`);
  return BigInt(j);
}
export function decU64(j: Json, path: string): bigint {
  const n = bigText(j, path, "u64");
  if (n < 0n || n > 0xffffffffffffffffn) throw new DecodeError("range", path, `${n} out of u64 range`);
  return n;
}
export function decI64(j: Json, path: string): bigint {
  const n = bigText(j, path, "i64");
  if (n < -(1n << 63n) || n >= 1n << 63n) throw new DecodeError("range", path, `${n} out of i64 range`);
  return n;
}
export const encBytes = (b: Uint8Array): Json => b64(b);
export function decBytes(j: Json, path: string): Uint8Array {
  if (typeof j !== "string") throw typeErr(path, "base64 string", j);
  return unb64(j, path);
}
export function validId(s: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$/.test(s);
}
export function decId(j: Json, path: string): string {
  if (typeof j !== "string") throw typeErr(path, "id string", j);
  if (!validId(j)) throw new DecodeError("invalid_id", path, `invalid id ${JSON.stringify(j)}`);
  return j;
}
export function decDigest(j: Json, path: string): string {
  if (typeof j !== "string") throw typeErr(path, "digest string", j);
  if (!/^sha256:[0-9a-f]{64}$/.test(j)) throw new DecodeError("invalid_digest", path, `invalid digest ${JSON.stringify(j)}`);
  return j;
}
export function encMap<T>(m: Map<string, T>, f: (x: T) => Json): Json {
  return new JObj(new Map([...m].map(([k, v]) => [k, f(v)])));
}
export function decMap<T>(f: (j: Json, path: string) => T): (j: Json, path: string) => Map<string, T> {
  return (j, path) => {
    if (!(j instanceof JObj)) throw typeErr(path, "object", j);
    return new Map([...j.m].map(([k, v]) => [k, f(v, `${path}.${k}`)]));
  };
}
export function decList<T>(f: (j: Json, path: string) => T): (j: Json, path: string) => T[] {
  return (j, path) => {
    if (!Array.isArray(j)) throw typeErr(path, "array", j);
    return j.map((x, k) => f(x, `${path}[${k}]`));
  };
}
export function obj(j: Json, path: string): Map<string, Json> {
  if (!(j instanceof JObj)) throw typeErr(path, "object", j);
  return j.m;
}
export function onlyFields(m: Map<string, Json>, allowed: string[], path: string): void {
  for (const k of m.keys()) if (!allowed.includes(k)) throw new DecodeError("unknown_field", path, `unknown field ${JSON.stringify(k)}`);
}
export function req<T>(m: Map<string, Json>, k: string, path: string, f: (j: Json, path: string) => T): T {
  const v = m.get(k);
  if (v === undefined) throw new DecodeError("missing_field", path, `missing field ${JSON.stringify(k)}`);
  return f(v, `${path}.${k}`);
}
export function opt<T>(m: Map<string, Json>, k: string, path: string, f: (j: Json, path: string) => T): T | undefined {
  const v = m.get(k);
  if (v === undefined) return undefined;
  if (v === null) throw new DecodeError("type", path, `optional field ${JSON.stringify(k)} must be omitted, not null`);
  return f(v, `${path}.${k}`);
}
export function decEnum<T extends string>(j: Json, path: string, values: readonly T[], what: string): T {
  if (typeof j !== "string") throw typeErr(path, "enum string", j);
  if (!(values as readonly string[]).includes(j)) throw new DecodeError("unknown_variant", path, `unknown ${what} ${JSON.stringify(j)}`);
  return j as T;
}
