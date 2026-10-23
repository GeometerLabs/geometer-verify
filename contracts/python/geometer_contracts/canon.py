"""Canonical encoding runtime for Python (hand-written; mirrors
crates/geo-contracts/src/{json,value,codec}.rs).

Numbers stay lexical until a typed decoder reads them; object keys sort by
UTF-8 bytes; duplicate keys and lone surrogates are rejected. Shared vectors
check parity with Rust and TypeScript.
"""

from __future__ import annotations

import base64
import binascii
import re
import struct
from dataclasses import dataclass, field

MAX_DEPTH = 64
MAX_NUMERIC_CHARS = 1000


class DecodeError(Exception):
    def __init__(self, cls: str, path: str, msg: str):
        super().__init__(f"{cls} at {path}: {msg}")
        self.cls = cls
        self.path = path


@dataclass(frozen=True)
class JNum:
    lex: str


# Json = None | bool | JNum | str | list | dict


def _kind(j) -> str:
    if j is None:
        return "null"
    if isinstance(j, bool):
        return "bool"
    if isinstance(j, str):
        return "string"
    if isinstance(j, JNum):
        return "number"
    if isinstance(j, list):
        return "array"
    return "object"


# ------------------------------------------------------------ parser


def parse(data: bytes):
    b = data
    n = len(b)
    pos = [0]

    def syntax(msg):
        return DecodeError("syntax", "$", f"{msg} at byte {pos[0]}")

    def ws():
        while pos[0] < n and b[pos[0]] in (0x20, 0x09, 0x0A, 0x0D):
            pos[0] += 1

    def hex4():
        i = pos[0]
        h = b[i : i + 4]
        if len(h) < 4:
            raise syntax("short \\u escape")
        if not all(c in b"0123456789abcdefABCDEF" for c in h):
            raise syntax("bad \\u escape")
        pos[0] += 4
        return int(h, 16)

    def string():
        pos[0] += 1
        out = bytearray()
        while True:
            if pos[0] >= n:
                raise syntax("unterminated string")
            c = b[pos[0]]
            if c == 0x22:
                pos[0] += 1
                try:
                    return out.decode("utf-8")
                except UnicodeDecodeError:
                    raise syntax("invalid UTF-8") from None
            if c == 0x5C:
                pos[0] += 1
                if pos[0] >= n:
                    raise syntax("bad escape")
                e = b[pos[0]]
                pos[0] += 1
                simple = {0x22: 0x22, 0x5C: 0x5C, 0x2F: 0x2F, 0x62: 8, 0x66: 12, 0x6E: 10, 0x72: 13, 0x74: 9}
                if e in simple:
                    cp = simple[e]
                elif e == 0x75:
                    hi = hex4()
                    if 0xD800 <= hi < 0xDC00:
                        if b[pos[0] : pos[0] + 2] != b"\\u":
                            raise syntax("lone high surrogate")
                        pos[0] += 2
                        lo = hex4()
                        if not (0xDC00 <= lo < 0xE000):
                            raise syntax("invalid low surrogate")
                        cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                    elif 0xDC00 <= hi < 0xE000:
                        raise syntax("lone low surrogate")
                    else:
                        cp = hi
                else:
                    raise syntax("bad escape")
                out += chr(cp).encode("utf-8")
                continue
            if c < 0x20:
                raise syntax("control character in string")
            out.append(c)
            pos[0] += 1

    def number():
        s = pos[0]
        if pos[0] < n and b[pos[0]] == 0x2D:
            pos[0] += 1
        if pos[0] < n and b[pos[0]] == 0x30:
            pos[0] += 1
        elif pos[0] < n and 0x31 <= b[pos[0]] <= 0x39:
            while pos[0] < n and 0x30 <= b[pos[0]] <= 0x39:
                pos[0] += 1
        else:
            raise syntax("invalid number")
        if pos[0] < n and b[pos[0]] == 0x2E:
            pos[0] += 1
            d = pos[0]
            while pos[0] < n and 0x30 <= b[pos[0]] <= 0x39:
                pos[0] += 1
            if d == pos[0]:
                raise syntax("invalid fraction")
        if pos[0] < n and b[pos[0]] in (0x65, 0x45):
            pos[0] += 1
            if pos[0] < n and b[pos[0]] in (0x2B, 0x2D):
                pos[0] += 1
            d = pos[0]
            while pos[0] < n and 0x30 <= b[pos[0]] <= 0x39:
                pos[0] += 1
            if d == pos[0]:
                raise syntax("invalid exponent")
        return JNum(b[s : pos[0]].decode("ascii"))

    def lit(word, v):
        if b[pos[0] : pos[0] + len(word)] != word:
            raise syntax("invalid literal")
        pos[0] += len(word)
        return v

    def value(depth):
        if depth > MAX_DEPTH:
            raise DecodeError("depth", "$", f"nesting deeper than {MAX_DEPTH}")
        ws()
        if pos[0] >= n:
            raise syntax("unexpected end")
        c = b[pos[0]]
        if c == 0x6E:
            return lit(b"null", None)
        if c == 0x74:
            return lit(b"true", True)
        if c == 0x66:
            return lit(b"false", False)
        if c == 0x22:
            return string()
        if c == 0x5B:
            pos[0] += 1
            v = []
            ws()
            if pos[0] < n and b[pos[0]] == 0x5D:
                pos[0] += 1
                return v
            while True:
                v.append(value(depth + 1))
                ws()
                if pos[0] < n and b[pos[0]] == 0x2C:
                    pos[0] += 1
                elif pos[0] < n and b[pos[0]] == 0x5D:
                    pos[0] += 1
                    return v
                else:
                    raise syntax("expected , or ]")
        if c == 0x7B:
            pos[0] += 1
            m = {}
            ws()
            if pos[0] < n and b[pos[0]] == 0x7D:
                pos[0] += 1
                return m
            while True:
                ws()
                if pos[0] >= n or b[pos[0]] != 0x22:
                    raise syntax("expected object key")
                k = string()
                ws()
                if pos[0] >= n or b[pos[0]] != 0x3A:
                    raise syntax("expected :")
                pos[0] += 1
                v = value(depth + 1)
                if k in m:
                    raise DecodeError("duplicate_key", "$", f"duplicate key {k!r}")
                m[k] = v
                ws()
                if pos[0] < n and b[pos[0]] == 0x2C:
                    pos[0] += 1
                elif pos[0] < n and b[pos[0]] == 0x7D:
                    pos[0] += 1
                    return m
                else:
                    raise syntax("expected , or }")
        if c == 0x2D or 0x30 <= c <= 0x39:
            return number()
        raise syntax(f"unexpected byte 0x{c:02x}")

    v = value(0)
    ws()
    if pos[0] != n:
        raise syntax("trailing data")
    return v


# ---------------------------------------------------- canonical writer

_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _wstr(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _ESC:
            out.append(_ESC[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _write(j) -> str:
    if j is None:
        return "null"
    if j is True:
        return "true"
    if j is False:
        return "false"
    if isinstance(j, str):
        return _wstr(j)
    if isinstance(j, JNum):
        return j.lex
    if isinstance(j, list):
        return "[" + ",".join(_write(x) for x in j) + "]"
    # Python str ordering is by code point, identical to UTF-8 byte order.
    return "{" + ",".join(_wstr(k) + ":" + _write(j[k]) for k in sorted(j)) + "}"


def to_canonical(j) -> bytes:
    return _write(j).encode("utf-8")


# ------------------------------------------------------------- values

_INT = re.compile(r"-?(0|[1-9][0-9]*)")
_DEC = re.compile(r"-?(0|[1-9][0-9]*)\.[0-9]+")


def valid_int_text(s: str) -> bool:
    return _INT.fullmatch(s) is not None and s != "-0"


def valid_dec_text(s: str) -> bool:
    return _DEC.fullmatch(s) is not None and not re.fullmatch(r"-0\.0+", s)


@dataclass(frozen=True)
class Value:
    """Portable value. t is the tag; v holds the payload for simple tags."""

    t: str
    v: object = None
    ns: str | None = None
    kind: str | None = None
    key: tuple = field(default_factory=tuple)


def encode_value(x: Value):
    t = x.t
    if t in ("null", "absent"):
        return [t]
    if t == "bool":
        return ["bool", x.v]
    if t == "int":
        return ["int", str(x.v)]
    if t == "dec":
        return ["dec", x.v]
    if t == "f64":
        return ["f64", f"{x.v:016x}"]
    if t == "str":
        return ["str", x.v]
    if t == "bytes":
        return ["bytes", base64.b64encode(x.v).decode("ascii")]
    if t == "list":
        return ["list", [encode_value(e) for e in x.v]]
    if t == "map":
        return ["map", {k: encode_value(e) for k, e in x.v.items()}]
    if t == "ref":
        return ["ref", {"key": [encode_value(e) for e in x.key], "kind": x.kind, "ns": x.ns}]
    raise ValueError(t)


def decode_value(j, path: str) -> Value:
    if not isinstance(j, list):
        raise DecodeError("type", path, "value must be a tagged array")
    if not j or not isinstance(j[0], str):
        raise DecodeError("type", path, "value tag must be a string")
    tag = j[0]

    def arity(k):
        if len(j) != k:
            raise DecodeError("type", path, f"{tag} takes {k - 1} element(s)")

    def text():
        if not isinstance(j[1], str):
            raise DecodeError("type", path, f"{tag} payload must be a string")
        return j[1]

    if tag in ("null", "absent"):
        arity(1)
        return Value(tag)
    if tag == "bool":
        arity(2)
        if not isinstance(j[1], bool):
            raise DecodeError("type", path, "bool payload must be a boolean")
        return Value("bool", j[1])
    if tag == "int":
        arity(2)
        s = text()
        if len(s) > MAX_NUMERIC_CHARS:
            raise DecodeError("range", path, "integer too long")
        if not valid_int_text(s):
            raise DecodeError("non_canonical", path, f"non-canonical integer {s!r}")
        return Value("int", int(s))
    if tag == "dec":
        arity(2)
        s = text()
        if len(s) > MAX_NUMERIC_CHARS:
            raise DecodeError("range", path, "decimal too long")
        if not valid_dec_text(s):
            raise DecodeError("non_canonical", path, f"non-canonical decimal {s!r}")
        return Value("dec", s)
    if tag == "f64":
        arity(2)
        s = text()
        if not re.fullmatch(r"[0-9a-f]{16}", s):
            raise DecodeError("non_canonical", path, "f64 must be 16 lowercase hex digits")
        bits = int(s, 16)
        f = struct.unpack(">d", bits.to_bytes(8, "big"))[0]
        if f != f:
            raise DecodeError("nan", path, "NaN is not a portable value")
        return Value("f64", bits)
    if tag == "str":
        arity(2)
        return Value("str", text())
    if tag == "bytes":
        arity(2)
        s = text()
        try:
            raw = base64.b64decode(s, validate=True)
        except (binascii.Error, ValueError):
            raise DecodeError("non_canonical", path, "invalid base64") from None
        if base64.b64encode(raw).decode("ascii") != s:
            raise DecodeError("non_canonical", path, "non-canonical base64")
        return Value("bytes", raw)
    if tag == "list":
        arity(2)
        if not isinstance(j[1], list):
            raise DecodeError("type", path, "list payload must be an array")
        return Value("list", tuple(decode_value(x, f"{path}[{i}]") for i, x in enumerate(j[1])))
    if tag == "map":
        arity(2)
        if not isinstance(j[1], dict):
            raise DecodeError("type", path, "map payload must be an object")
        return Value("map", {k: decode_value(x, f"{path}.{k}") for k, x in j[1].items()})
    if tag == "ref":
        arity(2)
        o = j[1]
        if not isinstance(o, dict):
            raise DecodeError("type", path, "ref payload must be an object")
        for k in o:
            if k not in ("key", "kind", "ns"):
                raise DecodeError("unknown_field", path, f"unknown ref field {k}")

        def s(k):
            if k not in o:
                raise DecodeError("missing_field", path, f"ref.{k} missing")
            if not isinstance(o[k], str):
                raise DecodeError("type", path, f"ref.{k} must be a string")
            return o[k]

        if "key" not in o:
            raise DecodeError("missing_field", path, "ref.key missing")
        if not isinstance(o["key"], list):
            raise DecodeError("type", path, "ref.key must be an array")
        key = tuple(decode_value(x, f"{path}.key[{i}]") for i, x in enumerate(o["key"]))
        return Value("ref", ns=s("ns"), kind=s("kind"), key=key)
    raise DecodeError("unknown_variant", path, f"unknown value tag {tag!r}")


# --------------------------------------------------------- primitives


def _type_err(path, want, j):
    return DecodeError("type", path, f"expected {want}, got {_kind(j)}")


def enc_string(s: str):
    return s


def dec_string(j, path):
    if not isinstance(j, str):
        raise _type_err(path, "string", j)
    return j


def enc_bool(b: bool):
    return b


def dec_bool(j, path):
    if not isinstance(j, bool):
        raise _type_err(path, "boolean", j)
    return j


def enc_u32(n: int):
    if not (isinstance(n, int) and 0 <= n <= 0xFFFFFFFF):
        raise ValueError(f"{n} is not a u32")
    return JNum(str(n))


def dec_u32(j, path):
    if not isinstance(j, JNum):
        raise _type_err(path, "u32 number", j)
    if not re.fullmatch(r"0|[1-9][0-9]*", j.lex):
        raise DecodeError("type", path, f"u32 must be a plain non-negative integer, got {j.lex}")
    n = int(j.lex)
    if n > 0xFFFFFFFF:
        raise DecodeError("range", path, f"{j.lex} exceeds u32")
    return n


def _big(j, path, what):
    if not isinstance(j, str):
        raise _type_err(path, f"{what} decimal string", j)
    if not valid_int_text(j):
        raise DecodeError("non_canonical", path, f"non-canonical {what} {j!r}")
    return int(j)


def enc_u64(n: int):
    if not 0 <= n <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"{n} is not a u64")
    return str(n)


def dec_u64(j, path):
    n = _big(j, path, "u64")
    if not 0 <= n <= 0xFFFFFFFFFFFFFFFF:
        raise DecodeError("range", path, f"{n} out of u64 range")
    return n


def enc_i64(n: int):
    if not -(1 << 63) <= n < (1 << 63):
        raise ValueError(f"{n} is not an i64")
    return str(n)


def dec_i64(j, path):
    n = _big(j, path, "i64")
    if not -(1 << 63) <= n < (1 << 63):
        raise DecodeError("range", path, f"{n} out of i64 range")
    return n


def enc_bytes(b: bytes):
    return base64.b64encode(b).decode("ascii")


def dec_bytes(j, path):
    if not isinstance(j, str):
        raise _type_err(path, "base64 string", j)
    try:
        raw = base64.b64decode(j, validate=True)
    except (binascii.Error, ValueError):
        raise DecodeError("non_canonical", path, "invalid base64") from None
    if base64.b64encode(raw).decode("ascii") != j:
        raise DecodeError("non_canonical", path, "non-canonical base64")
    return raw


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}")


def valid_id(s: str) -> bool:
    return _ID.fullmatch(s) is not None and s.isascii()


def dec_id(j, path):
    if not isinstance(j, str):
        raise _type_err(path, "id string", j)
    if not valid_id(j):
        raise DecodeError("invalid_id", path, f"invalid id {j!r}")
    return j


def dec_digest(j, path):
    if not isinstance(j, str):
        raise _type_err(path, "digest string", j)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", j):
        raise DecodeError("invalid_digest", path, f"invalid digest {j!r}")
    return j


def dec_list(f):
    def d(j, path):
        if not isinstance(j, list):
            raise _type_err(path, "array", j)
        return [f(x, f"{path}[{i}]") for i, x in enumerate(j)]

    return d


def dec_map(f):
    def d(j, path):
        if not isinstance(j, dict):
            raise _type_err(path, "object", j)
        return {k: f(x, f"{path}.{k}") for k, x in j.items()}

    return d


def obj(j, path):
    if not isinstance(j, dict):
        raise _type_err(path, "object", j)
    return j


def only_fields(m, allowed, path):
    for k in m:
        if k not in allowed:
            raise DecodeError("unknown_field", path, f"unknown field {k!r}")


def req(m, k, path, f):
    if k not in m:
        raise DecodeError("missing_field", path, f"missing field {k!r}")
    return f(m[k], f"{path}.{k}")


def opt(m, k, path, f):
    if k not in m:
        return None
    if m[k] is None:
        raise DecodeError("type", path, f"optional field {k!r} must be omitted, not null")
    return f(m[k], f"{path}.{k}")


def dec_enum(j, path, values, what):
    if not isinstance(j, str):
        raise _type_err(path, "enum string", j)
    if j not in values:
        raise DecodeError("unknown_variant", path, f"unknown {what} {j!r}")
    return j
