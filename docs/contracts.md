# Contracts: schemas, bindings and compatibility

The schemas in this repository are the contract that Geometer's records follow. They are written once, in TOML, and the Rust, TypeScript and Python code that reads and writes those records is generated from them.

## Files

| Path | What it is |
| --- | --- |
| `contracts/schemas/core.toml` | The schema: 59 records, 32 enums and 3 unions at the time of writing. It holds the records the verifier reads (evidence packs, ledger entries, checkpoints, the key log, anchors, signature suites, assessment certificates, bundles, trust policies and status) and the records those refer to. Geometer's own products use more records than these; they are not part of this repository. |
| `crates/geo-contracts/src/generated.rs` | Generated Rust records and codecs. |
| `contracts/ts/src/generated.ts` | Generated TypeScript records and codecs. |
| `contracts/python/geometer_contracts/generated.py` | Generated Python records and codecs. |
| `crates/geo-contracts/src/` (other files) | Hand-written Rust: strict JSON parser and canonical writer (`json.rs`), portable values (`value.rs`), the codec trait (`codec.rs`), errors, and the assessment rules the verifier uses (`assessment.rs`). |
| `contracts/ts/src/`, `contracts/python/geometer_contracts/` | The same hand-written parts for TypeScript and Python. |
| `contracts/fixtures/` | Shared test vectors (`vectors.json`, 30 accepted and 21 refused inputs) and assessment examples. Rust, TypeScript and Python all run them. |
| `tools/contractgen/` | The generator. |

## Encoding

Every record has one canonical byte form. Hashes and signatures are computed over it, so every implementation must produce exactly the same bytes.

- Records are JSON objects. Keys are sorted by their UTF-8 bytes; there is no whitespace.
- Strings use the minimal escape set: `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, and `\u00XX` (lower-case hex) for other control characters below U+0020. Everything else, including non-ASCII, is written as raw UTF-8.
- Numbers are kept as written; only `u32` is a JSON number (a plain non-negative integer with no leading zeros). `u64` and `i64` are decimal **strings**, never JSON numbers, so no language loses precision.
- Unknown fields are rejected. Duplicate keys, lone surrogates and nesting deeper than 64 are rejected by the parser.
- `option<T>` fields are omitted when absent; `null` is not a way to say absent.
- Unions are objects with a `kind` field plus the variant's fields. Enums are strings.
- `bytes` are standard base64 with padding. A `digest` is `sha256:` and 64 lower-case hex digits. An `id` matches `[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}`.
- A portable `value` is a tagged array: `["null"]`, `["absent"]`, `["bool",true]`, `["int","-12"]`, `["dec","-1.50"]` (exact decimal, scale kept), `["f64","3ff8000000000000"]` (IEEE-754 bits; NaN is rejected), `["str","x"]`, `["bytes","<base64>"]`, `["list",[...]]`, `["map",{...}]` and `["ref",{"key":[...],"kind":"k","ns":"n"}]`. Null and absent are different values; integers and decimals never pass through a binary float.

The shared vectors in `contracts/fixtures/vectors.json` and `contracts/fixtures/assessment/vectors.json` list inputs with the exact canonical output expected from every language, and inputs every language must refuse.

## Generating the bindings

The generated files are committed. After editing `core.toml`:

```
cargo run -p contractgen            # rewrites the three generated files
cargo run -p contractgen -- --check # fails if they are stale (CI runs this)
```

Run both from the repository root; the generator reads and writes paths relative to it.

## Compatibility rules

- **The protocol version** is the `meta.protocol` value in the schema (`geo/2`). Records of the current version are decoded strictly.
- **Additive changes only inside a version.** New records, new enum values and new optional fields may be added. A new optional field is omitted when absent, so records written without it keep their exact bytes and hashes. Nothing is renamed, removed or retyped inside a version.
- **A change to meaning is a new name or a new version.** The signature suites are an example: a different parameter set or context string is a new suite id (`geo-ml-dsa-65/2`), never a reinterpretation of existing bytes.
- **Older versions are read by migration, not by loosening.** If a record format is ever read across versions, the old form is migrated before strict decoding; current decoders stay strict.
- **Unknown values are refused, not guessed.** A decoder that meets an unknown field, an unknown enum value or an unsupported schema version fails with a typed error. The verifier reports an unknown signature suite or profile as unusable (never as valid).
- **Three languages, one behaviour.** A change is complete when Rust, TypeScript and Python all pass the shared vectors.

## Tests

```
cargo test --locked                      # Rust, including the shared vectors
cd contracts/ts && npm test              # TypeScript (Node 24 or later; no dependencies)
cd contracts/python && python3 -m unittest discover -s tests   # Python 3.11 or later; no dependencies
```

The assessment fixtures in `contracts/fixtures/assessment/` are synthetic or hand-written examples. Where a fixture mentions a signing key, it is a published test key that must never be used for real data. The example assessment is unsigned and labelled as an example; it is not an issued assessment.
