# geometer-verify

The standalone verifier for Geometer evidence, and the schemas that Geometer's records follow.

This repository holds:

- **`geo-verify`**: a command-line program and Rust library that checks an exported **evidence pack** and an **assessment certificate** using only files you give it. It uses no network, no database and no Geometer installation.
- **The contract schemas** (`contracts/schemas/core.toml`) with the Rust, TypeScript and Python code generated from them, the generator, and the shared test vectors.

It is licensed under Apache-2.0. **Status: alpha.** The formats may still change; see "Versioning".

## Who it is for

- Someone who received an evidence pack or an assessment from a team that uses Geometer (an auditor, a customer, a reviewer, an insurer) and wants to check it without installing or trusting the product that made it.
- Someone building their own reader or writer for these records, who needs the exact schema, the canonical byte form and test vectors.
- Anyone who wants to read the code that decides what "verified" means.

## What a result means

`geo-verify` answers one narrow question: **do these bytes match what an anchor or key that you chose to trust says they should be?**

| Result | Meaning |
| --- | --- |
| Verified (exit 0) | The records have not changed since your saved anchor, or since a key you trust signed them. |
| Invalid (exit 1) | Something was edited, reordered, deleted, cut short, rewritten, or signed by the wrong or a revoked key. |
| Incomplete (exit 2) | The pack declares that part of the history is missing. What remains is still checked. |
| Unverifiable (exit 3) | Nothing you supplied covers this record, so nothing is claimed. A chain with no anchor can be rewritten together with its hashes. |

**What a pass does not show.** It is a check of integrity relative to the anchors and keys you supplied. It does not establish that what was recorded is true, that everything that happened was recorded, that an explanation was the real reason, or who the issuer is: if you hand it an attacker's anchor or key, it will say the attacker's records match. It does not rerun an assessment or judge whether a finding is correct. The implementation has not been independently audited, and a verifier built from the same source as the writer is a separate program, not an independent implementation. Details are in [docs/evidence-pack.md](docs/evidence-pack.md).

## Build

You need Rust. The repository pins the toolchain in `rust-toolchain.toml` (rustup installs it on first use).

```
cargo build --locked --release -p geo-verify
# the program is at target/release/geo-verify
```

Run the tests:

```
cargo test --locked
cargo run --locked -q -p contractgen -- --check          # generated bindings are current
(cd contracts/ts && npm test)                            # Node 24 or later, no dependencies
(cd contracts/python && python3 -m unittest discover -s tests)   # Python 3.11 or later, no dependencies
```

## Verify an evidence pack

You need the pack (`pack.json`) and at least one anchor that you saved earlier somewhere the pack's owner cannot change:

```
geo-verify pack.json --anchor anchor.json
echo $?
```

The repository includes a small signed pack and two anchors you can try:

```
fx=crates/geo-verify/tests/fixtures/profile
target/release/geo-verify $fx/pack.json --anchor $fx/anchor-classical.json     # verified, exit 0 (entries 1 to 5 match the anchor; 6 to 10 are listed as not covered)
target/release/geo-verify $fx/pack.json                                         # no anchor: unverifiable, exit 3
target/release/geo-verify $fx/pack.json --anchor $fx/anchor-classical.json --require-profile hybrid   # exit 3
```

Options: `--anchor FILE` (repeatable), `--require-profile classical|pq|hybrid` (trust only checkpoints and anchors signed with every suite of that profile), `--json` (machine-readable report). Exit codes: 0 verified, 1 invalid, 2 incomplete, 3 unverifiable, 64 bad usage or unreadable input.

## Verify an assessment certificate

An assessment is a signed statement about a system. It can be a directory with `bundle.json` and its evidence files, a `bundle.json` file, or a bare assessment record:

```
geo-verify assessment ./assessment-bundle --trust-key issuer-key.json
```

Keys come only from you (`--trust-key`, `--key-log`), never from the bundle. A report with no key you trust is exit 3 ("unsigned or unverifiable"); a changed or wrongly signed report is exit 1. You can also pin what it must be about (`--expect-revision`, `--expect-rule ID=sha256:...`), supply status (`--status`), anchors and packs (`--anchor`, `--pack`), and ask for freshness (`--require-current`, `--max-status-age`). Run `geo-verify assessment --help` for the full list, and see [docs/evidence-pack.md](docs/evidence-pack.md) for each check and exit code. The tests in `crates/geo-verify/tests/cli.rs` build signed bundles end to end. The repository also includes unsigned example records; the verifier reads them but reports that nothing shows who made them:

```
target/release/geo-verify assessment contracts/fixtures/assessment/valid-unsigned.json   # exit 3
```

## The schemas are the contract

`contracts/schemas/core.toml` is the single source for Geometer's records: how they are named, typed and encoded to canonical bytes. Hashes and signatures are computed over those bytes, so the schema is what makes a record checkable by anyone. The Rust, TypeScript and Python codecs are generated from it and run against the same vectors. See [docs/contracts.md](docs/contracts.md).

## Relationship to the Geometer product

Geometer is a closed-source product that records what AI agents and automations do and checks them against rules. It writes evidence packs and assessment certificates. This repository is the open part: the verifier and the record formats, published so that you do not have to trust the product to check what it produced. The product's engine, host, adapters and workspace are not here, and nothing in this repository needs them.

The code here is exported from Geometer's main source tree by an allow-list, and a check refuses to publish a file that is not on it. Pull requests are welcome but may be reimplemented there; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Versioning

Releases are tagged on this repository and follow the Geometer release number (the first is `0.1.0-alpha.1`). The Rust crates currently declare `0.1.0`, and `geo-verify 0.1.0` is the name recorded in assessment verification results. The formats carry their own versions: the evidence pack is `geometer.evidence-pack` version 1, the assessment bundle is `geometer.assessment-bundle` version 1, and the protocol in the schema is `geo/2`. Inside a version, schema changes are additive only (docs/contracts.md).

## Licence and security

Apache License 2.0; see `LICENSE` and `NOTICE`. To report a vulnerability, see [SECURITY.md](SECURITY.md). All keys and seeds in the test fixtures are public synthetic constants and must never be trusted for real data.
