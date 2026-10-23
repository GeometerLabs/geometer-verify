# The evidence pack and how it is verified

This page describes the `geometer.evidence-pack` format (version 1) and what `geo-verify` checks. It is written from the code in `crates/geo-verify` and the schema in `contracts/schemas/core.toml`. If this page and the code disagree, the code is right; please open an issue.

## What a pack is

A pack is a JSON file that holds one tenant's slice of an append-only ledger: the entries from `from_seq` to `to_seq`, the signed checkpoints and the key log needed to check them, any declared gaps, and two derived views (`actions`, `coverage`) that the verifier ignores.

| Field | Meaning |
| --- | --- |
| `format`, `v` | Must be `geometer.evidence-pack` and `1`. Anything else is reported invalid. |
| `tenant`, `ledger` | Whose entries these are. Every entry, checkpoint and anchor must name the same tenant. |
| `generated_ms` | When the pack was exported. Not checked. |
| `from_seq`, `to_seq` | First and last sequence number the pack claims. Sequences start at 1. |
| `base_prev` | The hash of entry `from_seq - 1`, so a pack that starts mid-ledger can still be linked to what came before. Absent for a pack that starts at 1. |
| `entries` | The ledger entries. |
| `checkpoints` | Signed statements about the chain head at some sequence. |
| `key_log` | The hash-linked log of signing keys. |
| `gaps` | Evidence the exporter says is missing, with a kind (`missing_segment`, `missing_tail`, `retention`). |
| `actions`, `coverage` | Derived views for people to read. **Ignored by the verifier.** |
| `notes` | Free text. |

All records use the canonical JSON encoding described in [contracts.md](contracts.md). The verifier decodes strictly: unknown fields, duplicate keys and wrong types are refused before any check runs (exit 64).

## Entries: hashing and linking

Each entry has a `seq`, a `prev` (the previous entry's hash; absent for sequence 1), a `kind`, a `subject`, a `body_type` and `body`, an optional `payload` commitment, `links` to other entries, and its own `hash`.

- **Entry hash.** `hash = sha256("geo-ledger/1\n" || canonical bytes of the entry with hash set to 64 zero hex digits)`, written `sha256:<hex>`.
- **Chain.** Each entry's `prev` must equal the previous entry's `hash`. Editing an entry changes its hash; deleting or reordering entries breaks sequence numbers or links.
- **Kinds are never merged:** `observed_fact`, `guard_decision`, `approval`, `provider_receipt`, `inferred_explanation`, `tombstone`, `gap`. A `guard_decision` is a decision, not an effect; only a `provider_receipt` is the provider's own confirmation.
- **Payloads are stored apart.** An entry holds only a commitment, `sha256(salt || payload bytes)`, and the size. The payload and its salt are not part of the pack, so the verifier does not (and cannot) check payload contents. The salt is destroyed with the payload, so a deleted low-entropy payload cannot be recovered by guessing against the digest.

## Payload removal tombstones

Deleting or redacting a payload never rewrites an entry. The ledger appends a `tombstone` entry whose JSON body names the entry it applies to (`of_seq`, or `of_seqs` when several payloads shared one destroyed key). The verifier lists those sequences as `unavailable_payloads` and adds the note `payload_unavailable`. The original entries still verify; any replay that needed the payload is reduced.

A `gap` entry means the ledger itself recorded missing evidence. It makes the verdict `incomplete`.

## Checkpoints, the key log and anchors

**Checkpoints** are signed statements: "at `seq` the chain head was `head`, after `count` entries, when the key log had `key_log_seq` events". Checkpoints inside a pack sit beside the ledger and are not trusted on their own: whoever can rewrite the entries can usually rewrite those too.

**Anchors** are the trust roots. An anchor is a file (a checkpoint, the signer's public key or keys, and the key-log head) that the reader kept somewhere the ledger's owner cannot rewrite. `geo-verify` takes anchors with `--anchor`. Without one, the verdict is `unverifiable`.

**The key log** is a hash-linked list of key events:

| Event | Meaning |
| --- | --- |
| `genesis` | The first signing key. Must be event 1 and signed by itself. |
| `rotate` | A new key, signed by the new key and by an active key. |
| `revoke` | A key is no longer trusted. Needs another active key's signature. Marked `compromised` if the key was exposed. |
| `recover` | A new key after the old one was lost. Signed only by itself, so nothing in the log vouches for it; trust comes from an anchor. |
| `profile` | Sets the signature profile required from this log position on (see below). Must be signed under the profile in force and the new one, so a weaker key alone cannot downgrade. |

A key id is `key:` followed by the sha256 of the raw public key bytes. Key-log event hashes are `sha256("geo-keylog/1\n" || canonical bytes with signatures removed and hash zeroed)`. Revocation is counted by key-log position, not wall-clock time: a checkpoint that cites a `key_log_seq` at or after the revocation is invalid. If a key was reported compromised, checkpoints inside the pack that it signed are not trusted unless a saved anchor pins that exact checkpoint.

**How an anchor is used.** The verifier checks the anchor's key id and signature, checks that the key is in the pack's key log (and that the key log matches the head the anchor saw), then compares the anchor's `head` with the pack's entry at the anchor's `seq`:

- They match: the entries from the start of their unbroken run up to the anchor are `verified`.
- They differ: `invalid` (the history changed since you saved the anchor).
- The anchor is past the end of the pack: `invalid` (the tail was cut) unless the pack declares the tail missing, then `incomplete`.
- The anchor is just before the pack starts: the pack's `base_prev` must equal the anchor's head.
- The anchor is older than the pack, or falls in a missing range: it is noted or reported incomplete; nothing is verified against it.

Entries outside the verified range are listed as `unverifiable` (the note `unanchored_tail` says to save a newer anchor).

## Signature suites and profiles

A **suite** fixes the algorithm, its parameters and how the signed bytes are built. A **profile** names the suites a signed record must carry, all of them.

| Suite id | Algorithm | Public key | Signature |
| --- | --- | --- | --- |
| `geo-ed25519/1` | Ed25519 (RFC 8032) | 32 bytes | 64 bytes |
| `geo-ml-dsa-65/1` | ML-DSA-65 (FIPS 204, final), pure interface, empty context string | 1952 bytes | 3309 bytes |

| Profile id | Required suites |
| --- | --- |
| `geo-profile/classical/1` | `geo-ed25519/1` |
| `geo-profile/pq/1` | `geo-ml-dsa-65/1` |
| `geo-profile/hybrid/1` | both |

- **Classical (version 1) checkpoints** carry one hex Ed25519 signature `sig` over `"geo-checkpoint/1\n" || canonical bytes with sig empty`. Classical key events are signed over `"geo-keyevent/1\n" || canonical bytes with signatures removed and hash zeroed`. Their bytes are unchanged by the suite work.
- **Version 2 checkpoints** have `sig` empty, a `profile`, and `sigs`, one entry per suite. Each signature covers `"geo-suite-signature/1\n" || canonical bytes of a SuiteSignatureInput` (record type, the record's signature-free digest, profile, suite, algorithm and key). Binding the profile, suite and key into the signed bytes means a signature cannot be moved to another record, profile, suite or key, and a stripped or relabelled signature fails.
- A hybrid record with only one valid signature is not accepted as either single-suite profile.
- A suite or profile this verifier does not know is reported as not usable (a note, which leaves the history `unverifiable`), never as valid and not as invalid.
- `--require-profile classical|pq|hybrid` sets the **reader's own** requirement: only checkpoints and anchors carrying every suite of that profile are trusted, whatever the key log asked for. Others are `unverifiable`, not `invalid`.

## Verdicts

| State (`state` in `--json`) | Meaning |
| --- | --- |
| `verified_against_checkpoint` | The entries from the start of their unbroken chain up to the anchored sequence match the saved anchor byte for byte. Entries after the anchor are listed as unverifiable. |
| `unverifiable` | No anchor you supplied covers this history. A chain whose owner can rewrite it together with its hashes shows nothing on its own. |
| `incomplete` | The pack declares, or the ledger recorded, missing storage. What remains is still checked. |
| `invalid` | An edit, reorder, deletion, truncation, chain rewrite, wrong tenant, wrong key, bad signature or a signature from a key revoked at that log position was found. `invalid` wins over `incomplete`, which wins over `verified`. |

Finding codes in the report include `format`, `range`, `sequence`, `link`, `edited`, `tenant`, `key_log`, `wrong_key`, `signature`, `revoked_key`, `checkpoint_mismatch`, `anchor_mismatch`, `truncated`, `missing_range`, `missing_tail`, `recorded_gap`, `retention_removed`, `compromised_key`, `key_recovered`, `signature_profile`, `no_anchor`, `anchor_older`, `unanchored_tail` and `payload_unavailable`.

## What a verdict does not show

A match shows the record was not changed since the anchor. It does not show that:

- what was recorded is true (a sensor, tool or provider may have reported something wrong);
- everything that happened was recorded (an effect may have happened outside the record);
- an explanation (`inferred_explanation`) was the real reason;
- the signing keys belong to the person or organization you think they do. The verifier follows keys and anchors you give it; it does not establish who issued them;
- the signature algorithms and this implementation are free of flaws. The implementation has not been independently audited.

The report always repeats this in its `claim` field and in the last line of the text output.

## Command line

```
geo-verify PACK.json [--anchor ANCHOR.json]... [--require-profile classical|pq|hybrid] [--json]
```

| Exit code | Meaning |
| --- | --- |
| 0 | Verified against an anchor. |
| 1 | Invalid. |
| 2 | Incomplete. |
| 3 | Unverifiable (no usable anchor, or none that carries the signatures the required profile needs). |
| 64 | Bad usage, an unreadable file, or input that is not a valid pack or anchor. |

`--json` prints the report with these fields: `state`, `tenant`, `entries`, `anchors` (how many were usable), `verified` (`{from, to}` or null), `unverifiable` (ranges), `invalid`, `incomplete` and `notes` (lists of `{code, seq, detail}`), `unavailable_payloads`, `checkpoints_checked`, `key_events` and `claim`.

The verifier reads only the files you name. It does not use the network or any Geometer installation.

## Assessment certificates

`geo-verify assessment BUNDLE ...` checks an assessment bundle (a directory containing `bundle.json`, a `bundle.json` file, or a bare assessment). It reports each check apart and does not rerun the assessment:

`canonical_form`, `content_id`, `validation`, `signatures`, `subject_binding`, `rule_binding`, `evidence_digests`, `required_payloads`, `anchor_coverage`, `status` and `expiry`. Each is `passed`, `failed`, `limited` (checked, but something it needs is missing or unknown) or `not_checked` (you did not supply what it needs).

Trust comes only from you: keys given with `--trust-key` (a JSON file in the `AssessmentTrustedKey` format) and a key log given with `--key-log`. Keys, key logs and status that travel inside the bundle are hints; the verifier never trusts a key because the bundle names it. Evidence payload files listed in the bundle are read from the bundle directory and compared with the digest and size the assessment cites. Packs and anchors you supply with `--pack` and `--anchor` are used to check that cited ledger evidence is covered by an anchor.

The verdict has three separate axes: integrity (`verified_against_trusted_inputs`, `unsigned`, `unverifiable`, `invalid`), applicability (`current_for_declared_subject`, `superseded`, `invalidated`, `withdrawn`, `expired`, `status_unknown`) and the assessment's own outcome. An old bundle cannot say it was not withdrawn since; "current" needs status signed by a key you trust and younger than `--max-status-age` (default one day), or status you read from a source you control.

| Exit code | Meaning |
| --- | --- |
| 0 | Unchanged and signed with a key you trust (and all signatures the policy needs verify). |
| 1 | Changed, wrongly signed, a check you asked for failed, or not what you expected (`--expect-revision`, `--expect-rule ID=sha256:...`). |
| 2 | Only with `--require-current`: the integrity check passed but the assessment may no longer apply. |
| 3 | Unsigned, no key you trust, or (with `--require-profile`) not signed with every suite the profile needs. |
| 64 | Bad usage or unreadable input. |

Options: `--trust-key KEY.json`, `--key-log LOG`, `--status STATUS.json`, `--anchor ANCHOR.json`, `--pack PACK.json`, `--expect-revision sha256:...`, `--expect-rule ID=sha256:...`, `--max-status-age SECONDS`, `--now MILLISECONDS`, `--require-current`, `--require-profile classical|pq|hybrid`, `--json`. `--now` fixes the clock so a result can be reproduced.
