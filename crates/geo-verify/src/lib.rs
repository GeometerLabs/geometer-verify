//! Standalone evidence verifier.
//!
//! Input: an exported [`EvidencePack`] and zero or more trusted [`Anchor`]s
//! (signed checkpoints the person kept somewhere the store's owner cannot
//! rewrite). Output: a [`Report`] that labels the history it can vouch for and
//! the history it cannot.
//!
//! What a verdict means, stated once:
//!
//! - `verified_against_checkpoint`: the entries from the start of their
//!   unbroken chain up to the anchored sequence match the retained checkpoint
//!   byte for byte. Entries after the anchor are listed as unverifiable.
//! - `unverifiable`: nothing trusted covers this history. A hash chain the
//!   store's owner can rewrite together with its hashes proves nothing alone.
//! - `incomplete`: the pack declares (or the ledger recorded) missing storage;
//!   what remains is still checked.
//! - `invalid`: an edit, reorder, deletion, truncation, chain rewrite, wrong
//!   key, wrong tenant or a signature from a revoked key was detected.
//!
//! Integrity relative to an anchor is not truth: a valid chain does not show
//! that the sensors were honest, that interception was complete, that no
//! effect happened outside the record, or that an explanation was the real
//! reason. The derived views in a pack (actions, coverage) are ignored here.
//!
//! Assessment certificates are checked by
//! [`assessment::verify`]: canonical form, content id, validation, signatures
//! against keys the reader trusts, bindings, evidence digests, required
//! payloads, anchor coverage (through [`verify_pack`]), status and expiry,
//! each reported apart.
//!
//! This crate depends only on the contract records, sha2, ed25519 verification
//! and hex. Geometer's own ledger writer (part of the closed product) uses the
//! primitives below, so there is one definition of every hash and signed message;
//! the verifier is a separate binary with no host, database, runtime or network
//! code, not a second implementation.

pub mod assessment;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use geo_contracts::{
    Anchor, Canon, Checkpoint, Digest, EvidenceGap, EvidenceKind, EvidencePack, Id, IntegrityState, KeyEvent,
    KeyEventKind, LedgerEntry,
};
use sha2::Digest as _;
use std::collections::BTreeMap;

pub mod suite;

pub const PACK_FORMAT: &str = "geometer.evidence-pack";
pub const VERSION: u32 = 1;

// ------------------------------------------------------------ primitives

fn zero() -> Digest {
    Digest::parse(&format!("sha256:{}", "0".repeat(64))).expect("valid digest")
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Digest {
    Digest::of(&[domain, bytes].concat())
}

/// The hash of an entry: sha256 of `geo-ledger/1\n` and the canonical bytes
/// with `hash` replaced by 64 zero digits.
pub fn entry_hash(e: &LedgerEntry) -> Digest {
    let mut c = e.clone();
    c.hash = zero();
    domain_hash(b"geo-ledger/1\n", &c.encode())
}

/// The bytes a checkpoint signature covers.
pub fn checkpoint_message(c: &Checkpoint) -> Vec<u8> {
    let mut c = c.clone();
    c.sig = String::new();
    [b"geo-checkpoint/1\n".as_slice(), &c.encode()].concat()
}

fn key_event_body(k: &KeyEvent) -> Vec<u8> {
    let mut k = k.clone();
    k.sigs = vec![];
    k.hash = zero();
    k.encode()
}

/// The hash of a key event (its signatures are not part of it).
pub fn key_event_hash(k: &KeyEvent) -> Digest {
    domain_hash(b"geo-keylog/1\n", &key_event_body(k))
}

/// The bytes a key-event signature covers.
pub fn key_event_message(k: &KeyEvent) -> Vec<u8> {
    [b"geo-keyevent/1\n".as_slice(), &key_event_body(k)].concat()
}

/// A key's id: `key:` and the sha256 of its 32 public key bytes.
pub fn key_id_of(public_key_hex: &str) -> Result<Id, String> {
    let bytes = hex::decode(public_key_hex).map_err(|_| "public key is not hex".to_string())?;
    if bytes.len() != 32 {
        return Err("public key is not 32 bytes".into());
    }
    Id::new(format!("key:{}", hex::encode(sha2::Sha256::digest(&bytes)))).map_err(|e| e.to_string())
}

/// Verify a hex ed25519 signature.
pub fn verify_sig(public_key_hex: &str, message: &[u8], sig_hex: &str) -> bool {
    let (Ok(pk), Ok(sig)) = (hex::decode(public_key_hex), hex::decode(sig_hex)) else { return false };
    let Ok(pk) = <[u8; 32]>::try_from(pk.as_slice()) else { return false };
    let Ok(sig) = <[u8; 64]>::try_from(sig.as_slice()) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false };
    vk.verify(message, &Signature::from_bytes(&sig)).is_ok()
}

// ------------------------------------------------------------ report

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub code: String,
    pub seq: Option<u64>,
    pub detail: String,
}

impl Finding {
    fn new(code: &str, seq: Option<u64>, detail: impl Into<String>) -> Finding {
        Finding { code: code.into(), seq, detail: detail.into() }
    }
    fn json(&self) -> serde_json::Value {
        serde_json::json!({"code": self.code, "seq": self.seq, "detail": self.detail})
    }
}

#[derive(Debug, Clone)]
pub struct Report {
    pub state: IntegrityState,
    pub tenant: String,
    pub entries: u64,
    pub anchors: u32,
    /// The inclusive range of entries whose chain is tied to a matching anchor.
    pub verified: Option<(u64, u64)>,
    /// Entries this verifier cannot vouch for, as inclusive ranges.
    pub unverifiable: Vec<(u64, u64)>,
    pub invalid: Vec<Finding>,
    pub incomplete: Vec<Finding>,
    pub notes: Vec<Finding>,
    /// Sequence numbers of entries whose payload is deleted or redacted.
    pub unavailable_payloads: Vec<u64>,
    pub checkpoints_checked: u32,
    pub key_events: u64,
}

impl Report {
    pub fn to_json(&self) -> serde_json::Value {
        let list = |v: &[Finding]| v.iter().map(Finding::json).collect::<Vec<_>>();
        serde_json::json!({
            "state": self.state.as_str(), "tenant": self.tenant, "entries": self.entries, "anchors": self.anchors,
            "verified": self.verified.map(|(a, b)| serde_json::json!({"from": a, "to": b})),
            "unverifiable": self.unverifiable.iter().map(|(a, b)| serde_json::json!({"from": a, "to": b})).collect::<Vec<_>>(),
            "invalid": list(&self.invalid), "incomplete": list(&self.incomplete), "notes": list(&self.notes),
            "unavailable_payloads": self.unavailable_payloads,
            "checkpoints_checked": self.checkpoints_checked, "key_events": self.key_events,
            "claim": "Integrity relative to a trusted anchor only: not the truth of what was recorded, not that every action was recorded.",
        })
    }

    /// Plain text for a terminal.
    pub fn text(&self) -> String {
        let mut o = String::new();
        let head = match self.state {
            IntegrityState::VerifiedAgainstCheckpoint => "VERIFIED against your saved anchor",
            IntegrityState::Incomplete => "INCOMPLETE: some evidence is missing",
            IntegrityState::Unverifiable => "UNVERIFIABLE: no saved anchor covers this history",
            IntegrityState::Invalid => "INVALID: the evidence does not match",
        };
        o.push_str(&format!("{head}\ntenant {}, {} entries, {} anchor(s)\n", self.tenant, self.entries, self.anchors));
        if let Some((a, b)) = self.verified {
            o.push_str(&format!("verified: entries {a} to {b} match the anchor\n"));
        }
        for (a, b) in &self.unverifiable {
            o.push_str(&format!("unverifiable: entries {a} to {b} are not covered by a saved anchor\n"));
        }
        for (label, v) in [("invalid", &self.invalid), ("incomplete", &self.incomplete), ("note", &self.notes)] {
            for f in v {
                o.push_str(&format!(
                    "{label}: {}{}\n",
                    f.detail,
                    f.seq.map(|s| format!(" (entry {s})")).unwrap_or_default()
                ));
            }
        }
        if !self.unavailable_payloads.is_empty() {
            o.push_str(&format!("payloads no longer available for entries {:?}\n", self.unavailable_payloads));
        }
        o.push_str("A match shows the record was not changed since the anchor, not that it is true or complete.\n");
        o
    }

    /// Process exit code: 0 verified, 1 invalid, 2 incomplete, 3 unverifiable.
    pub fn exit_code(&self) -> i32 {
        match self.state {
            IntegrityState::VerifiedAgainstCheckpoint => 0,
            IntegrityState::Invalid => 1,
            IntegrityState::Incomplete => 2,
            IntegrityState::Unverifiable => 3,
        }
    }
}

// ------------------------------------------------------------ key log

#[derive(Debug, Clone)]
pub struct KeyState {
    pub public_key: String,
    pub introduced: u64,
    /// The key-log position of the revocation and whether the key was compromised.
    pub revoked: Option<(u64, bool)>,
    /// Introduced by `recover`: nothing in the log vouches for it.
    pub unchained: bool,
    /// The key's signature suite (`geo-ed25519/1` unless the event named one).
    pub suite: String,
}

#[derive(Debug, Default)]
pub struct KeyLog {
    pub keys: BTreeMap<String, KeyState>,
    pub hashes: BTreeMap<u64, Digest>,
    pub len: u64,
    pub problems: Vec<Finding>,
    pub unchained: Vec<u64>,
    /// Profile events: (key-log position, profile required from there on).
    pub profiles: Vec<(u64, String)>,
    /// The first event that uses a suite or profile this verifier does not
    /// support; the log is not checked past it (unknown, not invalid).
    pub unsupported_from: Option<u64>,
}

/// Check a key log's links, hashes and signatures and derive each key's state.
pub fn check_key_log(events: &[KeyEvent]) -> KeyLog {
    let mut log = KeyLog::default();
    let mut prev: Option<Digest> = None;
    for (i, e) in events.iter().enumerate() {
        let seq = i as u64 + 1;
        let bad = |log: &mut KeyLog, d: String| log.problems.push(Finding::new("key_log", Some(seq), d));
        if e.seq != seq {
            bad(&mut log, format!("key log event {seq} is out of order or missing"));
            return log;
        }
        if e.prev != prev {
            bad(&mut log, format!("key log event {seq} does not link to the one before it"));
            return log;
        }
        if key_event_hash(e) != e.hash {
            bad(&mut log, format!("key log event {seq} was edited"));
            return log;
        }
        // Each signature is checked under its signer's registered suite; an
        // ed25519 signer uses the original key-event message.
        let signed_by = |log: &KeyLog, k: &str, need_active: bool| -> bool {
            e.sigs.iter().any(|s| {
                s.key.as_str() == k
                    && log.keys.get(k).is_some_and(|st| {
                        (!need_active || st.revoked.is_none())
                            && suite::key_event_sig_ok(st, k, e, &s.sig) == suite::SigCheck::Valid
                    })
            })
        };
        // The suites covered by valid signatures of active keys other than `except`.
        let covered = |log: &KeyLog, except: Option<&str>| -> std::collections::BTreeSet<String> {
            e.sigs
                .iter()
                .filter(|s| Some(s.key.as_str()) != except && signed_by(log, s.key.as_str(), true))
                .filter_map(|s| log.keys.get(s.key.as_str()).map(|k| k.suite.clone()))
                .collect()
        };
        let in_force = suite::profile_at(&log, seq.saturating_sub(1)).to_string();
        let required: Vec<&str> = suite::profile_suites(&in_force).map(|v| v.to_vec()).unwrap_or_default();
        match e.kind {
            KeyEventKind::Genesis | KeyEventKind::Rotate | KeyEventKind::Recover => {
                let Some(pk) = &e.public_key else {
                    bad(&mut log, format!("key log event {seq} introduces a key without its public key"));
                    return log;
                };
                let key_suite = e.suite.as_ref().map_or(suite::ED25519, |s| s.as_str()).to_string();
                if suite::suite(&key_suite).is_none() {
                    log.unsupported_from = Some(seq);
                    return log;
                }
                match hex::decode(pk).map_err(|_| "not hex".to_string()).and_then(|b| suite::key_id(&key_suite, &b)) {
                    Ok(id) if id == e.key => {}
                    _ => {
                        bad(&mut log, format!("key log event {seq}: the key id is not the digest of the public key"));
                        return log;
                    }
                }
                if log.keys.contains_key(e.key.as_str()) {
                    bad(&mut log, format!("key log event {seq} introduces a key that already exists"));
                    return log;
                }
                let me = KeyState {
                    public_key: pk.clone(),
                    introduced: seq,
                    revoked: None,
                    unchained: e.kind == KeyEventKind::Recover,
                    suite: key_suite,
                };
                let self_sig = e.sigs.iter().any(|s| {
                    s.key == e.key && suite::key_event_sig_ok(&me, e.key.as_str(), e, &s.sig) == suite::SigCheck::Valid
                });
                let ok = match e.kind {
                    KeyEventKind::Genesis => seq == 1 && self_sig,
                    KeyEventKind::Recover => self_sig,
                    // Another active key signs, covering every suite the profile in force requires.
                    _ => {
                        let cov = covered(&log, Some(e.key.as_str()));
                        self_sig && !cov.is_empty() && required.iter().all(|r| cov.contains(*r))
                    }
                };
                if !ok {
                    bad(&mut log, format!("key log event {seq} ({}) is not signed as required", e.kind.as_str()));
                    return log;
                }
                if e.kind == KeyEventKind::Recover {
                    log.unchained.push(seq);
                }
                log.keys.insert(e.key.as_str().to_string(), me);
            }
            KeyEventKind::Revoke => {
                let Some(target) = &e.target else {
                    bad(&mut log, format!("key log event {seq} revokes nothing"));
                    return log;
                };
                let cov = covered(&log, Some(target.as_str()));
                let by_other_active = !cov.is_empty() && required.iter().all(|r| cov.contains(*r));
                if !log.keys.contains_key(target.as_str()) || !by_other_active {
                    bad(&mut log, format!("key log event {seq}: a revocation needs another active key's signature"));
                    return log;
                }
                if let Some(st) = log.keys.get_mut(target.as_str()) {
                    st.revoked.get_or_insert((seq, e.compromised));
                }
            }
            KeyEventKind::Profile => {
                let Some(next) = e.profile.as_ref().map(|p| p.as_str().to_string()) else {
                    bad(&mut log, format!("key log event {seq} sets no profile"));
                    return log;
                };
                let Some(next_needs) = suite::profile_suites(&next) else {
                    log.unsupported_from = Some(seq);
                    return log;
                };
                // Signed under both the profile in force and the new one: a weaker key alone cannot downgrade.
                let cov = covered(&log, None);
                if !required.iter().chain(next_needs.iter()).all(|r| cov.contains(*r)) {
                    bad(
                        &mut log,
                        format!(
                            "key log event {seq}: a profile change must be signed under the profile in force and the new one"
                        ),
                    );
                    return log;
                }
                log.profiles.push((seq, next));
            }
        }
        log.hashes.insert(seq, e.hash.clone());
        prev = Some(e.hash.clone());
        log.len = seq;
    }
    log
}

// ------------------------------------------------------------ pack

fn declared_gap(gaps: &[EvidenceGap], from: u64, to: u64) -> bool {
    gaps.iter().any(|g| {
        // `retention`: removed on purpose under the ledger's retention policy (and recorded as such).
        matches!(g.kind.as_str(), "missing_segment" | "missing_tail" | "retention")
            && g.from_seq <= from
            && g.to_seq.is_none_or(|t| t >= to)
    })
}

/// Verify a pack against zero or more trusted anchors. See the module
/// documentation for what each state means.
pub fn verify_pack(pack: &EvidencePack, anchors: &[Anchor]) -> Report {
    verify_pack_with(pack, anchors, &suite::Policy::any())
}

/// [`verify_pack`] under a verifier's own signature policy (for example
/// [`suite::Policy::profile`]`("hybrid")`): a checkpoint or anchor that does not
/// carry the suites the policy requires is not trusted (unverifiable, not
/// invalid). The default policy accepts what the key log requires.
pub fn verify_pack_with(pack: &EvidencePack, anchors: &[Anchor], policy: &suite::Policy) -> Report {
    let mut inv: Vec<Finding> = vec![];
    let mut inc: Vec<Finding> = vec![];
    let mut notes: Vec<Finding> = vec![];
    if pack.format != PACK_FORMAT || pack.v != VERSION {
        inv.push(Finding::new("format", None, format!("not a version {VERSION} {PACK_FORMAT}")));
    }

    // Key log.
    let kl = check_key_log(&pack.key_log);
    inv.extend(kl.problems.iter().cloned());
    for s in &kl.unchained {
        notes.push(Finding::new(
            "key_recovered",
            None,
            format!("the key log recovered after a lost key at event {s}: trust in the new key comes from an anchor, not from the log"),
        ));
    }

    // Entries: hashes, links, order.
    let n = pack.entries.len() as u64;
    let mut hashes: BTreeMap<u64, Digest> = BTreeMap::new();
    // Start of the unbroken run each entry belongs to.
    let mut run_start: BTreeMap<u64, u64> = BTreeMap::new();
    let mut expected = pack.from_seq;
    let mut prev_hash = pack.base_prev.clone();
    let mut prev_known = true;
    let mut cur_run = pack.from_seq;
    let mut unavailable: Vec<u64> = vec![];
    if pack.from_seq == 0 {
        inv.push(Finding::new("range", None, "sequences start at 1"));
    }
    if pack.from_seq == 1 && pack.base_prev.is_some() {
        inv.push(Finding::new("range", Some(1), "the first entry cannot have a predecessor"));
    }
    for e in &pack.entries {
        if e.tenant != pack.tenant {
            inv.push(Finding::new(
                "tenant",
                Some(e.seq),
                format!("entry belongs to tenant {}, not {}", e.tenant, pack.tenant),
            ));
        }
        if entry_hash(e) != e.hash {
            inv.push(Finding::new("edited", Some(e.seq), "the entry's contents do not match its hash: it was edited"));
        }
        if e.seq != expected {
            if e.seq > expected && declared_gap(&pack.gaps, expected, e.seq - 1) {
                inc.push(Finding::new(
                    "missing_range",
                    Some(expected),
                    format!("entries {expected} to {} are missing (storage loss declared in the pack)", e.seq - 1),
                ));
                prev_known = false;
                cur_run = e.seq;
            } else {
                inv.push(Finding::new(
                    "sequence",
                    Some(e.seq),
                    format!(
                        "expected entry {expected} but found {}: entries were deleted, repeated or reordered",
                        e.seq
                    ),
                ));
                prev_known = false;
                cur_run = e.seq;
            }
        }
        if prev_known {
            if e.prev != prev_hash {
                inv.push(Finding::new(
                    "link",
                    Some(e.seq),
                    "the entry does not link to the one before it: edit, reorder, deletion or rewrite",
                ));
                cur_run = e.seq;
            }
        } else if e.seq == 1 && e.prev.is_some() {
            inv.push(Finding::new("link", Some(1), "the first entry cannot have a predecessor"));
        }
        if e.kind == EvidenceKind::Gap {
            inc.push(Finding::new(
                "recorded_gap",
                Some(e.seq),
                format!("the ledger recorded a gap: {}", one_line(&e.body)),
            ));
        }
        if e.kind == EvidenceKind::Tombstone
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&e.body)
        {
            // One payload (`of_seq`) or several whose data key was destroyed (`of_seqs`).
            unavailable.extend(v.get("of_seq").and_then(|x| x.as_u64()));
            unavailable
                .extend(v.get("of_seqs").and_then(|x| x.as_array()).into_iter().flatten().filter_map(|x| x.as_u64()));
        }
        hashes.insert(e.seq, e.hash.clone());
        run_start.insert(e.seq, cur_run);
        prev_hash = Some(e.hash.clone());
        prev_known = true;
        expected = e.seq + 1;
    }
    let last = expected.saturating_sub(1);
    if n > 0 && pack.to_seq != last {
        if pack.to_seq > last && declared_gap(&pack.gaps, last + 1, pack.to_seq) {
            inc.push(Finding::new(
                "missing_tail",
                Some(last + 1),
                format!("entries {} to {} are missing (declared)", last + 1, pack.to_seq),
            ));
        } else {
            inv.push(Finding::new(
                "range",
                None,
                format!("the pack claims entries up to {} but ends at {last}", pack.to_seq),
            ));
        }
    }
    if n == 0 && pack.to_seq >= pack.from_seq && !declared_gap(&pack.gaps, pack.from_seq, pack.to_seq) {
        inv.push(Finding::new("range", None, "the pack claims entries but contains none"));
    }

    // History removed under a retention policy is declared, never silent: what it held cannot be checked.
    for g in pack.gaps.iter().filter(|g| g.kind == "retention") {
        inc.push(Finding::new(
            "retention_removed",
            Some(g.from_seq),
            format!(
                "entries {} to {} were removed under the retention policy and cannot be checked",
                g.from_seq,
                g.to_seq.map_or("the end".to_string(), |t| t.to_string())
            ),
        ));
    }

    // Checkpoints carried in the pack: signature, key state, agreement with the entries.
    let mut checked = 0u32;
    'checkpoints: for c in &pack.checkpoints {
        checked += 1;
        if c.tenant != pack.tenant {
            inv.push(Finding::new("tenant", Some(c.seq), "a checkpoint belongs to another tenant"));
            continue;
        }
        // Signatures under the suites the key log's profile requires; a classical checkpoint is checked as before.
        let signers = match suite::checkpoint_signers(&kl, c, None, policy) {
            Ok(s) => s,
            Err(r) => {
                if r.invalid {
                    inv.push(r.finding);
                } else {
                    notes.push(r.finding);
                }
                continue;
            }
        };
        for kid in &signers {
            let Some(k) = kl.keys.get(kid) else { continue };
            if let Some((rs, comp)) = k.revoked {
                if c.key_log_seq >= rs {
                    inv.push(Finding::new(
                        "revoked_key",
                        Some(c.seq),
                        "a checkpoint was signed after its key was revoked",
                    ));
                    continue 'checkpoints;
                }
                if comp {
                    let pinned = anchors.iter().any(|a| a.checkpoint == *c);
                    if !pinned {
                        notes.push(Finding::new(
                            "compromised_key",
                            Some(c.seq),
                            "a checkpoint is signed by a key later reported compromised and no saved anchor pins it: not trusted",
                        ));
                        continue 'checkpoints;
                    }
                }
            }
        }
        match hashes.get(&c.seq) {
            Some(h) if *h != c.head => inv.push(Finding::new(
                "checkpoint_mismatch",
                Some(c.seq),
                "a signed checkpoint disagrees with the entry it covers: the history changed after it was signed",
            )),
            None if c.seq > last && !declared_gap(&pack.gaps, last + 1, c.seq) => inv.push(Finding::new(
                "truncated",
                Some(c.seq),
                "a signed checkpoint proves entries that the pack does not have: the tail was cut",
            )),
            _ => {}
        }
    }

    // Anchors: the trust comes from these, not from anything inside the pack.
    let mut good_anchors: Vec<&Anchor> = vec![];
    'anchors: for a in anchors {
        let c = &a.checkpoint;
        if c.tenant != pack.tenant {
            inv.push(Finding::new(
                "tenant",
                Some(c.seq),
                format!("the anchor is for tenant {}, not {}", c.tenant, pack.tenant),
            ));
            continue;
        }
        if c.profile.is_none() {
            // A classical anchor: its own key, checked exactly as before.
            match key_id_of(&a.public_key) {
                Ok(id) if id == c.key => {}
                _ => {
                    inv.push(Finding::new(
                        "wrong_key",
                        Some(c.seq),
                        "the anchor's key id is not the digest of its public key",
                    ));
                    continue;
                }
            }
            if !verify_sig(&a.public_key, &checkpoint_message(c), &c.sig) {
                inv.push(Finding::new("signature", Some(c.seq), "the anchor's signature does not verify"));
                continue;
            }
            match kl.keys.get(c.key.as_str()) {
                None => {
                    inv.push(Finding::new(
                        "wrong_key",
                        Some(c.seq),
                        "the anchor's key is not in the pack's key log (a wrong key or a rewritten key log)",
                    ));
                    continue;
                }
                Some(k) if k.public_key != a.public_key => {
                    inv.push(Finding::new(
                        "wrong_key",
                        Some(c.seq),
                        "the key log holds a different key under the anchor's key id",
                    ));
                    continue;
                }
                Some(_) => {}
            }
        }
        // The suites the key log's profile requires, each signature checked with the anchor's own copy of its key.
        let signers = match suite::checkpoint_signers(&kl, c, Some(a), policy) {
            Ok(s) => s,
            Err(r) => {
                if r.invalid {
                    inv.push(r.finding);
                } else {
                    notes.push(r.finding);
                }
                continue;
            }
        };
        for kid in &signers {
            let Some(k) = kl.keys.get(kid) else { continue };
            if let Some((rs, comp)) = k.revoked {
                if c.key_log_seq >= rs {
                    inv.push(Finding::new(
                        "revoked_key",
                        Some(c.seq),
                        "the anchor was signed after its key was revoked",
                    ));
                    continue 'anchors;
                }
                if comp {
                    notes.push(Finding::new(
                        "compromised_key",
                        Some(c.seq),
                        "the anchor's key was later reported compromised: trust in this anchor rests on your having kept your own copy",
                    ));
                }
            }
        }
        if let Some(h) = &a.key_log_head {
            match kl.hashes.get(&c.key_log_seq) {
                Some(kh) if kh == h => {}
                _ => {
                    inv.push(Finding::new(
                        "key_log",
                        Some(c.seq),
                        "the key log differs from the one the anchor saw (rewritten or cut)",
                    ));
                    continue;
                }
            }
        }
        if let Some(p) = &c.profile {
            notes.push(Finding::new(
                "signature_profile",
                Some(c.seq),
                format!(
                    "the anchor is signed under {p}: {}",
                    suite::profile_suites(p.as_str()).map(|v| v.join(" and ")).unwrap_or_default()
                ),
            ));
        }
        good_anchors.push(a);
    }

    // Tie the chain to the anchors.
    let mut verified: Option<(u64, u64)> = None;
    for a in &good_anchors {
        let c = &a.checkpoint;
        if let Some(h) = hashes.get(&c.seq) {
            if *h != c.head {
                inv.push(Finding::new(
                    "anchor_mismatch",
                    Some(c.seq),
                    "the history differs from your saved anchor: an edit, deletion or a rewritten chain",
                ));
            } else {
                let start = run_start.get(&c.seq).copied().unwrap_or(c.seq);
                verified = Some(match verified {
                    Some((s, e)) if s == start || e >= c.seq => (s.min(start), e.max(c.seq)),
                    Some((s, e)) if e > c.seq => (s, e),
                    _ => (start, c.seq),
                });
            }
        } else if c.seq > last {
            if declared_gap(&pack.gaps, last + 1, c.seq) {
                inc.push(Finding::new(
                    "missing_tail",
                    Some(c.seq),
                    "your saved anchor is past the end of the pack, which declares the tail missing",
                ));
            } else {
                inv.push(Finding::new(
                    "truncated",
                    Some(c.seq),
                    format!("your saved anchor is at entry {} but the pack ends at {last}: the tail was cut", c.seq),
                ));
            }
        } else if pack.from_seq > 0 && c.seq + 1 == pack.from_seq {
            if pack.base_prev.as_ref() != Some(&c.head) {
                inv.push(Finding::new(
                    "anchor_mismatch",
                    Some(c.seq),
                    "the pack does not continue from your saved anchor",
                ));
            }
        } else if c.seq >= pack.from_seq {
            inc.push(Finding::new(
                "missing_range",
                Some(c.seq),
                "your saved anchor falls in a missing range: nothing here can be checked against it",
            ));
        } else {
            notes.push(Finding::new(
                "anchor_older",
                Some(c.seq),
                "your saved anchor is older than the start of this pack: nothing connects them",
            ));
        }
    }
    if good_anchors.is_empty() {
        notes.push(Finding::new(
            "no_anchor",
            None,
            if anchors.is_empty() {
                "no saved anchor was given: an isolated chain can be rewritten with its hashes, so nothing is verified"
            } else {
                "none of the given anchors could be used"
            },
        ));
    }

    // Unverifiable: every entry outside the verified range.
    let mut unverifiable: Vec<(u64, u64)> = vec![];
    for e in &pack.entries {
        let covered = verified.is_some_and(|(s, t)| e.seq >= s && e.seq <= t);
        if !covered {
            match unverifiable.last_mut() {
                Some(r) if r.1 + 1 == e.seq => r.1 = e.seq,
                _ => unverifiable.push((e.seq, e.seq)),
            }
        }
    }
    if verified.is_some() && !unverifiable.is_empty() {
        notes.push(Finding::new(
            "unanchored_tail",
            None,
            "entries outside the verified range are not covered by a saved anchor: unverifiable until you save a newer one",
        ));
    }
    unavailable.sort_unstable();
    unavailable.dedup();
    if !unavailable.is_empty() {
        notes.push(Finding::new(
            "payload_unavailable",
            None,
            "some payloads were deleted or redacted; the entries stay verifiable but any replay that needed them is reduced",
        ));
    }
    let state = if !inv.is_empty() {
        IntegrityState::Invalid
    } else if !inc.is_empty() {
        IntegrityState::Incomplete
    } else if verified.is_some() {
        IntegrityState::VerifiedAgainstCheckpoint
    } else {
        IntegrityState::Unverifiable
    };
    Report {
        state,
        tenant: pack.tenant.to_string(),
        entries: n,
        anchors: good_anchors.len() as u32,
        verified,
        unverifiable,
        invalid: inv,
        incomplete: inc,
        notes,
        unavailable_payloads: unavailable,
        checkpoints_checked: checked,
        key_events: pack.key_log.len() as u64,
    }
}

fn one_line(s: &str) -> String {
    let t: String = s.chars().take(160).collect();
    t.replace('\n', " ")
}

/// Decode a pack and anchors from their canonical or pretty JSON bytes and verify.
pub fn verify_bytes(pack: &[u8], anchors: &[Vec<u8>]) -> Result<Report, String> {
    verify_bytes_with(pack, anchors, &suite::Policy::any())
}

/// [`verify_bytes`] under a verifier's own signature policy (see [`verify_pack_with`]).
pub fn verify_bytes_with(pack: &[u8], anchors: &[Vec<u8>], policy: &suite::Policy) -> Result<Report, String> {
    let pack = EvidencePack::decode(pack).map_err(|e| format!("not an evidence pack: {e}"))?;
    let mut a = vec![];
    for (i, b) in anchors.iter().enumerate() {
        a.push(Anchor::decode(b).map_err(|e| format!("anchor {}: not an anchor file: {e}", i + 1))?);
    }
    Ok(verify_pack_with(&pack, &a, policy))
}
