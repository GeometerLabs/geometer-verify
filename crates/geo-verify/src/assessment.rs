//! Assessment verification.
//!
//! Input: an [`AssessmentBundle`] (or a bare [`SystemAssessment`]), the bytes
//! of the payload files it includes, the reader's [`AssessmentTrustPolicy`],
//! optionally a status report and anchors the reader supplies, and what the
//! reader expects the assessment to be about. Output: an
//! [`AssessmentVerification`] with every check reported apart and the three
//! axes kept apart in its [`AssessmentStanding`].
//!
//! What this does and does not do, stated once:
//!
//! - It checks bytes, signatures and bindings. It never reruns the
//!   assessment, and it does not judge whether a finding is true.
//! - Trust comes only from the reader: the keys in the policy, the key log in
//!   the policy (rotation from a trusted key is followed through it, and a
//!   revocation in it is applied) and anchors the reader supplies. Keys, key
//!   logs and status that travel inside the bundle are hints; a key the
//!   bundle names is never trusted because the bundle names it.
//! - Signing time is the issuer's own claim (`issued_ms`); a key log orders
//!   events but does not date a signature.
//! - Applicability is "current" only with status signed by a trusted key
//!   that is younger than the policy's maximum age, or status from a source
//!   the reader reads directly (its own store). An old bundle cannot assert
//!   that it was not withdrawn since.
//! - Suites are dispatched in one function, [`verify_suite`], so a new suite
//!   (for example the post-quantum suite of C4) is one more arm; a suite this
//!   verifier does not know is reported unverifiable, never accepted.
//!
//! No network, no store, no host: the caller reads files and passes bytes.

use crate::{check_key_log, entry_hash, verify_pack};
use ed25519_dalek::{Signature, VerifyingKey};
use geo_contracts::assessment::{self as a, BindingKind, Expected};
use geo_contracts::*;
use sha2::Digest as _;
use std::collections::{BTreeMap, BTreeSet};

/// The verifier's name and version, recorded in every result.
pub const VERIFIER: &str = concat!("geo-verify ", env!("CARGO_PKG_VERSION"));
/// Format version of the verification record.
pub const VERIFICATION_VERSION: u32 = 1;
/// Status younger than this counts as current when the reader states no
/// maximum age of its own (one day).
pub const DEFAULT_MAX_STATUS_AGE_MS: u64 = 24 * 60 * 60 * 1000;

// ------------------------------------------------------------ suites

/// What checking one signature with one suite found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuiteCheck {
    Valid,
    Invalid(String),
    /// This verifier does not implement the suite (or the algorithm it names).
    Unsupported,
}

/// Verify one signature under one suite. The only place suites are
/// dispatched: add a suite here.
pub fn verify_suite(suite: &str, algorithm: &str, public_key: &[u8], message: &[u8], signature: &[u8]) -> SuiteCheck {
    match (suite, algorithm) {
        (a::SUITE_ED25519, a::ALG_ED25519) => {
            let Ok(pk) = <[u8; 32]>::try_from(public_key) else {
                return SuiteCheck::Invalid("the public key is not 32 bytes".into());
            };
            let Ok(sig) = <[u8; 64]>::try_from(signature) else {
                return SuiteCheck::Invalid("the signature is not 64 bytes".into());
            };
            let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
                return SuiteCheck::Invalid("the public key is not a valid ed25519 key".into());
            };
            match vk.verify_strict(message, &Signature::from_bytes(&sig)) {
                Ok(()) => SuiteCheck::Valid,
                Err(_) => SuiteCheck::Invalid("the signature does not verify".into()),
            }
        }
        // C4: ML-DSA-65, FIPS 204, pure interface with the suite's empty context.
        (crate::suite::ML_DSA_65, "ml-dsa-65") => {
            match crate::suite::verify(crate::suite::ML_DSA_65, public_key, message, signature) {
                crate::suite::SigCheck::Valid => SuiteCheck::Valid,
                crate::suite::SigCheck::Invalid(why) => SuiteCheck::Invalid(why),
                crate::suite::SigCheck::Unsupported(_) => SuiteCheck::Unsupported,
            }
        }
        _ => SuiteCheck::Unsupported,
    }
}

/// `key:` and the sha256 of a raw public key (the key log's key ids).
pub fn key_id_of_bytes(public_key: &[u8]) -> Id {
    Id::new(format!("key:{}", hex::encode(sha2::Sha256::digest(public_key)))).expect("hex key id is valid")
}

// ------------------------------------------------------------ time

/// `2026-09-29 14:02 UTC` from milliseconds since the epoch.
pub fn fmt_utc(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", rem / 3600, (rem % 3600) / 60)
}

// ------------------------------------------------------------ inputs

/// Status the reader hands the verifier, and how far the reader trusts its
/// source. `direct`: the reader read it from a store it controls (its own
/// Geometer home), so the snapshot's own time counts; otherwise only a
/// signed statement can show that it is recent.
#[derive(Debug, Clone)]
pub struct StatusInput {
    pub report: AssessmentStatusReport,
    pub source: String,
    pub direct: bool,
}

/// Everything one verification needs. `files` maps a bundle path to the bytes
/// read from it (`None`: listed but could not be read).
pub struct Inputs<'a> {
    pub bundle: &'a AssessmentBundle,
    pub files: &'a BTreeMap<String, Option<Vec<u8>>>,
    pub policy: &'a AssessmentTrustPolicy,
    pub status: Option<&'a StatusInput>,
    pub anchors: &'a [Anchor],
    /// Evidence packs the reader supplies (for example from `geo prove
    /// export`) to tie cited ledger entries to its anchors.
    pub packs: &'a [EvidencePack],
    pub expected: Option<&'a Expected>,
    pub now_ms: u64,
}

/// A bundle path is relative, inside the bundle and plain: no `..`, no
/// absolute path, no drive or scheme.
pub fn safe_path(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !p.starts_with('\\')
        && !p.contains(':')
        && !p.contains('\\')
        && p.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

// ------------------------------------------------------------ trust

#[derive(Debug, Clone)]
struct TrustedKey {
    public_key: Vec<u8>,
    suite: String,
    algorithm: String,
    label: String,
    /// When and whether it was revoked, from the reader's key log: (time, compromised).
    revoked: Option<(u64, bool)>,
}

struct Trust {
    keys: BTreeMap<String, TrustedKey>,
    /// Revocations of keys the reader does not trust (for messages).
    revoked_other: BTreeMap<String, (u64, bool)>,
    key_log_used: bool,
    notes: Vec<String>,
    problems: Vec<String>,
}

fn trust_of(p: &AssessmentTrustPolicy) -> Trust {
    let mut t = Trust {
        keys: BTreeMap::new(),
        revoked_other: BTreeMap::new(),
        key_log_used: false,
        notes: vec![],
        problems: vec![],
    };
    for k in &p.keys {
        if key_id_of_bytes(&k.public_key.0) != k.key {
            t.problems.push(format!(
                "the key you supplied as {} does not have that id: its public key digests to {}; it is not used",
                k.key,
                key_id_of_bytes(&k.public_key.0)
            ));
            continue;
        }
        t.keys.insert(
            k.key.to_string(),
            TrustedKey {
                public_key: k.public_key.0.clone(),
                suite: k.suite.to_string(),
                algorithm: k.algorithm.to_string(),
                label: k.label.clone(),
                revoked: None,
            },
        );
    }
    if p.key_log.is_empty() {
        return t;
    }
    let log = check_key_log(&p.key_log);
    if let Some(problem) = log.problems.first() {
        t.problems.push(format!("the key log you supplied is damaged and was not used: {}", problem.detail));
        return t;
    }
    t.key_log_used = true;
    // Follow the log in order: a key introduced by rotation is trusted when a
    // key trusted at that point signed the rotation; a recovered key is
    // vouched for by nothing in the log.
    for e in &p.key_log {
        match e.kind {
            KeyEventKind::Rotate => {
                let by: Vec<String> = e
                    .sigs
                    .iter()
                    .filter(|s| s.key != e.key && t.keys.get(s.key.as_str()).is_some_and(|k| k.revoked.is_none()))
                    .map(|s| s.key.to_string())
                    .collect();
                if let (Some(from), Some(pk)) = (by.first(), e.public_key.as_ref())
                    && let Ok(bytes) = hex::decode(pk)
                    && !t.keys.contains_key(e.key.as_str())
                {
                    t.notes.push(format!(
                        "key {} is trusted because key {from}, which you trust, rotated to it (key log event {})",
                        e.key, e.seq
                    ));
                    t.keys.insert(
                        e.key.to_string(),
                        TrustedKey {
                            public_key: bytes,
                            // The key log records each key's suite (C4); absent means ed25519.
                            suite: e.suite.as_ref().map_or(a::SUITE_ED25519, |s| s.as_str()).into(),
                            algorithm: crate::suite::suite(e.suite.as_ref().map_or(a::SUITE_ED25519, |s| s.as_str()))
                                .map_or("unknown", |s| s.algorithm)
                                .into(),
                            label: format!("rotated from {from}"),
                            revoked: None,
                        },
                    );
                }
            }
            KeyEventKind::Recover => t.notes.push(format!(
                "key {} was introduced after a lost key (key log event {}); nothing in the log vouches for it, so it is not trusted through the log",
                e.key, e.seq
            )),
            KeyEventKind::Revoke => {
                if let Some(target) = &e.target {
                    let r = (e.at_ms, e.compromised);
                    match t.keys.get_mut(target.as_str()) {
                        Some(k) => {
                            k.revoked.get_or_insert(r);
                        }
                        None => {
                            t.revoked_other.entry(target.to_string()).or_insert(r);
                        }
                    }
                }
            }
            // A profile event (C4) changes which signatures checkpoints need; it introduces and revokes no key.
            KeyEventKind::Genesis | KeyEventKind::Profile => {}
        }
    }
    t
}

// ------------------------------------------------------------ result

struct Builder {
    checks: Vec<AssessmentCheck>,
}

impl Builder {
    fn add(&mut self, check: AssessmentCheckKind, result: AssessmentCheckResult, details: Vec<String>) {
        self.checks.push(AssessmentCheck { check, result, details });
    }
    fn result(&self, k: AssessmentCheckKind) -> AssessmentCheckResult {
        self.checks.iter().find(|c| c.check == k).map(|c| c.result).unwrap_or(AssessmentCheckResult::NotChecked)
    }
    fn failed(&self, k: AssessmentCheckKind) -> bool {
        self.result(k) == AssessmentCheckResult::Failed
    }
}

fn plain_outcome(o: AssessmentOutcome) -> &'static str {
    match o {
        AssessmentOutcome::ViolationFound => "a rule was broken in at least one run",
        AssessmentOutcome::NoViolationObservedWithinScope => {
            "no rule was seen broken within the stated limits (this is not proof that none can be)"
        }
        AssessmentOutcome::UnknownOrIncomplete => {
            "the result is incomplete: some required rules or evidence are unknown"
        }
        AssessmentOutcome::NotExercised => "the rules were not exercised",
        AssessmentOutcome::ProvedForDeclaredModel => {
            "proved for the declared formal model only, not for the running system"
        }
    }
}

/// Verify an assessment. Never fails: everything it cannot establish is a
/// check result. The signatures the record itself requires are checked; see
/// [`verify_with`] for a reader who requires a profile of their own.
pub fn verify(i: &Inputs) -> AssessmentVerification {
    verify_with(i, &crate::suite::Policy::any())
}

/// [`verify`] under the reader's own signature policy (for example
/// [`crate::suite::Policy::profile`]`("hybrid")`): every suite the policy
/// requires must carry a valid signature by a key the reader trusts, whatever
/// the record says it needs. A record that does not is not trusted
/// (unverifiable, exit code 3), not invalid: a classical report is not a
/// forgery, it is only weaker than the reader asked for.
pub fn verify_with(i: &Inputs, require: &crate::suite::Policy) -> AssessmentVerification {
    use AssessmentCheckKind as K;
    use AssessmentCheckResult as R;
    let sa = &i.bundle.assessment;
    let m = &sa.manifest;
    let id = &sa.id;
    let mut b = Builder { checks: vec![] };
    let mut limits: Vec<String> = vec![
        "Verification checks that the record is unchanged, who signed it and what it is about. It does not rerun the assessment and does not show that its findings are true.".into(),
        format!(
            "The issue time ({}) is the issuer's own statement; a signature does not prove when it was made.",
            fmt_utc(m.issued_ms)
        ),
    ];

    // Canonical form: the caller decoded the bundle strictly (unknown fields,
    // types, digests and the schema version are refused before this point).
    let canonical = sa.encode();
    match SystemAssessment::decode(&canonical) {
        Ok(back) if back.encode() == canonical => b.add(
            K::CanonicalForm,
            R::Passed,
            vec![format!("the record decodes strictly as {} and re-encodes to the same bytes", a::SCHEMA)],
        ),
        _ => b.add(K::CanonicalForm, R::Failed, vec!["the record does not re-encode to the same bytes".into()]),
    }
    if i.bundle.format != a::BUNDLE_FORMAT || i.bundle.v != a::BUNDLE_VERSION {
        b.add(
            K::CanonicalForm,
            R::Failed,
            vec![format!(
                "not a version {} {} (found {} {})",
                a::BUNDLE_VERSION,
                a::BUNDLE_FORMAT,
                i.bundle.format,
                i.bundle.v
            )],
        );
    }

    // Content id.
    let expected_id = a::assessment_id(m);
    if *id == expected_id {
        b.add(K::ContentId, R::Passed, vec![format!("the id {id} is the manifest's content id")]);
    } else {
        b.add(
            K::ContentId,
            R::Failed,
            vec![format!("the id is {id} but the manifest's content is {expected_id}: the manifest was changed after its id was made")],
        );
    }

    // Validation (the id problem is reported above).
    let problems: Vec<String> =
        a::problems(sa).into_iter().filter(|p| p.code != a::Code::IdMismatch).map(|p| p.to_string()).collect();
    if problems.is_empty() {
        b.add(
            K::Validation,
            R::Passed,
            vec!["the manifest is well formed: proof only from a formal model, the summary is no better than its required rules and evidence allow, every reference resolves".into()],
        );
    } else {
        b.add(K::Validation, R::Failed, problems);
    }

    // Signatures.
    let trust = trust_of(i.policy);
    let Sigs {
        result: sig_result,
        details: sig_details,
        used: used_keys,
        any_valid,
        missing: required_missing,
        invalid: sig_invalid,
        reader_unmet,
    } = signatures(i, &trust, require);
    b.add(K::Signatures, sig_result, sig_details);
    if !trust.key_log_used {
        limits.push(
            "Key revocation was not checked: you did not supply the issuer's key log. A key revoked since would not show here.".into(),
        );
    } else if let Some(t) = i.policy.key_log_as_of_ms {
        limits.push(format!("Key revocation was checked against the key log you supplied, as of {}.", fmt_utc(t)));
    }

    // Bindings.
    let mut binding_mismatch = false;
    match i.expected {
        None => {
            b.add(
                K::SubjectBinding,
                R::NotChecked,
                vec!["you did not say which code, configuration or environment to compare with".into()],
            );
            b.add(K::RuleBinding, R::NotChecked, vec!["you did not say which rules to compare with".into()]);
        }
        Some(x) => {
            let mm = a::check_bindings(m, x);
            let describe = |w: &a::BindingMismatch| {
                format!(
                    "{}{}: expected {}, the assessment has {}",
                    w.binding.as_str(),
                    if w.name.is_empty() { String::new() } else { format!(" {}", w.name) },
                    w.expected.as_ref().map(|d| d.to_string()).unwrap_or_else(|| "nothing".into()),
                    w.found.as_ref().map(|d| d.to_string()).unwrap_or_else(|| "nothing".into())
                )
            };
            let subject: Vec<String> = mm
                .iter()
                .filter(|w| {
                    matches!(
                        w.binding,
                        BindingKind::Revision
                            | BindingKind::Build
                            | BindingKind::Environment
                            | BindingKind::Config
                            | BindingKind::Dependency
                    )
                })
                .map(describe)
                .collect();
            let rules: Vec<String> = mm.iter().filter(|w| w.binding == BindingKind::Rule).map(describe).collect();
            let evidence: Vec<String> =
                mm.iter().filter(|w| w.binding == BindingKind::Evidence).map(describe).collect();
            let asked_subject = x.revision.is_some()
                || x.build.is_some()
                || x.environment.is_some()
                || !x.config.is_empty()
                || !x.dependencies.is_empty();
            match (asked_subject, subject.is_empty()) {
                (false, _) => b.add(K::SubjectBinding, R::NotChecked, vec!["no subject to compare with".into()]),
                (true, true) => b.add(K::SubjectBinding, R::Passed, vec!["the subject is the one you expected".into()]),
                (true, false) => {
                    binding_mismatch = true;
                    b.add(K::SubjectBinding, R::Failed, subject)
                }
            }
            match (x.rules.is_empty(), rules.is_empty()) {
                (true, _) => b.add(K::RuleBinding, R::NotChecked, vec!["no rules to compare with".into()]),
                (false, true) => b.add(K::RuleBinding, R::Passed, vec!["the rules are the ones you expected".into()]),
                (false, false) => {
                    binding_mismatch = true;
                    b.add(K::RuleBinding, R::Failed, rules)
                }
            }
            if !evidence.is_empty() {
                b.add(K::EvidenceDigests, R::Failed, evidence);
            }
        }
    }

    // Evidence digests and required payloads.
    let (digest_result, digest_details, available) = evidence(i);
    if b.result(K::EvidenceDigests) != R::Failed {
        b.add(K::EvidenceDigests, digest_result, digest_details);
    }
    let (req_result, req_details) = required(i, &available);
    b.add(K::RequiredPayloads, req_result, req_details);

    // Anchor coverage.
    let (anchor_result, anchor_details, anchors_used) = anchors(i, &available);
    b.add(K::AnchorCoverage, anchor_result, anchor_details);

    // Status.
    let st = status(i, &trust);
    b.add(K::Status, st.result, st.details.clone());
    if let Some(l) = &st.limit {
        limits.push(l.clone());
    }

    // Expiry.
    let expired = m.claim.expires_ms.is_some_and(|e| i.now_ms > e);
    match m.claim.expires_ms {
        None => b.add(
            K::Expiry,
            R::Passed,
            vec!["the claim declares no expiry (that is not a promise that it never goes stale)".into()],
        ),
        Some(e) if expired => b.add(K::Expiry, R::Failed, vec![format!("the claim expired on {}", fmt_utc(e))]),
        Some(e) => b.add(K::Expiry, R::Passed, vec![format!("the claim expires on {}", fmt_utc(e))]),
    }

    // The three axes, apart.
    let integrity = if b.failed(K::CanonicalForm)
        || b.failed(K::ContentId)
        || b.failed(K::Validation)
        || sig_invalid
        || required_missing
        || b.failed(K::EvidenceDigests)
        || b.failed(K::AnchorCoverage)
    {
        AssessmentIntegrity::Invalid
    } else if sa.signatures.is_empty() && m.verification.required_suites.is_empty() {
        AssessmentIntegrity::Unsigned
    } else if sig_result == R::Passed && any_valid {
        AssessmentIntegrity::VerifiedAgainstTrustedInputs
    } else {
        AssessmentIntegrity::Unverifiable
    };
    let applicability = if st.withdrawn {
        AssessmentApplicability::Withdrawn
    } else if st.invalidated || binding_mismatch {
        AssessmentApplicability::Invalidated
    } else if st.superseded {
        AssessmentApplicability::Superseded
    } else if expired {
        AssessmentApplicability::Expired
    } else if st.current {
        AssessmentApplicability::CurrentForDeclaredSubject
    } else {
        AssessmentApplicability::StatusUnknown
    };

    let mut reasons = vec![format!("What it found: {}.", plain_outcome(m.summary.outcome))];
    reasons.push(match integrity {
        AssessmentIntegrity::VerifiedAgainstTrustedInputs => format!(
            "Unchanged since it was signed: it was signed with {}, which you chose to trust. Trusting a key is your decision; it does not make the issuer independent.",
            used_keys
                .iter()
                .map(|k| match trust.keys.get(k.as_str()) {
                    Some(t) if !t.label.is_empty() => format!("{k} ({})", t.label),
                    _ => k.to_string(),
                })
                .collect::<Vec<_>>()
                .join(", ")
        ),
        AssessmentIntegrity::Unsigned => {
            "Not signed: nothing shows who made it or that it is unchanged beyond its content id.".into()
        }
        AssessmentIntegrity::Unverifiable => {
            "Cannot tell whether it is unchanged since it was signed: no signature it requires was made with a key you trust (or the suite is not supported here).".into()
        }
        AssessmentIntegrity::Invalid => "Changed or wrongly signed: see the checks that failed.".into(),
    });
    reasons.push(match applicability {
        AssessmentApplicability::CurrentForDeclaredSubject => {
            format!("Still applies to what it was made for, as of {}.", st.as_of.map(fmt_utc).unwrap_or_default())
        }
        AssessmentApplicability::Superseded => "Replaced by a newer assessment.".into(),
        AssessmentApplicability::Invalidated => {
            "No longer applies: the code, settings or rules it was made for have changed.".into()
        }
        AssessmentApplicability::Withdrawn => "Withdrawn by its issuer.".into(),
        AssessmentApplicability::Expired => "Past its expiry.".into(),
        AssessmentApplicability::StatusUnknown => {
            "Unknown whether it still applies: no recent status from a source you trust.".into()
        }
    });
    if !reader_unmet.is_empty() {
        reasons.push(format!(
            "You require the {} signature profile, and this report has no valid {} signature by a key you trust, so it is not trusted under your policy.",
            require.name,
            reader_unmet.join(" or ")
        ));
    }
    reasons.extend(trust.problems.iter().cloned());
    reasons.extend(trust.notes.iter().cloned());

    AssessmentVerification {
        v: VERIFICATION_VERSION,
        assessment: id.clone(),
        standing: AssessmentStanding {
            assessment: id.clone(),
            outcome: m.summary.outcome,
            integrity,
            applicability,
            checked_ms: i.now_ms,
            status_as_of_ms: st.as_of,
            trust_policy: Some(i.policy.id.clone()),
            reasons,
        },
        checks: b.checks,
        trusted_keys: used_keys,
        status_source: st.source,
        anchors: anchors_used,
        verifier: VERIFIER.into(),
        limits,
    }
}

/// What checking the signatures found.
struct Sigs {
    result: AssessmentCheckResult,
    details: Vec<String>,
    /// Keys that verified.
    used: Vec<Id>,
    /// Any trusted signature is valid.
    any_valid: bool,
    /// A suite the record requires has no signature at all.
    missing: bool,
    /// A trusted signature failed.
    invalid: bool,
    /// Suites the reader's own policy requires that no trusted signature covers.
    reader_unmet: Vec<String>,
}

fn signatures(i: &Inputs, trust: &Trust, require: &crate::suite::Policy) -> Sigs {
    use AssessmentCheckResult as R;
    let sa = &i.bundle.assessment;
    let m = &sa.manifest;
    let mut details = vec![];
    let mut valid_suites: BTreeSet<String> = BTreeSet::new();
    let mut used: Vec<Id> = vec![];
    let mut invalid = false;
    for (n, s) in sa.signatures.iter().enumerate() {
        let n = n + 1;
        let msg = a::signature_message(&sa.id, s);
        let Some(k) = trust.keys.get(s.key.as_str()) else {
            let revoked = trust
                .revoked_other
                .get(s.key.as_str())
                .map(|(t, c)| {
                    format!(
                        " (the key log shows it {} on {})",
                        if *c { "reported compromised" } else { "revoked" },
                        fmt_utc(*t)
                    )
                })
                .unwrap_or_default();
            details.push(format!(
                "signature {n} ({}) is by key {}, which you have not chosen to trust{revoked}; it is not used",
                s.suite, s.key
            ));
            continue;
        };
        if k.suite != s.suite.as_str() || k.algorithm != s.algorithm.as_str() {
            invalid = true;
            details.push(format!(
                "signature {n} claims suite {} ({}) but the key you trust is for {} ({}): refused",
                s.suite, s.algorithm, k.suite, k.algorithm
            ));
            continue;
        }
        match verify_suite(s.suite.as_str(), s.algorithm.as_str(), &k.public_key, &msg, &s.signature.0) {
            SuiteCheck::Valid => match k.revoked {
                Some((at, true)) => {
                    invalid = true;
                    details.push(format!(
                        "signature {n} verifies, but key {} was reported compromised on {}: anyone may have made it",
                        s.key,
                        fmt_utc(at)
                    ));
                }
                Some((at, false)) if m.issued_ms >= at => {
                    invalid = true;
                    details.push(format!(
                        "signature {n} is by key {}, which was retired on {}, before the stated issue time {}",
                        s.key,
                        fmt_utc(at),
                        fmt_utc(m.issued_ms)
                    ));
                }
                Some((at, false)) => {
                    details.push(format!(
                        "signature {n} ({}) verifies with key {}; that key was retired later, on {} (the issue time before it is the issuer's own statement)",
                        s.suite,
                        s.key,
                        fmt_utc(at)
                    ));
                    valid_suites.insert(s.suite.to_string());
                    used.push(s.key.clone());
                }
                None => {
                    details.push(format!("signature {n} ({}) verifies with key {}, which you trust", s.suite, s.key));
                    valid_suites.insert(s.suite.to_string());
                    used.push(s.key.clone());
                }
            },
            SuiteCheck::Invalid(why) => {
                invalid = true;
                details.push(format!(
                    "signature {n} ({}) by key {} does not verify: {why}. The record or the signature was changed, or the signature belongs to another record",
                    s.suite, s.key
                ));
            }
            SuiteCheck::Unsupported => details.push(format!(
                "signature {n} uses suite {} ({}), which this verifier does not support",
                s.suite, s.algorithm
            )),
        }
    }
    used.sort();
    used.dedup();
    let mut missing = false;
    let mut unmet = false;
    for suite in &m.verification.required_suites {
        if valid_suites.contains(suite.as_str()) {
            continue;
        }
        if !sa.signatures.iter().any(|s| s.suite == *suite) {
            missing = true;
            details.push(format!(
                "the policy {} requires a {suite} signature and there is none: it was removed or never made",
                m.verification.policy
            ));
        } else {
            unmet = true;
            details.push(format!("the policy requires a {suite} signature by a key you trust; none could be verified"));
        }
    }
    // The reader's own requirement (a profile they ask for), apart from what the record claims to need.
    let mut reader_unmet = vec![];
    for suite in &require.require_suites {
        if !valid_suites.contains(suite.as_str()) {
            unmet = true;
            details.push(format!(
                "you require the {} profile, which needs a {suite} signature by a key you trust, and there is none that verifies: not trusted under your policy",
                require.name
            ));
            reader_unmet.push(suite.clone());
        }
    }
    if sa.signatures.is_empty() && m.verification.required_suites.is_empty() {
        details.push("the assessment is not signed and its policy requires no signature".into());
    }
    if trust.keys.is_empty() && !sa.signatures.is_empty() {
        details.push("you did not supply a key to trust, so no signature can be relied on".into());
    }
    let any_valid = !valid_suites.is_empty();
    let result = if invalid || missing {
        R::Failed
    } else if (sa.signatures.is_empty() && m.verification.required_suites.is_empty()) || unmet || !any_valid {
        R::Limited
    } else {
        R::Passed
    };
    Sigs { result, details, used, any_valid, missing, invalid, reader_unmet }
}

/// (result, details, evidence ids whose included payload matched).
fn evidence(i: &Inputs) -> (AssessmentCheckResult, Vec<String>, BTreeMap<Id, Vec<u8>>) {
    use AssessmentCheckResult as R;
    let m = &i.bundle.assessment.manifest;
    let cited: BTreeMap<&Id, &AssessmentEvidenceItem> = m.evidence.iter().map(|e| (&e.id, e)).collect();
    let mut details = vec![];
    let mut failed = false;
    let mut missing = false;
    let mut ok: BTreeMap<Id, Vec<u8>> = BTreeMap::new();
    let mut seen: BTreeSet<&Id> = BTreeSet::new();
    for f in &i.bundle.files {
        if !seen.insert(&f.evidence) {
            failed = true;
            details.push(format!("evidence {} is listed twice", f.evidence));
            continue;
        }
        let Some(item) = cited.get(&f.evidence) else {
            failed = true;
            details.push(format!("the bundle lists evidence {} that the assessment does not cite", f.evidence));
            continue;
        };
        if f.availability != AssessmentPayloadAvailability::Included {
            continue;
        }
        let Some(path) = f.path.as_deref() else {
            failed = true;
            details.push(format!("evidence {} is marked included but names no file", f.evidence));
            continue;
        };
        if !safe_path(path) {
            failed = true;
            details.push(format!("evidence {} names a file outside the bundle; it was not read", f.evidence));
            continue;
        }
        let Some(Some(bytes)) = i.files.get(path) else {
            missing = true;
            details.push(format!("evidence {} is marked included but its file is missing", f.evidence));
            continue;
        };
        let d = Digest::of(bytes);
        if d != item.digest || f.digest.as_ref().is_some_and(|x| *x != d) {
            failed = true;
            details.push(format!(
                "evidence {}: the file digests to {d} but the assessment cites {}: it was changed",
                f.evidence, item.digest
            ));
            continue;
        }
        if item.size.is_some_and(|s| s != bytes.len() as u64) {
            failed = true;
            details.push(format!("evidence {}: the size differs from the size the assessment cites", f.evidence));
            continue;
        }
        ok.insert(f.evidence.clone(), bytes.clone());
    }
    let n = ok.len();
    if n > 0 {
        details.insert(0, format!("{n} included evidence file(s) have exactly the digests the assessment cites"));
    }
    let result = if failed {
        R::Failed
    } else if missing || n == 0 {
        if n == 0 {
            details.push("no evidence files are included; only their digests can be shown".into());
        }
        R::Limited
    } else {
        R::Passed
    };
    (result, details, ok)
}

fn required(i: &Inputs, available: &BTreeMap<Id, Vec<u8>>) -> (AssessmentCheckResult, Vec<String>) {
    use AssessmentCheckResult as R;
    let m = &i.bundle.assessment.manifest;
    let mut details = vec![];
    let mut short = false;
    let mut n = 0;
    for e in m.evidence.iter().filter(|e| e.required) {
        n += 1;
        if e.payload == PayloadState::Deleted || e.payload == PayloadState::Redacted {
            short = true;
            details.push(format!(
                "required evidence {} was already {} when the assessment was issued",
                e.id,
                e.payload.as_str()
            ));
            continue;
        }
        if available.contains_key(&e.id) {
            continue;
        }
        short = true;
        let why = i
            .bundle
            .files
            .iter()
            .find(|f| f.evidence == e.id)
            .map(|f| match f.availability {
                AssessmentPayloadAvailability::Included => "its file is missing or does not match".to_string(),
                other => format!("{}: {}", other.as_str().replace('_', " "), f.reason),
            })
            .unwrap_or_else(|| "the bundle does not list it".into());
        details.push(format!("required evidence {} is not available here ({why})", e.id));
    }
    if n == 0 {
        return (R::Passed, vec!["the assessment cites no required evidence".into()]);
    }
    if short {
        (R::Limited, details)
    } else {
        (R::Passed, vec![format!("all {n} required evidence item(s) are included and match")])
    }
}

fn anchors(i: &Inputs, available: &BTreeMap<Id, Vec<u8>>) -> (AssessmentCheckResult, Vec<String>, Vec<Digest>) {
    use AssessmentCheckResult as R;
    let m = &i.bundle.assessment.manifest;
    let linked: Vec<&AssessmentEvidenceItem> = m.evidence.iter().filter(|e| e.ledger.is_some()).collect();
    let used: Vec<Digest> = i.anchors.iter().map(|x| Digest::of(&x.encode())).collect();
    if linked.is_empty() {
        return (
            R::NotChecked,
            vec!["the assessment cites no ledger evidence, so there is nothing to anchor".into()],
            vec![],
        );
    }
    let mut details = vec![];
    let mut failed = false;
    // An included ledger entry must be the entry its link names.
    for e in &linked {
        let link = e.ledger.as_ref().expect("filtered");
        if e.role == AssessmentEvidenceRole::LedgerEntry
            && let Some(bytes) = available.get(&e.id)
        {
            match LedgerEntry::decode(bytes) {
                Ok(le) if le.seq == link.seq && le.hash == link.hash && entry_hash(&le) == le.hash => {}
                _ => {
                    failed = true;
                    details.push(format!("evidence {} is not the ledger entry its link names", e.id));
                }
            }
        }
    }
    if i.anchors.is_empty() {
        details.push(format!(
            "{} cited ledger item(s); you supplied no anchor, so none can be tied to a record kept elsewhere",
            linked.len()
        ));
        return (if failed { R::Failed } else { R::NotChecked }, details, vec![]);
    }
    let mut packs: Vec<EvidencePack> = m
        .evidence
        .iter()
        .filter(|e| e.role == AssessmentEvidenceRole::EvidencePack)
        .filter_map(|e| available.get(&e.id))
        .filter_map(|b| EvidencePack::decode(b).ok())
        .collect();
    packs.extend(i.packs.iter().cloned());
    let mut covered = 0;
    for e in &linked {
        let link = e.ledger.as_ref().expect("filtered");
        let Some(pack) = packs.iter().find(|p| p.tenant == link.tenant) else {
            details.push(format!(
                "ledger item {} ({} entry {}): no evidence pack for it is included, so your anchors cannot be applied",
                e.id, link.tenant, link.seq
            ));
            continue;
        };
        let r = verify_pack(pack, i.anchors);
        if r.state == IntegrityState::Invalid {
            failed = true;
            details.push(format!(
                "the evidence pack for {} does not match your anchors: {}",
                link.tenant,
                r.invalid.first().map(|f| f.detail.clone()).unwrap_or_default()
            ));
            continue;
        }
        let in_range = r.verified.is_some_and(|(s, t)| link.seq >= s && link.seq <= t);
        let same = pack.entries.iter().any(|x| x.seq == link.seq && x.hash == link.hash);
        if in_range && same {
            covered += 1;
        } else if !same {
            failed = true;
            details.push(format!(
                "ledger item {}: the pack's entry {} is not the one the assessment cites",
                e.id, link.seq
            ));
        } else {
            details
                .push(format!("ledger item {} (entry {}) is not covered by any anchor you supplied", e.id, link.seq));
        }
    }
    if covered > 0 {
        details.insert(0, format!("{covered} of {} cited ledger item(s) are covered by your anchors", linked.len()));
    }
    let result = if failed {
        R::Failed
    } else if covered == linked.len() {
        R::Passed
    } else {
        R::Limited
    };
    (result, details, used)
}

struct StatusFindings {
    result: AssessmentCheckResult,
    details: Vec<String>,
    source: Option<String>,
    as_of: Option<u64>,
    current: bool,
    withdrawn: bool,
    invalidated: bool,
    superseded: bool,
    limit: Option<String>,
}

fn signed_by_trusted(
    trust: &Trust,
    record: &Digest,
    assessment: &Id,
    sigs: &[AssessmentSignature],
) -> (bool, Option<String>) {
    let mut bad = None;
    for s in sigs {
        let Some(k) = trust.keys.get(s.key.as_str()) else { continue };
        if k.suite != s.suite.as_str() || k.algorithm != s.algorithm.as_str() {
            bad = Some(format!("a signature claims suite {} but the key you trust is for {}", s.suite, k.suite));
            continue;
        }
        if k.revoked.is_some_and(|(_, c)| c) {
            bad = Some(format!("signed by key {}, which was reported compromised", s.key));
            continue;
        }
        let msg = a::status_signature_message(record, assessment, s);
        match verify_suite(s.suite.as_str(), s.algorithm.as_str(), &k.public_key, &msg, &s.signature.0) {
            SuiteCheck::Valid => return (true, None),
            SuiteCheck::Invalid(w) => bad = Some(format!("a signature by {} does not verify: {w}", s.key)),
            SuiteCheck::Unsupported => {}
        }
    }
    (false, bad)
}

fn status(i: &Inputs, trust: &Trust) -> StatusFindings {
    use AssessmentCheckResult as R;
    let id = &i.bundle.assessment.id;
    let mut f = StatusFindings {
        result: R::NotChecked,
        details: vec![],
        source: None,
        as_of: None,
        current: false,
        withdrawn: false,
        invalidated: false,
        superseded: false,
        limit: None,
    };
    let from_bundle;
    let input: &StatusInput = match i.status {
        Some(s) => s,
        None => match &i.bundle.status {
            Some(snap) => {
                from_bundle = StatusInput {
                    report: AssessmentStatusReport { snapshot: snap.clone(), statement: i.bundle.statement.clone() },
                    source: format!("the status inside the bundle, exported {}", fmt_utc(i.bundle.exported_ms)),
                    direct: false,
                };
                &from_bundle
            }
            None => {
                f.details.push("no status was supplied and the bundle carries none".into());
                f.limit = Some(
                    "Whether it was superseded, invalidated or withdrawn is unknown: no status was available.".into(),
                );
                return f;
            }
        },
    };
    let snap = &input.report.snapshot;
    f.source = Some(input.source.clone());
    let mut failed = false;
    let mut unauthenticated = false;
    if snap.assessment != *id {
        failed = true;
        f.details.push(format!(
            "the status is for {}, not for this assessment: it was taken from another record",
            snap.assessment
        ));
    }
    let mut prev: Option<Digest> = None;
    let mut authentic: Vec<&AssessmentStatusEvent> = vec![];
    for (n, e) in snap.events.iter().enumerate() {
        let seq = n as u64 + 1;
        if e.assessment != *id {
            failed = true;
            f.details.push(format!("status event {seq} belongs to {}: replayed from another record", e.assessment));
            break;
        }
        if e.seq != seq || e.prev != prev {
            failed = true;
            f.details.push(format!("status event {seq} is out of order or does not link to the one before it"));
            break;
        }
        if a::status_event_hash(e) != e.hash {
            failed = true;
            f.details.push(format!("status event {seq} was changed after it was recorded"));
            break;
        }
        match signed_by_trusted(trust, &e.hash, id, &e.signatures) {
            (true, _) => authentic.push(e),
            (false, Some(bad)) => {
                failed = true;
                f.details.push(format!("status event {seq}: {bad}"));
                break;
            }
            (false, None) => {
                unauthenticated = true;
                f.details.push(format!("status event {seq} is not signed by a key you trust; it is not used"));
            }
        }
        prev = Some(e.hash.clone());
    }
    // The statement dates the chain.
    let mut statement_ok = false;
    match &input.report.statement {
        None => f.details.push("no signed status statement came with it".into()),
        Some(s) => {
            let h = a::statement_hash(s);
            match signed_by_trusted(trust, &h, id, &s.signatures) {
                (true, _) if s.assessment != *id => {
                    failed = true;
                    f.details.push("the status statement is about another assessment".into());
                }
                (true, _)
                    if s.events != snap.events.len() as u64 || s.head != snap.events.last().map(|e| e.hash.clone()) =>
                {
                    failed = true;
                    f.details.push(format!(
                        "the issuer's statement says the status had {} event(s) on {}, but {} were supplied: status was cut or replayed",
                        s.events,
                        fmt_utc(s.as_of_ms),
                        snap.events.len()
                    ));
                }
                (true, _) => {
                    statement_ok = true;
                    f.as_of = Some(s.as_of_ms);
                }
                (false, Some(bad)) => {
                    failed = true;
                    f.details.push(format!("the status statement: {bad}"));
                }
                (false, None) => {
                    unauthenticated = true;
                    f.details
                        .push("the status statement is not signed by a key you trust; its date is not used".into());
                }
            }
        }
    }
    if !statement_ok && input.direct && !failed {
        f.as_of = Some(snap.as_of_ms);
    }
    if !failed {
        for e in &authentic {
            match &e.change {
                AssessmentStatusChange::Withdrawn { reason } => {
                    f.withdrawn = true;
                    f.details.push(format!("withdrawn on {}: {reason}", fmt_utc(e.at_ms)));
                }
                AssessmentStatusChange::Invalidated { triggers, reason } => {
                    f.invalidated = true;
                    f.details.push(format!(
                        "marked no longer applicable on {} ({}): {reason}",
                        fmt_utc(e.at_ms),
                        triggers.iter().map(|t| t.as_str()).collect::<Vec<_>>().join(", ")
                    ));
                }
                AssessmentStatusChange::Superseded { successor, reason } => {
                    f.superseded = true;
                    f.details.push(format!("replaced on {} by {successor}: {reason}", fmt_utc(e.at_ms)));
                }
                AssessmentStatusChange::Issued => {}
            }
        }
    }
    let max_age = i.policy.max_status_age_ms.unwrap_or(DEFAULT_MAX_STATUS_AGE_MS);
    let fresh = f.as_of.is_some_and(|t| i.now_ms.saturating_sub(t) <= max_age && t <= i.now_ms.saturating_add(60_000));
    f.current = !failed && !unauthenticated && fresh;
    match f.as_of {
        Some(t) if fresh => f.details.insert(0, format!("status from {} as of {}", input.source, fmt_utc(t))),
        Some(t) => {
            f.details.insert(
                0,
                format!(
                    "status from {} as of {}, older than the {} hour(s) you accept: it cannot show that nothing changed since",
                    input.source,
                    fmt_utc(t),
                    max_age / 3_600_000
                ),
            );
            f.limit = Some(format!(
                "The newest trusted status is from {}; a withdrawal or replacement after that would not show here.",
                fmt_utc(t)
            ));
        }
        None => {
            f.limit = Some(
                "No status from a source you trust is dated recently enough, so it is unknown whether this assessment was withdrawn or replaced since.".into(),
            );
        }
    }
    f.result = if failed {
        R::Failed
    } else if f.current {
        R::Passed
    } else {
        R::Limited
    };
    f
}

// ------------------------------------------------------------ reading

/// Read an assessment for verification from the bytes of `bundle.json` (or
/// of a bare `SystemAssessment`, which becomes a bundle with no files). An
/// unknown schema version is refused before strict decoding.
pub fn read_bundle(bytes: &[u8]) -> Result<AssessmentBundle, String> {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| format!("not JSON: {e}"))?;
    let assessment =
        if v.get("format").is_some() { v.get("assessment").cloned().unwrap_or_default() } else { v.clone() };
    a::check_schema(&serde_json::to_vec(&assessment).unwrap_or_default()).map_err(|e| e.to_string())?;
    if v.get("format").is_some() {
        AssessmentBundle::decode(bytes).map_err(|e| format!("not an assessment bundle: {e}"))
    } else {
        let sa = SystemAssessment::decode(bytes).map_err(|e| format!("not an assessment: {e}"))?;
        Ok(AssessmentBundle {
            format: a::BUNDLE_FORMAT.into(),
            v: a::BUNDLE_VERSION,
            assessment: sa,
            files: vec![],
            status: None,
            statement: None,
            renewals: vec![],
            key_hints: vec![],
            key_log: vec![],
            provenance: None,
            exported_ms: 0,
            notes: vec![],
        })
    }
}

/// Process exit code: 0 the integrity checks hold against keys the reader
/// trusts; 1 something was changed, a signature is wrong or a check the
/// reader asked for failed; 3 unsigned or unverifiable. Applicability is
/// reported, not folded in (see `--require-current` in the binary).
pub fn exit_code(v: &AssessmentVerification) -> i32 {
    if v.standing.integrity == AssessmentIntegrity::Invalid
        || v.checks.iter().any(|c| c.result == AssessmentCheckResult::Failed)
    {
        1
    } else if v.standing.integrity == AssessmentIntegrity::VerifiedAgainstTrustedInputs {
        0
    } else {
        3
    }
}

/// Plain text for a terminal.
pub fn text(v: &AssessmentVerification) -> String {
    let mut o = String::new();
    o.push_str(&format!("Assessment {}\n", v.assessment));
    for r in &v.standing.reasons {
        o.push_str(&format!("  {r}\n"));
    }
    o.push_str("Checks:\n");
    for c in &v.checks {
        let tag = match c.result {
            AssessmentCheckResult::Passed => "ok         ",
            AssessmentCheckResult::Failed => "FAILED     ",
            AssessmentCheckResult::Limited => "limited    ",
            AssessmentCheckResult::NotChecked => "not checked",
        };
        let first = c.details.first().cloned().unwrap_or_default();
        o.push_str(&format!("  {tag}  {}: {first}\n", c.check.as_str().replace('_', " ")));
        for d in c.details.iter().skip(1) {
            o.push_str(&format!("               {d}\n"));
        }
    }
    o.push_str("Limits:\n");
    for l in &v.limits {
        o.push_str(&format!("  {l}\n"));
    }
    o
}
