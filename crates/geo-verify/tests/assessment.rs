//! Assessment verification: tampering,
//! signature substitution and stripping, a wrong issuer, subject or rule,
//! replayed and stale status, missing and changed evidence, revoked, retired,
//! rotated and recovered keys, expiry, unsupported and hybrid suites.
//!
//! The bundle is built from the approved refund-agent example
//! (contracts/fixtures/assessment) with its real evidence files, its policy
//! changed to require the ed25519 suite and its id re-derived, then signed
//! with fixed test keys. These are implementer-written tests.

use ed25519_dalek::{Signer, SigningKey};
use geo_contracts::assessment::{self as a, Expected};
use geo_contracts::*;
use geo_verify::assessment::{Inputs, StatusInput, exit_code, key_id_of_bytes, read_bundle, verify};
use std::collections::BTreeMap;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/fixtures/assessment/");
const NOW: u64 = 1_792_300_000_000;
const HOUR: u64 = 3_600_000;

fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn kid(sk: &SigningKey) -> Id {
    key_id_of_bytes(&sk.verifying_key().to_bytes())
}

fn trusted(sk: &SigningKey, label: &str) -> AssessmentTrustedKey {
    AssessmentTrustedKey {
        key: kid(sk),
        suite: id(a::SUITE_ED25519),
        algorithm: id(a::ALG_ED25519),
        public_key: Bytes(sk.verifying_key().to_bytes().to_vec()),
        label: label.into(),
    }
}

fn policy(keys: Vec<AssessmentTrustedKey>) -> AssessmentTrustPolicy {
    AssessmentTrustPolicy {
        id: id("test-policy"),
        keys,
        key_log: vec![],
        key_log_as_of_ms: None,
        max_status_age_ms: Some(24 * HOUR),
    }
}

fn sign_entry(sk: &SigningKey, assessment: &Id) -> AssessmentSignature {
    let mut s = AssessmentSignature {
        suite: id(a::SUITE_ED25519),
        algorithm: id(a::ALG_ED25519),
        key: kid(sk),
        signature: Bytes(vec![]),
    };
    s.signature = Bytes(sk.sign(&a::signature_message(assessment, &s)).to_bytes().to_vec());
    s
}

fn status_sig(sk: &SigningKey, record: &Digest, assessment: &Id) -> AssessmentSignature {
    let mut s = AssessmentSignature {
        suite: id(a::SUITE_ED25519),
        algorithm: id(a::ALG_ED25519),
        key: kid(sk),
        signature: Bytes(vec![]),
    };
    s.signature = Bytes(sk.sign(&a::status_signature_message(record, assessment, &s)).to_bytes().to_vec());
    s
}

/// The example manifest with a signed policy, issued at `issued`.
fn manifest(issued: u64) -> AssessmentManifest {
    let ex = SystemAssessment::decode(&std::fs::read(format!("{DIR}example-refund-agent.json")).unwrap()).unwrap();
    let mut m = ex.manifest;
    m.issued_ms = issued;
    m.verification.policy = id(a::POLICY_LOCAL_ED25519);
    m.verification.required_suites = vec![id(a::SUITE_ED25519)];
    m
}

struct Fixture {
    bundle: AssessmentBundle,
    files: BTreeMap<String, Option<Vec<u8>>>,
}

fn fixture(sk: &SigningKey, issued: u64) -> Fixture {
    let m = manifest(issued);
    let aid = a::assessment_id(&m);
    let sa = SystemAssessment { id: aid.clone(), signatures: vec![sign_entry(sk, &aid)], manifest: m };
    let mut files = BTreeMap::new();
    let mut entries = vec![];
    for e in &sa.manifest.evidence {
        let loc = e.location.clone().unwrap();
        let name = loc.rsplit('/').next().unwrap().to_string();
        let bytes = std::fs::read(format!("{DIR}evidence/{name}")).unwrap();
        let path = format!("evidence/{}", e.id);
        entries.push(AssessmentBundleFile {
            evidence: e.id.clone(),
            availability: AssessmentPayloadAvailability::Included,
            path: Some(path.clone()),
            digest: Some(Digest::of(&bytes)),
            size: Some(bytes.len() as u64),
            reason: String::new(),
        });
        files.insert(path, Some(bytes));
    }
    let bundle = AssessmentBundle {
        format: a::BUNDLE_FORMAT.into(),
        v: a::BUNDLE_VERSION,
        assessment: sa,
        files: entries,
        status: None,
        statement: None,
        renewals: vec![],
        key_hints: vec![trusted(sk, "the issuer's own hint (never trusted by itself)")],
        key_log: vec![],
        provenance: None,
        exported_ms: issued,
        notes: vec![],
    };
    Fixture { bundle, files }
}

fn run(
    f: &Fixture,
    p: &AssessmentTrustPolicy,
    status: Option<&StatusInput>,
    expected: Option<&Expected>,
) -> AssessmentVerification {
    verify(&Inputs {
        bundle: &f.bundle,
        files: &f.files,
        policy: p,
        status,
        anchors: &[],
        packs: &[],
        expected,
        now_ms: NOW,
    })
}

fn check(v: &AssessmentVerification, k: AssessmentCheckKind) -> &AssessmentCheck {
    v.checks.iter().find(|c| c.check == k).unwrap_or_else(|| panic!("no {k:?} check"))
}

fn result(v: &AssessmentVerification, k: AssessmentCheckKind) -> AssessmentCheckResult {
    check(v, k).result
}

/// A status chain of `changes`, each event signed by `sk`.
fn chain(
    sk: &SigningKey,
    assessment: &Id,
    changes: Vec<AssessmentStatusChange>,
    start: u64,
) -> Vec<AssessmentStatusEvent> {
    let mut out: Vec<AssessmentStatusEvent> = vec![];
    for (n, change) in changes.into_iter().enumerate() {
        let mut e = AssessmentStatusEvent {
            v: 1,
            assessment: assessment.clone(),
            seq: n as u64 + 1,
            prev: out.last().map(|p| p.hash.clone()),
            at_ms: start + n as u64 * HOUR,
            actor: id("issuer"),
            change,
            signatures: vec![],
            hash: Digest::of(b"placeholder"),
        };
        e.hash = a::status_event_hash(&e);
        e.signatures = vec![status_sig(sk, &e.hash, assessment)];
        out.push(e);
    }
    out
}

fn statement(
    sk: &SigningKey,
    assessment: &Id,
    events: &[AssessmentStatusEvent],
    as_of: u64,
) -> AssessmentStatusStatement {
    let mut s = AssessmentStatusStatement {
        v: 1,
        assessment: assessment.clone(),
        as_of_ms: as_of,
        events: events.len() as u64,
        head: events.last().map(|e| e.hash.clone()),
        signatures: vec![],
    };
    let h = a::statement_hash(&s);
    s.signatures = vec![status_sig(sk, &h, assessment)];
    s
}

fn status_input(
    assessment: &Id,
    events: Vec<AssessmentStatusEvent>,
    st: Option<AssessmentStatusStatement>,
) -> StatusInput {
    StatusInput {
        report: AssessmentStatusReport {
            snapshot: AssessmentStatusSnapshot {
                assessment: assessment.clone(),
                as_of_ms: NOW,
                source: "test".into(),
                events,
            },
            statement: st,
        },
        source: "the issuer's status file".into(),
        direct: false,
    }
}

/// A key-log event signed by `signers`.
fn key_event(
    prev: Option<&KeyEvent>,
    kind: KeyEventKind,
    k: &SigningKey,
    target: Option<Id>,
    compromised: bool,
    at: u64,
    signers: &[&SigningKey],
) -> KeyEvent {
    let introduces = matches!(kind, KeyEventKind::Genesis | KeyEventKind::Rotate | KeyEventKind::Recover);
    let mut e = KeyEvent {
        v: 1,
        seq: prev.map_or(1, |p| p.seq + 1),
        prev: prev.map(|p| p.hash.clone()),
        kind,
        key: target.clone().unwrap_or_else(|| kid(k)),
        public_key: introduces.then(|| hex::encode(k.verifying_key().to_bytes())),
        target,
        compromised,
        at_ms: at,
        note: String::new(),
        sigs: vec![],
        hash: Digest::of(b"placeholder"),
        suite: None,
        profile: None,
    };
    e.hash = geo_verify::key_event_hash(&e);
    let msg = geo_verify::key_event_message(&e);
    e.sigs = signers.iter().map(|s| KeySig { key: kid(s), sig: hex::encode(s.sign(&msg).to_bytes()) }).collect();
    e
}

// ------------------------------------------------------------ tests

#[test]
fn a_signed_bundle_verifies_against_the_key_the_reader_trusts() {
    let issuer = key(1);
    let f = fixture(&issuer, NOW - HOUR);
    let v = run(&f, &policy(vec![trusted(&issuer, "my laptop")]), None, None);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::VerifiedAgainstTrustedInputs, "{v:#?}");
    assert_eq!(v.standing.outcome, AssessmentOutcome::ViolationFound);
    // No status was supplied and the bundle carries none: never "current".
    assert_eq!(v.standing.applicability, AssessmentApplicability::StatusUnknown);
    for k in [
        AssessmentCheckKind::CanonicalForm,
        AssessmentCheckKind::ContentId,
        AssessmentCheckKind::Validation,
        AssessmentCheckKind::Signatures,
        AssessmentCheckKind::EvidenceDigests,
        AssessmentCheckKind::RequiredPayloads,
    ] {
        assert_eq!(result(&v, k), AssessmentCheckResult::Passed, "{k:?}: {:?}", check(&v, k).details);
    }
    assert_eq!(result(&v, AssessmentCheckKind::SubjectBinding), AssessmentCheckResult::NotChecked);
    assert_eq!(result(&v, AssessmentCheckKind::AnchorCoverage), AssessmentCheckResult::NotChecked);
    assert_eq!(v.trusted_keys, vec![kid(&issuer)]);
    assert!(v.standing.reasons.iter().any(|r| r.contains("does not make the issuer independent")));
    assert!(v.limits.iter().any(|l| l.contains("Key revocation was not checked")));
    assert_eq!(exit_code(&v), 0);
    // The record round-trips through its codec.
    assert_eq!(AssessmentVerification::decode(&v.encode()).unwrap(), v);
}

#[test]
fn tampering_with_the_manifest_is_detected_with_or_without_a_new_id() {
    let issuer = key(1);
    let p = policy(vec![trusted(&issuer, "issuer")]);
    let mut f = fixture(&issuer, NOW - HOUR);
    f.bundle.assessment.manifest.findings[0].statement = "No problem was found.".into();
    let v = run(&f, &p, None, None);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::Invalid);
    assert_eq!(result(&v, AssessmentCheckKind::ContentId), AssessmentCheckResult::Failed);
    assert_eq!(exit_code(&v), 1);
    // An attacker who also re-derives the id cannot re-sign it.
    f.bundle.assessment.id = a::assessment_id(&f.bundle.assessment.manifest);
    let v = run(&f, &p, None, None);
    assert_eq!(result(&v, AssessmentCheckKind::ContentId), AssessmentCheckResult::Passed);
    assert_eq!(result(&v, AssessmentCheckKind::Signatures), AssessmentCheckResult::Failed);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::Invalid);
    // Upgrading a verdict breaks the recomputed summary as well.
    let mut g = fixture(&issuer, NOW - HOUR);
    g.bundle.assessment.manifest.summary.outcome = AssessmentOutcome::NoViolationObservedWithinScope;
    g.bundle.assessment.id = a::assessment_id(&g.bundle.assessment.manifest);
    let v = run(&g, &p, None, None);
    assert_eq!(result(&v, AssessmentCheckKind::Validation), AssessmentCheckResult::Failed);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::Invalid);
}

#[test]
fn a_signature_cannot_be_moved_stripped_or_relabelled() {
    let issuer = key(1);
    let p = policy(vec![trusted(&issuer, "issuer")]);
    // Substitution: a valid signature of another assessment by the same key.
    let mut f = fixture(&issuer, NOW - HOUR);
    let other = fixture(&issuer, NOW - 2 * HOUR);
    assert_ne!(other.bundle.assessment.id, f.bundle.assessment.id);
    f.bundle.assessment.signatures = other.bundle.assessment.signatures.clone();
    let v = run(&f, &p, None, None);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::Invalid, "{:?}", check(&v, AssessmentCheckKind::Signatures));
    // Stripped: the policy (inside the id) requires a suite with no signature left.
    let mut f = fixture(&issuer, NOW - HOUR);
    f.bundle.assessment.signatures.clear();
    let v = run(&f, &p, None, None);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::Invalid);
    assert!(check(&v, AssessmentCheckKind::Signatures).details.iter().any(|d| d.contains("removed or never made")));
    // Relabelled suite or algorithm: refused, not reinterpreted.
    let mut f = fixture(&issuer, NOW - HOUR);
    f.bundle.assessment.signatures[0].algorithm = id("ed448");
    let v = run(&f, &p, None, None);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::Invalid);
    // A flipped bit in the signature bytes.
    let mut f = fixture(&issuer, NOW - HOUR);
    f.bundle.assessment.signatures[0].signature.0[5] ^= 1;
    let v = run(&f, &p, None, None);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::Invalid);
}

#[test]
fn a_wrong_issuer_is_never_trusted_because_the_bundle_names_its_key() {
    let issuer = key(1);
    let attacker = key(9);
    // The attacker signs a bundle and ships its own key as a hint.
    let f = fixture(&attacker, NOW - HOUR);
    assert_eq!(f.bundle.key_hints[0].key, kid(&attacker));
    let v = run(&f, &policy(vec![trusted(&issuer, "issuer")]), None, None);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::Unverifiable);
    assert!(v.trusted_keys.is_empty());
    assert_eq!(exit_code(&v), 3);
    // No key supplied at all: still unverifiable, never verified.
    let v = run(&f, &policy(vec![]), None, None);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::Unverifiable);
    // A key file whose id does not match its public key is not used.
    let mut forged = trusted(&issuer, "forged");
    forged.key = kid(&attacker);
    let v = run(&f, &policy(vec![forged]), None, None);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::Unverifiable);
    assert!(v.standing.reasons.iter().any(|r| r.contains("does not have that id")));
}

#[test]
fn a_wrong_subject_or_rule_fails_its_binding_and_the_report_no_longer_applies() {
    let issuer = key(1);
    let p = policy(vec![trusted(&issuer, "issuer")]);
    let f = fixture(&issuer, NOW - HOUR);
    let m = &f.bundle.assessment.manifest;
    let right = Expected {
        revision: m.subject.revision.as_ref().map(|r| r.digest.clone()),
        rules: m.rules.iter().map(|r| (r.rule.id.clone(), r.rule.digest.clone())).collect(),
        ..Default::default()
    };
    let v = run(&f, &p, None, Some(&right));
    assert_eq!(result(&v, AssessmentCheckKind::SubjectBinding), AssessmentCheckResult::Passed);
    assert_eq!(result(&v, AssessmentCheckKind::RuleBinding), AssessmentCheckResult::Passed);
    assert_eq!(exit_code(&v), 0);
    let wrong_subject = Expected { revision: Some(Digest::of(b"the next commit")), ..right.clone() };
    let v = run(&f, &p, None, Some(&wrong_subject));
    assert_eq!(result(&v, AssessmentCheckKind::SubjectBinding), AssessmentCheckResult::Failed);
    assert_eq!(v.standing.applicability, AssessmentApplicability::Invalidated);
    // The integrity of the record itself is unaffected: it is a valid statement about another subject.
    assert_eq!(v.standing.integrity, AssessmentIntegrity::VerifiedAgainstTrustedInputs);
    assert_eq!(exit_code(&v), 1);
    let mut rules = right.rules.clone();
    rules.insert(id("refund-at-most-once"), Digest::of(b"a changed meaning"));
    let v = run(&f, &p, None, Some(&Expected { rules, ..right.clone() }));
    assert_eq!(result(&v, AssessmentCheckKind::RuleBinding), AssessmentCheckResult::Failed);
    assert_eq!(v.standing.applicability, AssessmentApplicability::Invalidated);
}

#[test]
fn changed_missing_and_withheld_evidence_are_told_apart() {
    let issuer = key(1);
    let p = policy(vec![trusted(&issuer, "issuer")]);
    // Changed evidence bytes: the record is not what was signed.
    let mut f = fixture(&issuer, NOW - HOUR);
    let path = f.bundle.files[0].path.clone().unwrap();
    f.files.get_mut(&path).unwrap().as_mut().unwrap().push(b' ');
    let v = run(&f, &p, None, None);
    assert_eq!(result(&v, AssessmentCheckKind::EvidenceDigests), AssessmentCheckResult::Failed);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::Invalid);
    // Missing file: a visible limit, not tampering.
    let mut f = fixture(&issuer, NOW - HOUR);
    f.files.insert(path.clone(), None);
    let v = run(&f, &p, None, None);
    assert_eq!(result(&v, AssessmentCheckKind::RequiredPayloads), AssessmentCheckResult::Limited);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::VerifiedAgainstTrustedInputs);
    // Withheld private evidence and evidence deleted after issuance say why.
    let mut f = fixture(&issuer, NOW - HOUR);
    f.bundle.files[0].availability = AssessmentPayloadAvailability::WithheldPrivate;
    f.bundle.files[0].reason = "private; not part of this export".into();
    f.bundle.files[2].availability = AssessmentPayloadAvailability::Deleted;
    f.bundle.files[2].reason = "removed by its owner".into();
    let v = run(&f, &p, None, None);
    let req = check(&v, AssessmentCheckKind::RequiredPayloads);
    assert_eq!(req.result, AssessmentCheckResult::Limited);
    assert!(req.details.iter().any(|d| d.contains("withheld private")), "{:?}", req.details);
    assert!(req.details.iter().any(|d| d.contains("deleted")), "{:?}", req.details);
    // A path that leaves the bundle is never read.
    let mut f = fixture(&issuer, NOW - HOUR);
    f.bundle.files[0].path = Some("../../etc/passwd".into());
    let v = run(&f, &p, None, None);
    assert_eq!(result(&v, AssessmentCheckKind::EvidenceDigests), AssessmentCheckResult::Failed);
    // Evidence the assessment does not cite.
    let mut f = fixture(&issuer, NOW - HOUR);
    f.bundle.files.push(AssessmentBundleFile {
        evidence: id("smuggled"),
        availability: AssessmentPayloadAvailability::WithheldPrivate,
        path: None,
        digest: None,
        size: None,
        reason: String::new(),
    });
    let v = run(&f, &p, None, None);
    assert_eq!(result(&v, AssessmentCheckKind::EvidenceDigests), AssessmentCheckResult::Failed);
}

#[test]
fn status_must_be_recent_signed_and_about_this_assessment() {
    let issuer = key(1);
    let p = policy(vec![trusted(&issuer, "issuer")]);
    let f = fixture(&issuer, NOW - 2 * HOUR);
    let aid = f.bundle.assessment.id.clone();
    let issued = chain(&issuer, &aid, vec![AssessmentStatusChange::Issued {}], NOW - 2 * HOUR);
    // Fresh, signed: current.
    let fresh = status_input(&aid, issued.clone(), Some(statement(&issuer, &aid, &issued, NOW - HOUR)));
    let v = run(&f, &p, Some(&fresh), None);
    assert_eq!(
        v.standing.applicability,
        AssessmentApplicability::CurrentForDeclaredSubject,
        "{:?}",
        check(&v, AssessmentCheckKind::Status)
    );
    assert_eq!(v.standing.status_as_of_ms, Some(NOW - HOUR));
    assert!(v.status_source.as_deref().unwrap().contains("status file"));
    // Stale: an old statement (a replay of last month's status) cannot say it was not withdrawn since.
    let stale = status_input(&aid, issued.clone(), Some(statement(&issuer, &aid, &issued, NOW - 30 * 24 * HOUR)));
    let v = run(&f, &p, Some(&stale), None);
    assert_eq!(v.standing.applicability, AssessmentApplicability::StatusUnknown);
    assert_eq!(result(&v, AssessmentCheckKind::Status), AssessmentCheckResult::Limited);
    assert!(v.limits.iter().any(|l| l.contains("would not show here")));
    // The snapshot's own unsigned time does not count when the source is not read directly.
    let undated = status_input(&aid, issued.clone(), None);
    let v = run(&f, &p, Some(&undated), None);
    assert_eq!(v.standing.applicability, AssessmentApplicability::StatusUnknown);
    // A truncated chain replayed under a newer statement is caught by the count.
    let withdrawn = chain(
        &issuer,
        &aid,
        vec![
            AssessmentStatusChange::Issued {},
            AssessmentStatusChange::Withdrawn { reason: "the claim was wrong".into() },
        ],
        NOW - 2 * HOUR,
    );
    let cut = status_input(&aid, withdrawn[..1].to_vec(), Some(statement(&issuer, &aid, &withdrawn, NOW - HOUR)));
    let v = run(&f, &p, Some(&cut), None);
    assert_eq!(result(&v, AssessmentCheckKind::Status), AssessmentCheckResult::Failed);
    assert_ne!(v.standing.applicability, AssessmentApplicability::CurrentForDeclaredSubject);
    // Status of another assessment, replayed here.
    let other = fixture(&issuer, NOW - 3 * HOUR);
    let oid = other.bundle.assessment.id.clone();
    let theirs = chain(&issuer, &oid, vec![AssessmentStatusChange::Issued {}], NOW - 2 * HOUR);
    let replayed = status_input(&aid, theirs.clone(), Some(statement(&issuer, &oid, &theirs, NOW - HOUR)));
    let v = run(&f, &p, Some(&replayed), None);
    assert_eq!(result(&v, AssessmentCheckKind::Status), AssessmentCheckResult::Failed);
    assert_eq!(v.standing.applicability, AssessmentApplicability::StatusUnknown);
    // Status signed by a key the reader does not trust is not used.
    let stranger = key(5);
    let forged = chain(&stranger, &aid, vec![AssessmentStatusChange::Issued {}], NOW - 2 * HOUR);
    let v =
        run(&f, &p, Some(&status_input(&aid, forged.clone(), Some(statement(&stranger, &aid, &forged, NOW)))), None);
    assert_eq!(v.standing.applicability, AssessmentApplicability::StatusUnknown);
    // An edited event.
    let mut edited = issued.clone();
    edited[0].actor = id("someone-else");
    let v = run(&f, &p, Some(&status_input(&aid, edited, None)), None);
    assert_eq!(result(&v, AssessmentCheckKind::Status), AssessmentCheckResult::Failed);
}

#[test]
fn withdrawal_supersession_and_invalidation_are_separate_and_never_change_results() {
    let issuer = key(1);
    let p = policy(vec![trusted(&issuer, "issuer")]);
    let f = fixture(&issuer, NOW - 3 * HOUR);
    let aid = f.bundle.assessment.id.clone();
    let cases = [
        (
            AssessmentStatusChange::Withdrawn { reason: "no longer stands behind it".into() },
            AssessmentApplicability::Withdrawn,
        ),
        (
            AssessmentStatusChange::Superseded { successor: id("assessment:next"), reason: "re-checked".into() },
            AssessmentApplicability::Superseded,
        ),
        (
            AssessmentStatusChange::Invalidated {
                triggers: vec![AssessmentInvalidation::ConfigChanged],
                reason: "rules.toml changed".into(),
            },
            AssessmentApplicability::Invalidated,
        ),
    ];
    for (change, expected) in cases {
        let ev = chain(&issuer, &aid, vec![AssessmentStatusChange::Issued {}, change], NOW - 3 * HOUR);
        // Even old status is definitive for a change it records.
        let s = status_input(&aid, ev.clone(), Some(statement(&issuer, &aid, &ev, NOW - 40 * 24 * HOUR)));
        let v = run(&f, &p, Some(&s), None);
        assert_eq!(v.standing.applicability, expected);
        assert_eq!(v.standing.outcome, AssessmentOutcome::ViolationFound, "results are never rewritten");
        assert_eq!(v.standing.integrity, AssessmentIntegrity::VerifiedAgainstTrustedInputs);
    }
}

#[test]
fn revoked_retired_rotated_and_recovered_keys() {
    let old = key(1);
    let new = key(2);
    let lost = key(3);
    let issued = NOW - 10 * HOUR;
    let genesis = key_event(None, KeyEventKind::Genesis, &old, None, false, NOW - 100 * HOUR, &[&old]);
    let rotate = key_event(Some(&genesis), KeyEventKind::Rotate, &new, None, false, NOW - 50 * HOUR, &[&old, &new]);
    // Rotated: the reader trusts the old key; the report is signed by the new one.
    let f = fixture(&new, issued);
    let mut p = policy(vec![trusted(&old, "the issuer's first key")]);
    let v = run(&f, &p, None, None);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::Unverifiable, "without the key log the new key is unknown");
    p.key_log = vec![genesis.clone(), rotate.clone()];
    p.key_log_as_of_ms = Some(NOW);
    let v = run(&f, &p, None, None);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::VerifiedAgainstTrustedInputs, "{:?}", v.checks);
    assert!(v.standing.reasons.iter().any(|r| r.contains("rotated to it")));
    // Retired later (a revocation that is not a compromise): still verifies, with the date. Another
    // active key signs a revocation, so the issuer rotates to a third key first.
    let third = key(4);
    let rotate2 = key_event(Some(&rotate), KeyEventKind::Rotate, &third, None, false, NOW - 2 * HOUR, &[&new, &third]);
    let retire = key_event(Some(&rotate2), KeyEventKind::Revoke, &third, Some(kid(&new)), false, NOW - HOUR, &[&third]);
    p.key_log = vec![genesis.clone(), rotate.clone(), rotate2.clone(), retire.clone()];
    let v = run(&f, &p, None, None);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::VerifiedAgainstTrustedInputs, "{:?}", v.checks);
    assert!(check(&v, AssessmentCheckKind::Signatures).details.iter().any(|d| d.contains("retired later")));
    // Retired before the stated issue time: refused.
    let early = fixture(&new, NOW - 30 * 60 * 1000);
    let v = run(&early, &p, None, None);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::Invalid);
    // Compromised: nothing it signed is relied on.
    let compromised =
        key_event(Some(&rotate2), KeyEventKind::Revoke, &third, Some(kid(&new)), true, NOW - HOUR, &[&third]);
    p.key_log = vec![genesis.clone(), rotate.clone(), rotate2.clone(), compromised];
    let v = run(&f, &p, None, None);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::Invalid);
    assert!(check(&v, AssessmentCheckKind::Signatures).details.iter().any(|d| d.contains("compromised")));
    // Recovered after a lost key: nothing in the log vouches for it.
    let recover = key_event(Some(&rotate), KeyEventKind::Recover, &lost, None, false, NOW - 20 * HOUR, &[&lost]);
    let mut p = policy(vec![trusted(&old, "the issuer's first key")]);
    p.key_log = vec![genesis, rotate, recover];
    let g = fixture(&lost, issued);
    let v = run(&g, &p, None, None);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::Unverifiable);
    assert!(v.standing.reasons.iter().any(|r| r.contains("nothing in the log vouches for it")));
    // A damaged key log is not used at all.
    let mut p2 = p.clone();
    p2.key_log[1].note = "edited".into();
    let v = run(&f, &p2, None, None);
    assert!(v.standing.reasons.iter().any(|r| r.contains("damaged")));
}

#[test]
fn expiry_unsupported_and_hybrid_suites() {
    let issuer = key(1);
    let p = policy(vec![trusted(&issuer, "issuer")]);
    // Expired claim.
    let mut m = manifest(NOW - 10 * HOUR);
    m.claim.expires_ms = Some(NOW - HOUR);
    let aid = a::assessment_id(&m);
    let mut f = fixture(&issuer, NOW - 10 * HOUR);
    f.bundle.assessment =
        SystemAssessment { id: aid.clone(), signatures: vec![sign_entry(&issuer, &aid)], manifest: m };
    let v = run(&f, &p, None, None);
    assert_eq!(v.standing.applicability, AssessmentApplicability::Expired);
    assert_eq!(result(&v, AssessmentCheckKind::Expiry), AssessmentCheckResult::Failed);
    // A profile requiring two suites never accepts just the easier one.
    let mut m = manifest(NOW - 10 * HOUR);
    m.verification.required_suites = vec![id(a::SUITE_ED25519), id("x-pq-suite/1")];
    let aid = a::assessment_id(&m);
    let mut pq = AssessmentSignature {
        suite: id("x-pq-suite/1"),
        algorithm: id("x-pq"),
        key: id("key:pq"),
        signature: Bytes(vec![1, 2, 3]),
    };
    let mut f = fixture(&issuer, NOW - 10 * HOUR);
    f.bundle.assessment =
        SystemAssessment { id: aid.clone(), signatures: vec![sign_entry(&issuer, &aid)], manifest: m.clone() };
    let v = run(&f, &p, None, None);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::Invalid, "the second suite is missing: stripped");
    f.bundle.assessment.signatures.push(pq.clone());
    let v = run(&f, &p, None, None);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::Unverifiable, "{:?}", v.checks);
    // A trusted key declared for the unknown suite: the suite is unsupported here, never accepted.
    let mut pk = trusted(&issuer, "pq");
    pk.suite = id("x-pq-suite/1");
    pk.algorithm = id("x-pq");
    pk.public_key = Bytes(vec![7; 40]);
    pk.key = key_id_of_bytes(&pk.public_key.0);
    pq.key = pk.key.clone();
    f.bundle.assessment.signatures[1] = pq;
    let v = run(&f, &policy(vec![trusted(&issuer, "issuer"), pk]), None, None);
    assert_eq!(v.standing.integrity, AssessmentIntegrity::Unverifiable);
    assert!(check(&v, AssessmentCheckKind::Signatures).details.iter().any(|d| d.contains("does not support")));
}

#[test]
fn an_unsigned_assessment_is_unsigned_and_a_bare_record_reads_as_a_bundle() {
    let bytes = std::fs::read(format!("{DIR}valid-unsigned.json")).unwrap();
    let bundle = read_bundle(&bytes).unwrap();
    assert!(bundle.files.is_empty());
    let files = BTreeMap::new();
    let v = verify(&Inputs {
        bundle: &bundle,
        files: &files,
        policy: &policy(vec![]),
        status: None,
        anchors: &[],
        packs: &[],
        expected: None,
        now_ms: NOW,
    });
    assert_eq!(v.standing.integrity, AssessmentIntegrity::Unsigned);
    assert_eq!(exit_code(&v), 3);
    // An unknown schema version is refused before decoding, by name.
    let mut j: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    j["manifest"]["schema"] = "geo_assessment_v2".into();
    let e = read_bundle(&serde_json::to_vec(&j).unwrap()).unwrap_err();
    assert!(e.contains("unsupported_schema_version"), "{e}");
    // The derived views of an example with signature placeholders: not trusted.
    let mixed = read_bundle(&std::fs::read(format!("{DIR}valid-mixed.json")).unwrap()).unwrap();
    let v = verify(&Inputs {
        bundle: &mixed,
        files: &files,
        policy: &policy(vec![]),
        status: None,
        anchors: &[],
        packs: &[],
        expected: None,
        now_ms: NOW,
    });
    assert_ne!(v.standing.integrity, AssessmentIntegrity::VerifiedAgainstTrustedInputs);
}
