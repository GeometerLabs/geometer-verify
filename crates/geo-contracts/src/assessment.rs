//! Assessment certificates: identity and validation of a [`SystemAssessment`]
//!.
//!
//! An assessment is a statement about one declared subject under declared
//! rules and a declared method, separate from evidence packs and from runtime
//! approval. This module defines, once, how its identity is derived and what a
//! well-formed assessment must satisfy. It does not sign, verify signatures,
//! judge integrity or applicability, or look up status: those belong to the
//! verifier (C3), which builds on the definitions here.
//!
//! - **Identity.** `id = "assessment:" + hex(sha256("geo-assessment/1\n" ||
//!   canonical bytes of the AssessmentManifest))`. The signatures are outside
//!   the manifest, so adding one never changes the id; the verification
//!   policy is inside it, so it cannot be swapped without changing the id.
//! - **Schema versions.** [`decode_assessment`] reads `manifest.schema` before
//!   anything else and refuses a version it does not know, so a newer manifest
//!   is reported as newer, not as an unknown field, and is never read
//!   best-effort. Version 1 is the first; nothing migrates into it.
//! - **Outcomes.** `proved_for_declared_model` needs a `formal_model_check`
//!   method with a declared model; bounded testing can never produce it. The
//!   summary is recomputed by [`summarize`] and must match: any required rule
//!   that is unknown or not exercised, or required evidence that is deleted,
//!   keeps it at `unknown_or_incomplete` or worse, and a found violation is
//!   never hidden.
//! - **Bindings.** [`check_bindings`] compares a manifest with the subject,
//!   rules, configuration and evidence a reader expects and names each binding
//!   that differs.
//!
//! TypeScript and Python implement the id derivation and the schema-version
//! refusal against the same vectors (`contracts/fixtures/assessment`).

use crate::codec::{Canon, Digest, Id};
use crate::error::DecodeError;
use crate::generated::*;
use crate::json::{Json, parse};
use std::collections::{BTreeMap, BTreeSet};

/// The only schema version this reader knows.
pub const SCHEMA: &str = "geo_assessment_v1";
/// Domain tag of the content id.
pub const ID_DOMAIN: &[u8] = b"geo-assessment/1\n";
/// Prefix of every assessment id.
pub const ID_PREFIX: &str = "assessment:";
/// Domain tag of the bytes a signature covers.
pub const SIGNATURE_DOMAIN: &[u8] = b"geo-assessment-signature/1\n";
/// Domain tag of a status event's hash.
pub const STATUS_DOMAIN: &[u8] = b"geo-assessment-status/1\n";

// ------------------------------------------------------------ identity

/// The content-derived id of a manifest.
pub fn assessment_id(m: &AssessmentManifest) -> Id {
    let d = Digest::of(&[ID_DOMAIN, &m.encode()].concat());
    Id::new(format!("{ID_PREFIX}{}", d.hex())).expect("hex id is valid")
}

/// The bytes one signature covers (C3 signs and verifies them; nothing here
/// signs): the domain tag and the canonical [`AssessmentSignatureInput`].
pub fn signature_message(assessment: &Id, s: &AssessmentSignature) -> Vec<u8> {
    let input = AssessmentSignatureInput {
        assessment: assessment.clone(),
        suite: s.suite.clone(),
        algorithm: s.algorithm.clone(),
        key: s.key.clone(),
    };
    [SIGNATURE_DOMAIN, &input.encode()].concat()
}

/// The hash of a status event: the domain tag and its canonical bytes with
/// `hash` zeroed and `signatures` empty.
pub fn status_event_hash(e: &AssessmentStatusEvent) -> Digest {
    let mut c = e.clone();
    c.hash = zero_digest();
    c.signatures.clear();
    Digest::of(&[STATUS_DOMAIN, &c.encode()].concat())
}

// ------------------------------------------------------------ C2/C3 formats

/// Domain tag of the bytes a signature on a status event, status statement or
/// renewal covers.
pub const STATUS_SIGNATURE_DOMAIN: &[u8] = b"geo-assessment-status-signature/1\n";
/// Domain tag of a status statement's hash.
pub const STATEMENT_DOMAIN: &[u8] = b"geo-assessment-status-statement/1\n";
/// Domain tag of a renewal's hash.
pub const RENEWAL_DOMAIN: &[u8] = b"geo-assessment-renewal/1\n";
/// `format` of an [`AssessmentBundle`].
pub const BUNDLE_FORMAT: &str = "geometer.assessment-bundle";
/// `v` of an [`AssessmentBundle`].
pub const BUNDLE_VERSION: u32 = 1;
/// The Ed25519 signature suite (every signed report carries it; a hybrid report also carries ML-DSA-65).
pub const SUITE_ED25519: &str = "geo-ed25519/1";
/// The algorithm id of [`SUITE_ED25519`].
pub const ALG_ED25519: &str = "ed25519";
/// The verification policy of an assessment signed with [`SUITE_ED25519`] by
/// the issuing computer's own key.
pub const POLICY_LOCAL_ED25519: &str = "geo-assessment-policy/local-ed25519/1";
/// The verification policy of an assessment signed by the issuing computer's
/// own keys under the hybrid profile: [`SUITE_ED25519`] and ML-DSA-65
///, both required.
pub const POLICY_LOCAL_HYBRID: &str = "geo-assessment-policy/local-hybrid/1";
/// The verification policy of an unsigned assessment.
pub const POLICY_UNSIGNED: &str = "geo-assessment-policy/unsigned-local/1";

fn zero_digest() -> Digest {
    Digest::parse(&format!("sha256:{}", "0".repeat(64))).expect("valid digest")
}

/// The bytes one signature on a status record covers: the domain tag and the
/// canonical [`AssessmentStatusSignatureInput`] naming the record's hash.
pub fn status_signature_message(record: &Digest, assessment: &Id, s: &AssessmentSignature) -> Vec<u8> {
    let input = AssessmentStatusSignatureInput {
        record: record.clone(),
        assessment: assessment.clone(),
        suite: s.suite.clone(),
        algorithm: s.algorithm.clone(),
        key: s.key.clone(),
    };
    [STATUS_SIGNATURE_DOMAIN, &input.encode()].concat()
}

/// The hash of a status statement: the domain tag and its canonical bytes
/// with `signatures` empty.
pub fn statement_hash(s: &AssessmentStatusStatement) -> Digest {
    let mut c = s.clone();
    c.signatures.clear();
    Digest::of(&[STATEMENT_DOMAIN, &c.encode()].concat())
}

/// The hash of a renewal: the domain tag and its canonical bytes with `hash`
/// zeroed and `signatures` empty.
pub fn renewal_hash(r: &AssessmentRenewal) -> Digest {
    let mut c = r.clone();
    c.hash = zero_digest();
    c.signatures.clear();
    Digest::of(&[RENEWAL_DOMAIN, &c.encode()].concat())
}

/// The digest a renewal cites for a verification result: sha256 of its
/// canonical bytes.
pub fn verification_digest(v: &AssessmentVerification) -> Digest {
    Digest::of(&v.encode())
}

// ------------------------------------------------------------ problems

/// Why a manifest is refused. The snake_case names are used by the shared
/// vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Code {
    /// `manifest.schema` names a version this reader does not know.
    UnsupportedSchemaVersion,
    /// The id is not the content id of the manifest.
    IdMismatch,
    /// `derived_from` is missing on a redacted derivative, or present on anything else.
    DerivationInconsistent,
    /// The assessed window does not end at or before issuance.
    TimesOutOfOrder,
    /// The subject names neither a revision nor a build.
    SubjectWithoutIdentity,
    /// Two rules have the same id.
    DuplicateRule,
    /// A rule's digest does not match its meaning.
    RuleDigestMismatch,
    /// A rule binding pins another rule or digest.
    BindingForOtherRule,
    /// Two methods have the same id.
    DuplicateMethod,
    /// A formal_model_check method declares no model, or another kind declares one.
    ModelDeclarationInconsistent,
    /// A bounded_exploration method states no budget.
    BoundedMethodWithoutBudget,
    /// Two evidence items have the same id.
    DuplicateEvidence,
    /// A finding, method or summary names a rule that is not declared.
    UnknownRule,
    /// A declared rule has no finding (a rule that was not assessed says not_exercised).
    RuleWithoutFinding,
    /// A rule has more than one finding.
    DuplicateFinding,
    /// A finding pins another digest than its rule.
    FindingRuleDigestMismatch,
    /// A finding cites a method that is not declared.
    UnknownMethod,
    /// A finding, action or the claim cites evidence that is not declared.
    UnknownEvidence,
    /// proved_for_declared_model without a formal model check of a declared model.
    ProofWithoutFormalModel,
    /// A rule the method lists as unexercised has another outcome than not_exercised.
    UnexercisedRuleOverclaims,
    /// A rule whose binding for the method's mode is unsupported has a definite outcome.
    UnsupportedBindingOverclaims,
    /// An action's dispatch and effect contradict each other.
    ActionStatesInconsistent,
    /// The claim's kind is not supported by the methods and findings.
    ClaimOverstatesMethod,
    /// The stored summary differs from the conservative recomputation.
    SummaryMismatch,
}

impl Code {
    /// Every code, in declaration order.
    pub const ALL: [Code; 24] = [
        Code::UnsupportedSchemaVersion,
        Code::IdMismatch,
        Code::DerivationInconsistent,
        Code::TimesOutOfOrder,
        Code::SubjectWithoutIdentity,
        Code::DuplicateRule,
        Code::RuleDigestMismatch,
        Code::BindingForOtherRule,
        Code::DuplicateMethod,
        Code::ModelDeclarationInconsistent,
        Code::BoundedMethodWithoutBudget,
        Code::DuplicateEvidence,
        Code::UnknownRule,
        Code::RuleWithoutFinding,
        Code::DuplicateFinding,
        Code::FindingRuleDigestMismatch,
        Code::UnknownMethod,
        Code::UnknownEvidence,
        Code::ProofWithoutFormalModel,
        Code::UnexercisedRuleOverclaims,
        Code::UnsupportedBindingOverclaims,
        Code::ActionStatesInconsistent,
        Code::ClaimOverstatesMethod,
        Code::SummaryMismatch,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Code::UnsupportedSchemaVersion => "unsupported_schema_version",
            Code::IdMismatch => "id_mismatch",
            Code::DerivationInconsistent => "derivation_inconsistent",
            Code::TimesOutOfOrder => "times_out_of_order",
            Code::SubjectWithoutIdentity => "subject_without_identity",
            Code::DuplicateRule => "duplicate_rule",
            Code::RuleDigestMismatch => "rule_digest_mismatch",
            Code::BindingForOtherRule => "binding_for_other_rule",
            Code::DuplicateMethod => "duplicate_method",
            Code::ModelDeclarationInconsistent => "model_declaration_inconsistent",
            Code::BoundedMethodWithoutBudget => "bounded_method_without_budget",
            Code::DuplicateEvidence => "duplicate_evidence",
            Code::UnknownRule => "unknown_rule",
            Code::RuleWithoutFinding => "rule_without_finding",
            Code::DuplicateFinding => "duplicate_finding",
            Code::FindingRuleDigestMismatch => "finding_rule_digest_mismatch",
            Code::UnknownMethod => "unknown_method",
            Code::UnknownEvidence => "unknown_evidence",
            Code::ProofWithoutFormalModel => "proof_without_formal_model",
            Code::UnexercisedRuleOverclaims => "unexercised_rule_overclaims",
            Code::UnsupportedBindingOverclaims => "unsupported_binding_overclaims",
            Code::ActionStatesInconsistent => "action_states_inconsistent",
            Code::ClaimOverstatesMethod => "claim_overstates_method",
            Code::SummaryMismatch => "summary_mismatch",
        }
    }
}

/// One reason a manifest is refused: the code, where (a path into the
/// manifest) and a plain explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub code: Code,
    pub at: String,
    pub detail: String,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at {}: {}", self.code.as_str(), self.at, self.detail)
    }
}

/// Why [`decode_assessment`] or [`validate`] refused an assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssessmentError {
    /// The bytes are not a well-formed record (the shared codec error classes).
    Decode(DecodeError),
    /// The manifest names a schema version this reader does not know.
    UnsupportedSchemaVersion(String),
    /// The record decodes but breaks the rules above (never empty).
    Invalid(Vec<Problem>),
}

impl AssessmentError {
    /// The codes, for comparison with the shared vectors.
    pub fn codes(&self) -> Vec<String> {
        match self {
            AssessmentError::Decode(e) => vec![e.class.as_str().to_owned()],
            AssessmentError::UnsupportedSchemaVersion(_) => vec![Code::UnsupportedSchemaVersion.as_str().to_owned()],
            AssessmentError::Invalid(ps) => ps.iter().map(|p| p.code.as_str().to_owned()).collect(),
        }
    }
}

impl std::fmt::Display for AssessmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssessmentError::Decode(e) => write!(f, "{e}"),
            AssessmentError::UnsupportedSchemaVersion(v) => {
                write!(f, "unsupported_schema_version: {v:?} is not {SCHEMA}; this reader does not read it")
            }
            AssessmentError::Invalid(ps) => {
                let parts: Vec<String> = ps.iter().map(|p| p.to_string()).collect();
                write!(f, "{}", parts.join("; "))
            }
        }
    }
}

impl std::error::Error for AssessmentError {}

// ------------------------------------------------------------ decoding

/// Refuse a schema version this reader does not know, before strict field
/// decoding. Only a string-valued `manifest.schema` is judged here; anything
/// else is left to the codec, which reports its usual error class.
pub fn check_schema(bytes: &[u8]) -> Result<(), AssessmentError> {
    let j = parse(bytes).map_err(AssessmentError::Decode)?;
    if let Json::Obj(top) = &j
        && let Some(Json::Obj(m)) = top.get("manifest")
        && let Some(Json::Str(s)) = m.get("schema")
        && s != SCHEMA
    {
        return Err(AssessmentError::UnsupportedSchemaVersion(s.clone()));
    }
    Ok(())
}

/// Read an assessment: refuse an unknown schema version, decode strictly
/// (unknown fields, wrong types and bad digests are refused with the shared
/// error classes), then [`validate`].
pub fn decode_assessment(bytes: &[u8]) -> Result<SystemAssessment, AssessmentError> {
    check_schema(bytes)?;
    let a = SystemAssessment::decode(bytes).map_err(AssessmentError::Decode)?;
    validate(&a)?;
    Ok(a)
}

/// Every problem with a decoded assessment, empty when it is well formed.
pub fn validate(a: &SystemAssessment) -> Result<(), AssessmentError> {
    let ps = problems(a);
    if ps.is_empty() { Ok(()) } else { Err(AssessmentError::Invalid(ps)) }
}

// ------------------------------------------------------------ outcomes

/// The assessment outcome of one rule-check verdict. `not_applicable` is not
/// an outcome: it belongs in the finding's exclusions.
pub fn outcome_of_verdict(v: CheckVerdict) -> Option<AssessmentOutcome> {
    match v {
        CheckVerdict::Violated => Some(AssessmentOutcome::ViolationFound),
        CheckVerdict::SatisfiedOnObservedExecution => Some(AssessmentOutcome::NoViolationObservedWithinScope),
        CheckVerdict::Unknown => Some(AssessmentOutcome::UnknownOrIncomplete),
        CheckVerdict::Unexercised => Some(AssessmentOutcome::NotExercised),
        CheckVerdict::NotApplicable => None,
    }
}

/// The outcome of one rule over many trials of a bounded method: any
/// violation is a violation; otherwise any unknown makes it unknown; otherwise
/// any satisfied trial means no violation was observed within scope; otherwise
/// (no trial reached it, or only not_applicable) it was not exercised. Never
/// a proof.
pub fn outcome_of_verdicts(vs: &[CheckVerdict]) -> AssessmentOutcome {
    let has = |x: CheckVerdict| vs.contains(&x);
    if has(CheckVerdict::Violated) {
        AssessmentOutcome::ViolationFound
    } else if has(CheckVerdict::Unknown) {
        AssessmentOutcome::UnknownOrIncomplete
    } else if has(CheckVerdict::SatisfiedOnObservedExecution) {
        AssessmentOutcome::NoViolationObservedWithinScope
    } else {
        AssessmentOutcome::NotExercised
    }
}

/// The conservative summary of a manifest (see `AssessmentSummary` in the
/// contract). A rule without a finding counts as not exercised.
pub fn summarize(m: &AssessmentManifest) -> AssessmentSummary {
    use AssessmentOutcome::*;
    let mut s = AssessmentSummary {
        outcome: UnknownOrIncomplete,
        violation_found: vec![],
        no_violation_observed: vec![],
        unknown_or_incomplete: vec![],
        not_exercised: vec![],
        proved: vec![],
        incomplete_required: vec![],
        missing_evidence: vec![],
    };
    let mut required = 0usize;
    let mut required_proved = 0usize;
    for r in &m.rules {
        let id = r.rule.id.clone();
        let outcome = m.findings.iter().find(|f| f.rule == id).map(|f| f.outcome).unwrap_or(NotExercised);
        match outcome {
            ViolationFound => s.violation_found.push(id.clone()),
            NoViolationObservedWithinScope => s.no_violation_observed.push(id.clone()),
            UnknownOrIncomplete => s.unknown_or_incomplete.push(id.clone()),
            NotExercised => s.not_exercised.push(id.clone()),
            ProvedForDeclaredModel => s.proved.push(id.clone()),
        }
        if r.required {
            required += 1;
            match outcome {
                UnknownOrIncomplete | NotExercised => s.incomplete_required.push(id),
                ProvedForDeclaredModel => required_proved += 1,
                _ => {}
            }
        }
    }
    s.missing_evidence =
        m.evidence.iter().filter(|e| e.required && e.payload == PayloadState::Deleted).map(|e| e.id.clone()).collect();
    s.outcome = if !s.violation_found.is_empty() {
        ViolationFound
    } else if required == 0 || !s.incomplete_required.is_empty() || !s.missing_evidence.is_empty() {
        UnknownOrIncomplete
    } else if required_proved == required {
        ProvedForDeclaredModel
    } else {
        NoViolationObservedWithinScope
    };
    s
}

// ------------------------------------------------------------ validation

fn modes_of(k: AssessmentMethodKind) -> &'static [RuleMode] {
    match k {
        AssessmentMethodKind::BoundedExploration
        | AssessmentMethodKind::RecordedReplay
        | AssessmentMethodKind::FixVerification => &[RuleMode::Explore],
        AssessmentMethodKind::RuntimeEvidence => &[RuleMode::Guard, RuleMode::Prove],
        AssessmentMethodKind::FormalModelCheck => &[],
    }
}

fn proof_capable(m: &AssessmentMethod) -> bool {
    m.kind == AssessmentMethodKind::FormalModelCheck && m.model.is_some()
}

/// Every problem with a decoded assessment, in a stable order.
pub fn problems(a: &SystemAssessment) -> Vec<Problem> {
    use AssessmentOutcome::*;
    let m = &a.manifest;
    let mut out = vec![];
    let mut p = |code: Code, at: String, detail: String| out.push(Problem { code, at, detail });

    let expected = assessment_id(m);
    if a.id != expected {
        p(Code::IdMismatch, "$.id".into(), format!("id is {} but the manifest's content id is {expected}", a.id));
    }
    match (m.artifact, &m.derived_from) {
        (AssessmentArtifactKind::RedactedDerivative, None) => p(
            Code::DerivationInconsistent,
            "$.manifest.derived_from".into(),
            "a redacted derivative must name the assessment it was derived from".into(),
        ),
        (k, Some(_)) if k != AssessmentArtifactKind::RedactedDerivative => p(
            Code::DerivationInconsistent,
            "$.manifest.derived_from".into(),
            format!("only a redacted derivative names an original, not an artifact of kind {}", k.as_str()),
        ),
        _ => {}
    }
    if m.assessed_from_ms > m.assessed_to_ms || m.assessed_to_ms > m.issued_ms {
        p(
            Code::TimesOutOfOrder,
            "$.manifest.assessed_from_ms".into(),
            format!(
                "assessed from {} to {} and issued at {}: the window must end at or before issuance",
                m.assessed_from_ms, m.assessed_to_ms, m.issued_ms
            ),
        );
    }
    if m.subject.revision.is_none() && m.subject.build.is_none() {
        p(
            Code::SubjectWithoutIdentity,
            "$.manifest.subject".into(),
            "the subject names neither a revision nor a build digest".into(),
        );
    }

    // Rules.
    let mut rules: BTreeMap<&Id, &AssessmentRule> = BTreeMap::new();
    for (i, r) in m.rules.iter().enumerate() {
        let at = format!("$.manifest.rules[{i}]");
        if rules.insert(&r.rule.id, r).is_some() {
            p(Code::DuplicateRule, at.clone(), format!("rule {} is declared twice", r.rule.id));
        }
        let d = Digest::of(&r.rule.meaning.encode());
        if d != r.rule.digest {
            p(
                Code::RuleDigestMismatch,
                format!("{at}.rule.digest"),
                format!("rule {} declares digest {} but its meaning digests to {d}", r.rule.id, r.rule.digest),
            );
        }
        for (j, b) in r.bindings.iter().enumerate() {
            if b.rule != r.rule.id || b.rule_digest != r.rule.digest {
                p(
                    Code::BindingForOtherRule,
                    format!("{at}.bindings[{j}]"),
                    format!(
                        "binding pins {} {} but the rule is {} {}",
                        b.rule, b.rule_digest, r.rule.id, r.rule.digest
                    ),
                );
            }
        }
    }

    // Methods.
    let mut methods: BTreeMap<&Id, &AssessmentMethod> = BTreeMap::new();
    for (i, x) in m.methods.iter().enumerate() {
        let at = format!("$.manifest.methods[{i}]");
        if methods.insert(&x.id, x).is_some() {
            p(Code::DuplicateMethod, at.clone(), format!("method {} is declared twice", x.id));
        }
        let formal = x.kind == AssessmentMethodKind::FormalModelCheck;
        if formal != x.model.is_some() {
            p(
                Code::ModelDeclarationInconsistent,
                format!("{at}.model"),
                if formal {
                    format!("formal model check {} declares no model", x.id)
                } else {
                    format!("method {} of kind {} declares a formal model", x.id, x.kind.as_str())
                },
            );
        }
        if x.kind == AssessmentMethodKind::BoundedExploration && x.budget.is_none() {
            p(
                Code::BoundedMethodWithoutBudget,
                format!("{at}.budget"),
                format!("bounded exploration {} states no budget, so its scope is unknown", x.id),
            );
        }
        for (j, r) in x.unexercised_rules.iter().enumerate() {
            if !rules.contains_key(r) {
                p(
                    Code::UnknownRule,
                    format!("{at}.unexercised_rules[{j}]"),
                    format!("method {} lists undeclared rule {r}", x.id),
                );
            }
        }
    }

    // Evidence.
    let mut evidence: BTreeSet<&Id> = BTreeSet::new();
    for (i, e) in m.evidence.iter().enumerate() {
        if !evidence.insert(&e.id) {
            p(
                Code::DuplicateEvidence,
                format!("$.manifest.evidence[{i}]"),
                format!("evidence {} is declared twice", e.id),
            );
        }
    }
    let cite = |p: &mut dyn FnMut(Code, String, String), ids: &[Id], at: &str| {
        for (j, id) in ids.iter().enumerate() {
            if !evidence.contains(id) {
                p(Code::UnknownEvidence, format!("{at}[{j}]"), format!("{id} is not a declared evidence item"));
            }
        }
    };

    // Findings.
    let mut seen: BTreeSet<&Id> = BTreeSet::new();
    for (i, f) in m.findings.iter().enumerate() {
        let at = format!("$.manifest.findings[{i}]");
        let rule = rules.get(&f.rule).copied();
        match rule {
            None => p(Code::UnknownRule, format!("{at}.rule"), format!("finding for undeclared rule {}", f.rule)),
            Some(r) if r.rule.digest != f.rule_digest => p(
                Code::FindingRuleDigestMismatch,
                format!("{at}.rule_digest"),
                format!("finding pins {} but rule {} is {}", f.rule_digest, f.rule, r.rule.digest),
            ),
            Some(_) => {}
        }
        if !seen.insert(&f.rule) {
            p(Code::DuplicateFinding, at.clone(), format!("rule {} has more than one finding", f.rule));
        }
        let method = methods.get(&f.method).copied();
        if method.is_none() {
            p(Code::UnknownMethod, format!("{at}.method"), format!("finding cites undeclared method {}", f.method));
        }
        cite(&mut p, &f.evidence, &format!("{at}.evidence"));
        if f.outcome == ProvedForDeclaredModel && !method.is_some_and(proof_capable) {
            p(
                Code::ProofWithoutFormalModel,
                format!("{at}.outcome"),
                format!(
                    "rule {} claims proved_for_declared_model but method {} is not a formal model check of a declared model; bounded testing never proves a rule",
                    f.rule, f.method
                ),
            );
        }
        if let Some(x) = method {
            if x.unexercised_rules.contains(&f.rule) && f.outcome != NotExercised {
                p(
                    Code::UnexercisedRuleOverclaims,
                    format!("{at}.outcome"),
                    format!(
                        "method {} lists {} as unexercised but the finding says {}",
                        x.id,
                        f.rule,
                        f.outcome.as_str()
                    ),
                );
            }
            if let Some(r) = rule
                && !matches!(f.outcome, NotExercised | UnknownOrIncomplete)
            {
                let modes = modes_of(x.kind);
                let relevant: Vec<&RuleBinding> = r.bindings.iter().filter(|b| modes.contains(&b.mode)).collect();
                if !relevant.is_empty()
                    && relevant.iter().all(|b| matches!(b.support, BindingSupport::Unsupported { .. }))
                {
                    p(
                        Code::UnsupportedBindingOverclaims,
                        format!("{at}.outcome"),
                        format!(
                            "rule {} is unsupported in the mode method {} uses, so its outcome can only be not_exercised or unknown_or_incomplete, not {}",
                            f.rule,
                            x.id,
                            f.outcome.as_str()
                        ),
                    );
                }
            }
        }
        for (j, act) in f.actions.iter().enumerate() {
            let aat = format!("{at}.actions[{j}]");
            let bad = match (act.dispatch, act.effect) {
                (DispatchState::NotDispatched, e) => e != EffectState::NotExecuted,
                (DispatchState::Dispatched, EffectState::NotExecuted) => true,
                _ => false,
            };
            if bad {
                p(
                    Code::ActionStatesInconsistent,
                    aat.clone(),
                    format!(
                        "dispatch {} with effect {}: a request never sent has no effect, and a sent one is not 'not executed'",
                        act.dispatch.as_str(),
                        act.effect.as_str()
                    ),
                );
            }
            cite(&mut p, &act.evidence, &format!("{aat}.evidence"));
        }
    }
    for (i, r) in m.rules.iter().enumerate() {
        if !seen.contains(&r.rule.id) {
            p(
                Code::RuleWithoutFinding,
                format!("$.manifest.rules[{i}]"),
                format!("rule {} has no finding; a rule that was not assessed must say not_exercised", r.rule.id),
            );
        }
    }

    // Claim.
    for (j, d) in m.claim.dependencies.iter().enumerate() {
        if !evidence.contains(d) && !d.as_str().starts_with(ID_PREFIX) {
            p(
                Code::UnknownEvidence,
                format!("$.manifest.claim.dependencies[{j}]"),
                format!("{d} is neither a declared evidence item nor an assessment id"),
            );
        }
    }
    if m.claim.kind == AssessmentClaimKind::FormalModelResult {
        let proved = m
            .findings
            .iter()
            .any(|f| f.outcome == ProvedForDeclaredModel && methods.get(&f.method).copied().is_some_and(proof_capable));
        if !proved {
            p(
                Code::ClaimOverstatesMethod,
                "$.manifest.claim.kind".into(),
                "a formal_model_result claim needs a rule proved by a formal model check of a declared model".into(),
            );
        }
    }

    // Summary.
    let s = summarize(m);
    if s != m.summary {
        p(
            Code::SummaryMismatch,
            "$.manifest.summary".into(),
            format!(
                "the stored summary ({}) differs from the conservative recomputation ({})",
                m.summary.outcome.as_str(),
                s.outcome.as_str()
            ),
        );
    }
    out
}

// ------------------------------------------------------------ bindings

/// What a reader expects an assessment to be about. Absent and empty fields
/// are not checked. `rules` and `evidence`, when given, must match exactly
/// (same ids, same digests, nothing extra); `config` and `dependencies` must
/// match for every key given.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Expected {
    pub revision: Option<Digest>,
    pub build: Option<Digest>,
    pub environment: Option<Digest>,
    pub config: BTreeMap<String, Digest>,
    pub dependencies: BTreeMap<String, Digest>,
    pub rules: BTreeMap<Id, Digest>,
    pub evidence: BTreeMap<Id, Digest>,
}

/// Which identity binding differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BindingKind {
    Revision,
    Build,
    Environment,
    Config,
    Dependency,
    Rule,
    Evidence,
}

impl BindingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BindingKind::Revision => "revision",
            BindingKind::Build => "build",
            BindingKind::Environment => "environment",
            BindingKind::Config => "config",
            BindingKind::Dependency => "dependency",
            BindingKind::Rule => "rule",
            BindingKind::Evidence => "evidence",
        }
    }
}

/// One binding that differs: what kind, which name (a config key, rule or
/// evidence id; empty for revision, build and environment), and the expected
/// and found digests (absent when that side has none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingMismatch {
    pub binding: BindingKind,
    pub name: String,
    pub expected: Option<Digest>,
    pub found: Option<Digest>,
}

fn compare_one(out: &mut Vec<BindingMismatch>, kind: BindingKind, expected: &Option<Digest>, found: Option<&Digest>) {
    if let Some(e) = expected
        && found != Some(e)
    {
        out.push(BindingMismatch {
            binding: kind,
            name: String::new(),
            expected: Some(e.clone()),
            found: found.cloned(),
        });
    }
}

fn compare_map<K: Ord + ToString>(
    out: &mut Vec<BindingMismatch>,
    kind: BindingKind,
    expected: &BTreeMap<K, Digest>,
    found: &BTreeMap<K, Digest>,
    exact: bool,
) {
    for (k, e) in expected {
        if found.get(k) != Some(e) {
            out.push(BindingMismatch {
                binding: kind,
                name: k.to_string(),
                expected: Some(e.clone()),
                found: found.get(k).cloned(),
            });
        }
    }
    if exact && !expected.is_empty() {
        for (k, f) in found {
            if !expected.contains_key(k) {
                out.push(BindingMismatch {
                    binding: kind,
                    name: k.to_string(),
                    expected: None,
                    found: Some(f.clone()),
                });
            }
        }
    }
}

/// Compare a manifest with what the reader expects and name every identity
/// binding that differs (empty: every binding asked about matches). This
/// says nothing about integrity: a forged manifest can name the right subject.
pub fn check_bindings(m: &AssessmentManifest, expected: &Expected) -> Vec<BindingMismatch> {
    let mut out = vec![];
    compare_one(&mut out, BindingKind::Revision, &expected.revision, m.subject.revision.as_ref().map(|r| &r.digest));
    compare_one(&mut out, BindingKind::Build, &expected.build, m.subject.build.as_ref());
    compare_one(&mut out, BindingKind::Environment, &expected.environment, m.subject.environment.as_ref());
    compare_map(&mut out, BindingKind::Config, &expected.config, &m.subject.config, false);
    compare_map(&mut out, BindingKind::Dependency, &expected.dependencies, &m.subject.dependencies, false);
    let rules: BTreeMap<Id, Digest> = m.rules.iter().map(|r| (r.rule.id.clone(), r.rule.digest.clone())).collect();
    compare_map(&mut out, BindingKind::Rule, &expected.rules, &rules, true);
    let evidence: BTreeMap<Id, Digest> = m.evidence.iter().map(|e| (e.id.clone(), e.digest.clone())).collect();
    compare_map(&mut out, BindingKind::Evidence, &expected.evidence, &evidence, true);
    out
}
