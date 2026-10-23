//! Assessment certificate vectors. The same fixture
//! file is run by the TypeScript and Python contract tests; validation and
//! binding checks are Rust only.

use geo_contracts::assessment::{self, AssessmentError, Code, Expected};
use geo_contracts::generated::roundtrip_named;
use geo_contracts::*;
use serde_json::Value as J;
use std::collections::BTreeMap;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/fixtures/assessment/");
const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../");

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn vectors() -> J {
    serde_json::from_slice(&read("vectors.json")).unwrap()
}

fn sha(b: &[u8]) -> String {
    Digest::of(b).to_string()
}

/// Apply `ops` ([["set", pointer, value] | ["remove", pointer]]) to a copy of `base`.
fn mutate(base: &J, ops: &J) -> J {
    let mut v = base.clone();
    for op in ops.as_array().unwrap() {
        let op = op.as_array().unwrap();
        let ptr = op[1].as_str().unwrap();
        let (parent, key) = ptr.rsplit_once('/').unwrap();
        let p = v.pointer_mut(parent).unwrap_or_else(|| panic!("no parent {parent}"));
        match (op[0].as_str().unwrap(), p) {
            ("set", J::Object(m)) => {
                m.insert(key.to_owned(), op[2].clone());
            }
            ("set", J::Array(a)) => a[key.parse::<usize>().unwrap()] = op[2].clone(),
            ("remove", J::Object(m)) => {
                m.remove(key).unwrap_or_else(|| panic!("nothing at {ptr}"));
            }
            ("remove", J::Array(a)) => {
                a.remove(key.parse::<usize>().unwrap());
            }
            ("append", J::Object(m)) => m[key].as_array_mut().unwrap().push(op[2].clone()),
            (o, _) => panic!("bad op {o} at {ptr}"),
        }
    }
    v
}

fn base(c: &J) -> J {
    serde_json::from_slice(&read(c["base"].as_str().unwrap())).unwrap()
}

/// Recompute the id after a mutation, so a vector isolates one problem.
fn reid(v: &mut J) {
    let m = AssessmentManifest::decode(&serde_json::to_vec(&v["manifest"]).unwrap()).unwrap();
    v["id"] = J::String(assessment::assessment_id(&m).to_string());
}

fn input_of(c: &J) -> Vec<u8> {
    match c.get("base") {
        Some(_) => serde_json::to_vec(&mutate(&base(c), &c["ops"])).unwrap(),
        None => c["input"].as_str().unwrap().as_bytes().to_vec(),
    }
}

#[test]
fn manifests_decode_validate_and_derive_their_ids() {
    let v = vectors();
    let mut n = 0;
    for c in v["manifests"].as_array().unwrap() {
        let name = c["file"].as_str().unwrap();
        let a = assessment::decode_assessment(&read(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        let canonical = a.encode();
        assert_eq!(sha(&canonical), c["canonical_sha256"].as_str().unwrap(), "{name} canonical bytes");
        assert_eq!(SystemAssessment::decode(&canonical).unwrap().encode(), canonical, "{name} fixed point");
        assert_eq!(a.id.as_str(), c["assessment_id"].as_str().unwrap(), "{name}");
        assert_eq!(assessment::assessment_id(&a.manifest), a.id, "{name}");
        assert_eq!(a.manifest.summary.outcome.as_str(), c["summary"].as_str().unwrap(), "{name}");
        assert_eq!(assessment::summarize(&a.manifest), a.manifest.summary, "{name}");
        assert_eq!(a.manifest.artifact.as_str(), c["artifact"].as_str().unwrap(), "{name}");
        assert_eq!(a.signatures.len() as u64, c["signatures"].as_u64().unwrap(), "{name}");
        n += 1;
    }
    assert!(n >= 5);
}

#[test]
fn codec_vectors_roundtrip_or_reject_with_the_declared_class() {
    let v = vectors();
    for c in v["codec_positive"].as_array().unwrap() {
        let t = c["type"].as_str().unwrap();
        let out = roundtrip_named(t, &input_of(c)).unwrap_or_else(|e| panic!("{}: {e}", c["id"]));
        assert_eq!(String::from_utf8(out).unwrap(), c["canonical"].as_str().unwrap(), "{}", c["id"]);
    }
    for c in v["codec_negative"].as_array().unwrap() {
        match roundtrip_named(c["type"].as_str().unwrap(), &input_of(c)) {
            Ok(out) => panic!("{} accepted: {}", c["id"], String::from_utf8_lossy(&out)),
            Err(e) => assert_eq!(e.class.as_str(), c["error"].as_str().unwrap(), "{}: {e}", c["id"]),
        }
    }
}

#[test]
fn unknown_schema_versions_and_wrong_ids_are_refused() {
    let v = vectors();
    for c in v["schema"].as_array().unwrap() {
        let err = assessment::decode_assessment(&input_of(c)).expect_err(c["id"].as_str().unwrap());
        assert_eq!(err.codes(), vec![c["refusal"].as_str().unwrap().to_owned()], "{}: {err}", c["id"]);
    }
    // A newer manifest that adds a field is reported as newer, not as an unknown field.
    let c = v["schema"].as_array().unwrap().iter().find(|c| c["id"] == "future-schema-with-new-fields").unwrap();
    assert!(matches!(assessment::decode_assessment(&input_of(c)), Err(AssessmentError::UnsupportedSchemaVersion(_))));
    assert_eq!(SystemAssessment::decode(&input_of(c)).unwrap_err().class.as_str(), "unknown_field");
}

#[test]
fn refusal_vectors_decode_but_fail_validation_with_exactly_their_codes() {
    let v = vectors();
    let mut n = 0;
    for c in v["refusals"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let mut j = mutate(&base(c), &c["ops"]);
        if c["reid"].as_bool().unwrap() {
            reid(&mut j);
        }
        let a = SystemAssessment::decode(&serde_json::to_vec(&j).unwrap()).unwrap_or_else(|e| panic!("{id}: {e}"));
        let mut got: Vec<String> = assessment::problems(&a).iter().map(|p| p.code.as_str().to_owned()).collect();
        let mut want: Vec<String> =
            c["codes"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_owned()).collect();
        got.sort();
        want.sort();
        assert_eq!(got, want, "{id}: {:?}", assessment::problems(&a));
        assert!(assessment::validate(&a).is_err(), "{id}");
        n += 1;
    }
    assert!(n >= 20);
}

fn digest_map(j: &J) -> BTreeMap<String, Digest> {
    j.as_object()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), Digest::parse(v.as_str().unwrap()).unwrap())).collect())
        .unwrap_or_default()
}

fn id_map(j: &J) -> BTreeMap<Id, Digest> {
    digest_map(j).into_iter().map(|(k, v)| (Id::new(k).unwrap(), v)).collect()
}

#[test]
fn binding_vectors_name_the_wrong_binding() {
    let v = vectors();
    for c in v["bindings"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let a = assessment::decode_assessment(&read(c["base"].as_str().unwrap())).unwrap();
        let e = &c["expected"];
        let opt = |k: &str| e.get(k).map(|x| Digest::parse(x.as_str().unwrap()).unwrap());
        let expected = Expected {
            revision: opt("revision"),
            build: opt("build"),
            environment: opt("environment"),
            config: digest_map(&e["config"]),
            dependencies: digest_map(&e["dependencies"]),
            rules: id_map(&e["rules"]),
            evidence: id_map(&e["evidence"]),
        };
        let got: Vec<(String, String)> = assessment::check_bindings(&a.manifest, &expected)
            .iter()
            .map(|m| (m.binding.as_str().to_owned(), m.name.clone()))
            .collect();
        let want: Vec<(String, String)> = c["mismatches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| (m[0].as_str().unwrap().to_owned(), m[1].as_str().unwrap().to_owned()))
            .collect();
        assert_eq!(got, want, "{id}");
    }
}

#[test]
fn verdicts_map_to_outcomes_without_ever_proving() {
    use AssessmentOutcome::*;
    use CheckVerdict::*;
    assert_eq!(assessment::outcome_of_verdict(NotApplicable), None);
    assert_eq!(assessment::outcome_of_verdicts(&[SatisfiedOnObservedExecution, Violated, Unknown]), ViolationFound);
    assert_eq!(assessment::outcome_of_verdicts(&[SatisfiedOnObservedExecution, Unknown]), UnknownOrIncomplete);
    assert_eq!(
        assessment::outcome_of_verdicts(&[SatisfiedOnObservedExecution, Unexercised]),
        NoViolationObservedWithinScope
    );
    assert_eq!(assessment::outcome_of_verdicts(&[Unexercised, NotApplicable]), NotExercised);
    assert_eq!(assessment::outcome_of_verdicts(&[]), NotExercised);
    let all = [Violated, SatisfiedOnObservedExecution, Unknown, Unexercised, NotApplicable];
    for v in all {
        assert_ne!(assessment::outcome_of_verdict(v), Some(ProvedForDeclaredModel));
    }
}

#[test]
fn signatures_and_status_events_are_outside_what_they_hash() {
    let mut a = assessment::decode_assessment(&read("valid-mixed.json")).unwrap();
    // Removing or adding a signature (a new suite is an added entry) keeps the id and validity.
    let sigs = std::mem::take(&mut a.signatures);
    assert!(assessment::validate(&a).is_ok());
    assert_eq!(a.id, assessment::assessment_id(&a.manifest));
    // A signature binds the assessment, suite, algorithm and key.
    let m1 = assessment::signature_message(&a.id, &sigs[0]);
    assert!(m1.starts_with(b"geo-assessment-signature/1\n"));
    let mut other = sigs[0].clone();
    other.algorithm = Id::new("ml-dsa-65").unwrap();
    assert_ne!(m1, assessment::signature_message(&a.id, &other));
    let elsewhere = Id::new(format!("assessment:{}", "0".repeat(64))).unwrap();
    assert_ne!(m1, assessment::signature_message(&elsewhere, &sigs[0]));

    let v = vectors();
    let ev = v["codec_positive"].as_array().unwrap().iter().find(|c| c["id"] == "status-issued").unwrap();
    let e = AssessmentStatusEvent::decode(ev["canonical"].as_str().unwrap().as_bytes()).unwrap();
    let h = assessment::status_event_hash(&e);
    let mut signed = e.clone();
    signed.signatures = sigs.clone();
    signed.hash = h.clone();
    assert_eq!(assessment::status_event_hash(&signed), h, "signatures and the stored hash are not hashed");
    let mut withdrawn = e.clone();
    withdrawn.change = AssessmentStatusChange::Withdrawn { reason: "x".into() };
    assert_ne!(assessment::status_event_hash(&withdrawn), h);
}

#[test]
fn the_refund_agent_example_is_labelled_and_built_from_the_real_sample() {
    let a = assessment::decode_assessment(&read("example-refund-agent.json")).unwrap();
    let m = &a.manifest;
    assert_eq!(m.artifact, AssessmentArtifactKind::Example);
    assert!(a.signatures.is_empty(), "the example is unsigned");
    assert!(m.verification.required_suites.is_empty());
    assert!(m.subject.models.iter().all(|x| x.precision == AssessmentModelPrecision::StandIn));
    assert!(m.findings.iter().all(|f| f.fidelity == Fidelity::Simulated));
    assert_eq!(m.summary.outcome, AssessmentOutcome::ViolationFound);
    assert_eq!(m.summary.incomplete_required.len(), 2, "limits stay visible next to the violation");
    let ids: Vec<&str> = m.rules.iter().map(|r| r.rule.id.as_str()).collect();
    assert_eq!(ids, ["refund-at-most-once", "mail-to-customers-only", "large-refunds-need-approval"]);
    // Cited evidence digests are those of the committed copies beside the
    // fixtures (the example stays about revision 4e36eea even if the sample
    // changes later, so its configuration digests are not compared with the
    // sample's current files).
    assert_eq!(
        m.subject.revision.as_ref().unwrap().vcs.as_ref().unwrap().revision,
        "4e36eea16e365f23e6c5350a747b167c10a46494"
    );
    for e in &m.evidence {
        assert!(e.location.as_ref().unwrap().starts_with("contracts/fixtures/assessment/evidence/"), "{}", e.id);
        let bytes = std::fs::read(format!("{ROOT}{}", e.location.as_ref().unwrap())).unwrap();
        assert_eq!(Digest::of(&bytes), e.digest, "{} changed: regenerate the assessment fixtures", e.id);
    }
}

#[test]
fn every_problem_code_is_exercised_by_a_vector() {
    let v = vectors();
    let mut used: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for c in v["refusals"].as_array().unwrap() {
        used.extend(c["codes"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_owned()));
    }
    for c in v["schema"].as_array().unwrap() {
        used.insert(c["refusal"].as_str().unwrap().to_owned());
    }
    let names: std::collections::BTreeSet<&str> = Code::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(names.len(), Code::ALL.len(), "code names are distinct");
    for c in Code::ALL {
        assert!(used.contains(c.as_str()), "no vector exercises {}", c.as_str());
    }
}

/// Status and renewal formats: a status-record signature, a statement's hash
/// and a renewal's hash each have their own domain tag, ignore the signatures
/// they carry, and bind the record they name.
#[test]
fn status_statement_and_renewal_hashes_are_domain_separated() {
    let v = vectors();
    let pos = |id: &str| -> Vec<u8> {
        let c = v["codec_positive"].as_array().unwrap().iter().find(|c| c["id"] == id).unwrap();
        c["canonical"].as_str().unwrap().as_bytes().to_vec()
    };
    let st = AssessmentStatusStatement::decode(&pos("status-statement")).unwrap();
    let mut unsigned = st.clone();
    unsigned.signatures.clear();
    assert_eq!(assessment::statement_hash(&st), assessment::statement_hash(&unsigned));
    let mut later = st.clone();
    later.as_of_ms += 1;
    assert_ne!(assessment::statement_hash(&st), assessment::statement_hash(&later), "as_of is covered");
    let sig = st.signatures[0].clone();
    let h = assessment::statement_hash(&st);
    let m = assessment::status_signature_message(&h, &st.assessment, &sig);
    assert!(m.starts_with(assessment::STATUS_SIGNATURE_DOMAIN));
    assert_ne!(m, assessment::signature_message(&st.assessment, &sig), "status and assessment signatures differ");
    let other = Digest::of(b"another record");
    assert_ne!(m, assessment::status_signature_message(&other, &st.assessment, &sig));
    let r = AssessmentRenewal::decode(&pos("renewal")).unwrap();
    let mut r2 = r.clone();
    r2.hash = Digest::of(b"x");
    r2.signatures.push(sig);
    assert_eq!(assessment::renewal_hash(&r), assessment::renewal_hash(&r2), "hash and signatures are outside");
    r2.integrity = AssessmentIntegrity::Invalid;
    assert_ne!(assessment::renewal_hash(&r), assessment::renewal_hash(&r2));
    let b = AssessmentBundle::decode(&pos("bundle")).unwrap();
    assert_eq!(b.format, assessment::BUNDLE_FORMAT);
    assert_eq!(b.v, assessment::BUNDLE_VERSION);
    assessment::validate(&b.assessment).unwrap();
}
