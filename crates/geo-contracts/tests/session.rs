//! Protocol guard behaviour: stale, duplicate and
//! out-of-order commands never cause a second application effect.

use geo_contracts::session::{Effect, SessionGuard};
use geo_contracts::*;
use std::collections::BTreeMap;

fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}

fn test_ctx(trial: &str, generation: u64) -> ExecutionContext {
    ExecutionContext::TestTrial { campaign: None, trial: id(trial), generation: Some(generation) }
}

fn env_in(context: ExecutionContext, seq: u64, cmd: &str, body: Command) -> Vec<u8> {
    Envelope { protocol: PROTOCOL.into(), session: id("s1"), context, seq, command: id(cmd), body }.encode()
}

fn env(trial: &str, generation: u64, seq: u64, cmd: &str, body: Command) -> Vec<u8> {
    env_in(test_ctx(trial, generation), seq, cmd, body)
}

fn decision() -> Decision {
    let alt = |a: &str| Alternative {
        id: id(a),
        op: OperationRef { boundary: Boundary::Sql, name: "update".into() },
        actor: Some(id(a)),
        footprints: vec![],
        enabled_by: None,
        kind: None,
    };
    Decision {
        id: id("d1"),
        context: test_ctx("t1", 1),
        trigger: "two pending writes".into(),
        eligible: vec![alt("a1"), alt("a2")],
        excluded: BTreeMap::new(),
        chosen: None,
    }
}

fn apply(choice: &str) -> Command {
    Command::Apply { decision: id("d1"), choice: id(choice) }
}

#[test]
fn permit_applies_once_and_retransmission_is_duplicate() {
    let mut g = SessionGuard::new(id("s1"), id("t1"), 1);
    g.note_offered(decision());
    let first = env("t1", 1, 0, "c0", apply("a1"));
    let r = g.receive(&first);
    assert_eq!(r.status, CommandStatus::Applied);
    assert_eq!(r.effect, Some(Effect::Apply { decision: id("d1"), choice: id("a1") }));
    // Byte-identical retransmission: acknowledged as duplicate, no effect.
    let r = g.receive(&first);
    assert_eq!((r.status, r.effect), (CommandStatus::Duplicate, None));
    // A new command permitting the same decision again must not dispatch twice.
    let r = g.receive(&env("t1", 1, 1, "c1", apply("a2")));
    assert_eq!((r.status, r.effect), (CommandStatus::Duplicate, None));
}

#[test]
fn reordered_whitespace_retransmission_is_still_duplicate() {
    let mut g = SessionGuard::new(id("s1"), id("t1"), 1);
    g.note_offered(decision());
    let first = env("t1", 1, 0, "c0", apply("a1"));
    assert_eq!(g.receive(&first).status, CommandStatus::Applied);
    let text = String::from_utf8(first).unwrap().replace(",", " , ");
    assert_eq!(g.receive(text.as_bytes()).status, CommandStatus::Duplicate);
}

#[test]
fn command_id_reuse_with_other_content_is_invalid() {
    let mut g = SessionGuard::new(id("s1"), id("t1"), 1);
    g.note_offered(decision());
    assert_eq!(g.receive(&env("t1", 1, 0, "c0", apply("a1"))).status, CommandStatus::Applied);
    let r = g.receive(&env("t1", 1, 1, "c0", Command::Stop { reason: "x".into() }));
    assert_eq!((r.status, r.effect), (CommandStatus::RejectedInvalid, None));
}

#[test]
fn out_of_order_and_gaps_are_rejected() {
    let mut g = SessionGuard::new(id("s1"), id("t1"), 1);
    g.note_offered(decision());
    let r = g.receive(&env("t1", 1, 1, "c1", apply("a1")));
    assert_eq!((r.status, r.effect), (CommandStatus::RejectedOutOfOrder, None));
    assert_eq!(g.receive(&env("t1", 1, 0, "c0", apply("a1"))).status, CommandStatus::Applied);
}

#[test]
fn stale_trial_generation_and_session_are_rejected() {
    let mut g = SessionGuard::new(id("s1"), id("t1"), 1);
    g.note_offered(decision());
    g.begin_trial(id("t2"), 2);
    // A worker still speaking about the previous trial/generation.
    let r = g.receive(&env("t1", 1, 0, "c0", apply("a1")));
    assert_eq!((r.status, r.effect), (CommandStatus::RejectedStale, None));
    let r = g.receive(&env("t2", 1, 0, "c0", apply("a1")));
    assert_eq!(r.status, CommandStatus::RejectedStale);
    let other = Envelope {
        protocol: PROTOCOL.into(),
        session: id("s9"),
        context: test_ctx("t2", 2),
        seq: 0,
        command: id("c0"),
        body: Command::Stop { reason: "x".into() },
    }
    .encode();
    assert_eq!(g.receive(&other).status, CommandStatus::RejectedStale);
    // Decisions of the old trial are gone: applying d1 in t2 is invalid.
    assert_eq!(g.receive(&env("t2", 2, 0, "c0", apply("a1"))).status, CommandStatus::RejectedInvalid);
}

#[test]
fn ineligible_choice_and_unoffered_decision_are_invalid() {
    let mut g = SessionGuard::new(id("s1"), id("t1"), 1);
    assert_eq!(g.receive(&env("t1", 1, 0, "c0", apply("a1"))).status, CommandStatus::RejectedInvalid);
    g.note_offered(decision());
    assert_eq!(g.receive(&env("t1", 1, 1, "c1", apply("zz"))).status, CommandStatus::RejectedInvalid);
    assert_eq!(g.receive(&env("t1", 1, 2, "c2", apply("a2"))).status, CommandStatus::Applied);
}

#[test]
fn reset_must_advance_and_stop_fences_the_session() {
    let mut g = SessionGuard::new(id("s1"), id("t1"), 3);
    assert_eq!(
        g.receive(&env("t1", 3, 0, "c0", Command::Reset { generation: 2 })).status,
        CommandStatus::RejectedStale
    );
    assert_eq!(g.receive(&env("t1", 3, 1, "c1", Command::Reset { generation: 4 })).status, CommandStatus::Accepted);
    assert_eq!(
        g.receive(&env("t1", 3, 2, "c2", Command::Stop { reason: "done".into() })).status,
        CommandStatus::Accepted
    );
    assert_eq!(
        g.receive(&env("t1", 3, 3, "c3", Command::Stop { reason: "again".into() })).status,
        CommandStatus::RejectedStale
    );
}

#[test]
fn malformed_bytes_are_invalid_not_panics() {
    let mut g = SessionGuard::new(id("s1"), id("t1"), 1);
    for bad in [&b"{"[..], b"[]", b"{\"protocol\":\"geo/1\"}", &[0xff, 0xfe]] {
        assert_eq!(g.receive(bad).status, CommandStatus::RejectedInvalid);
    }
    let wrong = String::from_utf8(env("t1", 1, 0, "c0", Command::Stop { reason: "x".into() }))
        .unwrap()
        .replace("geo/2", "geo/9");
    assert_eq!(g.receive(wrong.as_bytes()).status, CommandStatus::RejectedInvalid);
}

fn prod(tenant: &str, policy_generation: u64) -> ExecutionContext {
    ExecutionContext::ProductionSession {
        tenant: id(tenant),
        deployment: id("dep-1"),
        session: id("ps-1"),
        policy_generation,
    }
}

// a geo/1 envelope (bare trial + generation) is read as a test trial.
#[test]
fn legacy_geo1_envelope_migrates_to_a_test_trial() {
    let mut g = SessionGuard::new(id("s1"), id("t1"), 1);
    g.note_offered(decision());
    let legacy = br#"{"protocol":"geo/1","session":"s1","trial":"t1","generation":"1","seq":"0","command":"c0","body":{"kind":"apply","decision":"d1","choice":"a1"}}"#;
    assert_eq!(g.receive(legacy).status, CommandStatus::Applied);
    // Its retransmission is recognised after migration.
    assert_eq!(g.receive(legacy).status, CommandStatus::Duplicate);
    // A geo/1 envelope for another generation is stale, not silently re-fenced.
    let old = br#"{"protocol":"geo/1","session":"s1","trial":"t1","generation":"0","seq":"1","command":"c1","body":{"kind":"stop","reason":"x"}}"#;
    assert_eq!(g.receive(old).status, CommandStatus::RejectedStale);
    // Mixing shapes is invalid: a geo/1 envelope cannot also carry a context.
    let mixed = br#"{"protocol":"geo/1","session":"s1","trial":"t1","generation":"1","context":{"kind":"test_trial","trial":"t1","generation":"1"},"seq":"1","command":"c2","body":{"kind":"stop","reason":"x"}}"#;
    assert_eq!(g.receive(mixed).status, CommandStatus::RejectedInvalid);
    // geo/2 never accepts the legacy fields.
    let v2_with_trial = br#"{"protocol":"geo/2","session":"s1","trial":"t1","generation":"1","seq":"1","command":"c3","body":{"kind":"stop","reason":"x"}}"#;
    assert_eq!(g.receive(v2_with_trial).status, CommandStatus::RejectedInvalid);
}

#[test]
fn legacy_observation_outside_an_envelope_keeps_generation_unknown() {
    let o = geo_contracts::compat::decode_observation(
        br#"{"id":"o1","trial":"t1","seq":"0","phase":"committed","source":"x","op":{"boundary":"sql","name":"insert"},"footprints":[],"entities":[],"values":{},"causes":[],"observer":false}"#,
    )
    .unwrap();
    assert_eq!(o.context, ExecutionContext::TestTrial { campaign: None, trial: id("t1"), generation: None });
    // Such a fact is never accepted into a fenced trial.
    let mut g = SessionGuard::new(id("s1"), id("t1"), 1);
    let r = g.receive(&env("t1", 1, 0, "c0", Command::Observe { observation: o }));
    assert_eq!(r.status, CommandStatus::RejectedStale);
}

// production sessions are fenced by policy generation and never reset.
#[test]
fn production_context_is_never_reset_and_is_fenced() {
    let mut g = SessionGuard::with_context(id("s1"), prod("acme", 7));
    let r = g.receive(&env_in(prod("acme", 7), 0, "c0", Command::Reset { generation: 8 }));
    assert_eq!((r.status, r.effect), (CommandStatus::RejectedInvalid, None));
    // Another tenant, an older policy and a test trial are all stale here.
    for (i, c) in [prod("globex", 7), prod("acme", 6), test_ctx("t1", 7)].into_iter().enumerate() {
        let r = g.receive(&env_in(c, 1, &format!("x{i}"), Command::Stop { reason: "x".into() }));
        assert_eq!(r.status, CommandStatus::RejectedStale);
    }
    assert_eq!(
        g.receive(&env_in(prod("acme", 7), 1, "c1", Command::Stop { reason: "x".into() })).status,
        CommandStatus::Accepted
    );
}

#[test]
#[should_panic(expected = "production session has no trials")]
fn production_context_has_no_trials() {
    SessionGuard::with_context(id("s1"), prod("acme", 1)).begin_trial(id("t1"), 2);
}

#[test]
fn settlement_is_accepted_only_for_an_offered_decision_and_eligible_choice() {
    // Explorer side: the guard sees the adapter's offer, then its settlements.
    let mut g = SessionGuard::new(id("s1"), id("t1"), 1);
    let settle = |d: &str, c: &str| Command::Settle {
        decision: id(d),
        choice: id(c),
        phase: Phase::Committed,
        accesses: Some(vec![]),
        detail: None,
    };
    let r = g.receive(&env("t1", 1, 0, "m0", settle("d1", "a1")));
    assert_eq!((r.status, r.effect), (CommandStatus::RejectedInvalid, None), "settle before any offer");
    assert_eq!(
        g.receive(&env("t1", 1, 1, "m1", Command::Offer { decision: decision() })).status,
        CommandStatus::Accepted
    );
    let r = g.receive(&env("t1", 1, 2, "m2", settle("d1", "a9")));
    assert_eq!((r.status, r.effect), (CommandStatus::RejectedInvalid, None), "not an eligible alternative");
    let r = g.receive(&env("t1", 1, 3, "m3", settle("d1", "a1")));
    assert_eq!(r.status, CommandStatus::Accepted);
    assert!(matches!(r.effect, Some(Effect::Settle { phase: Phase::Committed, .. })));
    // A settlement from an earlier trial generation is stale.
    let r = g.receive(&env("t1", 0, 4, "m4", settle("d1", "a1")));
    assert_eq!((r.status, r.effect), (CommandStatus::RejectedStale, None));
}
