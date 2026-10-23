//! Endpoint policy and tool fidelity.

use geo_contracts::endpoint::{decide, safe_test_claim};
use geo_contracts::intent::admit_receipt;
use geo_contracts::*;
use std::collections::BTreeMap;

fn rule(host: &str, ports: Vec<u32>, action: EndpointAction, target: Option<&str>) -> EndpointRule {
    EndpointRule { host: host.into(), ports, action, target: target.map(|t| Id::new(t).unwrap()) }
}

fn test_policy() -> EndpointPolicy {
    EndpointPolicy {
        purpose: EndpointPurpose::Test,
        default: EndpointAction::Deny,
        rules: vec![
            rule("api.stripe.com", vec![443], EndpointAction::RouteToDouble, Some("payments-double")),
            rule("orders-db", vec![5432], EndpointAction::Allow, None),
        ],
        model_access: ModelAccess::Recorded,
        enforcement: "test".into(),
    }
}

fn tool(fidelity: Fidelity, receipt_lookup: bool) -> ToolContract {
    ToolContract {
        tool: Id::new("payments").unwrap(),
        operation: "refund".into(),
        semantics: "refund/1".into(),
        input_schema: None,
        effect_class: EffectClass::Effect,
        intent_key: IntentKey::Fields { names: vec!["refund_request".into()] },
        authority: vec![],
        units: BTreeMap::new(),
        provider_idempotency: None,
        receipt_lookup,
        fidelity,
        reset_scope: "account".into(),
        receipt: None,
    }
}

#[test]
fn bypass_attempts_fall_to_deny() {
    let p = test_policy();
    assert_eq!(decide(&p, "api.stripe.com", 443), EndpointAction::RouteToDouble);
    assert_eq!(decide(&p, "API.Stripe.com.", 443), EndpointAction::RouteToDouble);
    // Alternate IP literal, other port, lookalike and parent domains are not the rule's host.
    for (h, port) in [
        ("54.187.216.72", 443),
        ("[2600:1f14::1]", 443),
        ("api.stripe.com", 80),
        ("api.stripe.com.evil.example", 443),
        ("stripe.com", 443),
        ("files.stripe.com", 443),
    ] {
        assert_eq!(decide(&p, h, port), EndpointAction::Deny, "{h}:{port}");
    }
    let mut w = p.clone();
    w.rules.push(rule("*.example.test", vec![], EndpointAction::Allow, None));
    assert_eq!(decide(&w, "a.example.test", 1), EndpointAction::Allow);
    assert_eq!(decide(&w, "example.test", 1), EndpointAction::Deny);
}

#[test]
fn safe_test_claim_needs_test_purpose_default_deny_and_no_live_effects() {
    assert!(safe_test_claim(&test_policy(), &[tool(Fidelity::Simulated, true)]).is_ok());
    // Open discovery is never a safe test.
    let open = EndpointPolicy {
        purpose: EndpointPurpose::LiveDiscovery,
        default: EndpointAction::Allow,
        rules: vec![],
        model_access: ModelAccess::None,
        enforcement: "open".into(),
    };
    assert_eq!(safe_test_claim(&open, &[]).unwrap_err().len(), 2);
    // A live tool binding, or a live model broker with a provider test account, refuses the claim.
    assert!(safe_test_claim(&test_policy(), &[tool(Fidelity::Live, true)]).is_err());
    let mut brokered = test_policy();
    brokered.model_access = ModelAccess::Broker;
    assert!(safe_test_claim(&brokered, &[tool(Fidelity::Simulated, true)]).is_ok());
    let why = safe_test_claim(&brokered, &[tool(Fidelity::ProviderTestAccount, true)]).unwrap_err();
    assert!(why.iter().any(|w| w.contains("model broker")), "{why:?}");
    // Routing to a double must name it; wildcard allows reach uncontrolled hosts.
    let mut bad = test_policy();
    bad.rules.push(rule("mail.example", vec![], EndpointAction::RouteToDouble, None));
    bad.rules.push(rule("*.amazonaws.com", vec![], EndpointAction::Allow, None));
    assert_eq!(safe_test_claim(&bad, &[]).unwrap_err().len(), 2);
}

#[test]
fn response_only_mock_cannot_prove_a_committed_effect() {
    let ctx = ExecutionContext::TestTrial { campaign: None, trial: Id::new("t1").unwrap(), generation: Some(1) };
    let receipt = |strength| EffectReceipt {
        id: Id::new("rcpt-1").unwrap(),
        context: ctx.clone(),
        attempt: None,
        intent: None,
        provider: Id::new("payments-double").unwrap(),
        operation: "refund".into(),
        provider_account: Id::new("acct-1").unwrap(),
        provider_effect: Some("re_1".into()),
        arguments: Default::default(),
        status: EffectStatus::Committed,
        strength,
        observed_by: Id::new("tool-reply").unwrap(),
        readings: None,
    };
    let mock = tool(Fidelity::Simulated, false);
    assert!(admit_receipt(&mock, &receipt(EvidenceStrength::Proven)).is_err());
    assert!(admit_receipt(&mock, &receipt(EvidenceStrength::Inferred)).is_ok());
    // A stateful double with an independent effect ledger can.
    assert!(admit_receipt(&tool(Fidelity::Simulated, true), &receipt(EvidenceStrength::Proven)).is_ok());
}
