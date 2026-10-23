//! Endpoint policy decisions and the safe-test claim.
//!
//! Decisions are per connection by hostname and port. An IP literal never
//! matches a hostname rule, so reaching a service by address instead of
//! name falls to the default. A redirect is a new connection and is decided
//! again. These are the policy's semantics; the sandbox network enforces them.

use crate::generated::{EndpointAction, EndpointPolicy, EndpointPurpose, Fidelity, ModelAccess, ToolContract};

fn normalize(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn is_ip_literal(h: &str) -> bool {
    let h = h.trim_start_matches('[').trim_end_matches(']');
    h.parse::<std::net::IpAddr>().is_ok()
}

fn host_matches(rule: &str, host: &str) -> bool {
    let rule = normalize(rule);
    match rule.strip_prefix("*.") {
        Some(suffix) => host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}")),
        None => rule == host,
    }
}

/// The action for one connection attempt. First matching rule wins.
pub fn decide(p: &EndpointPolicy, host: &str, port: u32) -> EndpointAction {
    let h = normalize(host);
    if is_ip_literal(&h) {
        return p.default;
    }
    p.rules
        .iter()
        .find(|r| host_matches(&r.host, &h) && (r.ports.is_empty() || r.ports.contains(&port)))
        .map(|r| r.action)
        .unwrap_or(p.default)
}

/// Whether a run under this policy, with these tool bindings, may be called
/// a safe test (no live effects). Every reason it may not is returned.
pub fn safe_test_claim(p: &EndpointPolicy, tools: &[ToolContract]) -> Result<(), Vec<String>> {
    let mut why = vec![];
    if p.purpose != EndpointPurpose::Test {
        why.push(format!("purpose is {}, not test", p.purpose.as_str()));
    }
    if p.default != EndpointAction::Deny {
        why.push(format!("default action is {}, not deny", p.default.as_str()));
    }
    for r in &p.rules {
        if r.action == EndpointAction::RouteToDouble && r.target.is_none() {
            why.push(format!("{} routes to a double without naming the binding", r.host));
        }
        if r.action == EndpointAction::Allow && r.host.starts_with("*.") {
            why.push(format!("wildcard allow {} can reach uncontrolled hosts", r.host));
        }
    }
    for t in tools {
        if t.fidelity == Fidelity::Live {
            why.push(format!("tool {}.{} is bound live", t.tool, t.operation));
        }
    }
    // A live model broker is only acceptable when no tool can take a live effect.
    if p.model_access == ModelAccess::Broker && tools.iter().any(|t| t.fidelity != Fidelity::Simulated) {
        why.push("a live model broker is combined with non-simulated tools".into());
    }
    if why.is_empty() { Ok(()) } else { Err(why) }
}
