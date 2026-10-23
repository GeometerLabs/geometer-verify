//! Receiver-side protocol guard.
//!
//! Every effectful command carries session, execution context (with its
//! fencing generation), sequence and command identity. geo/1 envelopes are
//! migrated to a test-trial context before checking. The guard accepts a command at most once:
//! a retransmission with the same command id and identical bytes is reported
//! as `duplicate` with no effect; stale sessions/trials/generations and
//! out-of-order sequences are rejected; a decision can be applied once, and
//! only with one of its eligible alternatives. Command acceptance is not the
//! completed effect: the caller acknowledges application separately.

use crate::codec::{Canon, Digest, Id};
use crate::generated::{
    AdapterManifest, Command, CommandStatus, Decision, ExecutionContext, Footprint, Observation, PROTOCOL, Phase,
};
use std::collections::{BTreeMap, VecDeque};

/// Remembered command ids per generation (bounded).
pub const DEDUP_WINDOW: usize = 4096;

// Effects are short-lived; boxing the observation would only add churn.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    Hello(AdapterManifest),
    Observe(Observation),
    Offer(Decision),
    Apply { decision: Id, choice: Id },
    Ack { of: Id, status: CommandStatus, detail: Option<String> },
    Settle { decision: Id, choice: Id, phase: Phase, accesses: Option<Vec<Footprint>>, detail: Option<String> },
    Reset(u64),
    Stop(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Receipt {
    pub status: CommandStatus,
    /// Present only when this receipt authorizes a new effect.
    pub effect: Option<Effect>,
    pub detail: String,
}

impl Receipt {
    fn reject(status: CommandStatus, detail: impl Into<String>) -> Self {
        Receipt { status, effect: None, detail: detail.into() }
    }
}

pub struct SessionGuard {
    session: Id,
    context: ExecutionContext,
    next_seq: u64,
    seen: BTreeMap<Id, (Digest, CommandStatus)>,
    seen_order: VecDeque<Id>,
    offered: BTreeMap<Id, Decision>,
    applied: BTreeMap<Id, Id>,
    stopped: bool,
}

impl SessionGuard {
    /// A guard for one test trial at a reset generation.
    pub fn new(session: Id, trial: Id, generation: u64) -> Self {
        Self::with_context(session, ExecutionContext::TestTrial { campaign: None, trial, generation: Some(generation) })
    }

    /// A guard for any execution context. A test context must carry its
    /// generation: without one nothing could be fenced.
    pub fn with_context(session: Id, context: ExecutionContext) -> Self {
        assert!(
            !matches!(context, ExecutionContext::TestTrial { generation: None, .. }),
            "a guarded test trial needs a generation"
        );
        SessionGuard {
            session,
            context,
            next_seq: 0,
            seen: BTreeMap::new(),
            seen_order: VecDeque::new(),
            offered: BTreeMap::new(),
            applied: BTreeMap::new(),
            stopped: false,
        }
    }

    /// The fencing generation: reset generation of a test trial, or policy
    /// generation of a production session.
    pub fn generation(&self) -> u64 {
        match &self.context {
            ExecutionContext::TestTrial { generation, .. } => generation.unwrap_or(0),
            ExecutionContext::ProductionSession { policy_generation, .. } => *policy_generation,
        }
    }

    pub fn context(&self) -> &ExecutionContext {
        &self.context
    }

    /// Register a decision this side offered, so an `apply` can be validated.
    pub fn note_offered(&mut self, d: Decision) {
        self.offered.insert(d.id.clone(), d);
    }

    /// Move to a new trial (after a verified reset); all decisions, sequence
    /// numbers and remembered command ids of the old trial become stale.
    /// Production sessions are never reset; they have no next trial.
    pub fn begin_trial(&mut self, trial: Id, generation: u64) {
        let ExecutionContext::TestTrial { campaign, .. } = &self.context else {
            panic!("a production session has no trials");
        };
        assert!(generation > self.generation(), "generation must increase");
        self.context = ExecutionContext::TestTrial { campaign: campaign.clone(), trial, generation: Some(generation) };
        self.next_seq = 0;
        self.seen.clear();
        self.seen_order.clear();
        self.offered.clear();
        self.applied.clear();
        self.stopped = false;
    }

    fn remember(&mut self, id: Id, digest: Digest, status: CommandStatus) {
        if self.seen_order.len() >= DEDUP_WINDOW
            && let Some(old) = self.seen_order.pop_front()
        {
            self.seen.remove(&old);
        }
        self.seen_order.push_back(id.clone());
        self.seen.insert(id, (digest, status));
    }

    pub fn receive(&mut self, bytes: &[u8]) -> Receipt {
        let env = match crate::compat::decode_envelope(bytes) {
            Ok(e) => e,
            Err(e) => return Receipt::reject(CommandStatus::RejectedInvalid, e.to_string()),
        };
        if env.protocol != PROTOCOL {
            return Receipt::reject(CommandStatus::RejectedInvalid, format!("protocol {} not supported", env.protocol));
        }
        if env.session != self.session || env.context != self.context {
            return Receipt::reject(
                CommandStatus::RejectedStale,
                format!(
                    "envelope for {} {} but guard is at {} {}",
                    env.session,
                    String::from_utf8_lossy(&env.context.encode()),
                    self.session,
                    String::from_utf8_lossy(&self.context.encode())
                ),
            );
        }
        // Canonical digest of what was received: identical retransmissions
        // are recognisable regardless of the sender's whitespace/key order.
        let digest = Digest::of(&env.encode());
        if let Some((d, status)) = self.seen.get(&env.command) {
            return if *d == digest {
                Receipt {
                    status: CommandStatus::Duplicate,
                    effect: None,
                    detail: format!("already {}", status.as_str()),
                }
            } else {
                Receipt::reject(CommandStatus::RejectedInvalid, "command id reused with different content")
            };
        }
        if env.seq != self.next_seq {
            return Receipt::reject(
                CommandStatus::RejectedOutOfOrder,
                format!("expected seq {}, got {}", self.next_seq, env.seq),
            );
        }
        if self.stopped {
            return Receipt::reject(CommandStatus::RejectedStale, "session stopped");
        }
        let (status, effect, detail) = match env.body {
            Command::Hello { adapter } => (CommandStatus::Accepted, Some(Effect::Hello(adapter)), String::new()),
            Command::Observe { observation } => {
                if observation.context != self.context {
                    (CommandStatus::RejectedStale, None, "observation for another context".into())
                } else {
                    (CommandStatus::Accepted, Some(Effect::Observe(observation)), String::new())
                }
            }
            Command::Offer { decision } => {
                if decision.context != self.context {
                    (CommandStatus::RejectedStale, None, "decision for another context".into())
                } else if self.offered.contains_key(&decision.id) {
                    (CommandStatus::RejectedInvalid, None, "decision id already offered".into())
                } else {
                    self.offered.insert(decision.id.clone(), decision.clone());
                    (CommandStatus::Accepted, Some(Effect::Offer(decision)), String::new())
                }
            }
            Command::Apply { decision, choice } => match self.offered.get(&decision) {
                None => (CommandStatus::RejectedInvalid, None, format!("decision {decision} was not offered")),
                Some(_) if self.applied.contains_key(&decision) => {
                    // A second permit for the same decision never dispatches twice.
                    (
                        CommandStatus::Duplicate,
                        None,
                        format!("decision {decision} already applied with {}", self.applied[&decision]),
                    )
                }
                Some(d) if !d.eligible.iter().any(|a| a.id == choice) => {
                    (CommandStatus::RejectedInvalid, None, format!("{choice} is not eligible for {decision}"))
                }
                Some(_) => {
                    self.applied.insert(decision.clone(), choice.clone());
                    (CommandStatus::Applied, Some(Effect::Apply { decision, choice }), String::new())
                }
            },
            Command::Ack { of, status, detail } => {
                (CommandStatus::Accepted, Some(Effect::Ack { of, status, detail }), String::new())
            }
            // Settlement of an operation this session saw offered; whether it
            // was permitted and dispatched is the explorer's ledger's check.
            Command::Settle { decision, choice, phase, accesses, detail } => match self.offered.get(&decision) {
                None => (CommandStatus::RejectedInvalid, None, format!("decision {decision} was not offered")),
                Some(d) if !d.eligible.iter().any(|a| a.id == choice) => {
                    (CommandStatus::RejectedInvalid, None, format!("{choice} is not eligible for {decision}"))
                }
                Some(_) => (
                    CommandStatus::Accepted,
                    Some(Effect::Settle { decision, choice, phase, accesses, detail }),
                    String::new(),
                ),
            },
            Command::Reset { generation } => {
                if matches!(self.context, ExecutionContext::ProductionSession { .. }) {
                    (CommandStatus::RejectedInvalid, None, "production sessions are never reset".into())
                } else if generation <= self.generation() {
                    (
                        CommandStatus::RejectedStale,
                        None,
                        format!("reset to generation {generation} not after {}", self.generation()),
                    )
                } else {
                    (CommandStatus::Accepted, Some(Effect::Reset(generation)), String::new())
                }
            }
            Command::Stop { reason } => {
                self.stopped = true;
                (CommandStatus::Accepted, Some(Effect::Stop(reason)), String::new())
            }
        };
        // Sequence advances for every well-formed in-order command, including
        // rejected bodies, so the sender can continue deterministically.
        self.next_seq += 1;
        self.remember(env.command, digest, status);
        Receipt { status, effect, detail }
    }
}
