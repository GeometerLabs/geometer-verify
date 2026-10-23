//! Geometer contracts: canonical encoding, portable values, the generated
//! record types from `contracts/schemas`, bounded framing and the adapter
//! protocol session guard.
//!
//! This crate has no dependency on any runtime, database, framework or model
//! provider.

pub mod assessment;
pub mod codec;
pub mod compat;
pub mod endpoint;
pub mod error;
pub mod framing;
pub mod intent;
pub mod json;
pub mod redact;
pub mod session;
pub mod value;

#[rustfmt::skip]
pub mod generated;

pub use codec::{Bytes, Canon, Digest, Id};
pub use error::{DecodeError, ErrorClass};
pub use generated::*;
pub use value::Value;
