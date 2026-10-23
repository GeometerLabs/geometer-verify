//! Geometer contracts: canonical encoding, portable values and the generated record types from
//! `contracts/schemas`, plus the assessment rules the verifier uses.
//!
//! This crate has no dependency on any runtime, database, framework or model provider.

pub mod assessment;
pub mod codec;
pub mod error;
pub mod json;
pub mod value;

#[rustfmt::skip]
pub mod generated;

pub use codec::{Bytes, Canon, Digest, Id};
pub use error::{DecodeError, ErrorClass};
pub use generated::*;
pub use value::Value;
