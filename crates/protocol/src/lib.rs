//! Core protocol types for Fedi-style privacy-preserving credentials.
//!
//! This crate intentionally keeps application semantics out of the core
//! protocol. Credential `info` and `blind_msg` fields are arbitrary JSON values;
//! callers decide what schema, issuer identifiers, holder identifiers, and
//! claims mean.

pub mod canonical;
pub mod nostr;
pub mod types;

pub use canonical::*;
pub use nostr::*;
pub use types::*;
