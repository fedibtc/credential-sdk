//! Core protocol types for Fedi-style privacy-preserving credentials.
//!
//! This crate intentionally keeps application semantics out of the core
//! protocol. Credential `info` and `blind_msg` fields are arbitrary JSON values;
//! callers decide what schema, holder identifiers, and claims mean.

pub mod canonical;
pub mod holder;
pub mod issuer;
pub mod nostr;
pub mod pbrsa;
pub mod types;
pub mod verifier;

pub use canonical::*;
pub use holder::*;
pub use issuer::*;
pub use nostr::*;
pub use pbrsa::*;
pub use types::*;
pub use verifier::*;
