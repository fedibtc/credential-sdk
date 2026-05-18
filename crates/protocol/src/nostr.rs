//! Nostr integration for protocol-level revocations.
//!
//! This module deliberately does not fetch from relays. Callers provide Nostr
//! events they already trust enough to inspect; this module verifies event
//! identity/signature and maps valid revocation events into core protocol
//! [`Revocation`] values.

use ::nostr::{Event, Kind};
use sha2::{digest::Output, Sha256};
use thiserror::Error;

use crate::{IssuerId, Revocation};

/// Custom Nostr kind used for credential revocation events.
///
/// This is an application-level placeholder until a stable NIP/custom kind is
/// assigned. Revocation events of other kinds are ignored by
/// [`revocation_from_event`].
pub const REVOCATION_EVENT_KIND_NUMBER: u16 = 7_777;

/// Custom Nostr kind used for credential revocation events.
pub const REVOCATION_EVENT_KIND: Kind = Kind::Custom(REVOCATION_EVENT_KIND_NUMBER);

/// Tag name carrying the SHA-256 digest of the finalized credential.
///
/// Expected tag shape:
///
/// `["credential_digest", "<64 lowercase/uppercase hex sha256 digest>"]`
pub const CREDENTIAL_DIGEST_TAG: &str = "credential_digest";

/// Errors returned while validating a Nostr revocation event.
#[derive(Debug, Error)]
pub enum RevocationEventError {
    /// The Nostr event id or signature is invalid.
    #[error("invalid Nostr event: {0}")]
    InvalidEvent(#[source] ::nostr::event::Error),
    /// A revocation event did not include a credential digest tag.
    #[error("missing {tag:?} tag", tag = CREDENTIAL_DIGEST_TAG)]
    MissingCredentialDigestTag,
    /// A credential digest tag was present but was not a 32-byte hex digest.
    #[error("invalid credential digest: {0:?}")]
    InvalidCredentialDigest(String),
}

/// Validate a Nostr event as a credential revocation.
///
/// Returns `Ok(None)` for events whose kind is not [`REVOCATION_EVENT_KIND`].
/// For revocation-kind events, verifies the event id and Schnorr signature,
/// extracts the issuer from `event.pubkey`, and parses the
/// [`CREDENTIAL_DIGEST_TAG`] tag into a [`Revocation`].
pub fn revocation_from_event(event: &Event) -> Result<Option<Revocation>, RevocationEventError> {
    if event.kind != REVOCATION_EVENT_KIND {
        return Ok(None);
    }

    event.verify().map_err(RevocationEventError::InvalidEvent)?;

    let credential_digest = event
        .tags
        .iter()
        .find_map(|tag| {
            let values = tag.as_slice();
            (values.first().map(String::as_str) == Some(CREDENTIAL_DIGEST_TAG))
                .then(|| values.get(1))
                .flatten()
        })
        .ok_or(RevocationEventError::MissingCredentialDigestTag)
        .and_then(|digest| parse_sha256_hex(digest))?;

    Ok(Some(Revocation {
        issuer_id: IssuerId(event.pubkey),
        credential_digest,
    }))
}

fn parse_sha256_hex(digest: &str) -> Result<Output<Sha256>, RevocationEventError> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(digest, &mut bytes)
        .map_err(|_| RevocationEventError::InvalidCredentialDigest(digest.to_owned()))?;

    Ok(bytes.into())
}
