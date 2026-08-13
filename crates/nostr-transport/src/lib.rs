//! Nostr helpers for standalone holder credential publication.
//!
//! This crate validates the kind-37702 transport envelope. It does not interpret
//! schema-specific `blind_msg` values. The application must validate the
//! credential schema, resolve its holder public key, and supply that key here.

use fedi_credential_sdk_protocol::{credential_digest, CredentialDigest, SignedCredential};
use nostr::{Event, Kind, PublicKey, Tag, Timestamp, UnsignedEvent};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Provisional addressable kind for a standalone holder credential event.
pub const KIND_HOLDER_CREDENTIAL: Kind = Kind::Custom(37_702);
/// Required address prefix for the credential digest.
pub const CREDENTIAL_D_TAG_PREFIX: &str = "credential:";
/// Required topic tag for standalone credentials.
pub const CREDENTIAL_TOPIC: &str = "fedi-credential";

/// A fully validated standalone holder credential publication.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ParsedHolderCredentialEvent {
    pub event: Event,
    pub credential: SignedCredential,
    pub credential_digest: CredentialDigest,
}

/// Error returned by standalone credential event preparation or validation.
#[derive(Debug, Error)]
pub enum NostrTransportError {
    #[error("failed to serialize or parse credential JSON: {0}")]
    CredentialJson(#[from] serde_json::Error),
    #[error("failed to compute credential digest: {0}")]
    CredentialDigest(#[from] fedi_credential_sdk_protocol::CredentialsError),
    #[error("invalid Nostr event signature or id")]
    InvalidEventSignature,
    #[error("unexpected Nostr event kind")]
    WrongKind,
    #[error("standalone credential event must contain exactly one valid d tag")]
    InvalidDTag,
    #[error("standalone credential event is missing its required topic tag")]
    MissingTopicTag,
    #[error("standalone credential event must contain one holder p tag")]
    InvalidPTag,
    #[error("credential digest does not match the d tag")]
    DigestMismatch,
    #[error("event author does not match the expected credential holder")]
    HolderMismatch,
}

/// Prepare an unsigned kind-37702 event for an external signer.
///
/// Content uses the ordinary SDK JSON representation. JCS is used only by the
/// protocol credential digest. The caller must obtain `holder_pubkey` by
/// validating the credential with its application-specific schema.
pub fn prepare_holder_credential_event(
    holder_pubkey: PublicKey,
    credential: &SignedCredential,
    created_at: Timestamp,
) -> Result<UnsignedEvent, NostrTransportError> {
    let digest = digest_string(&credential_digest(credential)?)?;
    let d_tag = Tag::parse(["d", &format!("{CREDENTIAL_D_TAG_PREFIX}{digest}")])
        .map_err(|_| NostrTransportError::InvalidDTag)?;
    let t_tag =
        Tag::parse(["t", CREDENTIAL_TOPIC]).map_err(|_| NostrTransportError::MissingTopicTag)?;
    let p_tag = Tag::parse(["p", &holder_pubkey.to_string()])
        .map_err(|_| NostrTransportError::InvalidPTag)?;

    Ok(UnsignedEvent::new(
        holder_pubkey,
        created_at,
        KIND_HOLDER_CREDENTIAL,
        [d_tag, t_tag, p_tag],
        serde_json::to_string(credential)?,
    ))
}

/// Parse and validate a signed kind-37702 holder credential event.
///
/// The caller must validate the credential schema and resolve
/// `expected_holder_pubkey` from it. This function then verifies that the event
/// author and holder `p` tag match that key.
pub fn parse_holder_credential_event(
    event: &Event,
    expected_holder_pubkey: &PublicKey,
) -> Result<ParsedHolderCredentialEvent, NostrTransportError> {
    event
        .verify()
        .map_err(|_| NostrTransportError::InvalidEventSignature)?;
    if event.kind != KIND_HOLDER_CREDENTIAL {
        return Err(NostrTransportError::WrongKind);
    }
    if !event.tags.iter().any(|tag| {
        tag.as_slice().len() == 2
            && tag.as_slice()[0] == "t"
            && tag.as_slice()[1] == CREDENTIAL_TOPIC
    }) {
        return Err(NostrTransportError::MissingTopicTag);
    }

    require_holder(event, expected_holder_pubkey)?;
    let tagged_digest = parse_d_tag(event)?;
    let credential: SignedCredential = serde_json::from_str(&event.content)?;
    let actual_digest = credential_digest(&credential)?;
    if actual_digest != tagged_digest {
        return Err(NostrTransportError::DigestMismatch);
    }
    Ok(ParsedHolderCredentialEvent {
        event: event.clone(),
        credential,
        credential_digest: actual_digest,
    })
}

/// Validate all candidates before selecting the newest publication.
pub fn select_newest_valid_holder_credential_event<'a>(
    events: impl IntoIterator<Item = &'a Event>,
    expected_holder_pubkey: &PublicKey,
) -> Option<ParsedHolderCredentialEvent> {
    events
        .into_iter()
        .filter_map(|event| parse_holder_credential_event(event, expected_holder_pubkey).ok())
        .max_by_key(|parsed| parsed.event.created_at)
}

fn parse_d_tag(event: &Event) -> Result<CredentialDigest, NostrTransportError> {
    let value = exactly_one_two_element_tag(event, "d").ok_or(NostrTransportError::InvalidDTag)?;
    let digest = value
        .strip_prefix(CREDENTIAL_D_TAG_PREFIX)
        .filter(|digest| !digest.is_empty())
        .ok_or(NostrTransportError::InvalidDTag)?;

    serde_json::from_value(serde_json::Value::String(digest.to_owned()))
        .map_err(|_| NostrTransportError::InvalidDTag)
}

fn require_holder(
    event: &Event,
    expected_holder_pubkey: &PublicKey,
) -> Result<(), NostrTransportError> {
    if &event.pubkey != expected_holder_pubkey {
        return Err(NostrTransportError::HolderMismatch);
    }
    let value = exactly_one_two_element_tag(event, "p").ok_or(NostrTransportError::InvalidPTag)?;
    if value != expected_holder_pubkey.to_string() {
        return Err(NostrTransportError::InvalidPTag);
    }
    Ok(())
}

fn exactly_one_two_element_tag<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    let mut tags = event
        .tags
        .iter()
        .filter(|tag| tag.as_slice().first().map(String::as_str) == Some(name));
    let tag = tags.next()?;
    if tags.next().is_some() || tag.as_slice().len() != 2 {
        return None;
    }
    Some(tag.as_slice()[1].as_str())
}

fn digest_string(digest: &CredentialDigest) -> Result<String, serde_json::Error> {
    let value = serde_json::to_value(digest)?;
    value
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| serde_json::Error::io(std::io::Error::other("digest was not a string")))
}

#[cfg(test)]
mod tests;
