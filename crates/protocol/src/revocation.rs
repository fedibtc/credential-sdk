//! Issuer bundle and revocation support.
//!
//! This module is intentionally outside the core issuance and credential
//! verification flow. Revocation transport, issuer-bundle publication, and
//! trust-list policy can change without breaking the core credential protocol.

use std::str::FromStr;

use ::nostr::{Event, Kind};
use nostr::secp256k1::{schnorr::Signature, Message};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, base64::UrlSafe, formats::Unpadded, serde_as};
use sha2::{digest::Output, Digest, Sha256};
use thiserror::Error;

use crate::{
    canonicalize_issuer_bundle, canonicalize_revocation, CredentialsError, IssuerId, PbrsaPublicKey,
};

/// Unpadded URL-safe base64 encoding used for byte fields in JSON.
type Base64UrlUnpadded = Base64<UrlSafe, Unpadded>;

/// Signed issuer metadata used by verifiers before accepting credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerBundle {
    pub issuer: Issuer,
    pub proof: SignatureProof,
}

/// Issuer metadata signed by the issuer identity key.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issuer {
    pub issuer_id_pubkey: IssuerId,
    /// DER-encoded PBRSA public key used to verify credentials.
    ///
    /// Serializes as unpadded URL-safe base64.
    #[serde_as(as = "Base64UrlUnpadded")]
    // review: it shouldn't be Vec<u8> should be actual key
    pub issuance_key: Vec<u8>,
    pub revocation: Vec<RevocationLocation>,
}

/// Location where issuer revocations may be published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationLocation {
    pub protocol: String,
    pub location: String,
}

/// Schnorr signature proof encoded as a 64-byte hex string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureProof {
    pub signature: String,
}

/// Runtime revocation target.
///
/// Authentication, discovery, and wire serialization of revocations are handled
/// by an external trust or transport layer, e.g. Nostr events signed by an
/// issuer key. The core protocol only needs the issuer and finalized credential
/// digest that a revocation targets.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Revocation {
    pub issuer_id: IssuerId,
    pub credential_digest: Output<Sha256>,
}

/// Signed revocation wire object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRevocation {
    pub revocation: RevocationEntry,
    pub proof: IssuerSignatureProof,
}

/// Revocation payload signed by the issuer identity key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// Hex-encoded SHA-256 digest of the finalized credential.
    pub credential_digest: String,
}

/// Issuer identity proof for a signed revocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerSignatureProof {
    pub issuer_id_pubkey: IssuerId,
    /// Schnorr signature proof encoded as a 64-byte hex string.
    pub signature: String,
}

/// Domain separator for issuer bundle identity signatures.
pub const ISSUER_BUNDLE_SIGNATURE_DOMAIN_SEPARATOR: &[u8] =
    b"fedi-credential/issuer-bundle-signature/v1\0";

/// Domain separator for revocation identity signatures.
pub const REVOCATION_SIGNATURE_DOMAIN_SEPARATOR: &[u8] =
    b"fedi-credential/revocation-signature/v1\0";

/// Custom Nostr kind used for credential revocation events.
///
/// This is an application-level placeholder until a stable NIP/custom kind is
/// assigned. Revocation events of other kinds are ignored by
/// revocation_from_event.
pub const REVOCATION_EVENT_KIND_NUMBER: u16 = 7_777;

/// Custom Nostr kind used for credential revocation events.
pub const REVOCATION_EVENT_KIND: Kind = Kind::Custom(REVOCATION_EVENT_KIND_NUMBER);

/// Tag name carrying the SHA-256 digest of the finalized credential.
///
/// Expected tag shape:
///
/// ["credential_digest", "<64 lowercase/uppercase hex sha256 digest>"]
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

/// Verify a signed issuer bundle.
pub fn verify_issuer_bundle(bundle: &IssuerBundle) -> Result<(), CredentialsError> {
    validate_revocation_locations(&bundle.issuer.revocation)?;
    PbrsaPublicKey::from_der(&bundle.issuer.issuance_key)?;

    let signing_message = signing_message(
        ISSUER_BUNDLE_SIGNATURE_DOMAIN_SEPARATOR,
        &canonicalize_issuer_bundle(&bundle.issuer)?,
    );
    verify_identity_signature(
        &bundle.issuer.issuer_id_pubkey,
        &bundle.proof.signature,
        signing_message,
    )
}

/// Verify a signed revocation object.
pub fn verify_revocation(revocation: &SignedRevocation) -> Result<(), CredentialsError> {
    parse_sha256_hex(&revocation.revocation.credential_digest)?;
    let signing_message = signing_message(
        REVOCATION_SIGNATURE_DOMAIN_SEPARATOR,
        &canonicalize_revocation(&revocation.revocation)?,
    );

    verify_identity_signature(
        &revocation.proof.issuer_id_pubkey,
        &revocation.proof.signature,
        signing_message,
    )
}

pub(crate) fn verified_revocation(
    revocation: &SignedRevocation,
) -> Result<Revocation, CredentialsError> {
    verify_revocation(revocation)?;
    let credential_digest = parse_sha256_hex(&revocation.revocation.credential_digest)?;

    Ok(Revocation {
        issuer_id: revocation.proof.issuer_id_pubkey.clone(),
        credential_digest,
    })
}

/// Validate a Nostr event as a credential revocation.
///
/// Returns Ok(None) for events whose kind is not REVOCATION_EVENT_KIND.
/// For revocation-kind events, verifies the event id and Schnorr signature,
/// extracts the issuer from event.pubkey, and parses the
/// CREDENTIAL_DIGEST_TAG tag into a Revocation.
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
        .and_then(|digest| parse_event_sha256_hex(digest))?;

    Ok(Some(Revocation {
        issuer_id: IssuerId(event.pubkey),
        credential_digest,
    }))
}

fn validate_revocation_locations(locations: &[RevocationLocation]) -> Result<(), CredentialsError> {
    if locations
        .iter()
        .any(|location| location.protocol.is_empty() || location.location.is_empty())
    {
        return Err(CredentialsError::VerificationFailed);
    }

    Ok(())
}

pub(crate) fn signing_message(domain_separator: &[u8], canonical_payload: &[u8]) -> Message {
    let digest = Sha256::new()
        .chain_update(domain_separator)
        .chain_update(canonical_payload)
        .finalize();

    Message::from_digest(digest.into())
}

fn verify_identity_signature(
    issuer_id: &IssuerId,
    signature: &str,
    message: Message,
) -> Result<(), CredentialsError> {
    let signature =
        Signature::from_str(signature).map_err(|_| CredentialsError::VerificationFailed)?;
    let public_key = issuer_id
        .0
        .xonly()
        .map_err(|_| CredentialsError::VerificationFailed)?;

    nostr::SECP256K1
        .verify_schnorr(&signature, &message, &public_key)
        .map_err(|_| CredentialsError::VerificationFailed)
}

fn parse_sha256_hex(digest: &str) -> Result<Output<Sha256>, CredentialsError> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(digest, &mut bytes).map_err(|_| CredentialsError::VerificationFailed)?;

    Ok(bytes.into())
}

fn parse_event_sha256_hex(digest: &str) -> Result<Output<Sha256>, RevocationEventError> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(digest, &mut bytes)
        .map_err(|_| RevocationEventError::InvalidCredentialDigest(digest.to_owned()))?;

    Ok(bytes.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{canonicalize_issuer_bundle, canonicalize_revocation, IssuerContext};

    fn sign(keys: &nostr::Keys, domain_separator: &[u8], canonical_payload: &[u8]) -> String {
        keys.sign_schnorr(&signing_message(domain_separator, canonical_payload))
            .to_string()
    }

    fn issuer_bundle(keys: &nostr::Keys) -> IssuerBundle {
        let issuer_id = IssuerId(keys.public_key());
        let issuer_context = IssuerContext::generate(issuer_id.clone(), 1024).unwrap();
        let issuer = Issuer {
            issuer_id_pubkey: issuer_id,
            issuance_key: issuer_context.public_key().to_der().unwrap(),
            revocation: vec![RevocationLocation {
                protocol: "nostr".to_owned(),
                location: "wss://relay.example.com".to_owned(),
            }],
        };
        let signature = sign(
            keys,
            ISSUER_BUNDLE_SIGNATURE_DOMAIN_SEPARATOR,
            &canonicalize_issuer_bundle(&issuer).unwrap(),
        );

        IssuerBundle {
            issuer,
            proof: SignatureProof { signature },
        }
    }

    #[test]
    fn verify_issuer_bundle_accepts_signed_bundle() {
        let keys = nostr::Keys::generate();
        let bundle = issuer_bundle(&keys);

        verify_issuer_bundle(&bundle).unwrap();
    }

    #[test]
    fn verify_issuer_bundle_rejects_tampering() {
        let keys = nostr::Keys::generate();
        let mut bundle = issuer_bundle(&keys);
        bundle.issuer.revocation[0].location = "wss://evil.example.com".to_owned();

        assert!(matches!(
            verify_issuer_bundle(&bundle),
            Err(CredentialsError::VerificationFailed)
        ));
    }

    #[test]
    fn verify_revocation_accepts_signed_revocation() {
        let keys = nostr::Keys::generate();
        let revocation = signed_revocation(&keys, [7u8; 32]);

        verify_revocation(&revocation).unwrap();
    }

    #[test]
    fn verify_revocation_rejects_tampering() {
        let keys = nostr::Keys::generate();
        let mut revocation = signed_revocation(&keys, [7u8; 32]);
        revocation.revocation.credential_digest = hex::encode([8u8; 32]);

        assert!(matches!(
            verify_revocation(&revocation),
            Err(CredentialsError::VerificationFailed)
        ));
    }

    fn signed_revocation(keys: &nostr::Keys, credential_digest: [u8; 32]) -> SignedRevocation {
        let revocation = RevocationEntry {
            credential_digest: hex::encode(credential_digest),
        };
        let signature = sign(
            keys,
            REVOCATION_SIGNATURE_DOMAIN_SEPARATOR,
            &canonicalize_revocation(&revocation).unwrap(),
        );

        SignedRevocation {
            revocation,
            proof: IssuerSignatureProof {
                issuer_id_pubkey: IssuerId(keys.public_key()),
                signature,
            },
        }
    }
}
