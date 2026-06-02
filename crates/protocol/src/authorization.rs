//! Holder authorization protocol types.
//!
//! These types describe holder-signed authorizations that allow an auxiliary
//! subject key to present holder credentials without sharing the holder key.
//! This module is provisional until canonical serialization, digesting, signing,
//! verification APIs, and test vectors land.

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sha2::{digest::Output, Sha256};
use std::str::FromStr;

use crate::serde::Sha256DigestBase64UrlUnpadded;
use crate::types::{IssuerId, ProtocolV1, SchnorrSignatureProof};

/// Public identity of a credential holder.
///
/// This intentionally mirrors `IssuerId`: holder identities are Nostr public
/// keys encoded with the SDK's existing Nostr key serialization.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HolderId(pub nostr::PublicKey);

impl FromStr for HolderId {
    type Err = nostr::key::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        nostr::PublicKey::parse(value).map(Self)
    }
}

/// Public identity of the auxiliary key or actor authorized by the holder.
///
/// V1 keeps this as a Nostr public key, matching `IssuerId` and `HolderId`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SubjectPubkey(pub nostr::PublicKey);

impl FromStr for SubjectPubkey {
    type Err = nostr::key::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        nostr::PublicKey::parse(value).map(Self)
    }
}

/// Stable identifier for the credential or trust badge being delegated.
///
/// This is the same canonical credential digest form already used by
/// `Revocation.credential_digest`: `Credential::digest()` over canonical
/// `Credential`, encoded as unpadded URL-safe base64 on the JSON wire.
#[serde_as]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TrustBadgeId(#[serde_as(as = "Sha256DigestBase64UrlUnpadded")] pub Output<Sha256>);

/// A credential selected for holder-authorized presentation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct CredentialRef {
    /// Issuer id from `SignedCredential.credential.issuer_id_pubkey`.
    pub issuer_id_pubkey: IssuerId,

    /// Credential digest, also used as the trust badge id.
    pub trust_badge_id: TrustBadgeId,
}

/// Holder authorization scope.
///
/// Present is the only defined MVP value. Scope-specific verifier policy is
/// reserved for future protocol work; MVP verification only checks that the
/// authorization is valid for the credential, holder, subject, audience, and
/// time window.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HolderAuthorizationScope {
    Present,
}

/// Unsigned statement authorizing an auxiliary public key to present credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HolderAuthorizationStatement {
    /// The holder making the authorization.
    pub holder_id_pubkey: HolderId,

    /// The auxiliary key or actor that the holder authorizes.
    pub subject_pubkey: SubjectPubkey,

    /// Opaque application-defined audience or relying-party identifier.
    pub audience: String,

    /// Credentials this authorization grants the subject permission to present.
    pub credential_refs: Vec<CredentialRef>,

    /// Future-proof scope field.
    ///
    /// MVP code signs and preserves this field but does not implement
    /// scope-specific verifier policy.
    pub scope: Vec<HolderAuthorizationScope>,

    /// Unix timestamp in seconds.
    pub issued_at: u64,

    /// Unix timestamp in seconds.
    pub expires_at: u64,

    /// Future-proof application-chosen id.
    ///
    /// MVP code signs and preserves this field, but does not use it for
    /// replacement, replay tracking, or revocation.
    pub authorization_id: String,
}

/// Holder-signed authorization.
///
/// This intentionally stays close to upstream `SignedCredential { version,
/// credential, proof }`: a versioned signed claim plus a proof. The difference is
/// that this is a direct holder identity signature over an unblinded statement,
/// not an issuer PBRSA proof over a blind-issued credential.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HolderAuthorization {
    /// Protocol version for this shape.
    pub version: ProtocolV1,

    /// Statement signed by the holder.
    pub authorization: HolderAuthorizationStatement,

    /// Holder signature over canonical `authorization` with a versioned domain
    /// separator such as `fedi-credential/holder-authorization-signature/v1\0`.
    pub proof: SchnorrSignatureProof,
}
