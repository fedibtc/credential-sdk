//! Holder authorization protocol types.
//!
//! These types describe holder-signed authorizations that allow an auxiliary
//! subject key to present holder credentials without sharing the holder key.

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sha2::{digest::Output, Digest, Sha256};
use std::str::FromStr;

use crate::{
    canonical::canonicalize_holder_authorization,
    serde::Sha256DigestBase64UrlUnpadded,
    types::{
        verify_identity_signature_with_key, ProtocolV1, SchnorrSignatureProof, SignedCredential,
    },
    CredentialsError,
};

/// Domain separator for holder authorization identity signatures.
pub const HOLDER_AUTHORIZATION_SIGNATURE_DOMAIN_SEPARATOR: &[u8] =
    b"fedi-credential/holder-authorization-signature/v1\0";

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

/// Unix timestamp in seconds.
///
/// Serializes as a JSON number while keeping protocol timestamp fields strongly
/// typed in Rust.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// Return the timestamp as seconds since the Unix epoch.
    pub const fn as_secs(self) -> u64 {
        self.0
    }
}

impl From<u64> for Timestamp {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Timestamp> for u64 {
    fn from(value: Timestamp) -> Self {
        value.0
    }
}

/// Application input used by a holder context to create a signed authorization.
///
/// The caller supplies the credentials being delegated. The SDK derives
/// `holder_id_pubkey` from `HolderContext` and derives `trust_badge_id` from
/// the supplied credential using `Credential::digest()`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HolderAuthorizationRequest {
    /// The auxiliary key or actor that the holder authorizes.
    pub subject_pubkey: SubjectPubkey,

    /// Credential this authorization grants the subject permission to present.
    pub credential: SignedCredential,
}

impl HolderAuthorizationRequest {
    /// Convert this application input into the canonical statement to sign.
    pub fn into_statement(
        self,
        holder_id_pubkey: HolderId,
        issued_at: Timestamp,
    ) -> Result<HolderAuthorizationStatement, CredentialsError> {
        let trust_badge_id = TrustBadgeId(self.credential.credential.digest()?);

        Ok(HolderAuthorizationStatement {
            holder_id_pubkey,
            subject_pubkey: self.subject_pubkey,
            trust_badge_id,
            issued_at,
            authorization_id: String::new(),
        })
    }
}

/// Unsigned statement authorizing an auxiliary public key to present credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HolderAuthorizationStatement {
    /// The holder making the authorization.
    pub holder_id_pubkey: HolderId,

    /// The auxiliary key or actor that the holder authorizes.
    pub subject_pubkey: SubjectPubkey,

    /// Credential digest this authorization grants the subject permission to present.
    pub trust_badge_id: TrustBadgeId,

    /// Unix timestamp in seconds.
    pub issued_at: Timestamp,

    /// Future-proof application-chosen id.
    ///
    /// MVP code signs and preserves this field, but does not use it for
    /// replacement, replay tracking, or revocation.
    pub authorization_id: String,
}

impl HolderAuthorizationStatement {
    /// Compute the signature digest for this holder authorization statement.
    pub fn digest(&self) -> Result<Output<Sha256>, CredentialsError> {
        let canonical = canonicalize_holder_authorization(self)?;
        Ok(Sha256::new()
            .chain_update(HOLDER_AUTHORIZATION_SIGNATURE_DOMAIN_SEPARATOR)
            .chain_update(canonical)
            .finalize())
    }
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

impl HolderAuthorization {
    /// Compute the signature digest for this holder authorization payload.
    pub fn digest(&self) -> Result<Output<Sha256>, CredentialsError> {
        self.authorization.digest()
    }

    /// Verify this authorization's holder signature and return the statement.
    pub fn verify(&self) -> Result<HolderAuthorizationStatement, CredentialsError> {
        verify_identity_signature_with_key(
            &self.authorization.holder_id_pubkey.0,
            &self.proof.signature,
            nostr::secp256k1::Message::from_digest(self.digest()?.into()),
        )?;

        Ok(self.authorization.clone())
    }
}
