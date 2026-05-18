use blind_rsa_signatures::{
    BlindMessage as PbrsaBlindMessage, BlindSignature as PbrsaBlindSignature,
    Signature as PbrsaSignature,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use serde_with::{base64::Base64, base64::UrlSafe, formats::Unpadded, serde_as};
use sha2::{digest::Output, Sha256};

/// Unpadded URL-safe base64 encoding used for byte fields in JSON.
type Base64UrlUnpadded = Base64<UrlSafe, Unpadded>;

/// Protocol version used by the MVP credential format.
///
/// Version 1 implies the v1 canonicalization and blind-signature suite choices;
/// those are not repeated as per-credential `suite`/`alg` fields.
pub const PROTOCOL_VERSION_V1: ProtocolVersion = ProtocolVersion(1);

/// Protocol version.
///
/// Only version 1 is currently supported. Deserialization rejects all other
/// version numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ProtocolVersion(pub u16);

impl<'de> Deserialize<'de> for ProtocolVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let version = u16::deserialize(deserializer)?;
        if version == PROTOCOL_VERSION_V1.0 {
            Ok(Self(version))
        } else {
            Err(serde::de::Error::custom(format_args!(
                "unsupported protocol version: {version}"
            )))
        }
    }
}

/// Issuer identifier.
///
/// Issuer identities are hard-bound to Nostr public keys. Revocation events for
/// a credential must be signed by the same Nostr public key carried here.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IssuerId(pub nostr::PublicKey);

/// Final holder credential.
///
/// `info` is the JSON value visible to the issuer during issuance.
/// `blind_msg` is the JSON value hidden from the issuer while signing and
/// disclosed in the final credential. For the current Fedi/Nostr use case this
/// will likely contain a Nostr holder public key, but that is application data,
/// not a protocol-level field.
///
/// The credential revocation digest is computed over the full canonical form of
/// this object, including `signature`.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Credential {
    pub version: ProtocolVersion,
    pub issuer_id: IssuerId,
    pub info: Value,
    pub blind_msg: Value,
    /// PBRSA credential signature bytes.
    ///
    /// Serializes as unpadded URL-safe base64.
    #[serde_as(as = "Base64UrlUnpadded")]
    pub signature: PbrsaSignature,
}

/// Request produced by a holder during issuance.
///
/// The holder keeps the original unblinded `blind_msg` locally and sends only
/// the blinded message to the issuer.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceRequest {
    pub version: ProtocolVersion,
    /// PBRSA blinded message bytes sent by the holder during issuance.
    ///
    /// Serializes as unpadded URL-safe base64.
    #[serde_as(as = "Base64UrlUnpadded")]
    pub blinded_message: PbrsaBlindMessage,
}

/// Response produced by an issuer during issuance.
///
/// The response includes the issuer-selected public JSON and the blind
/// signature. The holder combines this with their original unblinded `blind_msg`
/// to assemble a final [`Credential`].
#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IssuanceResponse {
    pub version: ProtocolVersion,
    pub issuer_id: IssuerId,
    pub public: Value,
    /// PBRSA blind signature bytes returned by the issuer during issuance.
    ///
    /// Serializes as unpadded URL-safe base64.
    #[serde_as(as = "Base64UrlUnpadded")]
    pub blind_signature: PbrsaBlindSignature,
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
