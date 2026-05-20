use blind_rsa_signatures::{
    BlindMessage as PbrsaBlindMessage, BlindSignature as PbrsaBlindSignature,
    MessageRandomizer as PbrsaMessageRandomizer, Signature as PbrsaSignature,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use serde_with::{base64::Base64, base64::UrlSafe, formats::Unpadded, serde_as};
use serde_with::{DeserializeAs, SerializeAs};
use sha2::{digest::Output, Digest, Sha256};
use std::str::FromStr;

use crate::{canonicalize_credential, CredentialsError};

/// Unpadded URL-safe base64 encoding used for byte fields in JSON.
type Base64UrlUnpadded = Base64<UrlSafe, Unpadded>;

struct MessageRandomizerBase64UrlUnpadded;

impl SerializeAs<PbrsaMessageRandomizer> for MessageRandomizerBase64UrlUnpadded {
    fn serialize_as<S>(source: &PbrsaMessageRandomizer, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Base64UrlUnpadded::serialize_as(&source.0, serializer)
    }
}

impl<'de> DeserializeAs<'de, PbrsaMessageRandomizer> for MessageRandomizerBase64UrlUnpadded {
    fn deserialize_as<D>(deserializer: D) -> Result<PbrsaMessageRandomizer, D::Error>
    where
        D: Deserializer<'de>,
    {
        Base64UrlUnpadded::deserialize_as(deserializer).map(PbrsaMessageRandomizer)
    }
}

/// Protocol version marker used by the MVP credential format.
///
/// Version 1 implies the v1 canonicalization and blind-signature suite choices;
/// those are not repeated as per-credential `suite`/`alg` fields.
///
/// Serializes as the JSON number `1`. Deserialization rejects all other version
/// numbers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolV1;

impl Serialize for ProtocolV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(1)
    }
}

impl<'de> Deserialize<'de> for ProtocolV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let version = u16::deserialize(deserializer)?;
        if version == 1 {
            Ok(Self)
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

impl FromStr for IssuerId {
    type Err = nostr::key::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        nostr::PublicKey::parse(value).map(Self)
    }
}

/// Domain separator prepended to canonical credential JSON before hashing.
pub const CREDENTIAL_DIGEST_DOMAIN_SEPARATOR: &[u8] = b"fedi-credential/credential-digest/v1\0";

/// Final holder credential.
///
/// `info` is the JSON value visible to the issuer during issuance.
/// `blind_msg` is the JSON value hidden from the issuer while signing and
/// disclosed in the final credential. For the current Fedi/Nostr use case this
/// will likely contain a Nostr holder public key, but that is application data,
/// not a protocol-level field.
///
/// The credential revocation digest is computed over the full canonical form of
/// this object, including `message_randomizer` and `signature`.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Credential {
    pub version: ProtocolV1,
    pub issuer_id: IssuerId,
    pub info: Value,
    pub blind_msg: Value,
    /// PBRSA message randomizer used when preparing the signed message.
    ///
    /// The randomized PBRSA suite requires this value to verify the finalized
    /// signature. It serializes as unpadded URL-safe base64.
    #[serde_as(as = "MessageRandomizerBase64UrlUnpadded")]
    pub message_randomizer: PbrsaMessageRandomizer,
    /// PBRSA credential signature bytes.
    ///
    /// Serializes as unpadded URL-safe base64.
    #[serde_as(as = "Base64UrlUnpadded")]
    pub signature: PbrsaSignature,
}

impl Credential {
    /// Compute the revocation digest for this finalized credential.
    ///
    /// The digest is `SHA256(domain_separator || canonical_credential_json)`,
    /// where `canonical_credential_json` is the RFC 8785 / JCS canonical JSON
    /// form of the full serialized credential, including `signature`.
    pub fn digest(&self) -> Result<Output<Sha256>, CredentialsError> {
        let canonical = canonicalize_credential(self)?;

        let mut hasher = Sha256::new();
        hasher.update(CREDENTIAL_DIGEST_DOMAIN_SEPARATOR);
        hasher.update(canonical);
        Ok(hasher.finalize())
    }
}

/// Request produced by a holder during issuance.
///
/// The holder keeps the original unblinded `blind_msg` locally and sends only
/// the blinded message to the issuer.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceRequest {
    pub version: ProtocolV1,
    /// PBRSA blinded message bytes sent by the holder during issuance.
    ///
    /// Serializes as unpadded URL-safe base64.
    #[serde_as(as = "Base64UrlUnpadded")]
    pub blinded_message: PbrsaBlindMessage,
}

/// Response produced by an issuer during issuance.
///
/// The response includes the issuer-selected `info` JSON and the blind signature.
/// The holder combines this with their original unblinded `blind_msg` and
/// message randomizer to assemble a final [`Credential`].
#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IssuanceResponse {
    pub version: ProtocolV1,
    pub issuer_id: IssuerId,
    pub info: Value,
    /// PBRSA blind signature bytes returned by the issuer during issuance.
    ///
    /// Serializes as unpadded URL-safe base64.
    #[serde_as(as = "Base64UrlUnpadded")]
    pub blind_signature: PbrsaBlindSignature,
}

#[cfg(test)]
mod tests {
    use blind_rsa_signatures::{
        MessageRandomizer as PbrsaMessageRandomizer, Signature as PbrsaSignature,
    };
    use serde_json::json;
    use sha2::Digest;

    use super::*;

    fn credential() -> Credential {
        Credential {
            version: ProtocolV1,
            issuer_id: IssuerId(nostr::PublicKey::from_byte_array([1u8; 32])),
            info: json!({
                "z": 1,
                "a": {
                    "b": true,
                    "a": false,
                },
            }),
            blind_msg: json!({
                "holder": "alice",
                "nonce": 7,
            }),
            message_randomizer: PbrsaMessageRandomizer([9u8; 32]),
            signature: PbrsaSignature(vec![1, 2, 3, 4]),
        }
    }

    #[test]
    fn credential_message_randomizer_serializes_as_unpadded_url_safe_base64() {
        let credential = Credential {
            version: ProtocolV1,
            issuer_id: IssuerId(nostr::PublicKey::from_byte_array([1u8; 32])),
            info: json!({ "kind": "test" }),
            blind_msg: json!({ "holder": "alice" }),
            message_randomizer: PbrsaMessageRandomizer([0xff; 32]),
            signature: PbrsaSignature(vec![1, 2, 3]),
        };

        let value = serde_json::to_value(&credential).unwrap();
        assert_eq!(
            value["message_randomizer"],
            json!("__________________________________________8")
        );

        let roundtrip: Credential = serde_json::from_value(value).unwrap();
        assert_eq!(roundtrip.message_randomizer, credential.message_randomizer);
    }

    #[test]
    fn digest_hashes_domain_separator_and_canonical_credential_json() {
        let credential = credential();

        let canonical = canonicalize_credential(&credential).unwrap();
        let expected = Sha256::new()
            .chain_update(CREDENTIAL_DIGEST_DOMAIN_SEPARATOR)
            .chain_update(canonical)
            .finalize();

        assert_eq!(credential.digest().unwrap(), expected);
    }

    #[test]
    fn digest_includes_signature() {
        let mut first = credential();
        let mut second = credential();
        first.signature = PbrsaSignature(vec![1, 2, 3, 4]);
        second.signature = PbrsaSignature(vec![1, 2, 3, 5]);

        assert_ne!(first.digest().unwrap(), second.digest().unwrap());
    }
}
