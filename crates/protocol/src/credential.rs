use crate::keys::{PbrsaKeyPair, PbrsaPublicKey};
use crate::types::{ByteArray, CredentialData};
use crate::Result;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredentialTemplate {
    pub credential: CredentialBody,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlindSignedCredential {
    pub credential: BlindSignedCredentialBody,
    pub proof: BlindSignatureProof,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifiableCredential {
    pub credential: CredentialBody,
    pub proof: SignatureProof,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredentialBody {
    pub info: CredentialData,
    pub blind_msg: CredentialData,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlindSignedCredentialBody {
    pub info: CredentialData,
    pub blind_msg: ByteArray,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlindSignatureProof {
    pub signature: ByteArray,
    pub blinded_msg: ByteArray,
    pub blind_msg: ByteArray,
    pub info: ByteArray,
    #[serde(rename = "messageRandomizer")]
    pub message_randomizer: ByteArray,
    #[serde(rename = "blindingSecret")]
    pub blinding_secret: ByteArray,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignatureProof {
    pub signature: ByteArray,
}

pub fn create_credential(
    blinded_data: CredentialData,
    visible_data: CredentialData,
) -> Result<CredentialTemplate> {
    ensure_credential_data_object(&blinded_data, "blinded_data")?;
    ensure_credential_data_object(&visible_data, "visible_data")?;

    Ok(CredentialTemplate {
        credential: CredentialBody {
            info: visible_data,
            blind_msg: blinded_data,
        },
    })
}

pub fn blind_sign_credential(
    blinded_data: CredentialData,
    visible_data: CredentialData,
    issuer_keys: &PbrsaKeyPair,
) -> Result<BlindSignedCredential> {
    let _ = (blinded_data, visible_data, issuer_keys);
    todo!("partially blind-sign a credential from visible and blinded data")
}

pub fn finalize_credential(
    signed_credential: BlindSignedCredential,
    issuer_public_key: &PbrsaPublicKey,
) -> Result<VerifiableCredential> {
    let _ = (signed_credential, issuer_public_key);
    todo!("unblind and verify a blind-signed credential")
}

pub fn verify_credential(
    credential: &VerifiableCredential,
    issuer_public_key: &PbrsaPublicKey,
) -> Result<bool> {
    let _ = (credential, issuer_public_key);
    todo!("verify a finalized credential")
}

fn ensure_credential_data_object(data: &CredentialData, path: &str) -> Result<()> {
    if data.is_object() {
        Ok(())
    } else {
        Err(format!("{path} must be an object"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn create_credential_uses_visible_data_as_info() {
        let credential = create_credential(
            json!({
                "holder_pubkey": "holder",
            }),
            json!({
                "schema": "trust-score-v1",
                "issuer_id_pubkey": "issuer",
                "score": 7,
                "display_name": "Alice",
            }),
        )
        .unwrap();

        assert_eq!(credential.credential.info["schema"], "trust-score-v1");
        assert_eq!(credential.credential.blind_msg["holder_pubkey"], "holder");
        assert_eq!(credential.credential.info["score"], 7);
    }

    #[test]
    fn create_credential_does_not_validate_schema_shape() {
        let credential = create_credential(
            json!({ "holder_pubkey": "holder" }),
            json!({ "schema": "trust-score-v1", "score": 7, "unexpected": true }),
        )
        .unwrap();

        assert_eq!(credential.credential.info["unexpected"], true);
    }

    #[test]
    fn create_credential_requires_object_data() {
        assert!(create_credential(json!("holder"), json!({ "schema": "trust-score-v1" })).is_err());
        assert!(create_credential(json!({ "holder_pubkey": "holder" }), json!(7)).is_err());
    }
}
