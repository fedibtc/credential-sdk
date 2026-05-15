use crate::schema::SchemaFields;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub type ByteArray = Vec<u8>;
pub type CredentialData = Value;
pub type Digest = String;
pub type SchemaName = String;
pub type PublicKey = String;
pub type SignatureValue = String;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IssuerBundle {
    pub issuer: Issuer,
    pub proof: SignatureProof,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Issuer {
    pub issuer_id_pubkey: PublicKey,
    pub issuance_key: PublicKey,
    pub revocation: Vec<RevocationLocation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RevocationLocation {
    pub protocol: String,
    pub location: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SchemaDefinition {
    pub schema: Schema,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Schema {
    pub id: String,
    pub version: String,
    pub fields: SchemaFields,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Revocation {
    pub revocation: RevocationEntry,
    pub proof: IssuerSignatureProof,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub credential_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignatureProof {
    pub signature: SignatureValue,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IssuerSignatureProof {
    pub issuer_id_pubkey: PublicKey,
    pub signature: SignatureValue,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn issuer_bundle_deserializes_from_design_shape() {
        let bundle: IssuerBundle = serde_json::from_value(json!({
            "issuer": {
                "issuer_id_pubkey": "issuer-id-pubkey",
                "issuance_key": "rsa-pubkey-for-credential-issuance",
                "revocation": [{
                    "protocol": "https",
                    "location": "https://example.com/revocations"
                }]
            },
            "proof": {
                "signature": "issuer-signature"
            }
        }))
        .unwrap();

        assert_eq!(bundle.issuer.revocation[0].protocol, "https");
        assert_eq!(
            serde_json::to_value(&bundle).unwrap()["issuer"]["issuance_key"],
            "rsa-pubkey-for-credential-issuance"
        );
    }

    #[test]
    fn schema_definition_deserializes_from_design_shape() {
        let schema_definition: SchemaDefinition = serde_json::from_value(json!({
            "schema": {
                "id": "fedi-trust-score",
                "version": "1.0.0",
                "fields": {
                    "schema": "string",
                    "issuer_id_pubkey": "string",
                    "score": "string",
                    "blind_msg": "string"
                }
            }
        }))
        .unwrap();

        assert_eq!(schema_definition.schema.fields["blind_msg"], "string");
        assert_eq!(schema_definition.schema.fields["score"], "string");
    }

    #[test]
    fn revocation_deserializes_from_design_shape() {
        let revocation: Revocation = serde_json::from_value(json!({
            "revocation": {
                "credential_digest": "SHA256(canonical_credential)"
            },
            "proof": {
                "issuer_id_pubkey": "id-public-key",
                "signature": "partially-blinded-signature"
            }
        }))
        .unwrap();

        assert_eq!(
            revocation.revocation.credential_digest,
            "SHA256(canonical_credential)"
        );
        assert_eq!(
            serde_json::to_value(&revocation).unwrap()["proof"]["issuer_id_pubkey"],
            "id-public-key"
        );
    }
}
