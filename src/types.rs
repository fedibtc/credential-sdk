use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tsify::Tsify;

#[tsify::declare]
pub type Digest = String;

#[tsify::declare]
pub type BlindMessage = String;

#[tsify::declare]
pub type PublicKey = String;

#[tsify::declare]
pub type SignatureValue = String;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(type = "{ credential: Credential; proof: SignatureProof }")]
pub struct VerifiableCredential {
    pub credential: Credential,
    pub proof: SignatureProof,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(type = "{ info: CredentialInfo; blind_msg: BlindMessage }")]
pub struct Credential {
    pub info: CredentialInfo,
    pub blind_msg: BlindMessage,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(type = "{ schema: Digest; issuer_id_pubkey: PublicKey; score: number }")]
pub struct CredentialInfo {
    pub schema: Digest,
    pub issuer_id_pubkey: PublicKey,
    pub score: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(type = "{ issuer: Issuer; proof: SignatureProof }")]
pub struct IssuerBundle {
    pub issuer: Issuer,
    pub proof: SignatureProof,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(
    type = "{ issuer_id_pubkey: PublicKey; issuance_key: PublicKey; revocation: RevocationLocation[] }"
)]
pub struct Issuer {
    pub issuer_id_pubkey: PublicKey,
    pub issuance_key: PublicKey,
    pub revocation: Vec<RevocationLocation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(type = "{ protocol: string; location: string }")]
pub struct RevocationLocation {
    pub protocol: String,
    pub location: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(type = "{ schema: Schema }")]
pub struct SchemaDefinition {
    pub schema: Schema,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(
    type = "{ id: string; version: string; digest: Digest; fields: Record<string, SchemaField> }"
)]
pub struct Schema {
    pub id: String,
    pub version: String,
    pub digest: Digest,
    #[tsify(type = "Record<string, SchemaField>")]
    pub fields: SchemaFields,
}

pub type SchemaFields = BTreeMap<String, SchemaField>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(type = "string | Record<string, SchemaField>")]
#[serde(untagged)]
pub enum SchemaField {
    Type(String),
    Object(SchemaFields),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(type = "{ revocation: RevocationEntry; proof: IssuerSignatureProof }")]
pub struct Revocation {
    pub revocation: RevocationEntry,
    pub proof: IssuerSignatureProof,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(type = "{ credential_digest: Digest }")]
pub struct RevocationEntry {
    pub credential_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(type = "{ signature: SignatureValue }")]
pub struct SignatureProof {
    pub signature: SignatureValue,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(type = "{ issuer_id_pubkey: PublicKey; signature: SignatureValue }")]
pub struct IssuerSignatureProof {
    pub issuer_id_pubkey: PublicKey,
    pub signature: SignatureValue,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn verifiable_credential_deserializes_from_design_shape() {
        let credential: VerifiableCredential = serde_json::from_value(json!({
            "credential": {
                "info": {
                    "schema": "base64url-digest",
                    "issuer_id_pubkey": "issuer-id-pubkey",
                    "score": 7
                },
                "blind_msg": "anonymous-holder-public-key"
            },
            "proof": {
                "signature": "RSA-signature"
            }
        }))
        .unwrap();

        assert_eq!(credential.credential.info.score, 7);
        assert_eq!(
            serde_json::to_value(&credential).unwrap()["credential"]["blind_msg"],
            "anonymous-holder-public-key"
        );
    }

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
                "digest": "base64url-digest",
                "fields": {
                    "info": {
                        "schema": "string",
                        "issuer_id_pubkey": "string",
                        "score": "number"
                    },
                    "blind_msg": "string"
                }
            }
        }))
        .unwrap();

        assert!(matches!(
            schema_definition.schema.fields["blind_msg"],
            SchemaField::Type(ref field_type) if field_type == "string"
        ));
        assert!(matches!(
            schema_definition.schema.fields["info"],
            SchemaField::Object(_)
        ));
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
