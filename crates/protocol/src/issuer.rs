use crate::keys::PbrsaSecretKey;
use crate::types::{ByteArray, CredentialData};
use crate::Result;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredentialIssuancePayload {
    pub blinded_data: CredentialData,
    pub visible_data: CredentialData,
    pub holder_blind_message: ByteArray,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedCredentialResponse {
    pub payload: String,
    pub blind_signature: ByteArray,
}

pub fn create_credential_issuance_payload(
    blinded_data: CredentialData,
    visible_data: CredentialData,
    holder_blind_message: ByteArray,
) -> Result<CredentialIssuancePayload> {
    let _ = (blinded_data, visible_data, holder_blind_message);
    todo!("construct the canonical credential issuance payload")
}

pub fn validate_credential_issuance_payload(payload: &CredentialIssuancePayload) -> Result<bool> {
    let _ = payload;
    todo!("validate visible fields and holder blinded message")
}

pub fn create_signed_credential_response(
    payload: CredentialIssuancePayload,
    blind_signature: ByteArray,
) -> Result<SignedCredentialResponse> {
    let _ = (payload, blind_signature);
    todo!("serialize a signed credential issuance response")
}

pub fn issue_credential(
    issuance_secret_key: &PbrsaSecretKey,
    blinded_data: CredentialData,
    visible_data: CredentialData,
    holder_blind_message: ByteArray,
) -> Result<SignedCredentialResponse> {
    let _ = (
        issuance_secret_key,
        blinded_data,
        visible_data,
        holder_blind_message,
    );
    todo!("construct, validate, blind-sign, and serialize an issuance response")
}
