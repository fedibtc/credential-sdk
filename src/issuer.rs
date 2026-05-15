use crate::keys::PbrsaSecretKey;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = createCredentialIssuancePayload)]
pub fn create_credential_issuance_payload(
    schema: JsValue,
    blinded_data: JsValue,
    visible_data: JsValue,
    holder_blind_message: Vec<u8>,
) -> Result<String, JsError> {
    let _ = (schema, blinded_data, visible_data, holder_blind_message);
    todo!("construct canonical credential issuance payload")
}

#[wasm_bindgen(js_name = validateCredentialIssuancePayload)]
pub fn validate_credential_issuance_payload(payload: String) -> Result<bool, JsError> {
    let _ = payload;
    todo!("validate visible credential fields and holder blinded message")
}

#[wasm_bindgen(js_name = createSignedCredentialResponse)]
pub fn create_signed_credential_response(
    payload: String,
    blind_signature: Vec<u8>,
) -> Result<String, JsError> {
    let _ = (payload, blind_signature);
    todo!("serialize signed credential response for holder finalization")
}

#[wasm_bindgen(js_name = issueCredential)]
pub fn issue_credential(
    issuance_secret_key: &PbrsaSecretKey,
    schema: JsValue,
    blinded_data: JsValue,
    visible_data: JsValue,
    holder_blind_message: Vec<u8>,
) -> Result<String, JsError> {
    let _ = (
        issuance_secret_key,
        schema,
        blinded_data,
        visible_data,
        holder_blind_message,
    );
    todo!("construct, validate, blind-sign, and serialize a credential issuance response")
}
