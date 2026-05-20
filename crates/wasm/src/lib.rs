use std::str::FromStr;

use fedi_credential_sdk_protocol as protocol;
use serde::{de::DeserializeOwned, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const TYPESCRIPT_SURFACE: &'static str = r#"
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { readonly [key: string]: JsonValue };

export interface IssuanceRequest {
  readonly version: 1;
  readonly blinded_message: string;
}

export interface IssuanceResponse {
  readonly version: 1;
  readonly issuer_id: string;
  readonly info: JsonValue;
  readonly blind_signature: string;
}

export interface Credential {
  readonly version: 1;
  readonly issuer_id: string;
  readonly info: JsonValue;
  readonly blind_msg: JsonValue;
  readonly message_randomizer: string;
  readonly signature: string;
}

export interface IssuerBundle {
  readonly issuer: Issuer;
  readonly proof: SignatureProof;
}

export interface Issuer {
  readonly issuer_id_pubkey: string;
  readonly issuance_key: string;
  readonly revocation: readonly RevocationLocation[];
}

export interface RevocationLocation {
  readonly protocol: string;
  readonly location: string;
}

export interface SignatureProof {
  readonly signature: string;
}

export interface SignedRevocation {
  readonly revocation: RevocationEntry;
  readonly proof: IssuerSignatureProof;
}

export interface RevocationEntry {
  readonly credential_digest: string;
}

export interface IssuerSignatureProof {
  readonly issuer_id_pubkey: string;
  readonly signature: string;
}

export interface PendingIssuanceResult {
  readonly request: IssuanceRequest;
  readonly pending: PendingIssuance;
}

export function verifyIssuerBundle(issuerBundle: IssuerBundle): boolean;

export function verifyRevocation(revocation: SignedRevocation): boolean;
"#;

fn from_js<T: DeserializeOwned>(value: JsValue) -> Result<T, JsError> {
    serde_wasm_bindgen::from_value(value).map_err(|error| JsError::new(&error.to_string()))
}

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsError> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| JsError::new(&error.to_string()))
}

fn parse_issuer_id(issuer_id: &str) -> Result<protocol::IssuerId, JsError> {
    protocol::IssuerId::from_str(issuer_id).map_err(|error| JsError::new(&error.to_string()))
}

fn reflect_error(error: JsValue) -> JsError {
    JsError::new(
        &error
            .as_string()
            .unwrap_or_else(|| "failed to set JS object property".to_owned()),
    )
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct IssuerContext {
    inner: protocol::IssuerContext,
}

#[wasm_bindgen]
impl IssuerContext {
    #[wasm_bindgen(js_name = generate)]
    pub fn generate(issuer_id: String, modulus_bits: usize) -> Result<IssuerContext, JsError> {
        Ok(Self {
            inner: protocol::IssuerContext::generate(parse_issuer_id(&issuer_id)?, modulus_bits)?,
        })
    }

    #[wasm_bindgen(js_name = fromSecretKeyDer)]
    pub fn from_secret_key_der(issuer_id: String, der: Vec<u8>) -> Result<IssuerContext, JsError> {
        Ok(Self {
            inner: protocol::IssuerContext::from_secret_key_der(
                parse_issuer_id(&issuer_id)?,
                &der,
            )?,
        })
    }

    #[wasm_bindgen(getter, js_name = issuerId)]
    pub fn issuer_id(&self) -> String {
        self.inner.issuer_id.0.to_string()
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> PbrsaPublicKey {
        PbrsaPublicKey {
            inner: self.inner.public_key(),
        }
    }

    #[wasm_bindgen(js_name = secretKeyDer)]
    pub fn secret_key_der(&self) -> Result<Vec<u8>, JsError> {
        Ok(self.inner.secret_key_der()?)
    }

    #[wasm_bindgen(js_name = issueCredential)]
    pub fn issue_credential(&self, info: JsValue, request: JsValue) -> Result<JsValue, JsError> {
        let info: serde_json::Value = from_js(info)?;
        let request: protocol::IssuanceRequest = from_js(request)?;
        to_js(&self.inner.issue_credential(info, &request)?)
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct PbrsaPublicKey {
    inner: protocol::PbrsaPublicKey,
}

#[wasm_bindgen]
impl PbrsaPublicKey {
    #[wasm_bindgen(js_name = fromDer)]
    pub fn from_der(der: Vec<u8>) -> Result<PbrsaPublicKey, JsError> {
        Ok(Self {
            inner: protocol::PbrsaPublicKey::from_der(&der)?,
        })
    }

    #[wasm_bindgen(js_name = toDer)]
    pub fn to_der(&self) -> Result<Vec<u8>, JsError> {
        Ok(self.inner.to_der()?)
    }
}

#[wasm_bindgen]
pub struct PendingIssuance {
    inner: protocol::PendingIssuance,
}

#[wasm_bindgen]
impl PendingIssuance {
    #[wasm_bindgen(js_name = createRequest)]
    pub fn create_request(
        issuer_public_key: &PbrsaPublicKey,
        issuer_id: String,
        info: JsValue,
        blind_msg: JsValue,
    ) -> Result<JsValue, JsError> {
        let info: serde_json::Value = from_js(info)?;
        let blind_msg: serde_json::Value = from_js(blind_msg)?;
        let (request, pending) = protocol::PendingIssuance::create_request(
            &issuer_public_key.inner,
            parse_issuer_id(&issuer_id)?,
            info,
            blind_msg,
        )?;

        let result = js_sys::Object::new();
        // review: what is this code?
        js_sys::Reflect::set(&result, &JsValue::from_str("request"), &to_js(&request)?)
            .map_err(reflect_error)?;
        js_sys::Reflect::set(
            &result,
            &JsValue::from_str("pending"),
            &JsValue::from(PendingIssuance { inner: pending }),
        )
        .map_err(reflect_error)?;
        Ok(result.into())
    }

    pub fn finalize(
        self,
        issuer_public_key: &PbrsaPublicKey,
        response: JsValue,
    ) -> Result<JsValue, JsError> {
        let response: protocol::IssuanceResponse = from_js(response)?;
        to_js(&self.inner.finalize(&issuer_public_key.inner, &response)?)
    }
}

#[wasm_bindgen]
pub struct VerificationContext {
    inner: protocol::VerificationContext,
}

#[wasm_bindgen]
impl VerificationContext {
    #[wasm_bindgen(constructor)]
    pub fn new() -> VerificationContext {
        Self {
            inner: protocol::VerificationContext::new(),
        }
    }

    #[wasm_bindgen(js_name = addIssuerBundle)]
    pub fn add_issuer_bundle(&mut self, issuer_bundle: JsValue) -> Result<(), JsError> {
        let issuer_bundle: protocol::IssuerBundle = from_js(issuer_bundle)?;
        Ok(self.inner.add_issuer_bundle(&issuer_bundle)?)
    }

    #[wasm_bindgen(js_name = addRevocation)]
    pub fn add_revocation(&mut self, revocation: JsValue) -> Result<(), JsError> {
        let revocation: protocol::SignedRevocation = from_js(revocation)?;
        Ok(self.inner.add_revocation(&revocation)?)
    }

    #[wasm_bindgen(js_name = verifyCredential)]
    pub fn verify_credential(&self, credential: JsValue) -> Result<bool, JsError> {
        let credential: protocol::Credential = from_js(credential)?;
        self.inner.verify_credential(&credential)?;
        Ok(true)
    }
}

#[wasm_bindgen(js_name = verifyIssuerBundle)]
pub fn verify_issuer_bundle(issuer_bundle: JsValue) -> Result<bool, JsError> {
    let issuer_bundle: protocol::IssuerBundle = from_js(issuer_bundle)?;
    protocol::verify_issuer_bundle(&issuer_bundle)?;
    Ok(true)
}

#[wasm_bindgen(js_name = verifyRevocation)]
pub fn verify_revocation(revocation: JsValue) -> Result<bool, JsError> {
    let revocation: protocol::SignedRevocation = from_js(revocation)?;
    protocol::verify_revocation(&revocation)?;
    Ok(true)
}
