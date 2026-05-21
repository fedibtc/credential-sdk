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

export interface IssuerSecretKeys {
  readonly issuer_id_secret_key: string;
  readonly issuance_secret_key: string;
}

export interface SignedCredential {
  readonly version: 1;
  readonly credential: Credential;
  readonly proof: CredentialProof;
}

export interface Credential {
  readonly issuer_id_pubkey: string;
  readonly info: JsonValue;
  readonly blind_msg: JsonValue;
  readonly message_randomizer: string;
}

export interface CredentialProof {
  readonly signature: string;
}

export interface IssuerBundle {
  readonly version: 1;
  readonly issuer: Issuer;
  readonly proof: SchnorrSignatureProof;
}

export interface SchnorrSignatureProof {
  readonly signature: string;
}

export interface Issuer {
  readonly issuer_id_pubkey: string;
  readonly issuance_key: string;
  readonly revocation: readonly RevocationLocation[];
}

export interface SignedRevocation {
  readonly version: 1;
  readonly revocation: Revocation;
  readonly proof: RevocationProof;
}

export interface RevocationProof {
  readonly issuer_id_pubkey: string;
  readonly signature: string;
}

export interface Revocation {
  /** Unpadded URL-safe base64 encoded SHA-256 digest. */
  readonly credential_digest: string;
}

export interface RevocationLocation {
  readonly protocol: string;
  readonly location: string;
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
    pub fn generate() -> Result<IssuerContext, JsError> {
        Ok(Self {
            inner: protocol::IssuerContext::generate()?,
        })
    }

    #[wasm_bindgen(js_name = importSecretKey)]
    pub fn import_secret_key(secret_key: JsValue) -> Result<IssuerContext, JsError> {
        let secret_key: protocol::IssuerSecretKeys = from_js(secret_key)?;
        Ok(Self {
            inner: protocol::IssuerContext::import_secret_key(&secret_key)?,
        })
    }

    #[wasm_bindgen(js_name = exportSecretKey)]
    pub fn export_secret_key(&self) -> Result<JsValue, JsError> {
        to_js(&self.inner.export_secret_key()?)
    }

    #[wasm_bindgen(js_name = issueCredential)]
    pub fn issue_credential(&self, info: JsValue, request: JsValue) -> Result<JsValue, JsError> {
        let info: serde_json::Value = from_js(info)?;
        let request: protocol::IssuanceRequest = from_js(request)?;
        to_js(&self.inner.issue_credential(info, &request)?)
    }

    #[wasm_bindgen(js_name = issuerBundle)]
    pub fn issuer_bundle(&self, revocation: JsValue) -> Result<JsValue, JsError> {
        let revocation: Vec<protocol::RevocationLocation> = from_js(revocation)?;
        to_js(&self.inner.issuer_bundle(revocation)?)
    }

    #[wasm_bindgen(js_name = revokeCredential)]
    pub fn revoke_credential(&self, credential: JsValue) -> Result<JsValue, JsError> {
        let credential: protocol::SignedCredential = from_js(credential)?;
        to_js(&self.inner.revoke_credential(&credential)?)
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct HolderContext {
    inner: protocol::HolderContext,
}

#[wasm_bindgen]
impl HolderContext {
    #[wasm_bindgen(js_name = generate)]
    pub fn generate() -> HolderContext {
        Self {
            inner: protocol::HolderContext::generate(),
        }
    }

    #[wasm_bindgen(js_name = importSecretKey)]
    pub fn import_secret_key(secret_key: String) -> Result<HolderContext, JsError> {
        Ok(Self {
            inner: protocol::HolderContext::import_secret_key(&secret_key)?,
        })
    }

    #[wasm_bindgen(js_name = exportSecretKey)]
    pub fn export_secret_key(&self) -> String {
        self.inner.export_secret_key()
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> String {
        self.inner.public_key().to_string()
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
        issuer_bundle: JsValue,
        info: JsValue,
        blind_msg: JsValue,
    ) -> Result<JsValue, JsError> {
        let issuer_bundle: protocol::IssuerBundle = from_js(issuer_bundle)?;
        let info: serde_json::Value = from_js(info)?;
        let blind_msg: serde_json::Value = from_js(blind_msg)?;
        let (request, pending) = protocol::PendingIssuance::create_request(
            &issuer_bundle.issuer.issuance_key,
            issuer_bundle.issuer.issuer_id_pubkey,
            info,
            blind_msg,
        )?;

        let result = js_sys::Object::new();
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

    pub fn finalize(self, issuer_bundle: JsValue, response: JsValue) -> Result<JsValue, JsError> {
        let issuer_bundle: protocol::IssuerBundle = from_js(issuer_bundle)?;
        let response: protocol::IssuanceResponse = from_js(response)?;
        to_js(
            &self
                .inner
                .finalize(&issuer_bundle.issuer.issuance_key, &response)?,
        )
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
        let credential: protocol::SignedCredential = from_js(credential)?;
        self.inner.verify_credential(&credential)?;
        Ok(true)
    }
}

#[wasm_bindgen(js_name = verifyIssuerBundle)]
pub fn verify_issuer_bundle(issuer_bundle: JsValue) -> Result<bool, JsError> {
    let issuer_bundle: protocol::IssuerBundle = from_js(issuer_bundle)?;
    issuer_bundle.verify()?;
    Ok(true)
}

#[wasm_bindgen(js_name = verifyRevocation)]
pub fn verify_revocation(revocation: JsValue) -> Result<bool, JsError> {
    let revocation: protocol::SignedRevocation = from_js(revocation)?;
    revocation.verify()?;
    Ok(true)
}
