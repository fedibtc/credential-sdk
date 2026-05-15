use fedibtc_blind_rsa_signatures as protocol;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const TYPESCRIPT_SURFACE: &'static str = r#"
export type CredentialData = Record<string, unknown>;
export type Simplify<T> = { readonly [K in keyof T]: T[K] } & {};
export type ByteArray = readonly number[];
export interface CredentialTemplate<
  TBlindedData extends CredentialData = CredentialData,
  TVisibleData extends CredentialData = CredentialData,
> {
  readonly credential: {
    readonly info: Simplify<TVisibleData>;
    readonly blind_msg: Simplify<TBlindedData>;
  };
}
export interface BlindSignedCredential<
  TBlindedData extends CredentialData = CredentialData,
  TVisibleData extends CredentialData = CredentialData,
> {
  readonly credential: {
    readonly info: Simplify<TVisibleData>;
    readonly blind_msg: ByteArray;
  };
  readonly proof: {
    readonly signature: ByteArray;
    readonly blinded_msg: ByteArray;
    readonly blind_msg: ByteArray;
    readonly info: ByteArray;
    readonly messageRandomizer: ByteArray;
    readonly blindingSecret: ByteArray;
  };
}
export interface VerifiableCredential<
  TBlindedData extends CredentialData = CredentialData,
  TVisibleData extends CredentialData = CredentialData,
> {
  readonly credential: {
    readonly info: Simplify<TVisibleData>;
    readonly blind_msg: Simplify<TBlindedData>;
  };
  readonly proof: {
    readonly signature: ByteArray;
  };
}
export function createCredential<
  const TBlindedData extends CredentialData,
  const TVisibleData extends CredentialData,
>(
  blindedData: TBlindedData,
  visibleData: TVisibleData,
): CredentialTemplate<TBlindedData, TVisibleData>;
export function blindSignCredential<
  const TBlindedData extends CredentialData,
  const TVisibleData extends CredentialData,
>(
  blindedData: TBlindedData,
  visibleData: TVisibleData,
  blindingKeyPair: PbrsaKeyPair,
): BlindSignedCredential<TBlindedData, TVisibleData>;
export function finalizeCredential<
  const TBlindedData extends CredentialData,
  const TVisibleData extends CredentialData,
>(
  signedCredential: BlindSignedCredential<TBlindedData, TVisibleData>,
  blindingPublicKey: PbrsaPublicKey,
): VerifiableCredential<TBlindedData, TVisibleData>;
export function verifyCredential(
  credential: VerifiableCredential,
  issuerPublicKey: PbrsaPublicKey,
): boolean;
"#;

#[wasm_bindgen(js_name = generateIssuerKeys)]
pub fn generate_issuer_keys(modulus_bits: usize) -> Result<PbrsaKeyPair, JsError> {
    let _ = modulus_bits;
    todo!("delegate to fedibtc_blind_rsa_signatures::generate_issuer_keys")
}

#[wasm_bindgen(js_name = createCredential, skip_typescript)]
pub fn create_credential(blinded_data: JsValue, visible_data: JsValue) -> Result<JsValue, JsError> {
    let _ = (blinded_data, visible_data);
    todo!("deserialize JS input and delegate to protocol::create_credential")
}

#[wasm_bindgen(js_name = blindSignCredential, skip_typescript)]
pub fn blind_sign_credential(
    blinded_data: JsValue,
    visible_data: JsValue,
    issuer_keys: &PbrsaKeyPair,
) -> Result<JsValue, JsError> {
    let _ = (blinded_data, visible_data, issuer_keys);
    todo!("deserialize JS input and delegate to protocol::blind_sign_credential")
}

#[wasm_bindgen(js_name = finalizeCredential, skip_typescript)]
pub fn finalize_credential(
    signed_credential: JsValue,
    issuer_public_key: &PbrsaPublicKey,
) -> Result<JsValue, JsError> {
    let _ = (signed_credential, issuer_public_key);
    todo!("deserialize JS input and delegate to protocol::finalize_credential")
}

#[wasm_bindgen(js_name = verifyCredential, skip_typescript)]
pub fn verify_credential(
    credential: JsValue,
    issuer_public_key: &PbrsaPublicKey,
) -> Result<bool, JsError> {
    let _ = (credential, issuer_public_key);
    todo!("deserialize JS input and delegate to protocol::verify_credential")
}

#[wasm_bindgen(js_name = createCredentialIssuancePayload)]
pub fn create_credential_issuance_payload(
    blinded_data: JsValue,
    visible_data: JsValue,
    holder_blind_message: Vec<u8>,
) -> Result<String, JsError> {
    let _ = (blinded_data, visible_data, holder_blind_message);
    todo!("deserialize JS input and delegate to protocol::create_credential_issuance_payload")
}

#[wasm_bindgen(js_name = validateCredentialIssuancePayload)]
pub fn validate_credential_issuance_payload(payload: String) -> Result<bool, JsError> {
    let _ = payload;
    todo!("deserialize payload and delegate to protocol::validate_credential_issuance_payload")
}

#[wasm_bindgen(js_name = createSignedCredentialResponse)]
pub fn create_signed_credential_response(
    payload: String,
    blind_signature: Vec<u8>,
) -> Result<String, JsError> {
    let _ = (payload, blind_signature);
    todo!("deserialize payload and delegate to protocol::create_signed_credential_response")
}

#[wasm_bindgen(js_name = issueCredential)]
pub fn issue_credential(
    issuance_secret_key: &PbrsaSecretKey,
    blinded_data: JsValue,
    visible_data: JsValue,
    holder_blind_message: Vec<u8>,
) -> Result<String, JsError> {
    let _ = (
        issuance_secret_key,
        blinded_data,
        visible_data,
        holder_blind_message,
    );
    todo!("deserialize JS input and delegate to protocol::issue_credential")
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct PbrsaKeyPair {
    inner: protocol::PbrsaKeyPair,
}

#[wasm_bindgen]
impl PbrsaKeyPair {
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> PbrsaPublicKey {
        let _ = &self.inner;
        todo!("wrap protocol public key")
    }

    #[wasm_bindgen(getter, js_name = secretKey)]
    pub fn secret_key(&self) -> PbrsaSecretKey {
        let _ = &self.inner;
        todo!("wrap protocol secret key")
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct PbrsaPublicKey {
    inner: protocol::PbrsaPublicKey,
}

#[wasm_bindgen]
impl PbrsaPublicKey {
    pub fn blind(&self, blind_msg: Vec<u8>, info: Vec<u8>) -> Result<BlindingResultBytes, JsError> {
        let _ = (&self.inner, blind_msg, info);
        todo!("delegate to protocol::PbrsaPublicKey::blind")
    }

    pub fn verify(
        &self,
        signature: Vec<u8>,
        message_randomizer: Vec<u8>,
        blind_msg: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<bool, JsError> {
        let _ = (&self.inner, signature, message_randomizer, blind_msg, info);
        todo!("delegate to protocol::PbrsaPublicKey::verify")
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct PbrsaSecretKey {
    inner: protocol::PbrsaSecretKey,
}

#[wasm_bindgen]
impl PbrsaSecretKey {
    #[wasm_bindgen(js_name = blindSign)]
    pub fn blind_sign(&self, blind_msg: Vec<u8>, info: Vec<u8>) -> Result<Vec<u8>, JsError> {
        let _ = (&self.inner, blind_msg, info);
        todo!("delegate to protocol::PbrsaSecretKey::blind_sign")
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct BlindingResultBytes {
    inner: protocol::BlindingResult,
}

#[wasm_bindgen]
impl BlindingResultBytes {
    #[wasm_bindgen(getter, js_name = blind_msg)]
    pub fn blind_message(&self) -> Vec<u8> {
        self.inner.blind_msg.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Vec<u8> {
        self.inner.secret.clone()
    }

    #[wasm_bindgen(getter, js_name = messageRandomizer)]
    pub fn message_randomizer(&self) -> Vec<u8> {
        self.inner.message_randomizer.clone()
    }
}
