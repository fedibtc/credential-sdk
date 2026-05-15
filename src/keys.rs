use blind_rsa_signatures::pbrsa::{
    PartiallyBlindKeyPairSha384PSSRandomized, PartiallyBlindPublicKeySha384PSSRandomized,
    PartiallyBlindSecretKeySha384PSSRandomized,
};
use blind_rsa_signatures::{
    BlindMessage, BlindSignature, BlindingResult, DefaultRng, MessageRandomizer, Secret, Signature,
};
use wasm_bindgen::prelude::*;

type PbrsaKeyPairInner = PartiallyBlindKeyPairSha384PSSRandomized;
type PbrsaPublicKeyInner = PartiallyBlindPublicKeySha384PSSRandomized;
type PbrsaSecretKeyInner = PartiallyBlindSecretKeySha384PSSRandomized;

#[wasm_bindgen(js_name = generateIssuerKeys)]
pub fn generate_issuer_keys(modulus_bits: usize) -> Result<PbrsaKeyPair, JsError> {
    PbrsaKeyPair::generate(modulus_bits)
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct PbrsaKeyPair {
    public_key: PbrsaPublicKey,
    secret_key: PbrsaSecretKey,
}

impl PbrsaKeyPair {
    pub(crate) fn generate(modulus_bits: usize) -> Result<PbrsaKeyPair, JsError> {
        let key_pair =
            PbrsaKeyPairInner::generate(&mut DefaultRng, modulus_bits).map_err(js_error)?;
        Ok(PbrsaKeyPair {
            public_key: PbrsaPublicKey {
                inner: key_pair.pk,
                metadata: None,
            },
            secret_key: PbrsaSecretKey {
                inner: key_pair.sk,
                metadata: None,
            },
        })
    }
}

#[wasm_bindgen]
impl PbrsaKeyPair {
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> PbrsaPublicKey {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter, js_name = secretKey)]
    pub fn secret_key(&self) -> PbrsaSecretKey {
        self.secret_key.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct PbrsaPublicKey {
    inner: PbrsaPublicKeyInner,
    metadata: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl PbrsaPublicKey {
    pub fn blind(
        &self,
        message: Vec<u8>,
        metadata: Vec<u8>,
    ) -> Result<BlindingResultBytes, JsError> {
        let public_key = self.inner_for_metadata(&metadata)?;
        Ok(BlindingResultBytes {
            inner: public_key
                .blind(&mut DefaultRng, message, Some(&metadata))
                .map_err(js_error)?,
        })
    }

    pub fn verify(
        &self,
        signature: Vec<u8>,
        message_randomizer: Vec<u8>,
        message: Vec<u8>,
        metadata: Vec<u8>,
    ) -> Result<bool, JsError> {
        let public_key = self.inner_for_metadata(&metadata)?;
        let message_randomizer = Some(message_randomizer_from_bytes(message_randomizer)?);
        Ok(public_key
            .verify(
                &Signature(signature),
                message_randomizer,
                message,
                Some(&metadata),
            )
            .is_ok())
    }
}

impl PbrsaPublicKey {
    fn inner_for_metadata(&self, metadata: &[u8]) -> Result<PbrsaPublicKeyInner, JsError> {
        if let Some(expected) = &self.metadata {
            if expected != metadata {
                return Err(JsError::new(
                    "metadata must match the derived PBRSA public key metadata",
                ));
            }
            return Ok(self.inner.clone());
        }

        self.inner
            .derive_public_key_for_metadata(metadata)
            .map_err(js_error)
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct PbrsaSecretKey {
    inner: PbrsaSecretKeyInner,
    metadata: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl PbrsaSecretKey {
    #[wasm_bindgen(js_name = blindSign)]
    pub fn blind_sign(
        &self,
        blind_message: Vec<u8>,
        metadata: Vec<u8>,
    ) -> Result<Vec<u8>, JsError> {
        let secret_key = self.inner_for_metadata(&metadata)?;
        Ok(secret_key.blind_sign(blind_message).map_err(js_error)?.0)
    }
}

impl PbrsaSecretKey {
    fn inner_for_metadata(&self, metadata: &[u8]) -> Result<PbrsaSecretKeyInner, JsError> {
        if let Some(expected) = &self.metadata {
            if expected != metadata {
                return Err(JsError::new(
                    "metadata must match the derived PBRSA secret key metadata",
                ));
            }
            return Ok(self.inner.clone());
        }

        let public_key = self.inner.public_key().map_err(js_error)?;
        PbrsaKeyPairInner {
            pk: public_key,
            sk: self.inner.clone(),
        }
        .derive_secret_key_for_metadata(metadata)
        .map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct BlindingResultBytes {
    inner: BlindingResult,
}

#[wasm_bindgen]
impl BlindingResultBytes {
    #[wasm_bindgen(getter, js_name = blindMessage)]
    pub fn blind_message(&self) -> Vec<u8> {
        self.inner.blind_message.0.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Vec<u8> {
        self.inner.secret.0.clone()
    }

    #[wasm_bindgen(getter, js_name = messageRandomizer)]
    pub fn message_randomizer(&self) -> Vec<u8> {
        self.inner
            .msg_randomizer
            .map(|message_randomizer| message_randomizer.0.to_vec())
            .unwrap_or_default()
    }
}

pub(crate) fn finalize_pbrsa_signature(
    public_key: &PbrsaPublicKey,
    blind_signature: Vec<u8>,
    blind_message: Vec<u8>,
    secret: Vec<u8>,
    message_randomizer: Vec<u8>,
    message: Vec<u8>,
    metadata: Vec<u8>,
) -> Result<Vec<u8>, JsError> {
    let derived_public_key = public_key.inner_for_metadata(&metadata)?;
    let blinding_result = blinding_result_from_bytes(blind_message, secret, message_randomizer)?;
    Ok(derived_public_key
        .finalize(
            &BlindSignature(blind_signature),
            &blinding_result,
            message,
            Some(&metadata),
        )
        .map_err(js_error)?
        .0)
}

fn message_randomizer_from_bytes(
    message_randomizer: Vec<u8>,
) -> Result<MessageRandomizer, JsError> {
    let message_randomizer: [u8; 32] = message_randomizer
        .try_into()
        .map_err(|_| JsError::new("messageRandomizer must be exactly 32 bytes"))?;
    Ok(MessageRandomizer(message_randomizer))
}

fn blinding_result_from_bytes(
    blind_message: Vec<u8>,
    secret: Vec<u8>,
    message_randomizer: Vec<u8>,
) -> Result<BlindingResult, JsError> {
    Ok(BlindingResult {
        blind_message: BlindMessage(blind_message),
        secret: Secret(secret),
        msg_randomizer: Some(message_randomizer_from_bytes(message_randomizer)?),
    })
}

fn js_error(error: impl std::fmt::Display) -> JsError {
    JsError::new(&error.to_string())
}
