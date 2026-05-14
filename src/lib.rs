use blind_rsa_signatures::pbrsa::{
    PartiallyBlindKeyPairSha384PSSRandomized, PartiallyBlindPublicKeySha384PSSRandomized,
    PartiallyBlindSecretKeySha384PSSRandomized,
};
use blind_rsa_signatures::{
    BlindMessage, BlindSignature, BlindingResult, DefaultRng, KeyPairSha384PSSRandomized,
    MessageRandomizer, PublicKeySha384PSSRandomized, Secret, SecretKeySha384PSSRandomized,
    Signature,
};
use wasm_bindgen::prelude::*;

pub mod types;

pub use types::{IssuerBundle, Revocation, SchemaDefinition, VerifiableCredential};

type BrsaKeyPairInner = KeyPairSha384PSSRandomized;
type BrsaPublicKeyInner = PublicKeySha384PSSRandomized;
type BrsaSecretKeyInner = SecretKeySha384PSSRandomized;
type PbrsaKeyPairInner = PartiallyBlindKeyPairSha384PSSRandomized;
type PbrsaPublicKeyInner = PartiallyBlindPublicKeySha384PSSRandomized;
type PbrsaSecretKeyInner = PartiallyBlindSecretKeySha384PSSRandomized;

#[wasm_bindgen]
#[derive(Clone)]
pub struct BrsaKeyPair {
    public_key: BrsaPublicKey,
    secret_key: BrsaSecretKey,
}

#[wasm_bindgen]
impl BrsaKeyPair {
    #[wasm_bindgen(js_name = generate)]
    pub fn generate(modulus_bits: usize) -> Result<BrsaKeyPair, JsError> {
        let key_pair =
            BrsaKeyPairInner::generate(&mut DefaultRng, modulus_bits).map_err(js_error)?;
        Ok(BrsaKeyPair {
            public_key: BrsaPublicKey { inner: key_pair.pk },
            secret_key: BrsaSecretKey { inner: key_pair.sk },
        })
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> BrsaPublicKey {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter, js_name = secretKey)]
    pub fn secret_key(&self) -> BrsaSecretKey {
        self.secret_key.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct BrsaPublicKey {
    inner: BrsaPublicKeyInner,
}

#[wasm_bindgen]
impl BrsaPublicKey {
    #[wasm_bindgen(js_name = fromDer)]
    pub fn from_der(der: Vec<u8>) -> Result<BrsaPublicKey, JsError> {
        Ok(BrsaPublicKey {
            inner: BrsaPublicKeyInner::from_der(&der).map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = fromPem)]
    pub fn from_pem(pem: String) -> Result<BrsaPublicKey, JsError> {
        Ok(BrsaPublicKey {
            inner: BrsaPublicKeyInner::from_pem(&pem).map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = fromSpki)]
    pub fn from_spki(spki: Vec<u8>) -> Result<BrsaPublicKey, JsError> {
        Ok(BrsaPublicKey {
            inner: BrsaPublicKeyInner::from_spki(&spki).map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = toDer)]
    pub fn to_der(&self) -> Result<Vec<u8>, JsError> {
        self.inner.to_der().map_err(js_error)
    }

    #[wasm_bindgen(js_name = toPem)]
    pub fn to_pem(&self) -> Result<String, JsError> {
        self.inner.to_pem().map_err(js_error)
    }

    #[wasm_bindgen(js_name = toSpki)]
    pub fn to_spki(&self) -> Result<Vec<u8>, JsError> {
        self.inner.to_spki().map_err(js_error)
    }

    pub fn blind(&self, message: Vec<u8>) -> Result<BlindingResultBytes, JsError> {
        Ok(BlindingResultBytes {
            inner: self
                .inner
                .blind(&mut DefaultRng, message)
                .map_err(js_error)?,
        })
    }

    pub fn finalize(
        &self,
        blind_signature: Vec<u8>,
        blinding_result: &BlindingResultBytes,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, JsError> {
        Ok(self
            .inner
            .finalize(
                &BlindSignature(blind_signature),
                &blinding_result.inner,
                message,
            )
            .map_err(js_error)?
            .0)
    }

    pub fn verify(
        &self,
        signature: Vec<u8>,
        message_randomizer: Vec<u8>,
        message: Vec<u8>,
    ) -> Result<bool, JsError> {
        let message_randomizer = Some(message_randomizer_from_bytes(message_randomizer)?);
        Ok(self
            .inner
            .verify(&Signature(signature), message_randomizer, message)
            .is_ok())
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct BrsaSecretKey {
    inner: BrsaSecretKeyInner,
}

#[wasm_bindgen]
impl BrsaSecretKey {
    #[wasm_bindgen(js_name = fromDer)]
    pub fn from_der(der: Vec<u8>) -> Result<BrsaSecretKey, JsError> {
        Ok(BrsaSecretKey {
            inner: BrsaSecretKeyInner::from_der(&der).map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = fromPem)]
    pub fn from_pem(pem: String) -> Result<BrsaSecretKey, JsError> {
        Ok(BrsaSecretKey {
            inner: BrsaSecretKeyInner::from_pem(&pem).map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = toDer)]
    pub fn to_der(&self) -> Result<Vec<u8>, JsError> {
        self.inner.to_der().map_err(js_error)
    }

    #[wasm_bindgen(js_name = toPem)]
    pub fn to_pem(&self) -> Result<String, JsError> {
        self.inner.to_pem().map_err(js_error)
    }

    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Result<BrsaPublicKey, JsError> {
        Ok(BrsaPublicKey {
            inner: self.inner.public_key().map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = blindSign)]
    pub fn blind_sign(&self, blind_message: Vec<u8>) -> Result<Vec<u8>, JsError> {
        Ok(self.inner.blind_sign(blind_message).map_err(js_error)?.0)
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct PbrsaKeyPair {
    public_key: PbrsaPublicKey,
    secret_key: PbrsaSecretKey,
}

#[wasm_bindgen]
impl PbrsaKeyPair {
    #[wasm_bindgen(js_name = generate)]
    pub fn generate(modulus_bits: usize) -> Result<PbrsaKeyPair, JsError> {
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

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> PbrsaPublicKey {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter, js_name = secretKey)]
    pub fn secret_key(&self) -> PbrsaSecretKey {
        self.secret_key.clone()
    }

    #[wasm_bindgen(js_name = deriveForMetadata)]
    pub fn derive_for_metadata(&self, metadata: Vec<u8>) -> Result<PbrsaKeyPair, JsError> {
        self.secret_key.ensure_master()?;
        let key_pair = PbrsaKeyPairInner {
            pk: self.public_key.inner.clone(),
            sk: self.secret_key.inner.clone(),
        }
        .derive_key_pair_for_metadata(&metadata)
        .map_err(js_error)?;
        Ok(PbrsaKeyPair {
            public_key: PbrsaPublicKey {
                inner: key_pair.pk,
                metadata: Some(metadata.clone()),
            },
            secret_key: PbrsaSecretKey {
                inner: key_pair.sk,
                metadata: Some(metadata),
            },
        })
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
    #[wasm_bindgen(js_name = fromDer)]
    pub fn from_der(der: Vec<u8>) -> Result<PbrsaPublicKey, JsError> {
        Ok(PbrsaPublicKey {
            inner: PbrsaPublicKeyInner::from_der(&der).map_err(js_error)?,
            metadata: None,
        })
    }

    #[wasm_bindgen(js_name = fromPem)]
    pub fn from_pem(pem: String) -> Result<PbrsaPublicKey, JsError> {
        Ok(PbrsaPublicKey {
            inner: PbrsaPublicKeyInner::from_pem(&pem).map_err(js_error)?,
            metadata: None,
        })
    }

    #[wasm_bindgen(js_name = toDer)]
    pub fn to_der(&self) -> Result<Vec<u8>, JsError> {
        self.ensure_master()?;
        self.inner.to_der().map_err(js_error)
    }

    #[wasm_bindgen(js_name = toPem)]
    pub fn to_pem(&self) -> Result<String, JsError> {
        self.ensure_master()?;
        self.inner.to_pem().map_err(js_error)
    }

    #[wasm_bindgen(js_name = deriveForMetadata)]
    pub fn derive_for_metadata(&self, metadata: Vec<u8>) -> Result<PbrsaPublicKey, JsError> {
        self.ensure_master()?;
        Ok(PbrsaPublicKey {
            inner: self
                .inner
                .derive_public_key_for_metadata(&metadata)
                .map_err(js_error)?,
            metadata: Some(metadata),
        })
    }

    pub fn blind(
        &self,
        message: Vec<u8>,
        metadata: Vec<u8>,
    ) -> Result<BlindingResultBytes, JsError> {
        let metadata = self.checked_metadata(&metadata)?;
        Ok(BlindingResultBytes {
            inner: self
                .inner
                .blind(&mut DefaultRng, message, Some(metadata))
                .map_err(js_error)?,
        })
    }

    pub fn finalize(
        &self,
        blind_signature: Vec<u8>,
        blinding_result: &BlindingResultBytes,
        message: Vec<u8>,
        metadata: Vec<u8>,
    ) -> Result<Vec<u8>, JsError> {
        let metadata = self.checked_metadata(&metadata)?;
        Ok(self
            .inner
            .finalize(
                &BlindSignature(blind_signature),
                &blinding_result.inner,
                message,
                Some(metadata),
            )
            .map_err(js_error)?
            .0)
    }

    pub fn verify(
        &self,
        signature: Vec<u8>,
        message_randomizer: Vec<u8>,
        message: Vec<u8>,
        metadata: Vec<u8>,
    ) -> Result<bool, JsError> {
        let metadata = self.checked_metadata(&metadata)?;
        let message_randomizer = Some(message_randomizer_from_bytes(message_randomizer)?);
        Ok(self
            .inner
            .verify(
                &Signature(signature),
                message_randomizer,
                message,
                Some(metadata),
            )
            .is_ok())
    }

    fn checked_metadata<'a>(&'a self, metadata: &'a [u8]) -> Result<&'a [u8], JsError> {
        let expected = self
            .metadata
            .as_ref()
            .ok_or_else(|| JsError::new("derive PBRSA public key for metadata before use"))?;
        if expected != metadata {
            return Err(JsError::new(
                "metadata must match the derived PBRSA public key metadata",
            ));
        }
        Ok(metadata)
    }

    fn ensure_master(&self) -> Result<(), JsError> {
        if self.metadata.is_some() {
            return Err(JsError::new(
                "derived PBRSA public keys cannot be serialized or derived again",
            ));
        }
        Ok(())
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
    #[wasm_bindgen(js_name = fromDer)]
    pub fn from_der(der: Vec<u8>) -> Result<PbrsaSecretKey, JsError> {
        Ok(PbrsaSecretKey {
            inner: PbrsaSecretKeyInner::from_der(&der).map_err(js_error)?,
            metadata: None,
        })
    }

    #[wasm_bindgen(js_name = fromPem)]
    pub fn from_pem(pem: String) -> Result<PbrsaSecretKey, JsError> {
        Ok(PbrsaSecretKey {
            inner: PbrsaSecretKeyInner::from_pem(&pem).map_err(js_error)?,
            metadata: None,
        })
    }

    #[wasm_bindgen(js_name = toDer)]
    pub fn to_der(&self) -> Result<Vec<u8>, JsError> {
        self.ensure_master()?;
        self.inner.to_der().map_err(js_error)
    }

    #[wasm_bindgen(js_name = toPem)]
    pub fn to_pem(&self) -> Result<String, JsError> {
        self.ensure_master()?;
        self.inner.to_pem().map_err(js_error)
    }

    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Result<PbrsaPublicKey, JsError> {
        Ok(PbrsaPublicKey {
            inner: self.inner.public_key().map_err(js_error)?,
            metadata: self.metadata.clone(),
        })
    }

    #[wasm_bindgen(js_name = deriveForMetadata)]
    pub fn derive_for_metadata(&self, metadata: Vec<u8>) -> Result<PbrsaSecretKey, JsError> {
        self.ensure_master()?;
        let pk = self.inner.public_key().map_err(js_error)?;
        let key_pair = PbrsaKeyPairInner {
            pk,
            sk: self.inner.clone(),
        };
        Ok(PbrsaSecretKey {
            inner: key_pair
                .derive_secret_key_for_metadata(&metadata)
                .map_err(js_error)?,
            metadata: Some(metadata),
        })
    }

    #[wasm_bindgen(js_name = blindSign)]
    pub fn blind_sign(&self, blind_message: Vec<u8>) -> Result<Vec<u8>, JsError> {
        if self.metadata.is_none() {
            return Err(JsError::new(
                "derive PBRSA secret key for metadata before signing",
            ));
        }
        Ok(self.inner.blind_sign(blind_message).map_err(js_error)?.0)
    }

    fn ensure_master(&self) -> Result<(), JsError> {
        if self.metadata.is_some() {
            return Err(JsError::new(
                "derived PBRSA secret keys cannot be serialized or derived again",
            ));
        }
        Ok(())
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

fn message_randomizer_from_bytes(
    message_randomizer: Vec<u8>,
) -> Result<MessageRandomizer, JsError> {
    let message_randomizer: [u8; 32] = message_randomizer
        .try_into()
        .map_err(|_| JsError::new("messageRandomizer must be exactly 32 bytes"))?;
    Ok(MessageRandomizer(message_randomizer))
}

#[allow(dead_code)]
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
