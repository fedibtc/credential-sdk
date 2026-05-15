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

/// Generates an issuer PBRSA key pair for partially blind credential issuance.
///
/// The returned key pair exposes only the public key, secret key, and the
/// protocol operations needed by this library.
#[wasm_bindgen(js_name = generateIssuerKeys)]
pub fn generate_issuer_keys(modulus_bits: usize) -> Result<PbrsaKeyPair, JsError> {
    PbrsaKeyPair::generate(modulus_bits)
}

/// Issuer key pair used for partially blind credential issuance.
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
                info: None,
            },
            secret_key: PbrsaSecretKey {
                inner: key_pair.sk,
                info: None,
            },
        })
    }
}

#[wasm_bindgen]
impl PbrsaKeyPair {
    /// Returns the issuer public key used by holders for blinding and by verifiers for signatures.
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> PbrsaPublicKey {
        self.public_key.clone()
    }

    /// Returns the issuer secret key used to produce partial blind signatures.
    #[wasm_bindgen(getter, js_name = secretKey)]
    pub fn secret_key(&self) -> PbrsaSecretKey {
        self.secret_key.clone()
    }
}

/// Issuer public key for PBRSA blinding and signature verification.
#[wasm_bindgen]
#[derive(Clone)]
pub struct PbrsaPublicKey {
    inner: PbrsaPublicKeyInner,
    info: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl PbrsaPublicKey {
    /// Blinds holder-hidden credential data for the given issuer-visible credential info.
    ///
    /// `blind_msg` is the canonical holder-hidden payload. `info` is the
    /// canonical issuer-visible credential info and is bound into the PBRSA
    /// operation as public info.
    pub fn blind(&self, blind_msg: Vec<u8>, info: Vec<u8>) -> Result<BlindingResultBytes, JsError> {
        let public_key = self.inner_for_info(&info)?;
        Ok(BlindingResultBytes {
            inner: public_key
                .blind(&mut DefaultRng, blind_msg, Some(&info))
                .map_err(js_error)?,
        })
    }

    /// Verifies a finalized PBRSA signature over `blind_msg` and `info`.
    ///
    /// Returns `false` for cryptographic verification failure and `Err` for
    /// malformed inputs such as an invalid message randomizer length.
    pub fn verify(
        &self,
        signature: Vec<u8>,
        message_randomizer: Vec<u8>,
        blind_msg: Vec<u8>,
        info: Vec<u8>,
    ) -> Result<bool, JsError> {
        let public_key = self.inner_for_info(&info)?;
        let message_randomizer = Some(message_randomizer_from_bytes(message_randomizer)?);
        Ok(public_key
            .verify(
                &Signature(signature),
                message_randomizer,
                blind_msg,
                Some(&info),
            )
            .is_ok())
    }
}

impl PbrsaPublicKey {
    fn inner_for_info(&self, info: &[u8]) -> Result<PbrsaPublicKeyInner, JsError> {
        if let Some(expected) = &self.info {
            if expected != info {
                return Err(JsError::new(
                    "info must match the derived PBRSA public key info",
                ));
            }
            return Ok(self.inner.clone());
        }

        self.inner
            .derive_public_key_for_metadata(info)
            .map_err(js_error)
    }
}

/// Issuer secret key for producing PBRSA partial blind signatures.
#[wasm_bindgen]
#[derive(Clone)]
pub struct PbrsaSecretKey {
    inner: PbrsaSecretKeyInner,
    info: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl PbrsaSecretKey {
    /// Produces a partial blind signature for a blinded holder message and visible credential info.
    ///
    /// `blind_msg` must be the blinded output from `PbrsaPublicKey.blind`.
    /// `info` must be the same canonical credential info used during blinding.
    #[wasm_bindgen(js_name = blindSign)]
    pub fn blind_sign(&self, blind_msg: Vec<u8>, info: Vec<u8>) -> Result<Vec<u8>, JsError> {
        let secret_key = self.inner_for_info(&info)?;
        Ok(secret_key.blind_sign(blind_msg).map_err(js_error)?.0)
    }
}

impl PbrsaSecretKey {
    fn inner_for_info(&self, info: &[u8]) -> Result<PbrsaSecretKeyInner, JsError> {
        if let Some(expected) = &self.info {
            if expected != info {
                return Err(JsError::new(
                    "info must match the derived PBRSA secret key info",
                ));
            }
            return Ok(self.inner.clone());
        }

        let public_key = self.inner.public_key().map_err(js_error)?;
        PbrsaKeyPairInner {
            pk: public_key,
            sk: self.inner.clone(),
        }
        .derive_secret_key_for_metadata(info)
        .map_err(js_error)
    }
}

/// Holder-side blinding state returned from `PbrsaPublicKey.blind`.
#[wasm_bindgen]
pub struct BlindingResultBytes {
    inner: BlindingResult,
}

#[wasm_bindgen]
impl BlindingResultBytes {
    /// Returns the blinded holder message sent to the issuer for signing.
    #[wasm_bindgen(getter, js_name = blind_msg)]
    pub fn blind_message(&self) -> Vec<u8> {
        self.inner.blind_message.0.clone()
    }

    /// Returns the blinding secret retained by the holder until finalization.
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Vec<u8> {
        self.inner.secret.0.clone()
    }

    /// Returns the randomized PSS message randomizer needed for final verification.
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
    blinded_msg: Vec<u8>,
    secret: Vec<u8>,
    message_randomizer: Vec<u8>,
    blind_msg: Vec<u8>,
    info: Vec<u8>,
) -> Result<Vec<u8>, JsError> {
    let derived_public_key = public_key.inner_for_info(&info)?;
    let blinding_result = blinding_result_from_bytes(blinded_msg, secret, message_randomizer)?;
    Ok(derived_public_key
        .finalize(
            &BlindSignature(blind_signature),
            &blinding_result,
            blind_msg,
            Some(&info),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_blind_msg() -> Vec<u8> {
        b"holder-public-key".to_vec()
    }

    fn test_info() -> Vec<u8> {
        br#"{"schema":"sha256:test","score":7}"#.to_vec()
    }

    #[test]
    fn issuer_keygen_returns_blinding_and_signing_keys() {
        let key_pair = generate_issuer_keys(1024).unwrap();

        let public_key = key_pair.public_key();
        let secret_key = key_pair.secret_key();
        let info = test_info();
        let blinded = public_key
            .blind(test_blind_msg(), info.clone())
            .expect("public key should blind with info");

        assert!(!blinded.blind_message().is_empty());
        assert!(!blinded.secret().is_empty());
        assert_eq!(blinded.message_randomizer().len(), 32);
        assert!(
            secret_key
                .blind_sign(blinded.blind_message(), info)
                .expect("secret key should blind-sign")
                .len()
                > 0
        );
    }

    #[test]
    fn blind_sign_finalize_and_verify_round_trip() {
        let key_pair = generate_issuer_keys(1024).unwrap();
        let public_key = key_pair.public_key();
        let secret_key = key_pair.secret_key();
        let blind_msg = test_blind_msg();
        let info = test_info();

        let blinded = public_key.blind(blind_msg.clone(), info.clone()).unwrap();
        let blind_signature = secret_key
            .blind_sign(blinded.blind_message(), info.clone())
            .unwrap();
        let signature = finalize_pbrsa_signature(
            &public_key,
            blind_signature,
            blinded.blind_message(),
            blinded.secret(),
            blinded.message_randomizer(),
            blind_msg.clone(),
            info.clone(),
        )
        .unwrap();

        assert!(public_key
            .verify(signature, blinded.message_randomizer(), blind_msg, info,)
            .unwrap());
    }

    #[test]
    fn verify_returns_false_for_tampered_message() {
        let key_pair = generate_issuer_keys(1024).unwrap();
        let public_key = key_pair.public_key();
        let secret_key = key_pair.secret_key();
        let blind_msg = test_blind_msg();
        let info = test_info();

        let blinded = public_key.blind(blind_msg.clone(), info.clone()).unwrap();
        let blind_signature = secret_key
            .blind_sign(blinded.blind_message(), info.clone())
            .unwrap();
        let signature = finalize_pbrsa_signature(
            &public_key,
            blind_signature,
            blinded.blind_message(),
            blinded.secret(),
            blinded.message_randomizer(),
            blind_msg,
            info.clone(),
        )
        .unwrap();

        assert!(!public_key
            .verify(
                signature,
                blinded.message_randomizer(),
                b"tampered-message".to_vec(),
                info,
            )
            .unwrap());
    }

    #[test]
    fn info_bound_keys_work_with_matching_info() {
        let key_pair = generate_issuer_keys(1024).unwrap();
        let info = test_info();
        let derived_public_key = PbrsaPublicKey {
            inner: key_pair.public_key().inner_for_info(&info).unwrap(),
            info: Some(info.clone()),
        };
        let derived_secret_key = PbrsaSecretKey {
            inner: key_pair.secret_key().inner_for_info(&info).unwrap(),
            info: Some(info.clone()),
        };
        let blind_msg = test_blind_msg();
        let blinded = derived_public_key
            .blind(blind_msg.clone(), info.clone())
            .unwrap();
        let blind_signature = derived_secret_key
            .blind_sign(blinded.blind_message(), info.clone())
            .unwrap();
        let signature = finalize_pbrsa_signature(
            &derived_public_key,
            blind_signature,
            blinded.blind_message(),
            blinded.secret(),
            blinded.message_randomizer(),
            blind_msg.clone(),
            info.clone(),
        )
        .unwrap();

        assert!(derived_public_key
            .verify(signature, blinded.message_randomizer(), blind_msg, info)
            .unwrap());
    }

    #[test]
    fn verify_returns_false_for_wrong_info() {
        let key_pair = generate_issuer_keys(1024).unwrap();
        let public_key = key_pair.public_key();
        let secret_key = key_pair.secret_key();
        let blind_msg = test_blind_msg();
        let info = test_info();
        let wrong_info = b"wrong-info".to_vec();

        let blinded = public_key.blind(blind_msg.clone(), info.clone()).unwrap();
        let blind_signature = secret_key
            .blind_sign(blinded.blind_message(), info.clone())
            .unwrap();
        let signature = finalize_pbrsa_signature(
            &public_key,
            blind_signature,
            blinded.blind_message(),
            blinded.secret(),
            blinded.message_randomizer(),
            blind_msg.clone(),
            info,
        )
        .unwrap();

        assert!(!public_key
            .verify(
                signature,
                blinded.message_randomizer(),
                blind_msg,
                wrong_info,
            )
            .unwrap());
    }
}
