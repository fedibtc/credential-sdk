use crate::types::ByteArray;
use crate::Result;

#[derive(Clone, Debug)]
pub struct PbrsaKeyPair {
    pub public_key: PbrsaPublicKey,
    pub secret_key: PbrsaSecretKey,
}

#[derive(Clone, Debug)]
pub struct PbrsaPublicKey {
    inner: PbrsaPublicKeyInner,
    info: Option<ByteArray>,
}

#[derive(Clone, Debug)]
pub struct PbrsaSecretKey {
    inner: PbrsaSecretKeyInner,
    info: Option<ByteArray>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlindingResult {
    pub blind_msg: ByteArray,
    pub secret: ByteArray,
    pub message_randomizer: ByteArray,
}

#[derive(Clone, Debug)]
struct PbrsaPublicKeyInner;

#[derive(Clone, Debug)]
struct PbrsaSecretKeyInner;

pub fn generate_issuer_keys(modulus_bits: usize) -> Result<PbrsaKeyPair> {
    let _ = modulus_bits;
    todo!("generate a PBRSA issuer key pair")
}

impl PbrsaPublicKey {
    pub fn blind(&self, blind_msg: ByteArray, info: ByteArray) -> Result<BlindingResult> {
        let _ = (&self.inner, &self.info, blind_msg, info);
        todo!("blind holder-hidden data with issuer-visible info")
    }

    pub fn verify(
        &self,
        signature: ByteArray,
        message_randomizer: ByteArray,
        blind_msg: ByteArray,
        info: ByteArray,
    ) -> Result<bool> {
        let _ = (
            &self.inner,
            &self.info,
            signature,
            message_randomizer,
            blind_msg,
            info,
        );
        todo!("verify a finalized PBRSA signature")
    }

    #[allow(dead_code)]
    fn inner_for_info(&self, info: &[u8]) -> Result<PbrsaPublicKeyInner> {
        let _ = (&self.inner, &self.info, info);
        todo!("derive or validate a PBRSA public key for credential info")
    }
}

impl PbrsaSecretKey {
    pub fn blind_sign(&self, blind_msg: ByteArray, info: ByteArray) -> Result<ByteArray> {
        let _ = (&self.inner, &self.info, blind_msg, info);
        todo!("produce a partial blind signature")
    }

    #[allow(dead_code)]
    fn inner_for_info(&self, info: &[u8]) -> Result<PbrsaSecretKeyInner> {
        let _ = (&self.inner, &self.info, info);
        todo!("derive or validate a PBRSA secret key for credential info")
    }
}

#[allow(dead_code)]
pub(crate) fn finalize_pbrsa_signature(
    public_key: &PbrsaPublicKey,
    blind_signature: ByteArray,
    blinded_msg: ByteArray,
    secret: ByteArray,
    message_randomizer: ByteArray,
    blind_msg: ByteArray,
    info: ByteArray,
) -> Result<ByteArray> {
    let _ = (
        public_key,
        blind_signature,
        blinded_msg,
        secret,
        message_randomizer,
        blind_msg,
        info,
    );
    todo!("finalize a PBRSA blind signature")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_blind_msg() -> ByteArray {
        b"holder-public-key".to_vec()
    }

    fn test_info() -> ByteArray {
        br#"{"schema":"sha256:test","score":7}"#.to_vec()
    }

    #[test]
    #[ignore = "protocol implementation pending"]
    fn issuer_keygen_returns_blinding_and_signing_keys() {
        let key_pair = generate_issuer_keys(1024).unwrap();

        let public_key = key_pair.public_key;
        let secret_key = key_pair.secret_key;
        let info = test_info();
        let blinded = public_key
            .blind(test_blind_msg(), info.clone())
            .expect("public key should blind with info");

        assert!(!blinded.blind_msg.is_empty());
        assert!(!blinded.secret.is_empty());
        assert_eq!(blinded.message_randomizer.len(), 32);
        assert!(
            secret_key
                .blind_sign(blinded.blind_msg, info)
                .expect("secret key should blind-sign")
                .len()
                > 0
        );
    }

    #[test]
    #[ignore = "protocol implementation pending"]
    fn blind_sign_finalize_and_verify_round_trip() {
        let key_pair = generate_issuer_keys(1024).unwrap();
        let public_key = key_pair.public_key.clone();
        let secret_key = key_pair.secret_key;
        let blind_msg = test_blind_msg();
        let info = test_info();

        let blinded = public_key.blind(blind_msg.clone(), info.clone()).unwrap();
        let blind_signature = secret_key
            .blind_sign(blinded.blind_msg.clone(), info.clone())
            .unwrap();
        let signature = finalize_pbrsa_signature(
            &public_key,
            blind_signature,
            blinded.blind_msg.clone(),
            blinded.secret.clone(),
            blinded.message_randomizer.clone(),
            blind_msg.clone(),
            info.clone(),
        )
        .unwrap();

        assert!(public_key
            .verify(signature, blinded.message_randomizer, blind_msg, info)
            .unwrap());
    }

    #[test]
    #[ignore = "protocol implementation pending"]
    fn verify_returns_false_for_tampered_message() {
        let key_pair = generate_issuer_keys(1024).unwrap();
        let public_key = key_pair.public_key.clone();
        let secret_key = key_pair.secret_key;
        let blind_msg = test_blind_msg();
        let info = test_info();

        let blinded = public_key.blind(blind_msg.clone(), info.clone()).unwrap();
        let blind_signature = secret_key
            .blind_sign(blinded.blind_msg.clone(), info.clone())
            .unwrap();
        let signature = finalize_pbrsa_signature(
            &public_key,
            blind_signature,
            blinded.blind_msg.clone(),
            blinded.secret.clone(),
            blinded.message_randomizer.clone(),
            blind_msg,
            info.clone(),
        )
        .unwrap();

        assert!(!public_key
            .verify(
                signature,
                blinded.message_randomizer,
                b"tampered-message".to_vec(),
                info,
            )
            .unwrap());
    }

    #[test]
    #[ignore = "protocol implementation pending"]
    fn info_bound_keys_work_with_matching_info() {
        let key_pair = generate_issuer_keys(1024).unwrap();
        let info = test_info();
        let derived_public_key = PbrsaPublicKey {
            inner: key_pair.public_key.inner_for_info(&info).unwrap(),
            info: Some(info.clone()),
        };
        let derived_secret_key = PbrsaSecretKey {
            inner: key_pair.secret_key.inner_for_info(&info).unwrap(),
            info: Some(info.clone()),
        };
        let blind_msg = test_blind_msg();
        let blinded = derived_public_key
            .blind(blind_msg.clone(), info.clone())
            .unwrap();
        let blind_signature = derived_secret_key
            .blind_sign(blinded.blind_msg.clone(), info.clone())
            .unwrap();
        let signature = finalize_pbrsa_signature(
            &derived_public_key,
            blind_signature,
            blinded.blind_msg.clone(),
            blinded.secret.clone(),
            blinded.message_randomizer.clone(),
            blind_msg.clone(),
            info.clone(),
        )
        .unwrap();

        assert!(derived_public_key
            .verify(signature, blinded.message_randomizer, blind_msg, info)
            .unwrap());
    }

    #[test]
    #[ignore = "protocol implementation pending"]
    fn verify_returns_false_for_wrong_info() {
        let key_pair = generate_issuer_keys(1024).unwrap();
        let public_key = key_pair.public_key.clone();
        let secret_key = key_pair.secret_key;
        let blind_msg = test_blind_msg();
        let info = test_info();
        let wrong_info = b"wrong-info".to_vec();

        let blinded = public_key.blind(blind_msg.clone(), info.clone()).unwrap();
        let blind_signature = secret_key
            .blind_sign(blinded.blind_msg.clone(), info.clone())
            .unwrap();
        let signature = finalize_pbrsa_signature(
            &public_key,
            blind_signature,
            blinded.blind_msg.clone(),
            blinded.secret.clone(),
            blinded.message_randomizer.clone(),
            blind_msg.clone(),
            info,
        )
        .unwrap();

        assert!(!public_key
            .verify(signature, blinded.message_randomizer, blind_msg, wrong_info,)
            .unwrap());
    }
}
