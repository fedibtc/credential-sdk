//! Issuer-side PBRSA issuance operations.

use blind_rsa_signatures::{pbrsa::PartiallyBlindKeyPairSha384PSSRandomized, DefaultRng};
use serde_json::Value;

use crate::{
    canonicalize_pbrsa_info, Credential, CredentialsError, IssuanceRequest, IssuanceResponse,
    IssuerId, PbrsaPublicKey, ProtocolV1, Revocation,
};

/// Runtime issuer context containing issuer identity and PBRSA signing key.
#[derive(Clone)]
pub struct IssuerContext {
    pub issuer_id: IssuerId,
    key_pair: PartiallyBlindKeyPairSha384PSSRandomized,
}

impl IssuerContext {
    /// Generate an issuer context with a fresh PBRSA key pair.
    pub fn generate(issuer_id: IssuerId, modulus_bits: usize) -> Result<Self, CredentialsError> {
        Ok(Self {
            issuer_id,
            key_pair: PartiallyBlindKeyPairSha384PSSRandomized::generate(
                &mut DefaultRng,
                modulus_bits,
            )?,
        })
    }

    pub fn from_key_pair(
        issuer_id: IssuerId,
        key_pair: PartiallyBlindKeyPairSha384PSSRandomized,
    ) -> Self {
        Self {
            issuer_id,
            key_pair,
        }
    }

    pub fn public_key(&self) -> PbrsaPublicKey {
        self.key_pair.pk.clone()
    }

    pub fn secret_key_der(&self) -> Result<Vec<u8>, CredentialsError> {
        Ok(self.key_pair.sk.to_der()?)
    }

    pub fn from_secret_key_der(issuer_id: IssuerId, der: &[u8]) -> Result<Self, CredentialsError> {
        let secret_key =
            blind_rsa_signatures::pbrsa::PartiallyBlindSecretKeySha384PSSRandomized::from_der(der)?;
        let public_key = secret_key.public_key()?;
        Ok(Self {
            issuer_id,
            key_pair: PartiallyBlindKeyPairSha384PSSRandomized {
                pk: public_key,
                sk: secret_key,
            },
        })
    }

    /// Issue a blind signature over a holder issuance request.
    pub fn issue_credential(
        &self,
        info: Value,
        request: &IssuanceRequest,
    ) -> Result<IssuanceResponse, CredentialsError> {
        let metadata = canonicalize_pbrsa_info(ProtocolV1, &self.issuer_id, &info)?;
        let secret_key = self.key_pair.derive_secret_key_for_metadata(&metadata)?;
        Ok(IssuanceResponse {
            version: ProtocolV1,
            issuer_id: self.issuer_id.clone(),
            info,
            blind_signature: secret_key.blind_sign(&request.blinded_message)?,
        })
    }

    /// Build the revocation target for a finalized credential issued by this issuer.
    ///
    /// This computes the finalized credential digest and binds it to this issuer
    /// identity. It does not sign, publish, or transport the revocation; those
    /// concerns live in the revocation layer.
    pub fn revoke_credential(
        &self,
        credential: &Credential,
    ) -> Result<Revocation, CredentialsError> {
        if credential.issuer_id != self.issuer_id {
            return Err(CredentialsError::IssuerIdMismatch);
        }

        let credential_digest = credential.digest()?;

        Ok(Revocation {
            issuer_id: self.issuer_id.clone(),
            credential_digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{verifier::verify_credential_with_key, Credential, PendingIssuance};

    // review: this is stupid, just do random
    fn issuer_id(byte: u8) -> IssuerId {
        IssuerId(nostr::PublicKey::from_byte_array([byte; 32]))
    }

    #[test]
    fn pbrsa_roundtrip_and_secret_der_import_export() {
        let issuer_id = issuer_id(1);
        let issuer = IssuerContext::generate(issuer_id.clone(), 1024).unwrap();
        let public_key = issuer.public_key();
        let issuer = IssuerContext::from_secret_key_der(
            issuer_id.clone(),
            &issuer.secret_key_der().unwrap(),
        )
        .unwrap();
        let info = json!({ "credential": "test", "tier": 1 });
        let blind_msg = json!({ "holder": "alice", "nonce": 7 });

        let (bad_request, bad_pending) = PendingIssuance::create_request(
            &public_key,
            issuer_id.clone(),
            info.clone(),
            blind_msg.clone(),
        )
        .unwrap();
        let master_key_response = IssuanceResponse {
            version: ProtocolV1,
            issuer_id: issuer_id.clone(),
            info: info.clone(),
            blind_signature: issuer
                .key_pair
                .sk
                .blind_sign(&bad_request.blinded_message)
                .unwrap(),
        };
        // review: split this into multiple tests
        assert!(matches!(
            bad_pending.finalize(&public_key, &master_key_response),
            Err(CredentialsError::BlindRsa(
                blind_rsa_signatures::Error::VerificationFailed
            ))
        ));

        let (request, pending) = PendingIssuance::create_request(
            &public_key,
            issuer_id.clone(),
            info.clone(),
            blind_msg.clone(),
        )
        .unwrap();
        let response = issuer.issue_credential(info.clone(), &request).unwrap();
        let credential = pending.finalize(&public_key, &response).unwrap();

        assert_eq!(credential.issuer_id, issuer_id);
        assert_eq!(credential.info, info);
        assert_eq!(credential.blind_msg, blind_msg);
        verify_credential_with_key(&public_key, &credential).unwrap();
    }

    #[test]
    fn pbrsa_detects_tampering() {
        let issuer = IssuerContext::generate(issuer_id(2), 1024).unwrap();
        let public_key = issuer.public_key();
        let issuer_id = issuer.issuer_id.clone();
        let info = json!({ "credential": "test" });

        let (request, pending) = PendingIssuance::create_request(
            &public_key,
            issuer_id,
            info.clone(),
            json!({ "holder": "alice" }),
        )
        .unwrap();
        let response = issuer.issue_credential(info, &request).unwrap();
        let mut credential: Credential = pending.finalize(&public_key, &response).unwrap();

        credential.blind_msg = json!({ "holder": "mallory" });
        assert!(matches!(
            verify_credential_with_key(&public_key, &credential),
            Err(CredentialsError::BlindRsa(
                blind_rsa_signatures::Error::VerificationFailed
            ))
        ));
    }

    #[test]
    fn revoke_credential_returns_issuer_bound_digest() {
        let issuer_id = issuer_id(3);
        let issuer = IssuerContext::generate(issuer_id.clone(), 1024).unwrap();
        let public_key = issuer.public_key();
        let info = json!({ "credential": "test" });
        let blind_msg = json!({ "holder": "alice" });

        let (request, pending) = PendingIssuance::create_request(
            &public_key,
            issuer_id.clone(),
            info.clone(),
            blind_msg,
        )
        .unwrap();
        let response = issuer.issue_credential(info, &request).unwrap();
        let credential = pending.finalize(&public_key, &response).unwrap();

        let revocation = issuer.revoke_credential(&credential).unwrap();

        assert_eq!(revocation.issuer_id, issuer_id);
        assert_eq!(revocation.credential_digest, credential.digest().unwrap());
    }

    #[test]
    fn revoke_credential_rejects_wrong_issuer() {
        let issuer = IssuerContext::generate(issuer_id(4), 1024).unwrap();
        let public_key = issuer.public_key();
        let credential_issuer_id = issuer.issuer_id.clone();
        let info = json!({ "credential": "test" });

        let (request, pending) = PendingIssuance::create_request(
            &public_key,
            credential_issuer_id,
            info.clone(),
            json!({ "holder": "alice" }),
        )
        .unwrap();
        let response = issuer.issue_credential(info, &request).unwrap();
        let credential = pending.finalize(&public_key, &response).unwrap();
        let other_issuer = IssuerContext::generate(issuer_id(5), 1024).unwrap();

        assert!(matches!(
            other_issuer.revoke_credential(&credential),
            Err(CredentialsError::IssuerIdMismatch)
        ));
    }
}
