//! Holder-side PBRSA issuance operations.

use blind_rsa_signatures::BlindingResult;
use serde_json::Value;

use crate::{
    canonicalize_pbrsa_blind_msg, canonicalize_pbrsa_info, verifier::verify_credential_with_key,
    Credential, CredentialPayload, CredentialProof, CredentialsError, IssuanceRequest,
    IssuanceResponse, IssuerId, PbrsaPublicKey, ProtocolV1,
};

/// Holder-side pending issuance state.
pub struct PendingIssuance {
    pub issuer_id: IssuerId,
    pub info: Value,
    pub blind_msg: Value,
    blinding_result: BlindingResult,
}

impl PendingIssuance {
    /// Create a holder issuance request and local pending state.
    pub fn create_request(
        issuer_public_key: &PbrsaPublicKey,
        issuer_id: IssuerId,
        info: Value,
        blind_msg: Value,
    ) -> Result<(IssuanceRequest, Self), CredentialsError> {
        let mut rng = blind_rsa_signatures::DefaultRng;

        Self::create_request_with_rng(issuer_public_key, issuer_id, info, blind_msg, &mut rng)
    }

    pub(crate) fn create_request_with_rng(
        issuer_public_key: &PbrsaPublicKey,
        issuer_id: IssuerId,
        info: Value,
        blind_msg: Value,
        rng: &mut (impl blind_rsa_signatures::reexports::rsa::rand_core::CryptoRng + ?Sized),
    ) -> Result<(IssuanceRequest, Self), CredentialsError> {
        let metadata = canonicalize_pbrsa_info(ProtocolV1, &issuer_id, &info)?;
        let message = canonicalize_pbrsa_blind_msg(ProtocolV1, &blind_msg)?;
        let public_key = issuer_public_key.derive_public_key_for_metadata(&metadata)?;
        let blinding_result = public_key.blind(rng, &message, Some(&metadata))?;

        let request = IssuanceRequest {
            version: ProtocolV1,
            blinded_message: blinding_result.blind_message.clone(),
        };
        let pending = Self {
            issuer_id,
            info,
            blind_msg,
            blinding_result,
        };

        Ok((request, pending))
    }

    /// Finalize an issuer response into a holder credential.
    pub fn finalize(
        self,
        issuer_public_key: &PbrsaPublicKey,
        response: &IssuanceResponse,
    ) -> Result<Credential, CredentialsError> {
        if response.issuer_id != self.issuer_id {
            return Err(CredentialsError::IssuerIdMismatch);
        }
        if response.info != self.info {
            return Err(CredentialsError::InfoMismatch);
        }

        let metadata = canonicalize_pbrsa_info(ProtocolV1, &self.issuer_id, &self.info)?;
        let message = canonicalize_pbrsa_blind_msg(ProtocolV1, &self.blind_msg)?;
        let public_key = issuer_public_key.derive_public_key_for_metadata(&metadata)?;
        let signature = public_key.finalize(
            &response.blind_signature,
            &self.blinding_result,
            &message,
            Some(&metadata),
        )?;
        let message_randomizer = self
            .blinding_result
            .msg_randomizer
            .ok_or(CredentialsError::MissingMessageRandomizer)?;

        let credential = Credential {
            credential: CredentialPayload {
                issuer_id_pubkey: self.issuer_id,
                info: self.info,
                blind_msg: self.blind_msg,
                message_randomizer,
            },
            proof: CredentialProof { signature },
        };
        verify_credential_with_key(issuer_public_key, &credential)?;
        Ok(credential)
    }
}
