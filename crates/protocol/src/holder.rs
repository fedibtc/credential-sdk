//! Holder-side PBRSA issuance operations.

use blind_rsa_signatures::{
    pbrsa::PartiallyBlindPublicKeySha384PSSRandomized, BlindingResult as UpstreamBlindingResult,
    DefaultRng,
};
use serde_json::Value;

use crate::{
    canonicalize_pbrsa_blind_msg, canonicalize_pbrsa_info, pbrsa::check_version, verify_credential,
    Credential, IssuanceRequest, IssuanceResponse, IssuerId, PbrsaError, PROTOCOL_VERSION_V1,
};

/// Holder-side pending issuance state.
#[derive(Clone, Debug, PartialEq)]
pub struct PendingIssuance {
    pub issuer_id: IssuerId,
    pub info: Value,
    pub blind_msg: Value,
    blinding_result: UpstreamBlindingResult,
}

impl PendingIssuance {
    /// Create a holder issuance request and local pending state.
    pub fn create_request(
        issuer_public_key: &PartiallyBlindPublicKeySha384PSSRandomized,
        issuer_id: IssuerId,
        info: Value,
        blind_msg: Value,
    ) -> Result<(IssuanceRequest, Self), PbrsaError> {
        let metadata = canonicalize_pbrsa_info(PROTOCOL_VERSION_V1, &issuer_id, &info)?;
        let message = canonicalize_pbrsa_blind_msg(PROTOCOL_VERSION_V1, &blind_msg)?;
        let public_key = issuer_public_key.derive_public_key_for_metadata(&metadata)?;
        let blinding_result = public_key.blind(&mut DefaultRng, &message, Some(&metadata))?;

        let request = IssuanceRequest {
            version: PROTOCOL_VERSION_V1,
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
        issuer_public_key: &PartiallyBlindPublicKeySha384PSSRandomized,
        response: &IssuanceResponse,
    ) -> Result<Credential, PbrsaError> {
        check_version(response.version)?;
        if response.issuer_id != self.issuer_id {
            return Err(PbrsaError::IssuerIdMismatch);
        }
        if response.info != self.info {
            return Err(PbrsaError::InfoMismatch);
        }

        let metadata = canonicalize_pbrsa_info(PROTOCOL_VERSION_V1, &self.issuer_id, &self.info)?;
        let message = canonicalize_pbrsa_blind_msg(PROTOCOL_VERSION_V1, &self.blind_msg)?;
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
            .ok_or(PbrsaError::MissingMessageRandomizer)?;

        let credential = Credential {
            version: PROTOCOL_VERSION_V1,
            issuer_id: self.issuer_id,
            info: self.info,
            blind_msg: self.blind_msg,
            message_randomizer,
            signature,
        };
        verify_credential(issuer_public_key, &credential)?;
        Ok(credential)
    }
}
