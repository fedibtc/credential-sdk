//! Shared PBRSA runtime error handling.

pub use blind_rsa_signatures::pbrsa::PartiallyBlindPublicKeySha384PSSRandomized as PbrsaPublicKey;
use thiserror::Error;

use crate::PROTOCOL_VERSION_V1;

/// Error returned by runtime PBRSA operations.
#[derive(Debug, Error)]
pub enum PbrsaError {
    #[error("blind RSA operation failed: {0}")]
    BlindRsa(#[from] blind_rsa_signatures::Error),
    #[error("failed to build canonicalized payload: {0}")]
    Canonicalize(#[from] serde_json::Error),
    #[error("unsupported protocol version: {}", .0.get())]
    UnsupportedProtocolVersion(crate::ProtocolVersion),
    #[error("issuance response issuer_id does not match")]
    IssuerIdMismatch,
    #[error("issuance response info does not match")]
    InfoMismatch,
    #[error("randomized PBRSA suite did not return a message randomizer")]
    MissingMessageRandomizer,
}

pub(crate) fn check_version(version: crate::ProtocolVersion) -> Result<(), PbrsaError> {
    if version == PROTOCOL_VERSION_V1 {
        Ok(())
    } else {
        Err(PbrsaError::UnsupportedProtocolVersion(version))
    }
}
