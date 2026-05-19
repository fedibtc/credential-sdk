//! Shared PBRSA runtime error handling.

use blind_rsa_signatures::pbrsa::PartiallyBlindPublicKeySha384PSSRandomized;
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

/// Issuer PBRSA public key used for holder blinding and credential verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PbrsaPublicKey {
    inner: PartiallyBlindPublicKeySha384PSSRandomized,
}

impl PbrsaPublicKey {
    pub(crate) fn new(inner: PartiallyBlindPublicKeySha384PSSRandomized) -> Self {
        Self { inner }
    }

    pub(crate) fn as_inner(&self) -> &PartiallyBlindPublicKeySha384PSSRandomized {
        &self.inner
    }

    /// Import a PBRSA public key from DER bytes.
    pub fn from_der(der: &[u8]) -> Result<Self, PbrsaError> {
        Ok(Self::new(
            PartiallyBlindPublicKeySha384PSSRandomized::from_der(der)?,
        ))
    }

    /// Export this PBRSA public key as DER bytes.
    pub fn to_der(&self) -> Result<Vec<u8>, PbrsaError> {
        Ok(self.inner.to_der()?)
    }
}
