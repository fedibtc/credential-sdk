//! Shared credential protocol error handling.

pub use blind_rsa_signatures::pbrsa::PartiallyBlindPublicKeySha384PSSRandomized as PbrsaPublicKey;
use thiserror::Error;

/// Error returned by runtime credential protocol operations.
#[derive(Debug, Error)]
pub enum CredentialsError {
    #[error("blind RSA operation failed: {0}")]
    BlindRsa(#[from] blind_rsa_signatures::Error),
    #[error("failed to build canonicalized payload: {0}")]
    Canonicalize(#[from] serde_json::Error),
    #[error("issuer_id does not match")]
    IssuerIdMismatch,
    #[error("issuance response info does not match")]
    InfoMismatch,
    #[error("randomized PBRSA suite did not return a message randomizer")]
    MissingMessageRandomizer,
    #[error("unknown issuer")]
    UnknownIssuer,
    #[error("credential has been revoked")]
    CredentialRevoked,
    #[error("verification failed")]
    VerificationFailed,
}
