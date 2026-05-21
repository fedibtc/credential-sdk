//! Shared credential protocol error handling.

pub use blind_rsa_signatures::pbrsa::PartiallyBlindPublicKeySha384PSSDeterministic as PbrsaPublicKey;
use thiserror::Error;

/// Error returned by runtime credential protocol operations.
#[derive(Debug, Error)]
pub enum CredentialsError {
    #[error("blind RSA operation failed: {0}")]
    BlindRsa(#[from] blind_rsa_signatures::Error),
    #[error("failed to build canonicalized payload: {0}")]
    Canonicalize(#[from] serde_json::Error),
    #[error("invalid Nostr key: {0}")]
    NostrKey(#[from] nostr::key::Error),
    #[error("issuer_id does not match")]
    IssuerIdMismatch,
    #[error("issuance response info does not match")]
    InfoMismatch,
    #[error("invalid pending issuance state: {0}")]
    InvalidPendingIssuanceState(String),
    #[error("unknown issuer")]
    UnknownIssuer,
    #[error("credential has been revoked")]
    CredentialRevoked,
    #[error("verification failed")]
    VerificationFailed,
}
