pub mod credential;
pub mod issuer;
pub mod keys;
pub mod schema;
pub mod types;

pub type Result<T> = std::result::Result<T, String>;

pub use credential::{
    blind_sign_credential, create_credential, finalize_credential, verify_credential,
    BlindSignedCredential, CredentialTemplate, VerifiableCredential,
};
pub use issuer::{
    create_credential_issuance_payload, create_signed_credential_response, issue_credential,
    validate_credential_issuance_payload, CredentialIssuancePayload, SignedCredentialResponse,
};
pub use keys::{
    generate_issuer_keys, BlindingResult, PbrsaKeyPair, PbrsaPublicKey, PbrsaSecretKey,
};
pub use schema::SchemaFields;
pub use types::{
    ByteArray, CredentialData, Digest, IssuerBundle, Revocation, SchemaDefinition, SchemaName,
};
