//! Verifier-side PBRSA credential verification operations.

use crate::{
    canonicalize_pbrsa_blind_msg, canonicalize_pbrsa_info, pbrsa::check_version, Credential,
    PbrsaError, PbrsaPublicKey,
};

/// Verify a finalized credential.
pub fn verify_credential(
    issuer_public_key: &PbrsaPublicKey,
    credential: &Credential,
) -> Result<(), PbrsaError> {
    check_version(credential.version)?;
    let metadata =
        canonicalize_pbrsa_info(credential.version, &credential.issuer_id, &credential.info)?;
    let message = canonicalize_pbrsa_blind_msg(credential.version, &credential.blind_msg)?;
    let public_key = issuer_public_key
        .as_inner()
        .derive_public_key_for_metadata(&metadata)?;
    public_key.verify(
        &credential.signature,
        Some(credential.message_randomizer),
        &message,
        Some(&metadata),
    )?;
    Ok(())
}
