//! Verifier-side PBRSA credential verification operations.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    canonicalize_pbrsa_blind_msg, canonicalize_pbrsa_info, Credential, CredentialsError,
    IssuerBundle, IssuerId, PbrsaPublicKey, RevocationEntry, SignedRevocation,
};

/// Stateful verifier for trusted issuers, revocations, and credentials.
#[derive(Clone, Default)]
pub struct VerificationContext {
    issuers: BTreeMap<IssuerId, PbrsaPublicKey>,
    revocations: BTreeSet<RevocationEntry>,
}

impl VerificationContext {
    /// Create an empty verifier context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify and trust an issuer bundle for subsequent credential checks.
    pub fn add_issuer_bundle(&mut self, bundle: &IssuerBundle) -> Result<(), CredentialsError> {
        let issuer = bundle.verify()?;
        self.issuers
            .insert(issuer.issuer_id_pubkey.clone(), issuer.issuance_key.clone());

        Ok(())
    }

    /// Verify and store a signed revocation from a trusted issuer.
    pub fn add_revocation(
        &mut self,
        signed_revocation: &SignedRevocation,
    ) -> Result<(), CredentialsError> {
        let revocation = signed_revocation.verify()?;
        if !self.issuers.contains_key(&revocation.issuer_id_pubkey) {
            return Err(CredentialsError::UnknownIssuer);
        }

        self.revocations.insert(revocation);
        Ok(())
    }

    /// Verify a finalized credential against trusted issuers and revocations.
    pub fn verify_credential(&self, credential: &Credential) -> Result<(), CredentialsError> {
        let issuer_public_key = self
            .issuers
            .get(&credential.issuer_id)
            .ok_or(CredentialsError::UnknownIssuer)?;

        verify_credential_with_key(issuer_public_key, credential)?;

        let revocation = RevocationEntry {
            issuer_id_pubkey: credential.issuer_id.clone(),
            credential_digest: credential.digest()?,
        };

        if self.revocations.contains(&revocation) {
            return Err(CredentialsError::CredentialRevoked);
        }

        Ok(())
    }
}

pub(crate) fn verify_credential_with_key(
    issuer_public_key: &PbrsaPublicKey,
    credential: &Credential,
) -> Result<(), CredentialsError> {
    let metadata =
        canonicalize_pbrsa_info(credential.version, &credential.issuer_id, &credential.info)?;
    let message = canonicalize_pbrsa_blind_msg(credential.version, &credential.blind_msg)?;
    let public_key = issuer_public_key.derive_public_key_for_metadata(&metadata)?;
    public_key.verify(
        &credential.signature,
        Some(credential.message_randomizer),
        &message,
        Some(&metadata),
    )?;
    Ok(())
}
