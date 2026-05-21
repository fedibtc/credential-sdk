//! Verifier-side PBRSA credential verification operations.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    canonicalize_pbrsa_blind_msg, canonicalize_pbrsa_info, CredentialsError, IssuerBundle,
    IssuerId, PbrsaPublicKey, ProtocolV1, Revocation, SignedCredential, SignedRevocation,
};

/// Stateful verifier for trusted issuers, revocations, and credentials.
#[derive(Clone, Default)]
pub struct VerificationContext {
    issuers: BTreeMap<IssuerId, PbrsaPublicKey>,
    revocations: BTreeSet<Revocation>,
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
        if !self
            .issuers
            .contains_key(&signed_revocation.proof.issuer_id_pubkey)
        {
            return Err(CredentialsError::UnknownIssuer);
        }

        self.revocations.insert(revocation);
        Ok(())
    }

    /// Verify a finalized credential against trusted issuers and revocations.
    pub fn verify_credential(&self, credential: &SignedCredential) -> Result<(), CredentialsError> {
        let issuer_public_key = self
            .issuers
            .get(&credential.credential.issuer_id_pubkey)
            .ok_or(CredentialsError::UnknownIssuer)?;

        verify_credential_with_key(issuer_public_key, credential)?;

        let revocation = Revocation {
            credential_digest: credential.credential.digest()?,
        };

        if self.revocations.contains(&revocation) {
            return Err(CredentialsError::CredentialRevoked);
        }

        Ok(())
    }
}

pub(crate) fn verify_credential_with_key(
    issuer_public_key: &PbrsaPublicKey,
    credential: &SignedCredential,
) -> Result<(), CredentialsError> {
    let metadata = canonicalize_pbrsa_info(
        ProtocolV1,
        &credential.credential.issuer_id_pubkey,
        &credential.credential.info,
    )?;
    let message = canonicalize_pbrsa_blind_msg(ProtocolV1, &credential.credential.blind_msg)?;
    let public_key = issuer_public_key.derive_public_key_for_metadata(&metadata)?;
    public_key.verify(
        &credential.proof.signature,
        Some(credential.credential.message_randomizer),
        &message,
        Some(&metadata),
    )?;
    Ok(())
}
