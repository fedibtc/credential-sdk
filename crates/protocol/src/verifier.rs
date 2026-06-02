//! Verifier-side PBRSA credential verification operations.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    canonicalize_pbrsa_blind_msg, canonicalize_pbrsa_info, CredentialRef, CredentialsError,
    HolderAuthorization, HolderId, IssuerAuthority, IssuerId, PbrsaPublicKey, ProtocolV1,
    Revocation, SignedCredential, SignedRevocation, SubjectPubkey, TrustBadgeId,
};

/// Stateful verifier for trusted issuers, revocations, and credentials.
#[derive(Clone, Default)]
pub struct VerificationContext {
    issuers: BTreeMap<IssuerId, PbrsaPublicKey>,
    revocations: BTreeSet<(IssuerId, Revocation)>,
}

impl VerificationContext {
    /// Create an empty verifier context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify and trust an issuer authority for subsequent credential checks.
    pub fn add_issuer_authority(
        &mut self,
        authority: &IssuerAuthority,
    ) -> Result<(), CredentialsError> {
        let issuer = authority.verify()?;
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

        self.revocations
            .insert((signed_revocation.proof.issuer_id_pubkey.clone(), revocation));
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

        if self
            .revocations
            .contains(&(credential.credential.issuer_id_pubkey.clone(), revocation))
        {
            return Err(CredentialsError::CredentialRevoked);
        }

        Ok(())
    }

    /// Verify a credential and a holder authorization for a concrete subject.
    ///
    /// The consuming application must pass the holder id it extracted from its
    /// credential schema, plus the expected subject key established by its own
    /// authentication or transport flow. The SDK verifies signatures, issuer
    /// trust, credential revocation state, credential binding, audience, and the
    /// authorization time window.
    pub fn verify_credential_authorization(
        &self,
        credential: &SignedCredential,
        credential_holder_id: &HolderId,
        expected_subject_pubkey: &SubjectPubkey,
        authorization: &HolderAuthorization,
        expected_audience: &str,
        now: u64,
    ) -> Result<(), CredentialsError> {
        self.verify_credential(credential)?;

        let authorization = authorization.verify()?;

        if credential_holder_id != &authorization.holder_id_pubkey {
            return Err(CredentialsError::HolderIdMismatch);
        }

        if expected_subject_pubkey != &authorization.subject_pubkey {
            return Err(CredentialsError::SubjectPubkeyMismatch);
        }

        if expected_audience != authorization.audience {
            return Err(CredentialsError::AuthorizationAudienceMismatch);
        }

        if now < authorization.issued_at {
            return Err(CredentialsError::AuthorizationNotYetValid);
        }

        if now >= authorization.expires_at {
            return Err(CredentialsError::AuthorizationExpired);
        }

        let expected_ref = CredentialRef {
            issuer_id_pubkey: credential.credential.issuer_id_pubkey.clone(),
            trust_badge_id: TrustBadgeId(credential.credential.digest()?),
        };

        if !authorization.credential_refs.contains(&expected_ref) {
            return Err(CredentialsError::AuthorizationCredentialRefMissing);
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
    public_key.verify(&credential.proof.signature, None, &message, Some(&metadata))?;
    Ok(())
}
