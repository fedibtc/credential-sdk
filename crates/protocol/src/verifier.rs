//! Verifier-side PBRSA credential verification operations.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    canonicalize_pbrsa_blind_msg, canonicalize_pbrsa_info, revocation::verified_revocation,
    verify_issuer_bundle, Credential, CredentialsError, IssuerBundle, IssuerId, PbrsaPublicKey,
    Revocation, SignedRevocation,
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
        verify_issuer_bundle(bundle)?;
        let issuer_public_key = PbrsaPublicKey::from_der(&bundle.issuer.issuance_key)
            .map_err(CredentialsError::from)?;

        self.issuers
            .insert(bundle.issuer.issuer_id_pubkey.clone(), issuer_public_key);

        Ok(())
    }

    /// Verify and store a signed revocation from a trusted issuer.
    pub fn add_revocation(
        &mut self,
        signed_revocation: &SignedRevocation,
    ) -> Result<(), CredentialsError> {
        let revocation = verified_revocation(signed_revocation)?;
        if !self.issuers.contains_key(&revocation.issuer_id) {
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

        let revocation = Revocation {
            issuer_id: credential.issuer_id.clone(),
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{
        canonicalize_issuer_bundle, canonicalize_revocation, Issuer, IssuerContext,
        IssuerSignatureProof, PendingIssuance, RevocationEntry, RevocationLocation, SignatureProof,
        REVOCATION_SIGNATURE_DOMAIN_SEPARATOR,
    };

    fn sign(keys: &nostr::Keys, domain_separator: &[u8], canonical_payload: &[u8]) -> String {
        keys.sign_schnorr(&crate::revocation::signing_message(
            domain_separator,
            canonical_payload,
        ))
        .to_string()
    }

    fn issuer_bundle(keys: &nostr::Keys, issuer_context: &IssuerContext) -> IssuerBundle {
        let issuer = Issuer {
            issuer_id_pubkey: IssuerId(keys.public_key()),
            issuance_key: issuer_context.public_key().to_der().unwrap(),
            revocation: vec![RevocationLocation {
                protocol: "nostr".to_owned(),
                location: "wss://relay.example.com".to_owned(),
            }],
        };
        let signature = sign(
            keys,
            crate::ISSUER_BUNDLE_SIGNATURE_DOMAIN_SEPARATOR,
            &canonicalize_issuer_bundle(&issuer).unwrap(),
        );

        IssuerBundle {
            issuer,
            proof: SignatureProof { signature },
        }
    }

    fn credential(issuer_context: &IssuerContext) -> Credential {
        let issuer_id = issuer_context.issuer_id.clone();
        let public_key = issuer_context.public_key();
        let info = json!({ "credential": "test" });
        let blind_msg = json!({ "holder": "alice" });

        let (request, pending) =
            PendingIssuance::create_request(&public_key, issuer_id, info.clone(), blind_msg)
                .unwrap();
        let response = issuer_context.issue_credential(info, &request).unwrap();
        pending.finalize(&public_key, &response).unwrap()
    }

    fn signed_revocation(keys: &nostr::Keys, credential: &Credential) -> SignedRevocation {
        let revocation = RevocationEntry {
            credential_digest: hex::encode(credential.digest().unwrap()),
        };
        let signature = sign(
            keys,
            REVOCATION_SIGNATURE_DOMAIN_SEPARATOR,
            &canonicalize_revocation(&revocation).unwrap(),
        );

        SignedRevocation {
            revocation,
            proof: IssuerSignatureProof {
                issuer_id_pubkey: IssuerId(keys.public_key()),
                signature,
            },
        }
    }

    #[test]
    fn context_verifies_trusted_credential() {
        let keys = nostr::Keys::generate();
        let issuer_context = IssuerContext::generate(IssuerId(keys.public_key()), 1024).unwrap();
        let bundle = issuer_bundle(&keys, &issuer_context);
        let credential = credential(&issuer_context);

        let mut context = VerificationContext::new();
        context.add_issuer_bundle(&bundle).unwrap();

        context.verify_credential(&credential).unwrap();
    }

    #[test]
    fn context_rejects_unknown_issuer() {
        let keys = nostr::Keys::generate();
        let issuer_context = IssuerContext::generate(IssuerId(keys.public_key()), 1024).unwrap();
        let credential = credential(&issuer_context);

        let context = VerificationContext::new();

        assert!(matches!(
            context.verify_credential(&credential),
            Err(CredentialsError::UnknownIssuer)
        ));
    }

    #[test]
    fn context_rejects_revoked_credential() {
        let keys = nostr::Keys::generate();
        let issuer_context = IssuerContext::generate(IssuerId(keys.public_key()), 1024).unwrap();
        let bundle = issuer_bundle(&keys, &issuer_context);
        let credential = credential(&issuer_context);
        let signed_revocation = signed_revocation(&keys, &credential);

        let mut context = VerificationContext::new();
        context.add_issuer_bundle(&bundle).unwrap();
        context.add_revocation(&signed_revocation).unwrap();

        assert!(matches!(
            context.verify_credential(&credential),
            Err(CredentialsError::CredentialRevoked)
        ));
    }
}
