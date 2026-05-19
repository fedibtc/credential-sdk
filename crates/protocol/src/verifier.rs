//! Verifier-side PBRSA credential verification operations.

use std::str::FromStr;

use nostr::secp256k1::{schnorr::Signature, Message};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    canonicalize_issuer_bundle, canonicalize_pbrsa_blind_msg, canonicalize_pbrsa_info,
    canonicalize_revocation, pbrsa::check_version, Credential, IssuerBundle, IssuerId, PbrsaError,
    PbrsaPublicKey, RevocationLocation, SignedRevocation,
};

/// Domain separator for issuer bundle identity signatures.
pub const ISSUER_BUNDLE_SIGNATURE_DOMAIN_SEPARATOR: &[u8] =
    b"fedi-credential/issuer-bundle-signature/v1\0";

/// Domain separator for revocation identity signatures.
pub const REVOCATION_SIGNATURE_DOMAIN_SEPARATOR: &[u8] =
    b"fedi-credential/revocation-signature/v1\0";

/// Errors returned by verifier-side protocol checks.
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("failed to canonicalize signed payload: {0}")]
    Canonicalize(#[from] serde_json::Error),
    #[error(transparent)]
    Pbrsa(#[from] PbrsaError),
    #[error("verification failed")]
    VerificationFailed,
}

/// Verify a signed issuer bundle.
pub fn verify_issuer_bundle(bundle: &IssuerBundle) -> Result<(), VerificationError> {
    validate_revocation_locations(&bundle.issuer.revocation)?;
    PbrsaPublicKey::from_der(&bundle.issuer.issuance_key).map_err(PbrsaError::from)?;

    let signing_message = signing_message(
        ISSUER_BUNDLE_SIGNATURE_DOMAIN_SEPARATOR,
        &canonicalize_issuer_bundle(&bundle.issuer)?,
    );
    verify_identity_signature(
        &bundle.issuer.issuer_id_pubkey,
        &bundle.proof.signature,
        signing_message,
    )
}

/// Verify a signed revocation object.
pub fn verify_revocation(revocation: &SignedRevocation) -> Result<(), VerificationError> {
    parse_sha256_hex(&revocation.revocation.credential_digest)?;
    let signing_message = signing_message(
        REVOCATION_SIGNATURE_DOMAIN_SEPARATOR,
        &canonicalize_revocation(&revocation.revocation)?,
    );

    verify_identity_signature(
        &revocation.proof.issuer_id_pubkey,
        &revocation.proof.signature,
        signing_message,
    )
}

/// Verify a finalized credential.
pub fn verify_credential(
    issuer_public_key: &PbrsaPublicKey,
    credential: &Credential,
) -> Result<(), PbrsaError> {
    check_version(credential.version)?;
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

fn validate_revocation_locations(
    locations: &[RevocationLocation],
) -> Result<(), VerificationError> {
    if locations
        .iter()
        .any(|location| location.protocol.is_empty() || location.location.is_empty())
    {
        return Err(VerificationError::VerificationFailed);
    }

    Ok(())
}

fn signing_message(domain_separator: &[u8], canonical_payload: &[u8]) -> Message {
    let digest = Sha256::new()
        .chain_update(domain_separator)
        .chain_update(canonical_payload)
        .finalize();

    Message::from_digest(digest.into())
}

fn verify_identity_signature(
    issuer_id: &IssuerId,
    signature: &str,
    message: Message,
) -> Result<(), VerificationError> {
    let signature =
        Signature::from_str(signature).map_err(|_| VerificationError::VerificationFailed)?;
    let public_key = issuer_id
        .0
        .xonly()
        .map_err(|_| VerificationError::VerificationFailed)?;

    nostr::SECP256K1
        .verify_schnorr(&signature, &message, &public_key)
        .map_err(|_| VerificationError::VerificationFailed)
}

fn parse_sha256_hex(digest: &str) -> Result<(), VerificationError> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(digest, &mut bytes).map_err(|_| VerificationError::VerificationFailed)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Issuer, IssuerContext, IssuerSignatureProof, RevocationEntry, SignatureProof};

    fn sign(keys: &nostr::Keys, domain_separator: &[u8], canonical_payload: &[u8]) -> String {
        keys.sign_schnorr(&signing_message(domain_separator, canonical_payload))
            .to_string()
    }

    fn issuer_bundle(keys: &nostr::Keys) -> IssuerBundle {
        let issuer_id = IssuerId(keys.public_key());
        let issuer_context = IssuerContext::generate(issuer_id.clone(), 1024).unwrap();
        let issuer = Issuer {
            issuer_id_pubkey: issuer_id,
            issuance_key: issuer_context.public_key().to_der().unwrap(),
            revocation: vec![RevocationLocation {
                protocol: "nostr".to_owned(),
                location: "wss://relay.example.com".to_owned(),
            }],
        };
        let signature = sign(
            keys,
            ISSUER_BUNDLE_SIGNATURE_DOMAIN_SEPARATOR,
            &canonicalize_issuer_bundle(&issuer).unwrap(),
        );

        IssuerBundle {
            issuer,
            proof: SignatureProof { signature },
        }
    }

    #[test]
    fn verify_issuer_bundle_accepts_signed_bundle() {
        let keys = nostr::Keys::generate();
        let bundle = issuer_bundle(&keys);

        verify_issuer_bundle(&bundle).unwrap();
    }

    #[test]
    fn verify_issuer_bundle_rejects_tampering() {
        let keys = nostr::Keys::generate();
        let mut bundle = issuer_bundle(&keys);
        bundle.issuer.revocation[0].location = "wss://evil.example.com".to_owned();

        assert!(matches!(
            verify_issuer_bundle(&bundle),
            Err(VerificationError::VerificationFailed)
        ));
    }

    #[test]
    fn verify_revocation_accepts_signed_revocation() {
        let keys = nostr::Keys::generate();
        let revocation = signed_revocation(&keys, [7u8; 32]);

        verify_revocation(&revocation).unwrap();
    }

    #[test]
    fn verify_revocation_rejects_tampering() {
        let keys = nostr::Keys::generate();
        let mut revocation = signed_revocation(&keys, [7u8; 32]);
        revocation.revocation.credential_digest = hex::encode([8u8; 32]);

        assert!(matches!(
            verify_revocation(&revocation),
            Err(VerificationError::VerificationFailed)
        ));
    }

    fn signed_revocation(keys: &nostr::Keys, credential_digest: [u8; 32]) -> SignedRevocation {
        let revocation = RevocationEntry {
            credential_digest: hex::encode(credential_digest),
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
}
