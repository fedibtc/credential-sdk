//! Issuer-side PBRSA issuance operations.

use blind_rsa_signatures::{
    pbrsa::PartiallyBlindKeyPairSha384PSSDeterministic,
    reexports::rand::{rand_core::UnwrapErr, rngs::SysRng},
};
use serde_json::Value;

use crate::{
    canonicalize_pbrsa_info, CredentialsError, IssuanceRequest, IssuanceResponse, Issuer,
    IssuerBundle, IssuerId, IssuerSecretKeys, ProtocolV1, Revocation, RevocationLocation,
    RevocationProof, SchnorrSignatureProof, SignedCredential, SignedRevocation,
};

pub const ISSUER_MODULUS_BITS: usize = 2048;

/// Runtime issuer context containing issuer identity and PBRSA signing key.
#[derive(Clone)]
pub struct IssuerContext {
    identity_keys: nostr::Keys,
    key_pair: PartiallyBlindKeyPairSha384PSSDeterministic,
}

impl IssuerContext {
    /// Generate an issuer context with fresh Nostr identity and PBRSA key pairs.
    pub fn generate() -> Result<Self, CredentialsError> {
        Self::generate_with_rng(nostr::Keys::generate(), &mut UnwrapErr(SysRng))
    }

    pub(crate) fn generate_with_rng(
        identity_keys: nostr::Keys,
        rng: &mut (impl blind_rsa_signatures::reexports::rsa::rand_core::CryptoRng + ?Sized),
    ) -> Result<Self, CredentialsError> {
        Ok(Self {
            identity_keys,
            key_pair: PartiallyBlindKeyPairSha384PSSDeterministic::generate(
                rng,
                ISSUER_MODULUS_BITS,
            )?,
        })
    }

    /// Build and sign this issuer's public metadata.
    ///
    /// The returned bundle binds the issuer's derived Nostr identity key to the
    /// current PBRSA issuance public key and the supplied revocation locations.
    pub fn issuer_bundle(
        &self,
        revocation: Vec<RevocationLocation>,
    ) -> Result<IssuerBundle, CredentialsError> {
        self.issuer_bundle_with_rng(revocation, &mut nostr::secp256k1::rand::rngs::OsRng)
    }

    pub(crate) fn issuer_bundle_with_rng(
        &self,
        revocation: Vec<RevocationLocation>,
        rng: &mut (impl nostr::secp256k1::rand::Rng + nostr::secp256k1::rand::CryptoRng),
    ) -> Result<IssuerBundle, CredentialsError> {
        let issuer = Issuer {
            issuer_id_pubkey: self.issuer_id(),
            issuance_key: self.key_pair.pk.clone(),
            revocation,
        };
        let signature = self.sign_identity_digest_with_rng(issuer.digest()?, rng);

        Ok(IssuerBundle {
            version: ProtocolV1,
            issuer,
            proof: SchnorrSignatureProof { signature },
        })
    }

    fn issuer_id(&self) -> IssuerId {
        IssuerId(self.identity_keys.public_key())
    }

    pub fn export_secret_key(&self) -> Result<IssuerSecretKeys, CredentialsError> {
        Ok(IssuerSecretKeys {
            issuer_id_secret_key: self.identity_keys.secret_key().to_secret_hex(),
            issuance_secret_key: self.key_pair.sk.to_der()?,
        })
    }

    pub fn import_secret_key(secret_key: &IssuerSecretKeys) -> Result<Self, CredentialsError> {
        let identity_keys = nostr::Keys::parse(&secret_key.issuer_id_secret_key)?;
        let secret_key =
            blind_rsa_signatures::pbrsa::PartiallyBlindSecretKeySha384PSSDeterministic::from_der(
                &secret_key.issuance_secret_key,
            )?;
        let public_key = secret_key.public_key()?;
        Ok(Self {
            identity_keys,
            key_pair: PartiallyBlindKeyPairSha384PSSDeterministic {
                pk: public_key,
                sk: secret_key,
            },
        })
    }

    /// Issue a blind signature over a holder issuance request.
    pub fn issue_credential(
        &self,
        info: Value,
        request: &IssuanceRequest,
    ) -> Result<IssuanceResponse, CredentialsError> {
        self.issue_credential_with_rng(info, request, &mut UnwrapErr(SysRng))
    }

    pub(crate) fn issue_credential_with_rng(
        &self,
        info: Value,
        request: &IssuanceRequest,
        rng: &mut (impl blind_rsa_signatures::reexports::rsa::rand_core::TryCryptoRng + ?Sized),
    ) -> Result<IssuanceResponse, CredentialsError> {
        let issuer_id = self.issuer_id();
        let metadata = canonicalize_pbrsa_info(ProtocolV1, &issuer_id, &info)?;
        let secret_key = self.key_pair.derive_secret_key_for_metadata(&metadata)?;
        Ok(IssuanceResponse {
            version: ProtocolV1,
            issuer_id,
            info,
            blind_signature: secret_key.blind_sign_with_rng(rng, &request.blinded_message)?,
        })
    }

    /// Build and sign the revocation for a finalized credential issued by this issuer.
    ///
    /// This computes the finalized credential digest and binds it to this issuer
    /// identity. It does not publish or transport the revocation; those concerns
    /// live outside the core protocol.
    pub fn revoke_credential(
        &self,
        credential: &SignedCredential,
    ) -> Result<SignedRevocation, CredentialsError> {
        self.revoke_credential_with_rng(credential, &mut nostr::secp256k1::rand::rngs::OsRng)
    }

    pub(crate) fn revoke_credential_with_rng(
        &self,
        credential: &SignedCredential,
        rng: &mut (impl nostr::secp256k1::rand::Rng + nostr::secp256k1::rand::CryptoRng),
    ) -> Result<SignedRevocation, CredentialsError> {
        let issuer_id = self.issuer_id();
        if credential.credential.issuer_id_pubkey != issuer_id {
            return Err(CredentialsError::IssuerIdMismatch);
        }

        let revocation = Revocation {
            credential_digest: credential.credential.digest()?,
        };

        let signature = self.sign_identity_digest_with_rng(revocation.digest()?, rng);

        Ok(SignedRevocation {
            version: ProtocolV1,
            revocation,
            proof: RevocationProof {
                issuer_id_pubkey: issuer_id,
                signature,
            },
        })
    }

    fn sign_identity_digest_with_rng(
        &self,
        digest: sha2::digest::Output<sha2::Sha256>,
        rng: &mut (impl nostr::secp256k1::rand::Rng + nostr::secp256k1::rand::CryptoRng),
    ) -> nostr::secp256k1::schnorr::Signature {
        self.identity_keys.sign_schnorr_with_ctx(
            nostr::SECP256K1,
            &nostr::secp256k1::Message::from_digest(digest.into()),
            rng,
        )
    }
}
