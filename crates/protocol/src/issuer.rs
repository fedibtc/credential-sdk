//! Issuer-side PBRSA issuance operations.

use blind_rsa_signatures::{pbrsa::PartiallyBlindKeyPairSha384PSSRandomized, DefaultRng};
use serde_json::Value;

use crate::{
    canonicalize_issuer_bundle, canonicalize_pbrsa_info, canonicalize_revocation, signing_message,
    Credential, CredentialsError, IssuanceRequest, IssuanceResponse, Issuer, IssuerBundle,
    IssuerId, IssuerSignatureProof, PbrsaPublicKey, ProtocolV1, Revocation, RevocationEntry,
    RevocationLocation, SignatureProof, SignedRevocation, ISSUER_BUNDLE_SIGNATURE_DOMAIN_SEPARATOR,
    REVOCATION_SIGNATURE_DOMAIN_SEPARATOR,
};

/// Runtime issuer context containing issuer identity and PBRSA signing key.
#[derive(Clone)]
pub struct IssuerContext {
    identity_keys: nostr::Keys,
    key_pair: PartiallyBlindKeyPairSha384PSSRandomized,
}

impl IssuerContext {
    /// Generate an issuer context with fresh Nostr identity and PBRSA key pairs.
    pub fn generate(modulus_bits: usize) -> Result<Self, CredentialsError> {
        Self::generate_with_rng(nostr::Keys::generate(), modulus_bits, &mut DefaultRng)
    }

    pub(crate) fn generate_with_rng(
        identity_keys: nostr::Keys,
        modulus_bits: usize,
        rng: &mut (impl blind_rsa_signatures::reexports::rsa::rand_core::CryptoRng + ?Sized),
    ) -> Result<Self, CredentialsError> {
        Ok(Self {
            identity_keys,
            key_pair: PartiallyBlindKeyPairSha384PSSRandomized::generate(rng, modulus_bits)?,
        })
    }

    pub fn from_key_pair(
        identity_keys: nostr::Keys,
        key_pair: PartiallyBlindKeyPairSha384PSSRandomized,
    ) -> Self {
        Self {
            identity_keys,
            key_pair,
        }
    }

    pub fn issuer_id(&self) -> IssuerId {
        IssuerId(self.identity_keys.public_key())
    }

    pub fn nostr_secret_key(&self) -> String {
        self.identity_keys.secret_key().to_secret_hex()
    }

    pub fn public_key(&self) -> PbrsaPublicKey {
        self.key_pair.pk.clone()
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
            issuance_key: self.public_key(),
            revocation,
        };
        let signature = self.sign_identity_with_rng(
            ISSUER_BUNDLE_SIGNATURE_DOMAIN_SEPARATOR,
            &canonicalize_issuer_bundle(&issuer)?,
            rng,
        );

        Ok(IssuerBundle {
            issuer,
            proof: SignatureProof { signature },
        })
    }

    pub fn secret_key_der(&self) -> Result<Vec<u8>, CredentialsError> {
        Ok(self.key_pair.sk.to_der()?)
    }

    pub fn from_secret_key_der(
        identity_secret_key: &str,
        der: &[u8],
    ) -> Result<Self, CredentialsError> {
        let identity_keys = nostr::Keys::parse(identity_secret_key)?;
        let secret_key =
            blind_rsa_signatures::pbrsa::PartiallyBlindSecretKeySha384PSSRandomized::from_der(der)?;
        let public_key = secret_key.public_key()?;
        Ok(Self {
            identity_keys,
            key_pair: PartiallyBlindKeyPairSha384PSSRandomized {
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
        self.issue_credential_with_rng(info, request, &mut DefaultRng)
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

    /// Build the revocation target for a finalized credential issued by this issuer.
    ///
    /// This computes the finalized credential digest and binds it to this issuer
    /// identity. It does not sign, publish, or transport the revocation; those
    /// concerns live in the revocation layer.
    pub fn revoke_credential(
        &self,
        credential: &Credential,
    ) -> Result<Revocation, CredentialsError> {
        let issuer_id = self.issuer_id();
        if credential.issuer_id != issuer_id {
            return Err(CredentialsError::IssuerIdMismatch);
        }

        let credential_digest = credential.digest()?;

        Ok(Revocation {
            issuer_id,
            credential_digest,
        })
    }

    /// Sign a revocation target with this issuer's Nostr identity key.
    pub fn sign_revocation(
        &self,
        revocation: &Revocation,
    ) -> Result<SignedRevocation, CredentialsError> {
        self.sign_revocation_with_rng(revocation, &mut nostr::secp256k1::rand::rngs::OsRng)
    }

    pub(crate) fn sign_revocation_with_rng(
        &self,
        revocation: &Revocation,
        rng: &mut (impl nostr::secp256k1::rand::Rng + nostr::secp256k1::rand::CryptoRng),
    ) -> Result<SignedRevocation, CredentialsError> {
        let issuer_id = self.issuer_id();
        if revocation.issuer_id != issuer_id {
            return Err(CredentialsError::IssuerIdMismatch);
        }

        let revocation = RevocationEntry {
            credential_digest: hex::encode(revocation.credential_digest),
        };
        let signature = self.sign_identity_with_rng(
            REVOCATION_SIGNATURE_DOMAIN_SEPARATOR,
            &canonicalize_revocation(&revocation)?,
            rng,
        );

        Ok(SignedRevocation {
            revocation,
            proof: IssuerSignatureProof {
                issuer_id_pubkey: issuer_id,
                signature,
            },
        })
    }

    fn sign_identity_with_rng(
        &self,
        domain_separator: &[u8],
        canonical_payload: &[u8],
        rng: &mut (impl nostr::secp256k1::rand::Rng + nostr::secp256k1::rand::CryptoRng),
    ) -> String {
        self.identity_keys
            .sign_schnorr_with_ctx(
                nostr::SECP256K1,
                &signing_message(domain_separator, canonical_payload),
                rng,
            )
            .to_string()
    }
}
