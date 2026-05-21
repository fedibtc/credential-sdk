use serde_json::json;

use crate::{
    HolderContext, IssuerContext, PendingIssuance, ProtocolV1, Revocation, RevocationLocation,
    RevocationProof, SignedCredential, SignedRevocation, VerificationContext,
};

const TEST_RNG_SEED: u64 = 0x5eed_f00d_cafe_babe;

type NostrRng = nostr::secp256k1::rand::rngs::StdRng;
type PbrsaRng = blind_rsa_signatures::reexports::rand::rngs::StdRng;

fn issuer_context(nostr_rng: &mut NostrRng, pbrsa_rng: &mut PbrsaRng) -> IssuerContext {
    let identity_keys = nostr::Keys::generate_with_rng(nostr_rng);
    IssuerContext::generate_with_rng(identity_keys, pbrsa_rng).unwrap()
}

fn revocation_signed_by(
    issuer: &IssuerContext,
    credential: &SignedCredential,
    rng: &mut NostrRng,
) -> SignedRevocation {
    let secret_keys = issuer.export_secret_key().unwrap();
    let identity_keys = nostr::Keys::parse(&secret_keys.issuer_id_secret_key).unwrap();
    let revocation = Revocation {
        credential_digest: credential.credential.digest().unwrap(),
    };
    let signature = identity_keys.sign_schnorr_with_ctx(
        nostr::SECP256K1,
        &nostr::secp256k1::Message::from_digest(revocation.digest().unwrap().into()),
        rng,
    );

    SignedRevocation {
        version: ProtocolV1,
        revocation,
        proof: RevocationProof {
            issuer_id_pubkey: crate::IssuerId(identity_keys.public_key()),
            signature,
        },
    }
}

#[test]
fn protocol_snapshots() {
    let mut nostr_rng =
        <NostrRng as nostr::secp256k1::rand::SeedableRng>::seed_from_u64(TEST_RNG_SEED);
    let mut pbrsa_seed = [0; 32];
    nostr::secp256k1::rand::RngCore::fill_bytes(&mut nostr_rng, &mut pbrsa_seed);
    let mut pbrsa_rng =
        <PbrsaRng as blind_rsa_signatures::reexports::rand::SeedableRng>::from_seed(pbrsa_seed);

    let credential_info = json!({
        "schema": "fedi-trust-score-v1.0",
        "trust_level": 7,
    });
    // Create issuer metadata before any holder interaction.
    let issuer = issuer_context(&mut nostr_rng, &mut pbrsa_rng);
    let issuer_bundle = issuer
        .issuer_bundle_with_rng(
            vec![RevocationLocation {
                protocol: "nostr".to_owned(),
                location: "wss://relay.example.com".to_owned(),
            }],
            &mut nostr_rng,
        )
        .unwrap();

    insta::assert_json_snapshot!(issuer_bundle, @r###"
    {
      "version": 1,
      "issuer": {
        "issuer_id_pubkey": "edf91ee8ef705ad30cdbffffe86cd1fb08a6114178ed998f7a5ad52e25a67f97",
        "issuance_key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwENRMLzlBb5UlNL78K0RbGaBbbMFEtZHadM8aZkhdXJWyrabmNk15IUrDlzLQMtgotrQkNf26r4obd6WE7hdipARWv9JWzV39fo1W43JL1oY1X0KEzVJ_UM71D0JJUgRKJBF4B474SOLwEmglkrZezrORX2VujCewjzbki6LriKCPWlk6ZT9vjw-AwvZMz97EQUroFb8egoD4zwqvU9XkM8udhHdfG6WNCCoLwZCp53No9ibrwxDUQ19isSx46cpgyYazAv6Uk8Up1DDp3KM3cPhyOxNSO7efYFol89EvFJOZKJtjUtseEFJBSo6cUMGq7qQDm1IbZw2i4wq7M8m8QIDAQAB",
        "revocation": [
          {
            "protocol": "nostr",
            "location": "wss://relay.example.com"
          }
        ]
      },
      "proof": {
        "signature": "vSX3b6J8C3rS3xgELRTy5OMxvpP74wWDWoG0sQ7elheUc05dYUSt1NSiqfDtIuTQZCWW-QUfbXVQSlX-g-5JWQ"
      }
    }
    "###);

    // Create the holder's blinded issuance request.
    let holder = HolderContext::generate_with_rng(&mut nostr_rng);
    let blind_msg = json!(holder.public_key());
    let (request, pending) = PendingIssuance::create_request_with_rng(
        &issuer_bundle.issuer.issuance_key,
        issuer_bundle.issuer.issuer_id_pubkey.clone(),
        credential_info.clone(),
        blind_msg,
        &mut pbrsa_rng,
    )
    .unwrap();

    insta::assert_json_snapshot!(request, @r###"
    {
      "version": 1,
      "blinded_message": "U6Fqf0yjnOp7NLJOBU7L-QUA9hxedZ3IRiIJmpHmX4oaSF_h6804QMQWbaH5bgU1mRuCEdWMTEkQJBIFroEmEU2JJG67Bp5x6P0yqbe2Jk6yjH8uxPuFHd-mAQlvONFgAi1xdQt-8Lp4Df93_h0wFTnex2O-Nf0fU0QtRFR9UEmcAGpBFwSE1op3QI5Pri91EBKOkwyfxvD3cFn_XWvi0A1sZDYGwQIx-oJELH5nrDlcNEKoAwmoudsU8EJQu0kvNtlo57jF-xiJMwbeMpaRdBFtHPMrRrMoceHgHRtEu38pG7Scwv1GXjgvGEjkLaKpHJnKTK8S4vjYiweN3w1dCw"
    }
    "###);

    // Issue the blinded credential response from the trusted issuer.
    let response = issuer
        .issue_credential_with_rng(credential_info, &request, &mut pbrsa_rng)
        .unwrap();

    insta::assert_json_snapshot!(response, @r###"
    {
      "version": 1,
      "issuer_id": "edf91ee8ef705ad30cdbffffe86cd1fb08a6114178ed998f7a5ad52e25a67f97",
      "info": {
        "schema": "fedi-trust-score-v1.0",
        "trust_level": 7
      },
      "blind_signature": "PSe0AMcYr24uwDkYwcgTm6fKIj_PDtC_7Gou9gTChMrLOr0XVoLSDX37uxawrQ9ayqvZ0rAsAZCh47RLAhhJ0CqyXHoLRm-cpvUmxvfENT956U1SSYmN_t6OEWdYB3Md-cGlC5WB85mO3CfDbK9qe3AscTQtJ9vDO1ic0bjrM477zRIf5HxduydypBXDQZhZCA4ABsfmXgWJSAFZ-wiL_D71h9uIvl7tikyiL3-3SEGQfK9mNJRtuJ7Rxm5znRAwtBUAmNCiE0O5j5PEuiLThE3x29JT-Ph43_nTuXjlABk5FBFhayDK0fSNVh_p0cnAj1S1yTOwU-Qdrx_gQL44Pg"
    }
    "###);

    // Finalize the blinded response into the holder's credential.
    let mut credential = pending
        .finalize(&issuer_bundle.issuer.issuance_key, &response)
        .unwrap();

    insta::assert_json_snapshot!(credential, @r###"
    {
      "version": 1,
      "credential": {
        "issuer_id_pubkey": "edf91ee8ef705ad30cdbffffe86cd1fb08a6114178ed998f7a5ad52e25a67f97",
        "info": {
          "schema": "fedi-trust-score-v1.0",
          "trust_level": 7
        },
        "blind_msg": "8ec0627df98259165e8f4cc88f57757bad9579c129d729bbd3bef47b0321cbf9"
      },
      "proof": {
        "signature": "GvDgrlvrK555RnO1m6S4pU0hJcvCks6E7f1UvdewLA0PGXlP4v6Jksbaamrp3PKTJP9sgTwsmLW4pnnqahf_EwVYsoauYZqVrYxXTTW1EtojUlQFSkoowSZ_s14NCC-3zohFGN-7qTn52KSECZzgLLpNjjvUbzNgQCGhGrSxFx0e7o_oB5dz-QU60DlCxvp64DmdHhycQUkfxTCKSGZ31aXTYZ0WroXkoG_yhgmxuEkPjcGldwjYrFAG-2HbtdLqJ-beLJuEVovkRCoJLJ-4XlthkTV3n7MLs6MiHqnA6NE6ZcU-UC2RUOMc4FkpDksrtaZCbarfDhDK5EHcJHu4cw"
      }
    }
    "###);

    // Revoke the finalized credential and snapshot the signed revocation.
    let signed_revocation = issuer
        .revoke_credential_with_rng(&credential, &mut nostr_rng)
        .unwrap();

    insta::assert_json_snapshot!(signed_revocation, @r###"
    {
      "version": 1,
      "revocation": {
        "credential_digest": "tetb3pX05--31jb9ZO8yoU5Wn2xSXm9YdB3tG9fVxUA"
      },
      "proof": {
        "issuer_id_pubkey": "edf91ee8ef705ad30cdbffffe86cd1fb08a6114178ed998f7a5ad52e25a67f97",
        "signature": "M7jsEWZOiuZFnAP8kpNQI6O5eLDSbPPDtS0P4eBKZyOLdvA6aLKFNE0IbY4_bTKtVxzdAwZpDRVAsMWLlBOn-g"
      }
    }
    "###);
    let other_issuer = issuer_context(&mut nostr_rng, &mut pbrsa_rng);
    let other_issuer_bundle = other_issuer
        .issuer_bundle_with_rng(vec![], &mut nostr_rng)
        .unwrap();
    let other_issuer_revocation = revocation_signed_by(&other_issuer, &credential, &mut nostr_rng);

    // Verify the same credential before and after trusting the issuer and revocation.
    let mut verifier = VerificationContext::new();
    let unknown_before_trust = verifier.verify_credential(&credential).unwrap_err();
    verifier.add_issuer_bundle(&issuer_bundle).unwrap();
    verifier.add_issuer_bundle(&other_issuer_bundle).unwrap();
    let verified_before_revocation = verifier.verify_credential(&credential).is_ok();
    verifier.add_revocation(&other_issuer_revocation).unwrap();
    let verified_after_other_issuer_revocation = verifier.verify_credential(&credential).is_ok();
    verifier.add_revocation(&signed_revocation).unwrap();
    let revoked_after_revocation = verifier.verify_credential(&credential).unwrap_err();

    insta::assert_json_snapshot!(json!({
        "unknown_before_trust": unknown_before_trust.to_string(),
        "verified_before_revocation": verified_before_revocation,
        "verified_after_other_issuer_revocation": verified_after_other_issuer_revocation,
        "revoked_after_revocation": revoked_after_revocation.to_string(),
    }), @r###"
    {
      "revoked_after_revocation": "credential has been revoked",
      "unknown_before_trust": "unknown issuer",
      "verified_after_other_issuer_revocation": true,
      "verified_before_revocation": true
    }
    "###);

    // Importing persisted issuer secrets must preserve both identity and issuance keys.
    let imported = IssuerContext::import_secret_key(&issuer.export_secret_key().unwrap()).unwrap();
    let imported_bundle = imported.issuer_bundle(vec![]).unwrap();

    insta::assert_json_snapshot!(json!({
        "original_issuer_id": issuer_bundle.issuer.issuer_id_pubkey,
        "imported_issuer_id": imported_bundle.issuer.issuer_id_pubkey,
        "same_issuance_public_key": issuer_bundle.issuer.issuance_key == imported_bundle.issuer.issuance_key,
    }), @r###"
    {
      "imported_issuer_id": "edf91ee8ef705ad30cdbffffe86cd1fb08a6114178ed998f7a5ad52e25a67f97",
      "original_issuer_id": "edf91ee8ef705ad30cdbffffe86cd1fb08a6114178ed998f7a5ad52e25a67f97",
      "same_issuance_public_key": true
    }
    "###);

    // Tampering checks cover signed issuer metadata, credential payloads, and issuer mismatch.
    let mut tampered_bundle = issuer_bundle.clone();
    tampered_bundle.issuer.revocation[0].location = "wss://evil.example.com".to_owned();

    credential.credential.blind_msg = json!("mallory-public-key");
    let mut verifier = VerificationContext::new();
    verifier.add_issuer_bundle(&issuer_bundle).unwrap();

    insta::assert_json_snapshot!(json!({
        "tampered_credential": verifier.verify_credential(&credential).unwrap_err().to_string(),
        "tampered_bundle": tampered_bundle.verify().unwrap_err().to_string(),
        "wrong_issuer_revoke": other_issuer.revoke_credential(&credential).unwrap_err().to_string(),
    }), @r###"
    {
      "tampered_bundle": "verification failed",
      "tampered_credential": "blind RSA operation failed: Verification failed",
      "wrong_issuer_revoke": "issuer_id does not match"
    }
    "###);
}
