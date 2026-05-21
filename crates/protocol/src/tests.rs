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
      "blinded_message": "FF9cznmgAmjeElZCEJ6MgQAA8XYUhFd07blk40zI6Bos9WVFAd-aGyi1YsWXahLmEwqFXesVUO5d18h4gdqCNtZo0EyCHsuluE8h_ZSd5b4lFYPg-kKG1IrXqI9kgX3bQKUMHtaZW6hPiiRTFrZsU9iavtgfm1sq7eMHh4en54mMlCikr9nFes-aYZBNvX06dSMofH8i-1W95bW7F0YYdKhiR0uAZbUiz84D0CXc7rNi7F7Yv1hHnVbRVQi4uca8zLA6LllZ0STtQy-5VyZoD7imHNM38R7cjCR4UksRbyiu7kkhVJmZaiMBx0d09K6UcCtjQO6UjIdv7cpB9urCAg"
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
      "blind_signature": "eQbtRHw1216fmcUD-oUDUPw78QzVIolAZpz-3LQGcVnD8EioIN-kYRWVWcg5dsiEpOOpHe2nrjcgrLYLdpmLxbpddXCL4mlEXB5RX-RM30S-kHlfQsOBsuDT-8bzOFBMUlL1nxQOpFhYWzYZqfVMxZBnQGHH2HACfQgKN5UZWo5MRniCgjMUfk3cL-RfGKG9tnWJ7j7vwtkvth91tlN0KSs85OPCR-r_-tjnUB-gbEb2PPOiIOQ_btBvDPt9CxeyJTcMjASAvhZcF4KEj_5zDV4hqusBs18XzTveeRTVTT-bv6BAS-X7sRl6WDXRh2a795yCOMRj9qiWBj2BC1lZRg"
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
        "blind_msg": "8ec0627df98259165e8f4cc88f57757bad9579c129d729bbd3bef47b0321cbf9",
        "message_randomizer": "wi6RVxdVBwxS29W5V2GJWvsdpLPh7CnXv6iRLcAIGH8"
      },
      "proof": {
        "signature": "j82xd1fr8OqPPvGhfLozdAi1bU5_G6ct3H34yUXA-SFf_vSiekRlKBJnWS-RloslonlswIajZm6LWu2mjPDfndcWvBd3RIGW6U0u_5FP-MmTqEeieGEHdpGyKEMPrZyB0T1WrswIWPHMEExP5cYA71UTJcKy4aSCIfLtu4aBiNXyQza_CKkKA7Pkdr4OSetVjQEKw37pzTFf4eSA700nvi93SRp7UqZMg7V5rfcPGH7Lgeo9hQRbkvt_Y4SSbiJx4xvATK_LOeP59e1Qq2almvE99kg5xPHR00aRLb1uw8hhKyKEglDD8RuyBAVd9q_pGAIyktmctDigiBBcEUaGoA"
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
        "credential_digest": "IAvaJQFvAs4j1xahtppMsLMS9qPIQbtOv3RRQmUrAY8"
      },
      "proof": {
        "issuer_id_pubkey": "edf91ee8ef705ad30cdbffffe86cd1fb08a6114178ed998f7a5ad52e25a67f97",
        "signature": "onca0kZ9BihkLahwMaMuA03H77Brxfdt7VQJ1zZ98Jr6dwucETJDolXOdwA1DUiFfnrrzWfyeogy6O9o2lW1IA"
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
