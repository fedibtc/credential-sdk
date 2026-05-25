use serde_json::json;

use crate::{
    HolderContext, IssuerContext, IssuerSecretKeys, PendingIssuance, ProtocolV1, Revocation,
    RevocationLocation, RevocationProof, SignedCredential, SignedRevocation, VerificationContext,
};

const TEST_RNG_SEED: u64 = 0x5eed_f00d_cafe_babe;

type NostrRng = nostr::secp256k1::rand::rngs::StdRng;
type PbrsaRng = blind_rsa_signatures::reexports::rand::rngs::StdRng;

// Keygen is super slow which makes the tests take minutes to run.
// This hard codes issuer keys for tests so they run in seconds.
fn test_issuer_secret_keys() -> IssuerSecretKeys {
    serde_json::from_value(json!({
        "issuer_id_secret_key": "76127aa07dc3a3dcad06c8f8835ff997adb9c542868434bc47d16f1c9ba860b8",
        "issuance_secret_key": "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDAQ1EwvOUFvlSU0vvwrRFsZoFtswUS1kdp0zxpmSF1clbKtpuY2TXkhSsOXMtAy2Ci2tCQ1_bqviht3pYTuF2KkBFa_0lbNXf1-jVbjckvWhjVfQoTNUn9QzvUPQklSBEokEXgHjvhI4vASaCWStl7Os5FfZW6MJ7CPNuSLouuIoI9aWTplP2-PD4DC9kzP3sRBSugVvx6CgPjPCq9T1eQzy52Ed18bpY0IKgvBkKnnc2j2JuvDENRDX2KxLHjpymDJhrMC_pSTxSnUMOncozdw-HI7E1I7t59gWiXz0S8Uk5kom2NS2x4QUkFKjpxQwarupAObUhtnDaLjCrszybxAgMBAAECggEAMxqxng7XoWsx-E0MgrC-DN5CUPJgyt0CJnLrf_YgGqPFxiQ7v6kc1h0_kJXBwPtOOHuJLLb6_vKEtI-RvLQoyQf6VQG-cewIcu2K-Ub6zwdXyoduAiUMAbG5WXTP1YUOaoXOzP-8Ut-r6fSoJsrGfCbpZTc4cUEzMdYTVwvgPOyhJr66lD26wWMnJD7hk8qi54lhpWG2fkwR61eSKhO_sBLUYXPywxkGVLRfXVpXZxxr8EDMDsxeD03Y6rZOMAS3-g4xv8-dIGFjbIPH_VsZn8g8eRmtAaaVLoDGfphaOfP5JSYw76QLzj5Y0Slzf3wUaaK3dxbAQoUIKi_RaCb7sQKBgQDRcOQ9hqQTF0g5TovWw8nLwJyCPrbqcjDT6MuQYDWKzKzPeQ6fPcjbpCgme7YCUZZ8AT2n9yZaFWOjNxGyRKps-YcBI2nhmQWzuV_UcmayxtehJ0ee3PyukKs8aJieuBwb9xFzZ5-ekSiDbghmA-wSvHDXoLFf1HDZXhH3XpxgBwKBgQDrANa5p1wmzNcW4Lvh8qkFhE9eGTbKugpxw94I6Qj2RQImupVBySSt1v_pi2771R66foBvspnzaEf505BNppYZ9jh3zLS3jjhztkkK76MOilho0cFHF0328s3AgNI8LFQDYpVp-_rCDb6NwPPLAhEewyecL690xvE_NbUMlTATRwKBgQDCnaZYzZ3053ODXMtwe2ouXQKRvHj4Dbf1kaJmvB_EpEAIYjMGIcFc54Mvj1EngmzVOcnzJCONHccCSQ-2mTvMG2op0qB2s1yrDpxPqyZnBYIlC3zvz-U0yNV1QrRe-DGWgtTCag3WqIf-6OYA9bAOEPDCTV3E8IEUWudS96VTTQKBgQDYbNlT-XHAuf2MsEPX_ubykbuWaZowcc2UoFIn2pXKWBt3F3bGMzx4bP0aVLNNciTuk_os5EssA-nlhpXrLXQnTL8MdZYpRe1vg30ZeUCt73MkdaiOlEPVHh-nHfyANkLZKz13cfyqIoZPflgHqkuiDRC5oqDv5xfeotOuVucDmQKBgH_9bUklrSGmRvIKwPyuaP52vSOWginmXzjRKvOGIleg6RRQs4tlbsVluHeQx7bZQQ4b578NYyK78FWfX1AG1OrbscHN8vUrSTN_viPGn6gXpxL0KDaX8okd7zdixwwxqYD0juxmLlaRSTGTAwUF0f-EkPDuNdisG-gkbbsBRJat",
    }))
    .unwrap()
}

fn test_issuer_context() -> IssuerContext {
    IssuerContext::import_secret_key(&test_issuer_secret_keys()).unwrap()
}

fn issuer_context_with_identity(identity_keys: nostr::Keys) -> IssuerContext {
    let mut secret_keys = test_issuer_secret_keys();
    secret_keys.issuer_id_secret_key = identity_keys.secret_key().to_secret_hex();
    IssuerContext::import_secret_key(&secret_keys).unwrap()
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
    let issuer = test_issuer_context();
    // Keep the Nostr RNG sequence aligned with the original generated-issuer
    // snapshots while avoiding slow safe-prime RSA key generation.
    let _discarded_identity_keys = nostr::Keys::generate_with_rng(&mut nostr_rng);
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
      "blinded_message": "lVObVKDwBk70A0XkJSeXNMLe6lRmF1wX6Im2RwN1xsAliAQ5t8b7BIvcl1YHml5fepA1tYrVWrgKvD8KcEMl63qFnzNqgAA8OiyLihlITB0nInmKlJuZDtiVECfHM9H6jlr-2_apoUp4W4YRrytP58rYLy-13B7OVAmJgdNmIKTPQTiObMhgiFj837vd5xRf8bfagBJRsvzqAv06sVaa1wB7_ZI4heUoa4EMkH6FUN80t1ZAv4yaASyK_LIJ_sfuNUfmGvYBrafkTG-5_9bkYCz6bYmte03kFZB0Y6owjr-PvQriPY5b2wS1aZCn850R3WNOHy98HJO_krUPoNw46A"
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
      "blind_signature": "O2YBb_kP0tCSPNbytQiKsNdfDQQ054RMnZcwmXxpSERC1lLZdsLPOY0V4N1kygVtIdy0cOrYPe22hM6x5kC3bPIEdDMLfHzuGuRSp-QfSY5rKHxpCPLvdAg31c4zVMF1V15sLjW0AfYebyg462LUqZXntt54TwsT_QTUOi9hgHT4N8tBuEbipAEhfQfF3MTOp024nwsvhoPKh6l4-iH7vWVgVNjh3y_bYPLbNKzXSHTJp5OjLMRkkb_qVGOl-zfohz9B7SaTPoSt4Xdwp5SnFY9jfqOlzYJ75v9mnshv4rjpwwlZgf6zH72itkCZzzjK34LpZD8eHAKocshAAccaMg"
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
        "signature": "jn5ZZhl_okr9S8jtf19fo7Ili71DYPiK5XRFg3MhpXBMnzerv6QWpTFZ3EoL7pHRlqFfZnQUbBEk3xco2tQHDzrrAJyqGQnHw25wpxn4rAZ_mTEj74tnelcIIiBdFXV6j51TRXFp7wbDo4jUYcOdpQ6PSvu0PljgHKI-OmKZRgQW_UgDQNUlvDu6hAiAQUrXaoGAk8vwOuzjm1Jt3z_mlKdWoUuXIiqaEFOrU3qc-g3LGpMB7PuW4mhBsiN74ah76K7MP2gkYsdVN4LXw-V2N-IpM-xWtSYVrhC2rilOwtQkf1tNuaxiV_q-Di-6xApem4dDKNL4rIrVFJYF9CodCQ"
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
    let other_identity_keys = nostr::Keys::generate_with_rng(&mut nostr_rng);
    let other_issuer = issuer_context_with_identity(other_identity_keys);
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

#[test]
#[ignore = "slow RSA safe-prime key generation; run with --ignored --nocapture to print timing"]
fn issuer_context_generate_reports_rsa_keygen_timing() {
    let started = std::time::Instant::now();
    let issuer = IssuerContext::generate().unwrap();
    let keygen_elapsed = started.elapsed();
    eprintln!(
        "IssuerContext::generate() RSA keygen completed in {:.3}s",
        keygen_elapsed.as_secs_f64()
    );

    let exported = issuer.export_secret_key().unwrap();
    assert!(!exported.issuer_id_secret_key.is_empty());
    assert!(!exported.issuance_secret_key.is_empty());

    let issuer_bundle = issuer.issuer_bundle(vec![]).unwrap();
    issuer_bundle.verify().unwrap();

    let credential_info = json!({
        "schema": "rsa-keygen-smoke-v1",
        "trust_level": 1,
    });
    let holder = HolderContext::generate();
    let blind_msg = json!(holder.public_key());
    let (request, pending) = PendingIssuance::create_request(
        &issuer_bundle.issuer.issuance_key,
        issuer_bundle.issuer.issuer_id_pubkey.clone(),
        credential_info.clone(),
        blind_msg,
    )
    .unwrap();
    let response = issuer.issue_credential(credential_info, &request).unwrap();
    let credential = pending
        .finalize(&issuer_bundle.issuer.issuance_key, &response)
        .unwrap();

    let mut verifier = VerificationContext::new();
    verifier.add_issuer_bundle(&issuer_bundle).unwrap();
    verifier.verify_credential(&credential).unwrap();
}
