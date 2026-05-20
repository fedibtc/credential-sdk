use serde_json::json;

use crate::{IssuerContext, PendingIssuance, RevocationLocation, VerificationContext};

const TEST_RNG_SEED: u64 = 0x5eed_f00d_cafe_babe;

type NostrRng = nostr::secp256k1::rand::rngs::StdRng;
type PbrsaRng = blind_rsa_signatures::reexports::rand::rngs::StdRng;

fn issuer_context(nostr_rng: &mut NostrRng, pbrsa_rng: &mut PbrsaRng) -> IssuerContext {
    let identity_keys = nostr::Keys::generate_with_rng(nostr_rng);
    IssuerContext::generate_with_rng(identity_keys, 1024, pbrsa_rng).unwrap()
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
        "schema": "trust-score-v1",
        "level": 7,
        "verified": true,
    });
    let blind_msg = json!({
        "holder_pubkey": "holder-pubkey",
        "nonce": 42,
    });

    // Create issuer metadata before any holder interaction.
    let issuer = issuer_context(&mut nostr_rng, &mut pbrsa_rng);
    let public_key = issuer.public_key();
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
      "issuer": {
        "issuer_id_pubkey": "edf91ee8ef705ad30cdbffffe86cd1fb08a6114178ed998f7a5ad52e25a67f97",
        "issuance_key": "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHqlcEXhOsb7YTTOFty0DtofgEZMxIXHDGgfjef6dL7wNZ6EBqknxMfT3s40XP32uKbuen2AzFSOC_ml41YiiZSkMh-PLyrmo9LxtpCDh2SIzRDPFb9PiCMmC0uDtebIh6wffxYon4OGlQghC0cE_GavsswisZVlQoNM9OkfSTetAgMBAAE",
        "revocation": [
          {
            "protocol": "nostr",
            "location": "wss://relay.example.com"
          }
        ]
      },
      "proof": {
        "signature": "738473e3ba3141e98b2c9c276676c2c8dece6bf36dbe13cb2af890f1271e08153c6cc622a67da30329ee3642802bfd0f4905acbd81b13aeb6142d354738da46b"
      }
    }
    "###);

    // Create the holder's blinded issuance request.
    let (request, pending) = PendingIssuance::create_request_with_rng(
        &public_key,
        issuer.issuer_id(),
        credential_info.clone(),
        blind_msg,
        &mut pbrsa_rng,
    )
    .unwrap();

    insta::assert_json_snapshot!(request, @r###"
    {
      "version": 1,
      "blinded_message": "U3cBLAo8aDgo-11EB6c6ULdR89NGGV6PBzRWQ5M8uC_b8cbaAicIoDI3CSmmSCG78qSb5l4GUBHHfzJwNxOYHHzmKOxphBpR-QXggQ40b8RK_vWARGji1gjfHO1BtgqeAOv3Ax91JXQWh9vt_sR4S7gziz5_V6kn3dUwNtOFQVw"
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
        "level": 7,
        "schema": "trust-score-v1",
        "verified": true
      },
      "blind_signature": "a63kve0Yy6jM_XvZXmRdQo4i2p8PaV9YFFRrOjxqMHHI1_D6ZNImpAxguy6sehxOTF8j1y23So1WD1eK-UiwP21QHx2Mu3Ietqj4MUqWmvqg13IA8qjLFOG1w2nzmadWmrl204HbsVUU5CdpzzUhdGD7Mj3t-mwG_249PLsWtQ0"
    }
    "###);

    // Finalize the blinded response into the holder's credential.
    let mut credential = pending.finalize(&public_key, &response).unwrap();

    insta::assert_json_snapshot!(credential, @r###"
    {
      "version": 1,
      "issuer_id": "edf91ee8ef705ad30cdbffffe86cd1fb08a6114178ed998f7a5ad52e25a67f97",
      "info": {
        "level": 7,
        "schema": "trust-score-v1",
        "verified": true
      },
      "blind_msg": {
        "holder_pubkey": "holder-pubkey",
        "nonce": 42
      },
      "message_randomizer": "esz5fHBn-obcvSswhfHLrN8_HcpnUuIkmXlhsKIwgaM",
      "signature": "JmLeoUbgQbzBccAtLTmd4_fYRBzvFiciPlnj9NzTvW5yGNn-8ZISbvJEhqf_fXaxutkBn64Z1_ZEa5tWbPTa0PsRGyiGRmJy7THDiClpZkIQL-QBBM5hK7EL3ASbcXvAOFnnWz8kzy4SHrp-IF-OroeQFrBTY5wK5aAsOWzDAEs"
    }
    "###);

    // Revoke the finalized credential and snapshot the signed revocation entry.
    let revocation = issuer.revoke_credential(&credential).unwrap();
    let signed_revocation = issuer
        .sign_revocation_with_rng(&revocation, &mut nostr_rng)
        .unwrap();

    insta::assert_json_snapshot!(signed_revocation, @r###"
    {
      "revocation": {
        "credential_digest": "67b61bb9f487288859cd7c767626e1e328a3108f4c8dadf5e5cf6caa74c726de"
      },
      "proof": {
        "issuer_id_pubkey": "edf91ee8ef705ad30cdbffffe86cd1fb08a6114178ed998f7a5ad52e25a67f97",
        "signature": "42e7cf3f268f697a016ae0c987588cc64e8ac8dc40616c090bf186f6c9ff29e9f6c977ff50276971a85f422c49d21b37c279067a23b9c30304ad39265c6be54b"
      }
    }
    "###);
    let other_issuer = issuer_context(&mut nostr_rng, &mut pbrsa_rng);

    // Verify the same credential before and after trusting the issuer and revocation.
    let mut verifier = VerificationContext::new();
    let unknown_before_trust = verifier.verify_credential(&credential).unwrap_err();
    verifier.add_issuer_bundle(&issuer_bundle).unwrap();
    let verified_before_revocation = verifier.verify_credential(&credential).is_ok();
    verifier.add_revocation(&signed_revocation).unwrap();
    let revoked_after_revocation = verifier.verify_credential(&credential).unwrap_err();

    insta::assert_json_snapshot!(json!({
        "unknown_before_trust": unknown_before_trust.to_string(),
        "verified_before_revocation": verified_before_revocation,
        "revoked_after_revocation": revoked_after_revocation.to_string(),
    }), @r###"
    {
      "revoked_after_revocation": "credential has been revoked",
      "unknown_before_trust": "unknown issuer",
      "verified_before_revocation": true
    }
    "###);

    // Importing persisted issuer secrets must preserve both identity and issuance keys.
    let imported = IssuerContext::from_secret_key_der(
        &issuer.nostr_secret_key(),
        &issuer.secret_key_der().unwrap(),
    )
    .unwrap();

    insta::assert_json_snapshot!(json!({
        "original_issuer_id": issuer.issuer_id(),
        "imported_issuer_id": imported.issuer_id(),
        "same_issuance_public_key": issuer.public_key() == imported.public_key(),
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

    credential.blind_msg = json!({ "holder_pubkey": "mallory", "nonce": 42 });
    let mut verifier = VerificationContext::new();
    verifier.add_issuer_bundle(&issuer_bundle).unwrap();

    insta::assert_json_snapshot!(json!({
        "tampered_credential": verifier.verify_credential(&credential).unwrap_err().to_string(),
        "tampered_bundle": crate::verify_issuer_bundle(&tampered_bundle).unwrap_err().to_string(),
        "wrong_issuer_revoke": other_issuer.revoke_credential(&credential).unwrap_err().to_string(),
    }), @r###"
    {
      "tampered_bundle": "verification failed",
      "tampered_credential": "blind RSA operation failed: Verification failed",
      "wrong_issuer_revoke": "issuer_id does not match"
    }
    "###);
}
