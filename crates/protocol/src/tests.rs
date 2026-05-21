use serde_json::json;

use crate::{
    HolderContext, IssuerContext, PendingIssuance, RevocationLocation, VerificationContext,
};

const TEST_RNG_SEED: u64 = 0x5eed_f00d_cafe_babe;

type NostrRng = nostr::secp256k1::rand::rngs::StdRng;
type PbrsaRng = blind_rsa_signatures::reexports::rand::rngs::StdRng;

fn issuer_context(nostr_rng: &mut NostrRng, pbrsa_rng: &mut PbrsaRng) -> IssuerContext {
    let identity_keys = nostr::Keys::generate_with_rng(nostr_rng);
    IssuerContext::generate_with_rng(identity_keys, pbrsa_rng).unwrap()
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
        "issuance_key": "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHqlcEXhOsb7YTTOFty0DtofgEZMxIXHDGgfjef6dL7wNZ6EBqknxMfT3s40XP32uKbuen2AzFSOC_ml41YiiZSkMh-PLyrmo9LxtpCDh2SIzRDPFb9PiCMmC0uDtebIh6wffxYon4OGlQghC0cE_GavsswisZVlQoNM9OkfSTetAgMBAAE",
        "revocation": [
          {
            "protocol": "nostr",
            "location": "wss://relay.example.com"
          }
        ]
      },
      "proof": {
        "signature": "c4Rz47oxQemLLJwnZnbCyN7Oa_NtvhPLKviQ8SceCBU8bMYipn2jAynuNkKAK_0PSQWsvYGxOuthQtNUc42kaw"
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
      "blinded_message": "biva9Mtwux4vnhe3gfc6WBigwh57Rmq7DU01mIVSMeTrEnYDP6GxzqIVN1bS9Db0EksVvgQcHwvaFQ6eBSVj-EgGwQe6AOcOriJBFQTd5NO0YWfyz0tdTvcfDWdv4YhCXgWqYkN_2XhOdLoagg6UyStV1zRvre81W_JeJI1VCUg"
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
      "blind_signature": "S0RczqfNDsK_I1lRs7a_8wJJ-G09l9kqiAyNZePTEmh2ixu1mnPEs4zm696ehk8w30uBoCI-vxkAHNKzxbgMo3QpQ67pTc5-De_bT5slcYGCe4m-hVWQ_gq2T_ACQ5Eny_6QTpU3OWugChzM24RU2O3wxdzAGg7wLrr8CLJbKOI"
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
        "message_randomizer": "esz5fHBn-obcvSswhfHLrN8_HcpnUuIkmXlhsKIwgaM"
      },
      "proof": {
        "signature": "alZM3tiyvAaNAt58iydlsLycNF3W3kHF3LWd7w3T_mm74azyTnWZD_T1ITd3luXOYCjKlzeKHTOAoayzvXC_eTGPtERNk7Nex5QItVwGoIr2CQax_s-ptPm7xPZGgCWognN4IClzLvw2o2JeLQLFp01P773cavcJkz91W8aR-Mg"
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
        "credential_digest": "YCzBI1n8Rz5MqWMPup7bP-K4MkmmSYrnNG8LMbcR_UE"
      },
      "proof": {
        "issuer_id_pubkey": "edf91ee8ef705ad30cdbffffe86cd1fb08a6114178ed998f7a5ad52e25a67f97",
        "signature": "0OfCg_G3Y4GNvEwbqBTp_CG_bGzxENxGdRSV56KD9YoEYA367zvpBMs4Sl_CtUyYZAEvHGTRvSwjOIpUjlVHNw"
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
