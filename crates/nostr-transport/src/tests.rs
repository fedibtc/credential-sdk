use fedi_credential_sdk_protocol::{credential_digest, SignedCredential};
use nostr::{Event, Keys, Kind, Tag, Timestamp, UnsignedEvent};
use serde::Deserialize;
use serde_json::Value;

use super::*;

const GOLDEN_VECTOR: &str = include_str!("../../schemas/fixtures/trust-score-v1.json");
const GOLDEN_DIGEST: &str = "QK-voxaw9juOY7kZRJVcpWqi7hJP_Q33pAeto-Kg8NM";

#[derive(Deserialize)]
struct GoldenVector {
    holder_secret_key: String,
    signed_credential: SignedCredential,
}

fn vector() -> GoldenVector {
    serde_json::from_str(GOLDEN_VECTOR).unwrap()
}

fn prepared_at(seconds: u64) -> (Keys, SignedCredential, UnsignedEvent) {
    let vector = vector();
    let keys = Keys::parse(&vector.holder_secret_key).unwrap();
    let unsigned = prepare_holder_credential_event(
        keys.public_key(),
        &vector.signed_credential,
        Timestamp::from(seconds),
    )
    .unwrap();
    (keys, vector.signed_credential, unsigned)
}

fn signed_with(keys: &Keys, kind: Kind, tags: Vec<Tag>, content: String) -> Event {
    UnsignedEvent::new(keys.public_key(), Timestamp::from(10), kind, tags, content)
        .sign_with_keys(keys)
        .unwrap()
}

fn d_tag(value: &str) -> Tag {
    Tag::parse(["d", value]).unwrap()
}

fn topic_tag() -> Tag {
    Tag::parse(["t", CREDENTIAL_TOPIC]).unwrap()
}

fn p_tag(keys: &Keys) -> Tag {
    Tag::parse(["p", &keys.public_key().to_string()]).unwrap()
}

#[test]
fn ordinary_json_keeps_the_draft_event_shape() {
    let (keys, credential, unsigned) = prepared_at(1_755_000_000);

    assert_eq!(unsigned.pubkey, keys.public_key());
    assert_eq!(unsigned.kind, KIND_HOLDER_CREDENTIAL);
    assert_eq!(unsigned.created_at, Timestamp::from(1_755_000_000));
    assert_eq!(
        unsigned.tags.clone().to_vec(),
        vec![
            d_tag(&format!("credential:{GOLDEN_DIGEST}")),
            topic_tag(),
            p_tag(&keys),
        ]
    );
    assert_eq!(
        serde_json::from_str::<Value>(&unsigned.content).unwrap(),
        serde_json::to_value(&credential).unwrap()
    );

    let parsed =
        parse_holder_credential_event(&unsigned.sign_with_keys(&keys).unwrap(), &keys.public_key())
            .unwrap();
    assert_eq!(parsed.credential, credential);
}

#[test]
fn rejects_wrong_kind_and_invalid_required_tags() {
    let (keys, _, unsigned) = prepared_at(10);
    let wrong_kind = signed_with(
        &keys,
        Kind::Custom(37_703),
        unsigned.tags.to_vec(),
        unsigned.content.clone(),
    );
    assert!(matches!(
        parse_holder_credential_event(&wrong_kind, &keys.public_key()),
        Err(NostrTransportError::WrongKind)
    ));

    for tags in [
        vec![d_tag(&format!("credential:{GOLDEN_DIGEST}")), p_tag(&keys)],
        vec![d_tag(&format!("credential:{GOLDEN_DIGEST}")), topic_tag()],
        vec![
            d_tag("credential:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            topic_tag(),
            p_tag(&keys),
        ],
    ] {
        let event = signed_with(
            &keys,
            KIND_HOLDER_CREDENTIAL,
            tags,
            unsigned.content.clone(),
        );
        assert!(parse_holder_credential_event(&event, &keys.public_key()).is_err());
    }
}

#[test]
fn rejects_invalid_signature_and_unexpected_holder() {
    let (keys, _, unsigned) = prepared_at(10);
    let mut invalid_signature = unsigned.clone().sign_with_keys(&keys).unwrap();
    invalid_signature.content.push(' ');
    assert!(matches!(
        parse_holder_credential_event(&invalid_signature, &keys.public_key()),
        Err(NostrTransportError::InvalidEventSignature)
    ));

    let other_holder = Keys::generate().public_key();
    assert!(matches!(
        parse_holder_credential_event(&unsigned.sign_with_keys(&keys).unwrap(), &other_holder),
        Err(NostrTransportError::HolderMismatch)
    ));
}

#[test]
fn transport_does_not_interpret_schema_specific_blind_msg() {
    let vector = vector();
    let keys = Keys::parse(&vector.holder_secret_key).unwrap();
    let mut credential = vector.signed_credential;
    credential.credential.blind_msg = serde_json::json!({"holder": "schema-specific"});

    let unsigned =
        prepare_holder_credential_event(keys.public_key(), &credential, Timestamp::from(10))
            .unwrap();
    let parsed =
        parse_holder_credential_event(&unsigned.sign_with_keys(&keys).unwrap(), &keys.public_key())
            .unwrap();

    assert_eq!(parsed.credential, credential);
}

#[test]
fn proof_changes_do_not_change_the_credential_digest() {
    let vector = vector();
    let mut changed = vector.signed_credential.clone();
    changed.proof.signature.0[0] ^= 1;

    assert_eq!(
        credential_digest(&vector.signed_credential).unwrap(),
        credential_digest(&changed).unwrap()
    );
}

#[test]
fn invalid_newer_event_cannot_supersede_an_older_valid_event() {
    let (keys, _, older) = prepared_at(10);
    let older = older.sign_with_keys(&keys).unwrap();
    let (_, _, newer) = prepared_at(20);
    let mut newer = newer.sign_with_keys(&keys).unwrap();
    newer.content.push(' ');

    let selected =
        select_newest_valid_holder_credential_event([&older, &newer], &keys.public_key()).unwrap();
    assert_eq!(selected.event.created_at, Timestamp::from(10));
}
