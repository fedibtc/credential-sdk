//! Open Nostr publication profile for Fedi credential protocol documents.
//!
//! This crate owns the transport mapping between credential documents and
//! Nostr events. It does not select relays, establish issuer trust, or define
//! application policy.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use fedi_credential_sdk_protocol::{
    CredentialDigest, CredentialsError, IssuerAuthority, SignedRevocation,
};
use nostr::{Event, EventBuilder, Kind, Tag, TagKind};

/// Issuer-authority distribution event kind.
pub const ISSUER_AUTHORITY_EVENT_KIND: u16 = 37703;

/// `d` tag value used for issuer-authority events.
pub const ISSUER_AUTHORITY_D_TAG: &str = "issuer-authority";

/// Hashtag used to index issuer-authority events.
pub const ISSUER_AUTHORITY_HASHTAG: &str = "peer-badge-issuer";

/// [`fedi_credential_sdk_protocol::RevocationLocation::protocol`] value naming
/// a Nostr relay.
pub const NOSTR_REVOCATION_LOCATION_PROTOCOL: &str = "nostr";

/// Credential-revocation event kind.
pub const CREDENTIAL_REVOCATION_EVENT_KIND: u16 = 37704;

/// Hashtag used to index credential-revocation events.
pub const CREDENTIAL_REVOCATION_HASHTAG: &str = "peer-badge-credential-revocation";

/// Prefix for credential-revocation `d` tags.
pub const CREDENTIAL_REVOCATION_D_TAG_PREFIX: &str = "credential-revocation";

/// Build the addressable Nostr event envelope for an issuer authority.
///
/// The caller must sign the returned builder with the authority issuer's Nostr
/// identity key. Admission rejects events signed by any other key.
///
/// # Errors
///
/// Returns an error when the authority fails credential-protocol verification
/// or cannot be serialized.
pub fn issuer_authority_event_builder(
    authority: &IssuerAuthority,
) -> Result<EventBuilder, CredentialNostrEventError> {
    authority
        .verify()
        .map_err(CredentialNostrEventError::InvalidDocument)?;
    let content = serde_json::to_string(authority).map_err(CredentialNostrEventError::Serialize)?;
    Ok(
        EventBuilder::new(Kind::Custom(ISSUER_AUTHORITY_EVENT_KIND), content).tags([
            Tag::identifier(ISSUER_AUTHORITY_D_TAG),
            Tag::hashtag(ISSUER_AUTHORITY_HASHTAG),
        ]),
    )
}

/// Build the addressable Nostr event envelope for a credential revocation.
///
/// The caller must sign the returned builder with the revocation issuer's Nostr
/// identity key. Admission rejects events signed by any other key.
///
/// # Errors
///
/// Returns an error when the revocation fails credential-protocol verification
/// or cannot be serialized.
pub fn credential_revocation_event_builder(
    revocation: &SignedRevocation,
) -> Result<EventBuilder, CredentialNostrEventError> {
    let verified = revocation
        .verify()
        .map_err(CredentialNostrEventError::InvalidDocument)?;
    let content =
        serde_json::to_string(revocation).map_err(CredentialNostrEventError::Serialize)?;
    Ok(
        EventBuilder::new(Kind::Custom(CREDENTIAL_REVOCATION_EVENT_KIND), content).tags([
            Tag::identifier(credential_revocation_d_tag(&verified.credential_digest)),
            Tag::hashtag(CREDENTIAL_REVOCATION_HASHTAG),
        ]),
    )
}

/// Fully authenticate and admit an issuer-authority publication.
///
/// Hashtags are indexing hints and are not trusted during admission.
///
/// # Errors
///
/// Returns an error when the Nostr signature, kind, exact `d` tag, content,
/// credential-protocol signature, or event-author binding is invalid.
pub fn admit_issuer_authority_event(
    event: &Event,
) -> Result<IssuerAuthority, CredentialNostrEventError> {
    authenticate_event(event, ISSUER_AUTHORITY_EVENT_KIND, ISSUER_AUTHORITY_D_TAG)?;
    let authority: IssuerAuthority =
        serde_json::from_str(&event.content).map_err(CredentialNostrEventError::InvalidContent)?;
    authority
        .verify()
        .map_err(CredentialNostrEventError::InvalidDocument)?;
    if event.pubkey != authority.issuer.issuer_id_pubkey.0 {
        return Err(CredentialNostrEventError::WrongAuthor);
    }
    Ok(authority)
}

/// Fully authenticate and admit a credential-revocation publication.
///
/// Hashtags are indexing hints and are not trusted during admission.
///
/// # Errors
///
/// Returns an error when the Nostr signature, kind, exact digest-derived `d`
/// tag, content, credential-protocol signature, or event-author binding is
/// invalid.
pub fn admit_credential_revocation_event(
    event: &Event,
) -> Result<SignedRevocation, CredentialNostrEventError> {
    event
        .verify()
        .map_err(|_| CredentialNostrEventError::InvalidEvent)?;
    if event.kind != Kind::Custom(CREDENTIAL_REVOCATION_EVENT_KIND) {
        return Err(CredentialNostrEventError::WrongKind);
    }

    let revocation: SignedRevocation =
        serde_json::from_str(&event.content).map_err(CredentialNostrEventError::InvalidContent)?;
    let verified = revocation
        .verify()
        .map_err(CredentialNostrEventError::InvalidDocument)?;
    if event.pubkey != revocation.proof.issuer_id_pubkey.0 {
        return Err(CredentialNostrEventError::WrongAuthor);
    }
    if !has_exact_d_tag(
        event,
        &credential_revocation_d_tag(&verified.credential_digest),
    ) {
        return Err(CredentialNostrEventError::WrongDTag);
    }
    Ok(revocation)
}

/// Build the credential-revocation `d` tag for a credential digest.
#[must_use]
pub fn credential_revocation_d_tag(credential_digest: &CredentialDigest) -> String {
    let mut tag = String::with_capacity(CREDENTIAL_REVOCATION_D_TAG_PREFIX.len() + 1 + 43);
    tag.push_str(CREDENTIAL_REVOCATION_D_TAG_PREFIX);
    tag.push(':');
    URL_SAFE_NO_PAD.encode_string(&credential_digest.0[..], &mut tag);
    tag
}

fn authenticate_event(
    event: &Event,
    expected_kind: u16,
    expected_d_tag: &str,
) -> Result<(), CredentialNostrEventError> {
    event
        .verify()
        .map_err(|_| CredentialNostrEventError::InvalidEvent)?;
    if event.kind != Kind::Custom(expected_kind) {
        return Err(CredentialNostrEventError::WrongKind);
    }
    if !has_exact_d_tag(event, expected_d_tag) {
        return Err(CredentialNostrEventError::WrongDTag);
    }
    Ok(())
}

fn has_exact_d_tag(event: &Event, expected: &str) -> bool {
    let mut d_tags = event
        .tags
        .as_slice()
        .iter()
        .filter(|tag| tag.kind() == TagKind::d());
    let Some(d_tag) = d_tags.next() else {
        return false;
    };
    let d_tag = d_tag.as_slice();
    d_tag.len() == 2 && d_tag[0] == "d" && d_tag[1] == expected && d_tags.next().is_none()
}

/// Failure while building or admitting a credential Nostr event.
#[derive(Debug, thiserror::Error)]
pub enum CredentialNostrEventError {
    /// The credential document's own signature or structure is invalid.
    #[error("invalid credential document: {0}")]
    InvalidDocument(#[source] CredentialsError),

    /// A valid credential document could not be serialized.
    #[error("serialize credential document: {0}")]
    Serialize(#[source] serde_json::Error),

    /// The Nostr event ID or signature is invalid.
    #[error("invalid Nostr event")]
    InvalidEvent,

    /// The event does not use the required credential publication kind.
    #[error("unexpected credential event kind")]
    WrongKind,

    /// The event author does not match the document issuer.
    #[error("credential event author does not match document issuer")]
    WrongAuthor,

    /// The event does not contain exactly one required `d` tag.
    #[error("unexpected credential event d tag")]
    WrongDTag,

    /// The event content is not the expected credential document.
    #[error("invalid credential event content: {0}")]
    InvalidContent(#[source] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use fedi_credential_sdk_protocol::{
        IssuerId, ProtocolV1, Revocation, RevocationProof, SignedRevocation,
    };
    use nostr::{
        secp256k1::{rand::rngs::StdRng, rand::SeedableRng, Message},
        types::time::Instant,
        JsonUtil as _, Keys, Timestamp, SECP256K1,
    };

    use super::*;

    const ISSUER_SECRET_KEY: &str =
        "76127aa07dc3a3dcad06c8f8835ff997adb9c542868434bc47d16f1c9ba860b8";

    fn issuer_keys() -> Keys {
        Keys::parse(ISSUER_SECRET_KEY).expect("fixture issuer key parses")
    }

    fn issuer_authority() -> IssuerAuthority {
        serde_json::from_str(include_str!("../fixtures/issuer-authority-document.json"))
            .expect("fixture authority parses")
    }

    fn signed_revocation() -> SignedRevocation {
        let keys = issuer_keys();
        let authority = issuer_authority();
        let credential_digest = CredentialDigest([7_u8; 32].into());
        let revocation = Revocation { credential_digest };
        let mut rng = StdRng::seed_from_u64(41);
        let signature = keys.sign_schnorr_with_ctx(
            SECP256K1,
            &Message::from_digest(revocation.digest().expect("digest").into()),
            &mut rng,
        );
        SignedRevocation {
            version: ProtocolV1,
            revocation,
            proof: RevocationProof {
                issuer_id_pubkey: IssuerId(authority.issuer.issuer_id_pubkey.0),
                signature,
            },
        }
    }

    #[test]
    fn issuer_authority_round_trips_through_the_profile() {
        let authority = issuer_authority();
        let event = issuer_authority_event_builder(&authority)
            .expect("authority builds")
            .custom_created_at(Timestamp::from_secs(1_700_000_000))
            .sign_with_keys(&issuer_keys())
            .expect("event signs");

        assert_eq!(admit_issuer_authority_event(&event).unwrap(), authority);
    }

    #[test]
    fn credential_revocation_round_trips_through_the_profile() {
        let revocation = signed_revocation();
        let event = credential_revocation_event_builder(&revocation)
            .expect("revocation builds")
            .custom_created_at(Timestamp::from_secs(1_700_000_001))
            .sign_with_keys(&issuer_keys())
            .expect("event signs");

        assert_eq!(
            admit_credential_revocation_event(&event).unwrap(),
            revocation
        );
    }

    #[test]
    fn admission_rejects_a_different_event_author() {
        let authority = issuer_authority();
        let event = issuer_authority_event_builder(&authority)
            .expect("authority builds")
            .custom_created_at(Timestamp::from_secs(1_700_000_000))
            .sign_with_keys(&Keys::generate())
            .expect("event signs");

        assert!(matches!(
            admit_issuer_authority_event(&event),
            Err(CredentialNostrEventError::WrongAuthor)
        ));
    }

    #[test]
    fn signed_event_shapes_match_golden_fixtures() {
        let keys = issuer_keys();
        let mut rng = StdRng::seed_from_u64(42);
        let time_supplier = Instant::now();
        let authority_event = issuer_authority_event_builder(&issuer_authority())
            .expect("authority builds")
            .custom_created_at(Timestamp::from_secs(1_700_000_000))
            .sign_with_ctx(SECP256K1, &mut rng, &time_supplier, &keys)
            .expect("authority event signs");
        let revocation_event = credential_revocation_event_builder(&signed_revocation())
            .expect("revocation builds")
            .custom_created_at(Timestamp::from_secs(1_700_000_001))
            .sign_with_ctx(SECP256K1, &mut rng, &time_supplier, &keys)
            .expect("revocation event signs");

        if std::env::var_os("UPDATE_NOSTR_FIXTURES").is_some() {
            let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
            std::fs::write(
                fixtures.join("issuer-authority-event.json"),
                format!("{}\n", authority_event.as_json()),
            )
            .expect("write authority fixture");
            std::fs::write(
                fixtures.join("credential-revocation-event.json"),
                format!("{}\n", revocation_event.as_json()),
            )
            .expect("write revocation fixture");
            return;
        }

        assert_eq!(
            authority_event.as_json(),
            include_str!("../fixtures/issuer-authority-event.json").trim()
        );
        assert_eq!(
            revocation_event.as_json(),
            include_str!("../fixtures/credential-revocation-event.json").trim()
        );
    }
}
