//! RFC 8785 / JSON Canonicalization Scheme helpers.
//!
//! These helpers canonicalize arbitrary JSON values before they are signed,
//! verified, or hashed. The output is UTF-8 JSON with deterministic object key
//! ordering, no insignificant whitespace, and RFC 8785-compatible number and
//! string serialization.

use serde_json::{json, Value};

use crate::{Credential, IssuerId, ProtocolVersion};

/// Canonicalize a JSON value using RFC 8785 / JCS and return UTF-8 bytes.
///
/// This is a small protocol-facing wrapper around
/// [`serde_json_canonicalizer::to_vec`], which implements RFC 8785 for
/// `serde`/`serde_json`.
///
/// # Errors
///
/// Returns a [`serde_json::Error`] if serialization fails.
fn canonicalize_json_value(value: &Value) -> serde_json::Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(value)
}

/// Canonicalized payload type string for issuer-visible public credential information.
pub const PBRSA_PUBLIC_INFO_CANONICAL_TYPE: &str = "fedibtc.pbrsa.public-info";

/// Canonicalized payload type string for holder-hidden blind-message information.
pub const PBRSA_BLIND_MSG_CANONICAL_TYPE: &str = "fedibtc.pbrsa.blind-msg";

/// Build JCS canonical bytes for the PBRSA public credential info.
///
/// The canonicalized value includes a type string, protocol version, issuer
/// identifier, and issuer-visible credential `info` JSON.
pub fn canonicalize_pbrsa_info(
    version: ProtocolVersion,
    issuer_id: &IssuerId,
    info: &Value,
) -> serde_json::Result<Vec<u8>> {
    let payload = json!({
        "type": PBRSA_PUBLIC_INFO_CANONICAL_TYPE,
        "version": version,
        "issuer_id": issuer_id,
        "info": info,
    });

    canonicalize_json_value(&payload)
}

/// Build JCS canonical bytes for the PBRSA blind message.
///
/// The canonicalized value includes a type string, protocol version, and
/// holder-hidden credential `blind_msg` JSON.
pub fn canonicalize_pbrsa_blind_msg(
    version: ProtocolVersion,
    blind_msg: &Value,
) -> serde_json::Result<Vec<u8>> {
    let payload = json!({
        "type": PBRSA_BLIND_MSG_CANONICAL_TYPE,
        "version": version,
        "blind_msg": blind_msg,
    });

    canonicalize_json_value(&payload)
}

/// Build JCS canonical bytes for a finalized credential.
pub fn canonicalize_credential(credential: &Credential) -> serde_json::Result<Vec<u8>> {
    let value = serde_json::to_value(credential)?;
    canonicalize_json_value(&value)
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::{IssuerId, PROTOCOL_VERSION_V1};

    #[test]
    fn canonicalizes_object_keys_recursively() {
        let value = json!({
            "z": 1,
            "a": {
                "b": true,
                "a": false,
            },
            "m": [ { "y": null, "x": "value" } ],
        });

        assert_eq!(
            canonicalize_json_value(&value).unwrap(),
            br#"{"a":{"a":false,"b":true},"m":[{"x":"value","y":null}],"z":1}"#
        );
    }

    #[test]
    fn canonicalizes_numbers_without_insignificant_syntax() {
        let value: Value =
            serde_json::from_str(r#"{"b": false, "c": 12e1, "a": "Hello!"}"#).expect("valid json");

        assert_eq!(
            canonicalize_json_value(&value).unwrap(),
            br#"{"a":"Hello!","b":false,"c":120}"#
        );
    }

    #[test]
    fn public_info_payload_is_jcs_canonical() {
        let issuer_id = IssuerId(nostr::PublicKey::from_byte_array([1u8; 32]));
        let info = json!({
            "z": 1,
            "a": {
                "b": true,
                "a": false,
            },
        });

        let canonicalized =
            canonicalize_pbrsa_info(PROTOCOL_VERSION_V1, &issuer_id, &info).unwrap();
        let expected = format!(
            r#"{{"info":{{"a":{{"a":false,"b":true}},"z":1}},"issuer_id":"{}","type":"{}","version":1}}"#,
            issuer_id.0, PBRSA_PUBLIC_INFO_CANONICAL_TYPE,
        );

        assert_eq!(canonicalized, expected.as_bytes());
    }

    #[test]
    fn blind_msg_payload_is_jcs_canonical() {
        let blind_msg = json!({
            "holder": "alice",
            "nonce": 7,
        });

        assert_eq!(
            canonicalize_pbrsa_blind_msg(PROTOCOL_VERSION_V1, &blind_msg).unwrap(),
            format!(
                r#"{{"blind_msg":{{"holder":"alice","nonce":7}},"type":"{}","version":1}}"#,
                PBRSA_BLIND_MSG_CANONICAL_TYPE,
            )
            .as_bytes()
        );
    }
}
