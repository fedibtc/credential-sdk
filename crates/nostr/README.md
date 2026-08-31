# Peer Badge Nostr Publication Profile

This crate defines the open Nostr publication profile for credential documents from `fedi-credential-sdk-protocol`. It is application-neutral: Manifold and other consumers use the same event shapes without changing the credential protocol to fit their trust policy.

## Ownership

This crate owns:

- the Nostr event kinds and required addressable-event `d` tags;
- the mapping of `IssuerAuthority` and `SignedRevocation` documents into event content;
- producer builders for canonical event envelopes;
- structural, Nostr-signature, document-signature, author-binding, and `d`-tag admission;
- fixed, fully signed JSON fixtures for cross-program compatibility.

It does not own relay selection, network I/O, retry behavior, issuer trust policy, revocation refresh policy, or application-specific interpretation. Those remain with consuming applications.

## Version 1 wire profile

Both events are parameterized replaceable Nostr events. The hashtag is an indexing hint; admission does not trust or require it. Consumers authenticate the complete event and document.

| Document | Kind | Required `d` tag | Published hashtag |
| --- | ---: | --- | --- |
| `IssuerAuthority` | `37703` | `issuer-authority` | `peer-badge-issuer` |
| `SignedRevocation` | `37704` | `credential-revocation:<credential-digest>` | `peer-badge-credential-revocation` |

The event content is the compact JSON serialization of the corresponding protocol document. The event author must equal the document issuer. A credential digest in a revocation `d` tag uses the protocol's unpadded URL-safe base64 wire encoding.

The hashtags use the protocol's Peer Badge namespace rather than preserving the
legacy Manifold indexing values. Downstream migrations must update their relay
filters with the profile; hashtags are not authenticated content selectors.

These kind assignments remain provisional until they are checked and documented against the public Nostr kind registry. Existing deployments must coordinate any change because publishers and consumers filter on the exact values.

## Usage

```rust
use fedi_credential_sdk_nostr::{
    admit_issuer_authority_event, issuer_authority_event_builder,
};

let event = issuer_authority_event_builder(&authority)?
    .sign_with_keys(&issuer_nostr_keys)?;
let admitted = admit_issuer_authority_event(&event)?;
assert_eq!(admitted, authority);
# Ok::<(), Box<dyn std::error::Error>>(())
```
