# Nostr Credential Transport Architecture

## Status

Draft architecture for a future `fedi-credential-sdk-nostr-transport` crate.
This document is intentionally scoped to the MVP needed for holder-published
credentials and holder-published credential authorizations.

This crate is not a core part of the SDK. Transport is unrelated to the
cryptographic protocol, so the crate lives here as an optional
extension/utility crate that provides transport functionality for apps that
depend on this SDK. It sits on top of `fedi-credential-sdk-protocol` and is
never a dependency of it.

This transport is based on the holder authorization and Nostr publication
protocols described in
`fedibtc/decentralized-federations/docs/dpc/holder-authorizations.md` and
`docs/dpc/FMan-nostr.md`. Even though this crate stays generic and does not own
application-specific advertisement documents, implementation work should be
validated against those protocol documents as the compatibility source of truth.

## Outcome

An authorized application controls its own Nostr pubkey and presents that pubkey
to the holder, usually through a QR code carrying a protocol
`HolderAuthorizationRequest`.

The holder app selects an already-issued `SignedCredential`, signs a protocol
`HolderAuthorization` for the authorized application's pubkey, and publishes the
authorization plus the backing credential to Nostr. Later, the authorized
application can query relays for its own pubkey, fetch the publication, verify
it, and store the credential/authorization pair without talking to the holder
again.

## Goals

- Add a separate Rust crate for Nostr publication and discovery of credential
  protocol objects.
- Keep `fedi-credential-sdk-protocol` as the source of truth for credential and
  authorization wire types.
- Keep dependency direction one-way: the Nostr transport crate depends on the
  protocol crate; the protocol crate never depends on the transport crate.
- Let holders publish credentials and holder authorizations to Nostr relays.
- Let authorized applications fetch holder-published authorizations by their own
  pubkey.
- Let consumers parse Nostr notes into protocol types and run protocol
  verification without hand-rolling Nostr tags or JSON envelopes.

## Non-Goals

- Issuers do not publish anything in this MVP.
- The crate does not publish issuer authorities in this MVP.
- The crate does not publish revocations in this MVP. Add revocation event
  support later, after the holder publication flow is working.
- The crate does not define application-specific advertisements, discovery, or
  presentation documents.
- The crate does not decide which issuers, schemas, holders, credentials, or
  authorized applications a verifier trusts.
- The crate does not prove live possession of the authorized application's
  subject key. Applications prove possession through their own signatures,
  sessions, RPC authentication, or event signatures.
- The crate does not enforce a publish cooldown or time delay before a holder
  publishes a credential or authorization. That policy is left to the consuming
  app.

## Crate Boundary

Proposed crate:

```text
crates/nostr-transport
package name: fedi-credential-sdk-nostr-transport
```

Dependency direction:

```text
fedi-credential-sdk-nostr-transport
  -> fedi-credential-sdk-protocol
  -> no dependency on fedi-credential-sdk-nostr-transport
```

The transport crate owns:

- Nostr event kinds for credential transport.
- Transport envelope structs.
- Event tag construction and parsing.
- Event content serialization and deserialization.
- Relay publish/fetch code.
- Nostr event signature checks.
- Mapping fetched notes back to protocol objects.

The protocol crate owns:

- `SignedCredential`.
- `HolderAuthorizationRequest`.
- `HolderAuthorization`.
- Credential digesting.
- Holder authorization signing and proof verification.
- Credential verification through `VerificationContext`.

## WASM Boundary

Follow the existing repo pattern:

- Business logic lives in pure Rust crates.
- The WASM crate is a binding/package crate for web applications.

The Nostr transport logic should live in `fedi-credential-sdk-nostr-transport`.
If browser consumers need this functionality through npm, expose it from the
existing WASM package or a parallel WASM package as bindings over the Rust
transport crate. Do not put transport business logic directly in the WASM crate.

## Protocol Objects Reused

The transport crate should consume these protocol types directly:

- `SignedCredential`
- `HolderAuthorization`
- `HolderAuthorizationRequest`
- `CredentialDigest`
- `HolderId`
- `SubjectPubkey`
- `VerificationContext`

The transport crate should not fork these JSON shapes. Event content can wrap
them for transport, but the protocol objects inside the wrapper remain exactly
the protocol crate's serde output.

## Kind Selection

Use the updated `377xx` provisional addressable kind family from the consuming
Nostr transport reference. That reference assigns holder-published
authorization to `37705` and leaves standalone holder credential publication
outside its scope because the backing credential is carried inline with the
authorization publication. This SDK transport still needs a standalone
holder-published credential kind, so use the open slot `37702` in the same
family.

Use two holder-published addressable event kinds for this MVP:

```text
37702 Holder-published credential
37705 Holder-published credential authorization
```

These are provisional SDK transport kinds. Before implementation, confirm
again that they remain unassigned in NIPs and the Nostr kind registry. If they
become assigned before release, choose new addressable kinds or fall back to
kind `30078` with namespaced `d` tags.

## Addressing And Indexing

Use addressable events. A published credential or authorization is immutable,
so this is not about mutating content: the same immutable object keeps a single
stable `d`-tag address so relays replace, rather than accumulate, repeated
publications of that object. Re-publishing the same credential or authorization
(for example to refresh relay coverage) collapses to one addressable slot per
holder and object instead of leaving stale duplicate events behind. Consumers
still resolve any residual divergence between relays at fetch time by keeping
the copy with the newest `created_at` (see Fetching).

Rules:

- Use `d` as the addressable replacement key.
- Use `p` for public key lookup.
- Use `t` for the event family.
- Treat every tag as a lookup hint only.
- Verify all authoritative values from event content and protocol signatures.

Nostr relays commonly index single-letter tags. Multi-letter tags can be useful
for debugging, but fetch code must not depend on them.

The tag strings in this document are Nostr index values, not new SDK protocol
types:

- `["d", "credential:<credential_digest>"]` is the stable address for a
  holder-published credential event.
- `["d", "credential-authorization:<subject_pubkey>:<credential_digest>"]` is
  the stable address for a holder-published authorization event.
- `["p", "<subject_pubkey>"]` lets the authorized application find
  authorizations for its own pubkey.
- `["t", "..."]` is only a topic label. Applications may use their own `t` tag
  values; generic SDK fetching should not depend on them.

Tag value encoding is fixed so publishers and consumers compute the same
`#d`/`#p` index values for the same object:

- `<credential_digest>` is the exact serde string form of the protocol
  `CredentialDigest`: the SHA-256 credential digest encoded as unpadded
  URL-safe base64. It is not hex, padded base64, or the raw digest bytes.
- `<subject_pubkey>` and any holder pubkey are the serde string form the
  protocol crate uses for that pubkey type (`SubjectPubkey`/`HolderId`).
- The literal prefixes `credential:` and `credential-authorization:` and the
  `:` separators are part of the `d` value exactly as written.

Implementations must build these strings from the protocol serde output rather
than re-encoding the underlying bytes independently.

## Event Content Serialization

Event `content` should be canonical JSON for deterministic event IDs and stable
test fixtures. The transport crate owns this serialization for transport
envelopes. The protocol objects inside the transport envelope remain the
protocol crate's serde output.

## Holder Credential Event

This event publishes a holder-owned `SignedCredential` as a standalone object.
Only the holder publishes this event in the MVP.

Event wrapper:

```json5
{
  kind: 37702,
  pubkey: "<holder pubkey>",
  tags: [
    ["d", "credential:<credential_digest>"],
    ["t", "fedi-credential"],
    ["p", "<holder pubkey>"]
  ],
  content: "<canonical JSON string of fedi_credential_sdk_protocol::SignedCredential>"
}
```

Validation:

- The Nostr event signature is valid.
- `event.kind == 37702`.
- `content` parses as `SignedCredential`.
- `Credential::digest(content.credential)` equals the `credential_digest` in the
  `d` tag when that tag is present.
- The holder pubkey represented by `event.pubkey` matches the holder binding in
  the credential. In the current MVP schema, this means
  `credential.credential.blind_msg` is the holder pubkey string.
- The credential itself is verified through `VerificationContext` when the
  caller has issuer authorities and revocation state.

The transport crate should expose this as a holder-authored publication helper.
It should not support issuer-authored credential publication in the MVP.

## Holder Authorization Event

This is the primary event for the requested flow. The holder publishes one
authorization event that contains both the holder-signed authorization and the
backing credential.

Content envelope:

```json5
{
  version: 1,
  holder_id_pubkey: "<holder pubkey>",
  holder_authorization: {
    /* fedi_credential_sdk_protocol::HolderAuthorization */
  },
  signed_credential: {
    /* fedi_credential_sdk_protocol::SignedCredential */
  }
}
```

Event wrapper:

```json5
{
  kind: 37705,
  pubkey: "<holder pubkey>",
  tags: [
    ["d", "credential-authorization:<subject_pubkey>:<credential_digest>"],
    ["t", "fedi-credential-authorization"],
    ["p", "<subject_pubkey>"]
  ],
  content: "<canonical JSON string of the holder authorization envelope>"
}
```

`subject_pubkey` is the authorized application's pubkey. `credential_digest` is
`holder_authorization.authorization.credential_digest`, which is also the digest
of `signed_credential.credential`.

Validation:

- The Nostr event signature is valid.
- `event.kind == 37705`.
- `content` parses as `HolderAuthorizationPublication`.
- `event.pubkey == content.holder_id_pubkey`.
- `event.pubkey == holder_authorization.authorization.holder_id_pubkey`.
- `holder_authorization.verify()` succeeds.
- `holder_authorization.authorization.subject_pubkey` matches the expected
  authorized application pubkey when the caller supplied one. The subject-scoped
  fetch path (`fetch_authorizations_for_subject`) always supplies it: the `#p`
  relay tag is only a lookup hint, so the parser rejects any event whose signed
  `subject_pubkey` differs from the requested subject. `expected_subject: None`
  is only for callers that intentionally inspect an authorization without
  binding it to a specific subject, and must never be used on the authenticated
  subject-scoped fetch path.
- `Credential::digest(signed_credential.credential)` equals
  `holder_authorization.authorization.credential_digest`.
- The backing credential holder binding matches
  `holder_authorization.authorization.holder_id_pubkey`.
- When issuer trust state is available,
  `VerificationContext::verify_credential_authorization` succeeds for the
  backing credential and holder authorization.

## Fetching

Authorized applications fetch authorizations by querying for their own pubkey:

```json5
{
  kinds: [37705],
  "#p": ["<subject_pubkey>"],
  limit: 100
}
```

The fetch filter intentionally does not require a `t` tag. Applications may add
their own `t` tags, and the transport crate validates parsed event content
rather than trusting tag names.

The `#p` filter is likewise only a lookup hint. A relay can return an event
whose `p` tag matches the requested subject while the signed
`holder_authorization.authorization.subject_pubkey` names a different key.
`fetch_authorizations_for_subject` therefore parses every candidate with the
requested subject as `expected_subject` and drops any authorization whose signed
subject does not match, so a mismatched or malicious tag can never surface an
authorization for the wrong authenticated subject.

Consumers can fetch a holder-published credential by digest:

```json5
{
  kinds: [37702],
  "#d": ["credential:<credential_digest>"],
  limit: 20
}
```

Fetch code should:

- Query all configured relays.
- Wait for EOSE or a caller-configured timeout.
- Parse and verify every candidate event.
- Deduplicate authorization events by
  `(holder_id_pubkey, subject_pubkey, credential_digest)`, keeping the event
  with the newest `created_at`.
- Deduplicate credential events by `credential_digest`, keeping the event with
  the newest `created_at`.

Because the published objects are immutable, duplicates for the same key carry
the same authoritative content; the newest-`created_at` tie-break only decides
which relay copy to keep when relays are mid-propagation and briefly disagree.

## Publishing

Publishing should:

- Sign events with the holder's Nostr key or caller-provided Nostr signer.
- Publish to all configured relays concurrently.
- Return per-relay accepted/rejected/timeout results.
- Let callers choose success policy: at least one relay, quorum, or all relays.
- Treat duplicate acceptance as success.

The transport crate should expose prepare functions that produce unsigned event
builders, plus publish functions that sign and send those builders. This lets
applications with their own Nostr client reuse the SDK transport envelope logic
without adopting the SDK relay client.

Publish options may include additional caller-provided tags for application
metadata. Required SDK tags and validation rules stay generic and are not
replaced by application-specific tags.

## Public API Shape

Core constants:

```rust
pub const KIND_HOLDER_CREDENTIAL: Kind = Kind::Custom(37702);
pub const KIND_HOLDER_AUTHORIZATION: Kind = Kind::Custom(37705);
```

Content envelope:

```rust
pub struct HolderAuthorizationPublication {
    pub version: TransportV1,
    pub holder_id_pubkey: HolderId,
    pub holder_authorization: HolderAuthorization,
    pub signed_credential: SignedCredential,
}
```

Prepare functions:

```rust
pub fn prepare_holder_credential_event(
    credential: &SignedCredential,
    options: HolderCredentialPublishOptions,
) -> Result<EventBuilder, NostrTransportError>;

pub fn prepare_holder_authorization_event(
    authorization: &HolderAuthorization,
    credential: &SignedCredential,
    options: HolderAuthorizationPublishOptions,
) -> Result<EventBuilder, NostrTransportError>;
```

Parse functions:

```rust
pub fn parse_holder_credential_event(
    event: &nostr::Event,
) -> Result<SignedCredential, NostrTransportError>;

pub fn parse_holder_authorization_event(
    event: &nostr::Event,
    expected_subject: Option<&SubjectPubkey>,
) -> Result<HolderAuthorizationPublication, NostrTransportError>;
```

`expected_subject` binds the parsed authorization to a specific subject: when
`Some`, the parser rejects any event whose signed
`holder_authorization.authorization.subject_pubkey` differs. Subject-scoped
lookups such as `fetch_authorizations_for_subject` always pass `Some`; `None` is
reserved for callers that deliberately inspect an authorization without binding
it to an authenticated subject.

Relay client functions:

```rust
pub async fn publish_holder_credential<S: NostrEventSigner>(
    signer: &S,
    credential: &SignedCredential,
    options: HolderCredentialPublishOptions,
) -> Result<PublishReport, NostrTransportError>;

pub async fn publish_holder_authorization<S: NostrEventSigner>(
    signer: &S,
    authorization: &HolderAuthorization,
    credential: &SignedCredential,
    options: HolderAuthorizationPublishOptions,
) -> Result<PublishReport, NostrTransportError>;

pub async fn fetch_authorizations_for_subject(
    subject_pubkey: &SubjectPubkey,
    options: FetchAuthorizationOptions,
) -> Result<Vec<HolderAuthorizationPublication>, NostrTransportError>;

pub async fn fetch_holder_credentials_by_digest(
    digest: &CredentialDigest,
    options: FetchCredentialOptions,
) -> Result<Vec<SignedCredential>, NostrTransportError>;
```

`NostrEventSigner` should be an abstraction over a local key, remote signer, or
the signer trait provided by the selected Nostr SDK. Callers should not have to
hand private keys to the transport client if their application already has a
signer.

## Verification Responsibilities

Transport crate:

- Nostr event signature verification.
- Event kind validation.
- Content JSON parsing.
- Tag/content consistency checks.
- Holder authorization publication envelope validation.
- Credential digest calculation.
- Authorization-to-credential digest binding.

Protocol crate:

- Credential issuance and finalization.
- Holder authorization signing.
- Holder authorization proof verification.
- Credential verification with trusted issuer authorities and revocation state.

Application/verifier:

- Relay choice.
- Issuer trust policy.
- Credential schema policy.
- Holder and authorized application policy.
- Live subject-key possession.
- Authorization freshness policy.
- Publish cooldown policy. A time delay before a holder may publish a credential
  (or use it to issue and publish authorizations) is recommended, but this
  transport crate does not enforce it. The consuming app owns and implements the
  cooldown.

## TODO

- Add revocation event publication and fetching after the holder publication MVP.
- Re-check kind availability before implementation and before release.

## References

- [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) for Nostr
  event signatures, addressable kind ranges, tags, filters, and relay
  request/response behavior.
- [NIP-78](https://github.com/nostr-protocol/nips/blob/master/78.md) as a
  fallback option if custom addressable kind assignment changes before release.
- [Nostr kind registry](https://github.com/nostr-protocol/registry-of-kinds) as
  another source to re-check before implementation and release.
