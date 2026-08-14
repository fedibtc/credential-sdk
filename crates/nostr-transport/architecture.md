# Nostr Credential Transport Architecture

## Status

The holder-published credential half of this document (kind `37702`) is now
implemented in `fedi-credential-sdk-nostr-transport` and bound in the existing
WASM package. The holder-published credential authorization half (kind `37705`)
and the relay publish/fetch client remain draft. This document is intentionally
scoped to the MVP needed for holder-published credentials and holder-published
credential authorizations.

The implementation deliberately diverges from the draft that was reviewed in
PR #27 on a few points. Those changes and their rationale are recorded in
[Changes From The Reviewed Draft](#changes-from-the-reviewed-draft).

This crate is not part of the cryptographic protocol core. Transport is
unrelated to the credential protocol itself, so this crate lives here as an
extension/utility crate that provides Nostr transport functionality for apps
that depend on the SDK. The team's decision to house it in this repository is
a packaging convenience, not a statement that transport is part of the
protocol.

This transport is based on the holder authorization and Nostr publication
protocols described in
`fedibtc/decentralized-federations/docs/dpc/holder-authorizations.md` and
`docs/dpc/FMan-nostr.md`. Even though this crate stays generic and does not own
application-specific advertisement documents, implementation work should be
validated against those protocol documents as the compatibility source of truth.

## Changes From The Reviewed Draft

The kind `37702` implementation changes four things relative to the draft
reviewed in PR #27.

### 1. Event content is ordinary SDK JSON, not canonical JSON

The draft required RFC 8785/JCS canonical JSON for event `content`. The
implementation serializes `content` with the protocol crate's ordinary serde
JSON output instead.

Rationale: the Nostr event id already commits to the exact published content
bytes, and consumers must parse and validate `content` rather than compare its
bytes, so byte-level reproducibility across implementations buys nothing at
the transport layer. The one value that must be reproducible across systems is
the credential digest in the `d` tag, and the protocol crate computes that
digest over JCS internally (`credential_digest`), independent of how the event
content is formatted. Requiring JCS for `content` would force every consuming
system to ship a JCS implementation just to produce events; with ordinary JSON
they only need a JSON serializer, and any JSON encoding of the same
`SignedCredential` remains verifiable because validation recomputes the digest
from the parsed content. SDK test fixtures stay stable because serde output is
deterministic for a given SDK version.

### 2. The holder binding is caller-supplied, not read from `blind_msg`

The draft validated `event.pubkey` against
`credential.credential.blind_msg`, relying on the MVP schema convention that
`blind_msg` holds the holder pubkey. The implementation instead takes an
explicit holder pubkey argument (`holder_pubkey` in prepare,
`expected_holder_pubkey` in parse) and never interprets `blind_msg`.

Rationale: `blind_msg` is application data, not a protocol field (see the
protocol crate's `Credential` docs), so reading a holder pubkey out of it
would couple the transport crate to one schema and silently misvalidate
credentials from any other schema. Consuming systems already validate the
credential schema before trusting a credential; that validation is where the
holder key is resolved, and the transport then enforces that `event.pubkey`
and the `p` tag match the resolved key. The check from the draft still
happens — it has moved to the application layer where the schema is known.

### 3. Required tags are validated strictly, not treated as hints

The draft's rule was "treat every tag as a lookup hint only". The implemented
`37702` validation is stricter than the draft's validation list: an event is
rejected unless it has exactly one two-element `d` tag with a
`credential:<digest>` value matching the content digest, a two-element
`["t", "fedi-credential"]` tag, and exactly one two-element `p` tag equal to
the event author and the expected holder. In particular, a `p` tag carrying a
NIP-01 relay-hint third element is rejected.

Rationale: for this event the SDK owns the entire envelope — `prepare` is the
only intended producer — so every accepted event can be required to have
exactly the shape `prepare` emits. Strictness keeps the addressable slot
unambiguous (no duplicate `d` tags), removes any gap between what the SDK
publishes and what it accepts, and is the forward-compatible default while the
kind is provisional: loosening validation later keeps previously published
events valid, whereas tightening later would orphan them. Authoritative values
are still verified from content exactly as the draft required; the tags are
additionally pinned. Producers must publish the prepared `d`, `t`, and `p`
tags unmodified and must not append relay hints or extra elements to them.
Additional tags under other names are tolerated by validation, so application
metadata tags remain possible even though `prepare` does not emit any.

### 4. Prepare/parse API shape

Smaller, non-wire-visible changes from the draft's proposed Rust API:

- `prepare_holder_credential_event` returns a `nostr::UnsignedEvent` (not an
  `EventBuilder`) and takes `created_at` explicitly. An unsigned event is a
  plain serializable value, which suits external application-owned signers and
  the WASM boundary, and an explicit timestamp keeps event ids deterministic
  in tests. The WASM binding defaults `created_at` to the current time.
- `parse_holder_credential_event` returns a `ParsedHolderCredentialEvent`
  bundling the event, the parsed `SignedCredential`, and the verified
  `CredentialDigest`, so callers get the validated digest without recomputing
  it.
- `select_newest_valid_holder_credential_event` implements the
  validate-first, newest-`created_at`-wins fetch rule from this document as a
  reusable helper, since the relay client that would normally house it is
  deferred.
- The WASM bindings expose these as free functions named
  `prepareStandaloneCredentialEvent`, `parseStandaloneCredentialEvent`,
  `selectNewestStandaloneCredentialEvent`, and `credentialDigest` in the
  existing `@fedibtc/credential-sdk` package ("standalone credential" is the
  JS-facing name for the holder credential event).

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

Publishing cooldown (recommendation): integrators are encouraged to enforce a
time delay before a freshly issued credential may be published, or used to sign
and publish any authorization. A cooldown on the order of 30 days is the
recurring recommendation. This is a recommendation left up to integrators, not
a rule enforced by this transport crate: the cooldown is holder/application
policy and is more likely to live in the consuming credential app than here.

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

## Crate Boundary

Crate:

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

Use addressable events so the latest holder-published value cleanly supersedes
older equivalent publications for the same holder and object.

A published credential or authorization is itself immutable, so in the common
case there is only ever one value per address and replacement never triggers.
We keep the events addressable anyway for two reasons: it stays wire-compatible
with the Nostr transport reference, which keeps the holder authorization on an
addressable kind, and it gives a well-defined single-slot outcome if a holder
ever re-publishes (for example after a relay loses an event or after a future
non-MVP refresh flow). Because addressability lets different relays transiently
hold different versions of the same address, the fetch path resolves conflicts
by the newest `created_at` (see Fetching).

Rules:

- Use `d` as the addressable replacement key.
- Use `p` for public key lookup.
- Use `t` for the event family.
- Verify all authoritative values from event content and protocol signatures.
- For the fully SDK-owned `37702` event, additionally require the exact
  prepared tag shape (see
  [Changes From The Reviewed Draft](#changes-from-the-reviewed-draft)). For
  the application-namespaced `37705` event, tags beyond the validated
  bindings remain lookup hints only.

Nostr relays commonly index single-letter tags. Multi-letter tags can be useful
for debugging, but fetch code must not depend on them.

The tag strings in this document are Nostr index values, not new SDK protocol
types:

- `["d", "credential:<credential_digest>"]` is the stable address for a
  holder-published credential event. The SDK owns this string because it also
  fetches standalone credentials by this `d` value.
- The holder-published authorization event's `d` address is an
  application-namespaced string, not an SDK-fixed value. It carries the subject
  pubkey and credential digest so re-publications for the same
  `(application, subject, credential)` replace cleanly. The FMan flow uses
  `["d", "fman-authorization:<subject_pubkey>:<credential_digest>"]` per
  `FMan-nostr.md` (its `fman_id_pubkey` is the subject pubkey in SDK terms).
  Generic SDK fetching does not depend on this prefix; authorizations are
  discovered by `p`, so the SDK does not fix or require a particular `d` prefix
  here.
- `["p", "<subject_pubkey>"]` lets the authorized application find
  authorizations for its own pubkey.
- `["t", "..."]` is only a topic label. Applications may use their own `t` tag
  values; generic SDK fetching should not depend on them.

## Event Content Serialization

Event `content` is the protocol crate's ordinary serde JSON output. Canonical
(RFC 8785/JCS) serialization is not used at the transport layer; JCS is used
only inside the protocol crate's credential digest, which is what the `d` tag
and all cross-system digest comparisons rely on. See
[Changes From The Reviewed Draft](#changes-from-the-reviewed-draft) for the
rationale. The transport crate owns content serialization for transport
envelopes; the protocol objects inside remain the protocol crate's serde
output.

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
  content: "<SDK serde JSON string of fedi_credential_sdk_protocol::SignedCredential>"
}
```

Validation (as implemented in `parse_holder_credential_event`):

- The Nostr event signature and id are valid.
- `event.kind == 37702`.
- The event carries a two-element `["t", "fedi-credential"]` tag.
- The event carries exactly one two-element `p` tag, and both `event.pubkey`
  and the `p` tag value equal the caller-supplied expected holder pubkey. The
  caller resolves that pubkey by validating the credential schema (in the
  current MVP schema it lives in `blind_msg`, but the transport crate never
  interprets `blind_msg` — see
  [Changes From The Reviewed Draft](#changes-from-the-reviewed-draft)).
- The event carries exactly one two-element `d` tag with a
  `credential:<credential_digest>` value.
- `content` parses as `SignedCredential`.
- `Credential::digest(content.credential)` equals the `credential_digest` in
  the `d` tag.
- The credential itself is verified through `VerificationContext` by the
  caller when it has issuer authorities and revocation state; the transport
  crate does not run protocol verification.

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
    // `d` and `t` are application-namespaced. The values below are the FMan
    // flow from FMan-nostr.md; another application supplies its own namespace.
    ["d", "fman-authorization:<subject_pubkey>:<credential_digest>"],
    ["t", "fedi-fman-authorization"],
    ["p", "<subject_pubkey>"]
  ],
  content: "<SDK serde JSON string of the holder authorization envelope>"
}
```

`subject_pubkey` is the authorized application's pubkey. `credential_digest` is
`holder_authorization.authorization.credential_digest`, which is also the digest
of `signed_credential.credential`.

Validation:

- The Nostr event signature is valid.
- `event.kind == 37705`.
- `content` parses as `HolderAuthorizationPublication`.
- Authoritative values (subject pubkey, credential digest) come from the
  verified content, not the `d` tag. The `d` tag is an application-namespaced
  routing and replacement hint, so validation does not require a specific `d`
  prefix; this keeps the SDK able to parse and validate application-specific
  authorization events such as the FMan flow's `fman-authorization:` events in
  `FMan-nostr.md`.
- The `d` tag namespace prefix stays configurable, but a present `d` tag that
  embeds a `<subject_pubkey>:<credential_digest>` suffix must match the verified
  content's subject pubkey and credential digest. Reject the event on mismatch.
  Without this check a validly signed authorization could be stored under an
  addressable slot that disagrees with its body, so app code keying off the `d`
  address (caching or addressable replacement) would bind it under the wrong
  subject/digest even though the content itself verifies.
- `event.pubkey == content.holder_id_pubkey`.
- `event.pubkey == holder_authorization.authorization.holder_id_pubkey`.
- `holder_authorization.verify()` succeeds.
- `holder_authorization.authorization.subject_pubkey` matches the expected
  authorized application pubkey when the caller supplied one.
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
- Parse and verify every candidate event, and discard events that fail
  validation before deduplicating. Deduplication must run only over events that
  already passed validation.
- Deduplicate authorization events by
  `(holder_id_pubkey, subject_pubkey, credential_digest)`, keeping the event
  with the newest `created_at`.
- Deduplicate credential events by `credential_digest`, keeping the event with
  the newest `created_at`.

Relays do not all update at the same instant, so the same address can come back
in more than one version during a fetch. Validate first, then keep the newest
`created_at` among the validated events: this ensures the most recent valid
holder-published value wins instead of an arbitrary stale copy, and prevents a
malformed or unsigned event with a later timestamp from evicting a valid one.

## Publishing

Publishing should:

- Sign events with the holder's Nostr key or caller-provided Nostr signer.
- Publish to all configured relays concurrently.
- Return per-relay accepted/rejected/timeout results.
- Let callers choose success policy: at least one relay, quorum, or all relays.
- Treat duplicate acceptance as success.

The transport crate should expose prepare functions that produce unsigned
events, plus publish functions that sign and send them. This lets
applications with their own Nostr client reuse the SDK transport envelope logic
without adopting the SDK relay client.

Publish options may include additional caller-provided tags for application
metadata. Required SDK tags and validation rules stay generic and are not
replaced by application-specific tags.

## Public API Shape

Implemented (holder credential):

```rust
pub const KIND_HOLDER_CREDENTIAL: Kind = Kind::Custom(37702);
pub const CREDENTIAL_D_TAG_PREFIX: &str = "credential:";
pub const CREDENTIAL_TOPIC: &str = "fedi-credential";

pub fn prepare_holder_credential_event(
    holder_pubkey: PublicKey,
    credential: &SignedCredential,
    created_at: Timestamp,
) -> Result<UnsignedEvent, NostrTransportError>;

pub fn parse_holder_credential_event(
    event: &Event,
    expected_holder_pubkey: &PublicKey,
) -> Result<ParsedHolderCredentialEvent, NostrTransportError>;

pub fn select_newest_valid_holder_credential_event<'a>(
    events: impl IntoIterator<Item = &'a Event>,
    expected_holder_pubkey: &PublicKey,
) -> Option<ParsedHolderCredentialEvent>;
```

See [Changes From The Reviewed Draft](#changes-from-the-reviewed-draft) for
how these signatures differ from the draft below.

Draft (holder authorization, not yet implemented):

```rust
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
pub fn prepare_holder_authorization_event(
    authorization: &HolderAuthorization,
    credential: &SignedCredential,
    options: HolderAuthorizationPublishOptions,
) -> Result<EventBuilder, NostrTransportError>;
```

Parse functions:

```rust
pub fn parse_holder_authorization_event(
    event: &nostr::Event,
    expected_subject: Option<&SubjectPubkey>,
) -> Result<HolderAuthorizationPublication, NostrTransportError>;
```

When the authorization event is implemented, its prepare/parse pair should
follow the implemented credential-event signatures (an `UnsignedEvent` result
and an explicit expected-key argument) rather than the builder/options shape
drafted above.

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

## TODO

- Implement the `37705` holder authorization event (prepare/parse/validation).
- Add the relay publish/fetch client.
- Add revocation event publication and fetching after the holder publication MVP.
- Re-check kind availability before release (`37702` was re-checked when it was
  implemented; `37705` needs a re-check before its implementation).

## References

- [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) for Nostr
  event signatures, addressable kind ranges, tags, filters, and relay
  request/response behavior.
- [NIP-78](https://github.com/nostr-protocol/nips/blob/master/78.md) as a
  fallback option if custom addressable kind assignment changes before release.
- [Nostr kind registry](https://github.com/nostr-protocol/registry-of-kinds) as
  another source to re-check before implementation and release.
