# Nostr Credential Transport MVP Implementation Plan

## Status

Implementation plan for `fedi-credential-sdk-nostr-transport`. The
holder-published credential slice (kind `37702`: prepare, parse, newest-valid
selection, and WASM bindings) is implemented; the holder authorization event
(kind `37705`) and the relay publish/fetch client are not started. Where the
implementation deviates from this plan, the deviation and its rationale are
recorded in
[`architecture.md`](./architecture.md#changes-from-the-reviewed-draft), and
the checkpoint items below are annotated.

This plan implements the MVP in [`architecture.md`](./architecture.md):
holder-published credentials and holder-published credential authorizations over
Nostr. It deliberately avoids issuer publication, issuer authority publication,
revocation publication, application-specific advertisement documents, and
multi-credential authorizations.

The transport behavior is based on the holder authorization and Nostr
publication protocols defined in
`fedibtc/decentralized-federations/docs/dpc/holder-authorizations.md` and
`docs/dpc/FMan-nostr.md`. During implementation, use those documents as the
compatibility reference and validate the generic SDK transport against their
holder authorization publication flow.

## Reference Alignment

Cross-checked against the holder authorization and Nostr transport references on
June 15, 2026.

- [x] A holder authorizes a separate subject pubkey without sharing the holder
  secret key.
- [x] The protocol crate remains the source of truth for `SignedCredential`,
  `HolderAuthorizationRequest`, `HolderAuthorization`, credential digesting, and
  verification.
- [x] The Nostr event is only a transport wrapper around protocol objects.
- [x] Holder authorization publication is holder-authored kind `37705`.
- [x] The authorized application discovers authorizations by querying `37705`
  events with `#p = <subject_pubkey>`.
- [x] The holder authorization publication carries both `HolderAuthorization`
  and the backing `SignedCredential` inline.
- [x] Content and protocol signatures are the source of truth. (Amended: for
  the fully SDK-owned `37702` event the required `d`/`t`/`p` tags are also
  validated strictly rather than treated as hints — see the architecture doc's
  changes section. Tags-as-hints still applies to the `37705` design.)
- [x] Live subject-key possession stays outside the transport crate.

## MVP Checkpoints

### 1. Crate And Public Surface

- [x] Add `crates/nostr-transport` as a pure Rust workspace crate depending on
  `fedi-credential-sdk-protocol` and Nostr/serde support libraries.
- [ ] Define only the MVP event kinds: `37702` holder-published credential and
  `37705` holder-published credential authorization. (`37702` defined;
  `37705` not yet.)
- [ ] Define `HolderAuthorizationPublication` as the only new public transport
  envelope, containing `holder_id_pubkey`, `holder_authorization`, and
  `signed_credential`. (Not started; the credential slice added
  `ParsedHolderCredentialEvent` as a validated-result type, which wraps rather
  than forks protocol objects.)
- [x] Keep the public API centered on actual protocol or transport objects:
  `SignedCredential` and `HolderAuthorizationPublication`.

### 2. Event Construction

- [x] Build holder credential events with kind `37702`, `SignedCredential`
  content, and `d = credential:<credential_digest>`. (Amended: content is the
  SDK's ordinary serde JSON, not canonical JSON — see the architecture doc's
  changes section.)
- [ ] Build holder authorization events with kind `37705`, SDK serde JSON
  `HolderAuthorizationPublication` content, `p = <subject_pubkey>`, and an
  application-namespaced `d` address carrying the subject pubkey and credential
  digest (the FMan flow uses `d = fman-authorization:<subject_pubkey>:<credential_digest>`
  per `FMan-nostr.md`). Do not hardcode or require a fixed `d` prefix here.
- [ ] Allow caller-provided extra tags for application metadata without
  replacing the required SDK tags. (Not implemented for `37702`: `prepare`
  emits only the required tags. Validation tolerates extra tags under other
  names, so this can be added compatibly later.)
- [x] Require the event author to match the holder pubkey before preparing
  holder-published events. (`prepare` sets the event author to the
  caller-resolved holder pubkey by construction; `parse` enforces the match.)

### 3. Event Parsing And Validation

- [x] Parse holder credential events into `SignedCredential` (returned inside
  `ParsedHolderCredentialEvent` together with the verified digest).
- [ ] Parse holder authorization events into `HolderAuthorizationPublication`.
- [x] Verify Nostr event signatures, expected event kind, holder pubkey
  consistency, and credential digest binding for `37702`. (Amended: the holder
  pubkey is caller-supplied from application schema validation; the crate does
  not read it from `blind_msg`. Authorization subject binding is pending with
  `37705`.)
- [x] Keep issuer trust policy caller-owned. (Amended: the transport crate
  never invokes the protocol verifier; callers run `VerificationContext`
  themselves after parsing.)
- [x] Validate authoritative values from event content. (Amended for `37702`:
  the required `d`/`t`/`p` tags are validated strictly rather than treated as
  routing hints — see the architecture doc's changes section.)
- [ ] Reject the event if a present `d` tag embeds a
  `<subject_pubkey>:<credential_digest>` suffix that disagrees with the verified
  content, so an event cannot be addressed under a subject/digest it does not
  authorize (keep the namespace prefix configurable). (`37705`; the `37702`
  equivalent — `d` digest must match the content digest — is implemented.)

### 4. Relay Publish And Fetch

- [ ] Publish prepared holder credential and holder authorization events to a
  configured relay set using a caller-provided signer.
- [ ] Return a publish report with per-relay success/failure status.
- [ ] Fetch authorizations by subject pubkey using kind `37705` plus `#p`.
- [ ] Fetch holder-published credentials by digest using kind `37702` plus `#d`.
- [ ] Parse and validate fetched events, discarding invalid ones, then
  deduplicate only the validated events before returning protocol objects to
  callers, keeping the event with the newest `created_at` when the same address
  comes back in more than one version. (The relay client is not started, but
  this rule is already implemented and tested for `37702` as
  `select_newest_valid_holder_credential_event`, for callers that fetch with
  their own Nostr client.)

### 5. WASM Boundary

- [x] Keep all transport business logic in the Rust transport crate.
- [x] Add WASM bindings only after the Rust API is stable enough to bind.
- [x] Bind prepare/parse helpers first so web apps with their own Nostr clients
  can use the transport envelope logic. (Bound as free functions
  `prepareStandaloneCredentialEvent`, `parseStandaloneCredentialEvent`,
  `selectNewestStandaloneCredentialEvent`, and `credentialDigest` in the
  existing `@fedibtc/credential-sdk` package.)
- [x] Defer relay publish/fetch bindings unless the selected Nostr relay client
  works cleanly in the existing WASM build target. (Deferred; no relay client
  yet.)

### 6. Verification And Documentation

- [ ] Re-check `holder-authorizations.md` and `FMan-nostr.md` before coding the
  event constants and envelope shape. (Done for `37702`; repeat for `37705`.)
- [ ] Add tests covering successful credential publication, authorization
  publication, subject lookup, and full authorization-plus-credential
  validation. (Credential publication is covered, including a golden-vector
  digest cross-check between Rust and the WASM package; the authorization
  items are pending with `37705`.)
- [ ] Add negative tests for wrong holder, wrong subject, wrong kind, invalid
  event signature, and digest mismatch. (All covered for `37702` except wrong
  subject, which is a `37705` concept.)
- [ ] Confirm the implemented `37705` event shape can parse and validate the
  holder authorization publication described in `FMan-nostr.md` without adding
  application-specific assumptions to this crate.
- [ ] Confirm the implemented authorization verification follows the
  `HolderAuthorization` semantics from `holder-authorizations.md`.
- [ ] Add a README or guide showing the generic flow: authorized application
  presents `HolderAuthorizationRequest`, holder signs and publishes, authorized
  application fetches by `subject_pubkey`, verifier checks with
  `VerificationContext`.
- [ ] Document relay persistence and publish-report semantics.
- [ ] Document the recommended publishing cooldown (~30 days before a credential
  is published or used to sign/publish an authorization) as integrator policy,
  not a rule enforced by this crate.

## Future Work

- [ ] Revocation event publication and fetching.
- [ ] Issuer authority publication.
- [ ] Application-specific advertisement or presentation documents.
- [ ] Multi-credential holder authorizations.
- [ ] Holder authorization revocation.
