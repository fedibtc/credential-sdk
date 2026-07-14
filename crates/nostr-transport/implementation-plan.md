# Nostr Credential Transport MVP Implementation Plan

## Status

Draft implementation plan for `fedi-credential-sdk-nostr-transport`.

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
- [x] Tags are lookup hints only; content and protocol signatures are the source
  of truth.
- [x] Live subject-key possession stays outside the transport crate.

## MVP Checkpoints

### 1. Crate And Public Surface

- [ ] Add `crates/nostr-transport` as a pure Rust workspace crate depending on
  `fedi-credential-sdk-protocol` and Nostr/serde support libraries.
- [ ] Define only the MVP event kinds: `37702` holder-published credential and
  `37705` holder-published credential authorization.
- [ ] Define `HolderAuthorizationPublication` as the only new public transport
  envelope, containing `holder_id_pubkey`, `holder_authorization`, and
  `signed_credential`.
- [ ] Keep the public API centered on actual protocol or transport objects:
  `SignedCredential` and `HolderAuthorizationPublication`.

### 2. Event Construction

- [ ] Build holder credential events with kind `37702`, canonical JSON
  `SignedCredential` content, and `d = credential:<credential_digest>`.
- [ ] Build holder authorization events with kind `37705`, canonical JSON
  `HolderAuthorizationPublication` content, `p = <subject_pubkey>`, and an
  application-namespaced `d` address carrying the subject pubkey and credential
  digest (the FMan flow uses `d = fman-authorization:<subject_pubkey>:<credential_digest>`
  per `FMan-nostr.md`). Do not hardcode or require a fixed `d` prefix here.
- [ ] Allow caller-provided extra tags for application metadata without
  replacing the required SDK tags.
- [ ] Require the event author to match the holder pubkey before preparing
  holder-published events.

### 3. Event Parsing And Validation

- [ ] Parse holder credential events into `SignedCredential`.
- [ ] Parse holder authorization events into `HolderAuthorizationPublication`.
- [ ] Verify Nostr event signatures, expected event kind, holder pubkey
  consistency, authorization subject binding, and credential digest binding.
- [ ] Use the protocol verifier when issuer trust and revocation state are
  available; keep issuer trust policy caller-owned.
- [ ] Treat tags as routing hints and validate authoritative values from event
  content.

### 4. Relay Publish And Fetch

- [ ] Publish prepared holder credential and holder authorization events to a
  configured relay set using a caller-provided signer.
- [ ] Return a publish report with per-relay success/failure status.
- [ ] Fetch authorizations by subject pubkey using kind `37705` plus `#p`.
- [ ] Fetch holder-published credentials by digest using kind `37702` plus `#d`.
- [ ] Parse and validate fetched events, discarding invalid ones, then
  deduplicate only the validated events before returning protocol objects to
  callers, keeping the event with the newest `created_at` when the same address
  comes back in more than one version.

### 5. WASM Boundary

- [ ] Keep all transport business logic in the Rust transport crate.
- [ ] Add WASM bindings only after the Rust API is stable enough to bind.
- [ ] Bind prepare/parse helpers first so web apps with their own Nostr clients
  can use the transport envelope logic.
- [ ] Defer relay publish/fetch bindings unless the selected Nostr relay client
  works cleanly in the existing WASM build target.

### 6. Verification And Documentation

- [ ] Re-check `holder-authorizations.md` and `FMan-nostr.md` before coding the
  event constants and envelope shape.
- [ ] Add tests covering successful credential publication, authorization
  publication, subject lookup, and full authorization-plus-credential validation.
- [ ] Add negative tests for wrong holder, wrong subject, wrong kind, invalid
  event signature, and digest mismatch.
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
