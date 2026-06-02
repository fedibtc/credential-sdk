# Holder Authorization Implementation Plan

## Status

Draft implementation checklist for the design in `authorization-design.md`.

The plan keeps the same boundary used by issuance: protocol-sensitive signed
objects, canonicalization, signing, and verification live in the library;
storage, transport, QR codes, Nostr relay I/O, UI, and verifier policy live in
consuming applications.

## Architecture Placement

- [ ] Keep the existing issuer/holder/verifier role split.
- [x] Add initial holder authorization wire types in dedicated
      `crates/protocol/src/authorization.rs`.
- [x] Re-export `authorization.rs` from `crates/protocol/src/lib.rs`.
- [ ] Move final shared pieces into `types.rs` only if the dedicated module
      proves unnecessary.
- [ ] Add holder authorization canonicalization and domain separators to
      `crates/protocol/src/canonical.rs`.
- [ ] Add holder-side signing methods to `crates/protocol/src/holder.rs` on
      `HolderContext`.
- [ ] Add verifier-side signature checks, authorization checks, and revocation
      ingestion to `crates/protocol/src/verifier.rs`.
- [ ] Keep issuer code in `crates/protocol/src/issuer.rs` unchanged unless
      shared identity-signing helpers need to move out of issuer-specific code.
- [ ] Add serialization helpers only if existing `crates/protocol/src/serde.rs`
      encodings are insufficient.
- [ ] Add WASM and TypeScript bindings in `crates/wasm/src/lib.rs`.
- [ ] Add Rust protocol tests near existing protocol tests and TypeScript flow
      tests under `test/`.
- [ ] Do not add SDK modules for QR codes, Nostr relay queries, HTTP endpoints,
      browser storage, app pairing, or UI consent.

## Library-Owned Components

### 1. Protocol Types

- [x] Add `HolderId` as a transparent wrapper around `nostr::PublicKey`,
      matching the current `IssuerId` pattern.
- [x] Add `SubjectPubkey` as a transparent wrapper around `nostr::PublicKey`.
- [x] Add `TrustBadgeId` as a transparent wrapper around
      `sha2::digest::Output<Sha256>`, serialized with the same
      `Sha256DigestBase64UrlUnpadded` encoding used by
      `Revocation.credential_digest`.
- [x] Add `CredentialRef` containing issuer id and `TrustBadgeId`.
- [x] Add `HolderAuthorizationScope` with v1 value `Present`.
- [ ] Decide whether `authorization_id` stays a `String` or becomes a typed
      `AuthorizationId` wrapper for ordering, equality, and revocation maps.
- [x] Add `HolderAuthorizationStatement`.
- [x] Add `HolderAuthorization`.
- [ ] Add `AuthorizedPresentationStatement`.
- [ ] Add `AuthorizedPresentation`.
- [ ] Add `HolderAuthorizationRevocationStatement`.
- [ ] Add `HolderAuthorizationRevocation`.
- [x] Reuse `ProtocolV1` for `HolderAuthorization.version`.
- [x] Reuse `SchnorrSignatureProof` for `HolderAuthorization.proof`.
- [x] Reuse base64url-unpadded digest encoding for `TrustBadgeId`.
- [ ] Reuse `ProtocolV1`, `SchnorrSignatureProof`, and existing digest encoding
      for the remaining presentation and revocation types.
- [x] Preserve existing `SignedCredential`, `Credential`, `IssuerAuthority`,
      and `SignedRevocation` shapes.

### 2. Canonicalization And Digests

- [ ] Add canonical type strings for holder authorization, authorized
      presentation, and holder authorization revocation.
- [ ] Add
      `fedi-credential/holder-authorization-signature/v1\0`.
- [ ] Add
      `fedi-credential/authorized-presentation-signature/v1\0`.
- [ ] Add
      `fedi-credential/holder-authorization-revocation-signature/v1\0`.
- [ ] Add `canonicalize_holder_authorization`.
- [ ] Add `canonicalize_authorized_presentation`.
- [ ] Add `canonicalize_holder_authorization_revocation`.
- [ ] Add digest methods on `HolderAuthorizationStatement`.
- [ ] Add digest methods on `AuthorizedPresentationStatement`.
- [ ] Add digest methods on `HolderAuthorizationRevocationStatement`.
- [ ] Expose credential digest calculation to WASM/TypeScript so applications
      can build `CredentialRef` without reimplementing SDK canonicalization.

### 3. Identity Signature Helpers

- [ ] Refactor Schnorr verification so it is not tied only to `IssuerId`.
- [ ] Keep public APIs strongly typed instead of accepting raw key strings for
      internal protocol verification.
- [ ] Update issuer authority verification to use the shared helper.
- [ ] Update issuer revocation verification to use the shared helper.
- [ ] Use the shared helper for holder authorization verification.
- [ ] Use the shared helper for authorized presentation verification.
- [ ] Use the shared helper for holder authorization revocation verification.
- [ ] Add tests proving issuer authority and issuer revocation behavior remains
      unchanged after the helper refactor.

### 4. Holder-Side Signing

- [ ] Add `HolderContext::authorize_credential_use`.
- [ ] Add `HolderContext::revoke_holder_authorization`.
- [ ] Reject holder authorization statements whose `holder_id_pubkey` does not
      equal `HolderContext.publicKey`.
- [ ] Reject holder authorization revocation statements whose
      `holder_id_pubkey` does not equal `HolderContext.publicKey`.
- [ ] Keep external subject key custody out of `HolderContext`.
- [ ] Do not add wallet consent, storage, pairing, or transport logic to
      `holder.rs`.

Proposed Rust shape:

```rust
impl HolderContext {
    pub fn authorize_credential_use(
        &self,
        authorization: HolderAuthorizationStatement,
    ) -> Result<HolderAuthorization, CredentialsError>;

    pub fn revoke_holder_authorization(
        &self,
        revocation: HolderAuthorizationRevocationStatement,
    ) -> Result<HolderAuthorizationRevocation, CredentialsError>;
}
```

Proposed WASM shape:

```ts
class HolderContext {
  authorizeCredentialUse(
    authorization: HolderAuthorizationStatement,
  ): HolderAuthorization;

  revokeHolderAuthorization(
    revocation: HolderAuthorizationRevocationStatement,
  ): HolderAuthorizationRevocation;
}
```

### 5. Subject Presentation Support

- [ ] Define `AuthorizedPresentationStatement` and `AuthorizedPresentation` in
      `authorization.rs`.
- [ ] Add digest and verification helpers for `AuthorizedPresentation`.
- [ ] Do not add external application key storage to the SDK.
- [ ] Prefer not to add a `SubjectContext` in v1.
- [ ] Let consuming applications sign presentation digests with their own
      Nostr/key-management stack.
- [ ] Revisit SDK-owned subject signing only if consuming apps cannot reliably
      produce `SchnorrSignatureProof` objects.

### 6. Verifier-Side Checks

- [ ] Add pure verification helper for `HolderAuthorization`.
- [ ] Add pure verification helper for `AuthorizedPresentation`.
- [ ] Add pure verification helper for `HolderAuthorizationRevocation`.
- [ ] Add holder authorization revocation storage to `VerificationContext`,
      mirroring existing credential revocation ingestion.
- [ ] Add `VerificationContext::add_holder_authorization_revocation`.
- [ ] Add `VerificationContext::verify_credential_authorization` for the
      checks the SDK can perform generically.
- [ ] Require the consuming application to pass the holder id extracted from
      `credential.credential.blind_msg`.
- [ ] Verify the credential with existing `VerificationContext` issuer and
      credential revocation state.
- [ ] Compute the credential digest with SDK canonicalization.
- [ ] Match credential digest and issuer id to a `CredentialRef`.
- [ ] Verify the extracted credential holder id equals
      `authorization.holder_id_pubkey`.
- [ ] Verify the subject presentation proof.
- [ ] Check subject, authorization id, credential digest, audience, challenge,
      time bounds, and scope.
- [ ] Reject holder authorizations that match an ingested holder authorization
      revocation.
- [ ] Leave schema interpretation, trust decisions, and display behavior to the
      consuming verifier application.

Proposed Rust shape:

```rust
impl VerificationContext {
    pub fn add_holder_authorization_revocation(
        &mut self,
        revocation: &HolderAuthorizationRevocation,
    ) -> Result<(), CredentialsError>;

    pub fn verify_credential_authorization(
        &self,
        credential: &SignedCredential,
        credential_holder_id: &HolderId,
        authorization: &HolderAuthorization,
        presentation: &AuthorizedPresentation,
        expected_audience: &str,
        expected_challenge: &str,
        now: u64,
    ) -> Result<(), CredentialsError>;
}
```

### 7. Error Handling

- [ ] Add specific Rust error variants only where existing variants are too
      ambiguous.
- [ ] Cover at least wrong holder, wrong subject, expired authorization, future
      issued-at, wrong audience, wrong challenge, missing credential ref, and
      revoked holder authorization.
- [ ] Preserve current thrown-JavaScript-error behavior at the WASM boundary.
- [ ] Avoid broad result-shape changes until the existing machine-readable
      error-code TODO is addressed.

### 8. WASM And TypeScript Surface

- [ ] Add TypeScript interfaces for `HolderAuthorization`.
- [ ] Add TypeScript interfaces for `HolderAuthorizationStatement`.
- [ ] Add TypeScript interfaces for `CredentialRef`.
- [ ] Add TypeScript interface or alias for `TrustBadgeId`.
- [ ] Add TypeScript interfaces for `HolderAuthorizationScope`.
- [ ] Add TypeScript interfaces for `AuthorizedPresentation`.
- [ ] Add TypeScript interfaces for `AuthorizedPresentationStatement`.
- [ ] Add TypeScript interfaces for `HolderAuthorizationRevocation`.
- [ ] Add TypeScript interfaces for
      `HolderAuthorizationRevocationStatement`.
- [ ] Expose holder authorization signing on `HolderContext`.
- [ ] Expose holder authorization revocation signing on `HolderContext`.
- [ ] Expose credential digest calculation.
- [ ] Expose holder authorization verification.
- [ ] Expose authorized presentation verification.
- [ ] Expose holder authorization revocation verification.
- [ ] Expose credential-bound authorization verification on
      `VerificationContext`.

### 9. Tests

- [ ] Add deterministic canonical JSON tests for holder authorization.
- [ ] Add deterministic canonical JSON tests for authorized presentation.
- [ ] Add deterministic canonical JSON tests for holder authorization
      revocation.
- [ ] Add valid holder authorization signing and verification tests.
- [ ] Add rejection tests for wrong holder key.
- [ ] Add rejection tests for wrong subject key.
- [ ] Add rejection tests for wrong audience.
- [ ] Add rejection tests for expired authorization.
- [ ] Add rejection tests for future `issued_at`.
- [ ] Add rejection tests when credential digest does not match any
      `CredentialRef`.
- [ ] Add rejection tests when credential issuer does not match the selected
      `CredentialRef`.
- [ ] Add rejection tests when extracted credential holder key does not match
      `authorization.holder_id_pubkey`.
- [ ] Add subject presentation challenge mismatch tests.
- [ ] Add subject presentation replay-across-audience tests.
- [ ] Add holder authorization revocation acceptance and rejection tests.
- [ ] Add WASM serialization shape tests.
- [ ] Add thrown JavaScript error tests for representative failures.
- [ ] Add complete wallet-to-app-to-verifier TypeScript flow test.

### 10. Documentation

- [ ] Add guide: wallet grants credential use to an external app.
- [ ] Add guide: external app presents an authorized credential.
- [ ] Add guide: verifier checks an authorized credential presentation.
- [ ] Add guide: holder authorization revocation.
- [ ] Add guide: choosing a holder key representation inside
      `credential.blind_msg`.
- [ ] Update architecture docs to include the auxiliary subject authorization
      flow.
- [ ] Update README public API summary after the API lands.

## Application-Owned Components

### Wallet Application

- [ ] Let the user choose which credential an external app may use.
- [ ] Decide `audience`, `scope`, and expiration.
- [ ] Obtain or verify the external app's `subject_pubkey`.
- [ ] Build `CredentialRef` values from SDK credential digests.
- [ ] Show consent UI.
- [ ] Call `HolderContext.authorizeCredentialUse`.
- [ ] Store or deliver `HolderAuthorization`.
- [ ] Decide whether to create and publish holder authorization revocations.

### External Application

- [ ] Generate and store its subject key.
- [ ] Request authorization from the wallet.
- [ ] Store received holder authorizations.
- [ ] Receive verifier challenges.
- [ ] Sign `AuthorizedPresentationStatement` with the subject key.
- [ ] Build the application-specific envelope carrying credential,
      authorization, and presentation proof.
- [ ] Transport that envelope to verifiers.

### Verifier Application

- [ ] Choose trusted issuer authorities.
- [ ] Fetch and refresh issuer credential revocations.
- [ ] Fetch and refresh holder authorization revocations, if used.
- [ ] Generate challenges.
- [ ] Define acceptable audience strings.
- [ ] Parse credential schemas.
- [ ] Extract the holder key from `credential.blind_msg`.
- [ ] Apply policy to credential `info`, issuer, holder, subject, scope,
      audience, and freshness.
- [ ] Decide how errors are presented to users.

### Transport And Discovery

These remain outside the SDK:

- [ ] QR payloads.
- [ ] Deep links.
- [ ] HTTP endpoints.
- [ ] Nostr relay queries and publication.
- [ ] Encrypted setup channels.
- [ ] App-to-wallet pairing flows.
- [ ] Verifier challenge transport.

## Suggested Implementation Order

- [x] Add initial holder authorization protocol type stubs and serde encodings.
- [ ] Finish protocol types and serde encodings for authorized presentation and
      holder authorization revocation.
- [ ] Add canonicalization, domain separators, digest methods, and test
      vectors.
- [ ] Refactor identity signature verification to support non-issuer public
      keys.
- [ ] Add holder authorization signing in `holder.rs`.
- [ ] Add holder authorization verification in `verifier.rs`.
- [ ] Expose credential digest and holder authorization APIs through WASM.
- [ ] Add holder authorization revocation types, signing, ingestion, and
      verification.
- [ ] Add authorized presentation digest and verification.
- [ ] Add the credential-bound `VerificationContext` helper.
- [ ] Add TypeScript tests for the complete wallet-to-app-to-verifier flow.
- [ ] Add user-facing guides.

## Open Implementation Decisions

- [ ] Decide whether `CredentialRef` supports multiple credentials in v1 or
      forces one credential per authorization.
- [ ] Decide whether holder authorization revocations are required in the first
      release or whether short expirations are enough initially.
- [ ] Decide whether to add a conventional holder-key helper for common
      `blind_msg` shapes while keeping arbitrary schema parsing app-owned.
- [ ] Decide whether presentation signing remains app-owned permanently or gets
      a future generic identity-signing context.
