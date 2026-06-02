# Holder Authorization MVP Plan

## Status

Draft MVP checklist for the design in `authorization-design.md`.

The MVP keeps the same boundary used by issuance: protocol-sensitive signed
objects, canonicalization, signing, and verification live in the library;
storage, transport, QR codes, Nostr relay I/O, UI, subject authentication, and
verifier policy live in consuming applications.

Authorization revocation and SDK-owned presentation signatures are intentionally
out of scope for the MVP. A holder authorization is valid until `expires_at`,
assuming its referenced credential remains valid.

## Architecture Placement

- [ ] Keep the existing issuer/holder/verifier role split.
- [x] Add initial holder authorization wire types in
      `crates/protocol/src/authorization.rs`.
- [x] Re-export `authorization.rs` from `crates/protocol/src/lib.rs`.
- [ ] Keep holder authorization types in `authorization.rs` unless later code
      shows they belong in `types.rs`.
- [ ] Add holder authorization canonicalization and domain separator to
      `crates/protocol/src/canonical.rs`.
- [ ] Add holder-side signing to `crates/protocol/src/holder.rs` on
      `HolderContext`.
- [ ] Add verifier-side holder authorization checks to
      `crates/protocol/src/verifier.rs`.
- [ ] Keep issuer code in `crates/protocol/src/issuer.rs` unchanged unless a
      shared identity-signature helper needs to move.
- [ ] Add serialization helpers only if existing `crates/protocol/src/serde.rs`
      encodings are insufficient.
- [ ] Add WASM and TypeScript bindings in `crates/wasm/src/lib.rs`.
- [ ] Add Rust protocol tests near existing protocol tests and TypeScript flow
      tests under `test/`.
- [ ] Do not add SDK modules for QR codes, Nostr relay queries, HTTP endpoints,
      browser storage, app pairing, UI consent, or subject-key custody.

## Library-Owned Components

### 1. Protocol Types

- [x] Add `HolderId` as a transparent wrapper around `nostr::PublicKey`.
- [x] Add `SubjectPubkey` as a transparent wrapper around `nostr::PublicKey`.
- [x] Add `TrustBadgeId` as a transparent wrapper around
      `sha2::digest::Output<Sha256>`, serialized with the same
      `Sha256DigestBase64UrlUnpadded` encoding used by
      `Revocation.credential_digest`.
- [x] Add `CredentialRef` containing issuer id and `TrustBadgeId`.
- [x] Add `HolderAuthorizationScope` with MVP value `Present`.
- [x] Add `HolderAuthorizationStatement`.
- [x] Add `HolderAuthorization`.
- [x] Reuse `ProtocolV1` for `HolderAuthorization.version`.
- [x] Reuse `SchnorrSignatureProof` for `HolderAuthorization.proof`.
- [x] Preserve existing `SignedCredential`, `Credential`, `IssuerAuthority`,
      and `SignedRevocation` shapes.
- [x] Include `authorization_id` as a signed future-proof field.
- [x] Include authorization `scope` as a signed future-proof field.
- [ ] Defer any verifier semantics for `authorization_id`.
- [ ] Defer any scope-specific verifier policy.
- [x] Omit `AuthorizedPresentation` types from the MVP.
- [x] Omit holder authorization revocation types from the MVP.

### 2. Canonicalization And Digests

- [ ] Add a canonical type string for holder authorization.
- [ ] Add `fedi-credential/holder-authorization-signature/v1\0`.
- [ ] Add `canonicalize_holder_authorization`.
- [ ] Add a digest method on `HolderAuthorizationStatement`.
- [ ] Expose credential digest calculation to WASM/TypeScript so applications
      can build `CredentialRef` values without reimplementing SDK
      canonicalization.
- [ ] Do not add authorized-presentation digesting in the MVP.
- [ ] Do not add holder authorization revocation digesting in the MVP.

### 3. Identity Signature Helpers

- [ ] Refactor Schnorr verification so it can verify holder signatures as well
      as issuer signatures.
- [ ] Keep public APIs strongly typed instead of accepting raw key strings for
      internal protocol verification.
- [ ] Update issuer authority verification to use the shared helper, if the
      refactor touches that code.
- [ ] Update issuer revocation verification to use the shared helper, if the
      refactor touches that code.
- [ ] Use the shared helper for holder authorization verification.
- [ ] Add tests proving issuer authority and issuer revocation behavior remains
      unchanged after the helper refactor.

### 4. Holder-Side Signing

- [ ] Add `HolderContext::authorize_credential_use`.
- [ ] Reject holder authorization statements whose `holder_id_pubkey` does not
      equal `HolderContext.publicKey`.
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
}
```

Proposed WASM shape:

```ts
class HolderContext {
  authorizeCredentialUse(
    authorization: HolderAuthorizationStatement,
  ): HolderAuthorization;
}
```

### 5. Verifier-Side Checks

- [ ] Add pure verification helper for `HolderAuthorization`.
- [ ] Add `VerificationContext::verify_credential_authorization` for checks
      the SDK can perform generically.
- [ ] Require the consuming application to pass the holder id extracted from
      `credential.credential.blind_msg`.
- [ ] Require the consuming application to pass the expected subject key from
      its app-owned authentication or transport flow.
- [ ] Verify the credential with existing `VerificationContext` issuer and
      credential revocation state.
- [ ] Compute the credential digest with SDK canonicalization.
- [ ] Match credential digest and issuer id to a `CredentialRef`.
- [ ] Verify the extracted credential holder id equals
      `authorization.holder_id_pubkey`.
- [ ] Verify the expected subject key equals `authorization.subject_pubkey`.
- [ ] Check authorization `issued_at`, `expires_at`, and expected audience.
- [ ] Preserve but do not interpret `authorization_id` in MVP verification.
- [ ] Preserve but do not apply scope-specific policy in MVP verification.
- [ ] Leave schema interpretation, trust decisions, subject proof-of-possession,
      and display behavior to the consuming verifier application.

Proposed Rust shape:

```rust
impl VerificationContext {
    pub fn verify_credential_authorization(
        &self,
        credential: &SignedCredential,
        credential_holder_id: &HolderId,
        expected_subject_pubkey: &SubjectPubkey,
        authorization: &HolderAuthorization,
        expected_audience: &str,
        now: u64,
    ) -> Result<(), CredentialsError>;
}
```

### 6. Error Handling

- [ ] Add specific Rust error variants only where existing variants are too
      ambiguous.
- [ ] Cover at least wrong holder, wrong subject, expired authorization, future
      issued-at, wrong audience, and missing credential ref.
- [ ] Preserve current thrown-JavaScript-error behavior at the WASM boundary.
- [ ] Avoid broad result-shape changes until the existing machine-readable
      error-code TODO is addressed.

### 7. WASM And TypeScript Surface

- [ ] Add TypeScript interfaces for `HolderAuthorization`.
- [ ] Add TypeScript interfaces for `HolderAuthorizationStatement`.
- [ ] Add TypeScript interfaces for `CredentialRef`.
- [ ] Add TypeScript interface or alias for `TrustBadgeId`.
- [ ] Add TypeScript interface or alias for `HolderAuthorizationScope`.
- [ ] Expose holder authorization signing on `HolderContext`.
- [ ] Expose credential digest calculation.
- [ ] Expose holder authorization verification.
- [ ] Expose credential-bound authorization verification on
      `VerificationContext`.

### 8. Tests

- [ ] Add deterministic canonical JSON tests for holder authorization.
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
- [ ] Add WASM serialization shape tests.
- [ ] Add thrown JavaScript error tests for representative failures.
- [ ] Add complete wallet-to-app-to-verifier TypeScript flow test.

### 9. Documentation

- [ ] Add guide: wallet grants credential use to an external app.
- [ ] Add guide: external app presents an authorized credential using its own
      app-level subject authentication.
- [ ] Add guide: verifier checks an authorized credential.
- [ ] Add guide: choosing authorization lifetimes.
- [ ] Add guide: choosing a holder key representation inside
      `credential.blind_msg`.
- [ ] Update architecture docs to include the auxiliary subject authorization
      flow.
- [ ] Update README public API summary after the API lands.

## Application-Owned Components

### Wallet Application

- [ ] Let the user choose which credential an external app may use.
- [ ] Decide `audience` and expiration.
- [ ] Obtain or verify the external app's `subject_pubkey`.
- [ ] Build `CredentialRef` values from SDK credential digests.
- [ ] Show consent UI.
- [ ] Call `HolderContext.authorizeCredentialUse`.
- [ ] Store or deliver `HolderAuthorization`.
- [ ] Reissue a short-lived authorization if the external app still needs
      access after expiry.

### External Application

- [ ] Generate and store its subject key.
- [ ] Request authorization from the wallet.
- [ ] Store received holder authorizations.
- [ ] Authenticate to verifiers as `subject_pubkey` using app-owned protocol
      mechanics when a verifier requires live subject possession.
- [ ] Build the application-specific envelope carrying the credential and holder
      authorization.
- [ ] Transport that envelope to verifiers.

### Verifier Application

- [ ] Choose trusted issuer authorities.
- [ ] Fetch and refresh issuer credential revocations.
- [ ] Define acceptable audience strings.
- [ ] Authenticate or otherwise identify the external application's subject key
      when live subject possession matters.
- [ ] Parse credential schemas.
- [ ] Extract the holder key from `credential.blind_msg`.
- [ ] Apply policy to credential `info`, issuer, holder, subject, audience, and
      freshness.
- [ ] Decide how errors are presented to users.

### Transport And Discovery

These remain outside the SDK:

- [ ] QR payloads.
- [ ] Deep links.
- [ ] HTTP endpoints.
- [ ] Nostr relay queries and publication.
- [ ] Encrypted setup channels.
- [ ] App-to-wallet pairing flows.
- [ ] Verifier challenge transport or request authentication.

## Suggested Implementation Order

- [x] Add initial holder authorization protocol type stubs and serde encodings.
- [ ] Add holder authorization canonicalization, domain separator, digest
      method, and test vector.
- [ ] Refactor identity signature verification to support non-issuer public
      keys.
- [ ] Add holder authorization signing in `holder.rs`.
- [ ] Add holder authorization verification in `verifier.rs`.
- [ ] Expose credential digest and holder authorization APIs through WASM.
- [ ] Add the credential-bound `VerificationContext` helper.
- [ ] Add TypeScript tests for the complete wallet-to-app-to-verifier flow.
- [ ] Add user-facing guides.

## Deferred Past MVP

- [ ] Holder authorization revocation.
- [ ] SDK-owned authorized presentation/challenge signatures.
- [ ] Scope-specific verifier policy beyond carrying the signed field.
- [ ] Typed `AuthorizationId` and semantics beyond carrying the signed string.
- [ ] SDK-managed subject key contexts.

## Open MVP Decisions

- [ ] Decide whether `CredentialRef` supports multiple credentials in v1 or
      forces one credential per authorization.
- [ ] Decide whether to add a conventional holder-key helper for common
      `blind_msg` shapes while keeping arbitrary schema parsing app-owned.
