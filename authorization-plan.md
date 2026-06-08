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

- [x] Keep the existing issuer/holder/verifier role split.
- [x] Add initial holder authorization wire types in
      `crates/protocol/src/authorization.rs`.
- [x] Re-export `authorization.rs` from `crates/protocol/src/lib.rs`.
- [x] Keep holder authorization types in `authorization.rs` unless later code
      shows they belong in `types.rs`.
- [x] Add holder authorization canonicalization and domain separator to
      `crates/protocol/src/canonical.rs`.
- [x] Add holder-side signing to `crates/protocol/src/holder.rs` on
      `HolderContext`.
- [x] Add verifier-side holder authorization checks to
      `crates/protocol/src/verifier.rs`.
- [x] Keep issuer code in `crates/protocol/src/issuer.rs` unchanged unless a
      shared identity-signature helper needs to move.
- [x] Add serialization helpers only if existing `crates/protocol/src/serde.rs`
      encodings are insufficient.
- [x] Add WASM and TypeScript bindings in `crates/wasm/src/lib.rs`.
- [x] Add Rust protocol tests near existing protocol tests and TypeScript flow
      tests under `test/`.
- [x] Do not add SDK modules for QR codes, Nostr relay queries, HTTP endpoints,
      browser storage, app pairing, UI consent, or subject-key custody.

## Library-Owned Components

### 1. Protocol Types

- [x] Add `HolderId` as a transparent wrapper around `nostr::PublicKey`.
- [x] Add `SubjectPubkey` as a transparent wrapper around `nostr::PublicKey`.
- [x] Add `TrustBadgeId` as a transparent wrapper around
      `sha2::digest::Output<Sha256>`, serialized with the same
      `Sha256DigestBase64UrlUnpadded` encoding used by
      `Revocation.credential_digest`.
- [x] Add `trust_badge_id` containing a signed `TrustBadgeId` value.
- [x] Add `HolderAuthorizationStatement`.
- [x] Add `HolderAuthorization`.
- [x] Reuse `ProtocolV1` for `HolderAuthorization.version`.
- [x] Reuse `SchnorrSignatureProof` for `HolderAuthorization.proof`.
- [x] Preserve existing `SignedCredential`, `Credential`, `IssuerAuthority`,
      and `SignedRevocation` shapes.
- [x] Include `authorization_id` as a signed future-proof field.
- [x] Omit signed audience/purpose scoping from the MVP holder authorization.
- [x] Defer any verifier semantics for `authorization_id`.
- [x] Omit `AuthorizedPresentation` types from the MVP.
- [x] Omit holder authorization revocation types from the MVP.

### 2. Canonicalization And Digests

- [x] Add a canonical type string for holder authorization.
- [x] Add `fedi-credential/holder-authorization-signature/v1\0`.
- [x] Add `canonicalize_holder_authorization`.
- [x] Add a digest method on `HolderAuthorizationStatement`.
- [x] Keep credential digest calculation inside holder authorization creation
      instead of exposing standalone WASM/TypeScript digest plumbing.
- [x] Do not add authorized-presentation digesting in the MVP.
- [x] Do not add holder authorization revocation digesting in the MVP.

### 3. Identity Signature Helpers

- [x] Refactor Schnorr verification so it can verify holder signatures as well
      as issuer signatures.
- [x] Keep public APIs strongly typed instead of accepting raw key strings for
      internal protocol verification.
- [x] Update issuer authority verification to use the shared helper, if the
      refactor touches that code.
- [x] Update issuer revocation verification to use the shared helper, if the
      refactor touches that code.
- [x] Use the shared helper for holder authorization verification.
- [x] Add tests proving issuer authority and issuer revocation behavior remains
      unchanged after the helper refactor.

### 4. Holder-Side Signing

- [x] Add `HolderContext::authorize_credential_use`.
- [x] Derive signed `holder_id_pubkey` from `HolderContext.publicKey` instead
      of accepting a caller-provided holder id.
- [x] Derive signed `TrustBadgeId` from the supplied `SignedCredential`
      instead of accepting a caller-provided credential digest.
- [x] Derive signed `issued_at` and `authorization_id` in the SDK
      instead of requiring them in the wallet request.
- [x] Keep external subject key custody out of `HolderContext`.
- [x] Do not add wallet consent, storage, pairing, or transport logic to
      `holder.rs`.

Proposed Rust shape:

```rust
impl HolderContext {
    pub fn authorize_credential_use(
        &self,
        request: HolderAuthorizationRequest,
    ) -> Result<HolderAuthorization, CredentialsError>;
}
```

Proposed WASM shape:

```ts
class HolderContext {
  authorizeCredentialUse(
    request: HolderAuthorizationRequest,
  ): HolderAuthorization;
}
```

### 5. Verifier-Side Checks

- [x] Add pure verification helper for `HolderAuthorization`.
- [x] Add `VerificationContext::verify_credential_authorization` for checks
      the SDK can perform generically.
- [x] Extract the holder id from the `credential.credential.blind_msg` string
      shape used by the issuance guide.
- [x] Leave expected subject-key possession checks to app-owned authentication
      or transport flow.
- [x] Verify the credential with existing `VerificationContext` issuer and
      credential revocation state.
- [x] Compute the credential digest with SDK canonicalization.
- [x] Match credential digest to a signed `TrustBadgeId`.
- [x] Verify the extracted credential holder id equals
      `authorization.holder_id_pubkey`.
- [x] Check authorization `issued_at` and `expires_at`.
- [x] Leave credential schema and purpose policy to verifier applications.
- [x] Preserve but do not interpret `authorization_id` in MVP verification.
- [x] Leave schema interpretation, trust decisions, subject proof-of-possession,
      and display behavior to the consuming verifier application.

Proposed Rust shape:

```rust
impl VerificationContext {
    pub fn verify_credential_authorization(
        &self,
        credential: &SignedCredential,
        authorization: &HolderAuthorization,
    ) -> Result<(), CredentialsError>;
}
```

### 6. Error Handling

- [x] Add specific Rust error variants only where existing variants are too
      ambiguous.
- [x] Cover at least wrong holder, expired authorization, future issued-at, and
      missing trust badge id.
- [x] Preserve current thrown-JavaScript-error behavior at the WASM boundary.
- [x] Avoid broad result-shape changes until the existing machine-readable
      error-code TODO is addressed.

### 7. WASM And TypeScript Surface

- [x] Add TypeScript interfaces for `HolderAuthorization`.
- [x] Add TypeScript interfaces for `HolderAuthorizationRequest`.
- [x] Add TypeScript interfaces for `HolderAuthorizationStatement`.
- [x] Add TypeScript interface or alias for `TrustBadgeId`.
- [x] Expose holder authorization signing on `HolderContext`.
- [x] Do not expose standalone credential digest calculation for authorization
      creation; `HolderContext.authorizeCredentialUse` derives the trust badge id.
- [x] Expose holder authorization verification.
- [x] Expose credential-bound authorization verification on
      `VerificationContext`.

### 8. Tests

- [x] Add deterministic canonical JSON tests for holder authorization.
- [x] Add valid holder authorization signing and verification tests.
- [x] Add tests that holder authorization signing derives holder id and
      the trust badge id from the high-level request.
- [x] Add verifier rejection tests for wrong holder key.
- [x] Add rejection tests for expired authorization.
- [x] Add rejection tests for future `issued_at`.
- [x] Add rejection tests when credential digest does not match any
      `TrustBadgeId`.
- [x] Add rejection tests when extracted credential holder key does not match
      `authorization.holder_id_pubkey`.
- [x] Add WASM serialization shape tests.
- [ ] Add thrown JavaScript error tests for representative failures.
- [x] Add complete wallet-to-app-to-verifier TypeScript flow test.

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
- [ ] Decide authorization expiration.
- [ ] Obtain or verify the external app's `subject_pubkey`.
- [ ] Select the `SignedCredential` value to authorize; SDK code derives the
      `TrustBadgeId` value.
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
- [ ] Authenticate or otherwise identify the external application's subject key
      when live subject possession matters.
- [ ] Compare the expected subject key to `authorization.subject_pubkey`.
- [ ] Parse credential schemas.
- [ ] Use the SDK-supported `credential.blind_msg` holder key string shape.
- [ ] Apply policy to credential schema and `info`, issuer, holder, subject, and
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
- [x] Add holder authorization canonicalization, domain separator, digest
      method, and test vector.
- [x] Refactor identity signature verification to support non-issuer public
      keys.
- [x] Add holder authorization signing in `holder.rs`.
- [x] Add holder authorization verification in `verifier.rs`.
- [x] Expose high-level holder authorization creation through WASM without
      standalone credential digest plumbing.
- [x] Add the credential-bound `VerificationContext` helper.
- [x] Add TypeScript tests for the complete wallet-to-app-to-verifier flow.
- [ ] Add user-facing guides.

## Deferred Past MVP

- [ ] Holder authorization revocation.
- [ ] SDK-owned authorized presentation/challenge signatures.
- [ ] Scope-specific verifier policy beyond carrying the signed field.
- [ ] Typed `AuthorizationId` and semantics beyond carrying the signed string.
- [ ] SDK-managed subject key contexts.

## Open MVP Decisions

- [x] Decide that v1 authorizations support one `trust_badge_id` directly.
- [ ] Decide whether to add a conventional holder-key helper for common
      `blind_msg` shapes while keeping arbitrary schema parsing app-owned.
