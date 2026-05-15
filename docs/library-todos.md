# Shared Protocol Library TODOs

This document tracks the TODOs for the reusable verifiable credential protocol library. The library should own protocol correctness, cryptographic operations, validation, canonicalization, serialization, and machine-readable verification results.

The library should not own browser storage, QR code generation/scanning, camera access, UI state, Nostr relay I/O, HTTP fetching, file downloads, or verifier trust-list policy.

## 1. Protocol Data Model

- [x] Define canonical TypeScript/Rust structs for issuer bundles.
- [ ] Define canonical structs for partially blind credential issuance requests.
- [x] Define canonical structs for finalized holder credentials.
- [x] Define canonical structs for revocation objects.
- [ ] Define canonical structs for verification results.

## 2. Canonicalization and Digests

- [ ] Choose and document canonical JSON encoding, for example JCS.
- [ ] Implement canonical serialization for issuer bundles.
- [ ] Implement canonical serialization for credentials.
- [ ] Implement canonical serialization for revocation objects.
- [ ] Implement `credentialDigest(canonicalCredential)`.
- [x] Add tests proving object key order does not affect digests.
- [x] Add tests covering invalid, missing, and extra fields.

## 3. Key Management Primitives

- [x] Implement pbRSA issuance key generation.
- [x] Implement pbRSA public key derivation.
- [ ] Implement pbRSA key import/parsing.
- [ ] Implement pbRSA key export/encoding.
- [ ] Validate supported key sizes and algorithms.
- [ ] Reject unsupported or weak key parameters.

## 4. Issuer Bundle

- [ ] Implement `createIssuerBundle`.
- [ ] Include issuer identity public key.
- [x] Include pbRSA issuance public key.
- [x] Include revocation locations.
- [ ] Sign issuer bundle with issuer identity secret key.
- [ ] Implement `verifyIssuerBundle`.
- [ ] Verify issuer identity signature.
- [ ] Validate revocation location structure.
- [ ] Validate issuance key format.
- [ ] Return structured issuer bundle verification errors.

## 5. Holder Blinding Flow

- [x] Implement holder blind-message construction.
- [x] Implement `blind`.
- [x] Bind the blinded message to the selected issuer pbRSA public key.
- [x] Return blinded data in a portable serialized format.
- [x] Return local unblinding state that the holder must retain until issuance completes.
- [x] Validate blinded data received by issuer.
- [x] Add negative tests for mismatched issuer keys and corrupted blinded data.

## 6. Credential Issuance

- [x] Implement credential template construction.
- [x] Accept holder blinded message.
- [x] Implement pbRSA partially blind signing.
- [x] Return signed credential response for holder finalization.
- [x] Ensure issuer cannot accidentally sign malformed credential payloads.
- [ ] Add tests using stable vectors where possible.

## 7. Credential Finalization

- [x] Implement holder-side signature unblinding.
- [x] Implement finalized credential construction.
- [x] Include visible credential info.
- [x] Include holder public key or committed blind message output, according to final protocol shape.
- [x] Include unblinded issuer signature.
- [x] Validate finalized credential structure before returning it.
- [x] Add tests for successful end-to-end issuance.
- [x] Add tests for failed finalization with wrong unblinding state.

## 8. Credential Verification

- [ ] Implement `verifyCredential`.
- [ ] Verify credential structure.
- [ ] Verify issuer bundle structure.
- [x] Verify credential signature using issuer issuance public key.
- [ ] Check credential issuer matches issuer bundle identity.
- [ ] Accept caller-provided trusted issuer bundles.
- [ ] Return machine-readable verification status.

## 9. Revocation

- [ ] Implement `createRevocation`.
- [ ] Compute credential digest from canonical finalized credential.
- [ ] Sign revocation object with issuer identity secret key.
- [ ] Implement `verifyRevocation`.
- [ ] Verify revocation object structure.
- [ ] Verify revocation signature against issuer identity public key.
- [ ] Implement `isCredentialRevoked`.
- [ ] Compare credential digest against verified revocation objects.
- [ ] Support multiple revocation objects from multiple locations.
- [ ] Return structured revocation verification errors.

## 11. Serialization Formats

- [x] Define stable wire format for issuer bundles.
- [x] Define stable wire format for blinded holder messages.
- [x] Define stable wire format for signed credential responses.
- [x] Define stable wire format for finalized credentials.
- [x] Define stable wire format for revocation objects.
- [ ] Implement encode/decode helpers for all protocol messages.

## 14. Public API Surface

- [x] Expose `generateIssuerKeys`.

- [ ] Expose `createIssuerBundle`.
- [ ] Expose `verifyIssuerBundle`.
- [x] Expose `blind`. // blinding of data to be included in blind_msg to prep for issuer pbrsa signature
- [x] Expose `createCredential`.
- [x] Expose `blindSignCredential`.
- [x] Expose `finalizeCredential`. // unblind (done by holder)

- [ ] Expose `verifyCredential`.
- [ ] Expose `createRevocation`. // create_digest helper
- [ ] Expose `verifyRevocation`.

## 15. Security Review Checklist

- [ ] Confirm chosen pbRSA library implements RFC 9474 and partially blind RSA requirements correctly.
- [ ] Confirm all signatures are over canonical bytes, not ad hoc JSON strings.
- [x] Confirm issuer-visible and issuer-hidden fields are separated correctly.
- [ ] Confirm holder unblinding state cannot be reused unsafely.
- [ ] Confirm all secret key material is zeroized where the runtime supports it.
- [ ] Confirm random number generation uses a cryptographically secure source.
- [ ] Confirm protocol messages are domain-separated by type and version.
- [ ] Confirm verification fails closed for unknown algorithms or versions.
- [ ] Confirm revocation signatures use issuer identity keys, not issuance keys, unless the protocol explicitly changes this.
- [ ] Confirm test coverage includes tampering, replay, mismatched issuers, and malformed encodings.

## 16. House Cleaning

- [ ] remove unused code (src folder, unused types)

## Out of Scope for the Library

- Browser local storage or IndexedDB.
- QR code rendering.
- QR code scanning.
- Camera permissions.
- Nostr relay publishing.
- Nostr relay fetching.
- HTTPS fetching.
- File picker integration.
- Download buttons.
- Clipboard buttons.
- App tabs, forms, previews, history screens, or success/failure UI.
- Verifier policy for deciding which issuers are trusted.
- Background refresh jobs for revocation lists.
- Attaching credentials to Nostr events.
