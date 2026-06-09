# Holder Authorization Design

## Status

Draft design for adding holder-authorized credential use to the credential SDK.
The implementation plan lives in `authorization-plan.md`.

This document is the intended source of truth for the SDK-facing design. It is
adapted from the holder authorization design in
`fedibtc/decentralized-federations` PR 11, but coerces the proposed shapes to the
credential SDK's existing protocol types and boundaries.

## Motivation

Users may receive credentials in one application or wallet and use them in a
different external application. The wallet should be able to grant that external
application permission to use a selected credential without sharing the wallet's
long-lived holder secret key.

The core pattern is auxiliary identity authorization:

```text
<holder key> authorizes <external app key> to present <selected credential>
```

The external application controls its own key. The holder wallet signs an
authorization that links that external key to specific credential use. In the
MVP, the SDK verifies that signed authorization, its issued-at time, and its
binding to the credential. Any live proof that the external application
currently controls the subject key remains part of the consuming application's
authentication or transport protocol.

## Existing SDK Boundary

The SDK currently owns the protocol-sensitive pieces of issuance and
verification:

- Holder blinding and pending issuance state.
- Issuer partial blind signing.
- Holder finalization into `SignedCredential`.
- Credential, issuer authority, and revocation verification.
- Canonical JSON and domain-separated digest construction.
- WASM and TypeScript bindings for protocol wire objects.

The SDK deliberately does not own application concerns:

- Browser storage or secure storage.
- QR codes, deep links, HTTP, Nostr relay I/O, or any transport.
- UI state and consent prompts.
- Which issuers, schemas, or holders a verifier trusts.
- Revocation publication and refresh jobs.

Holder authorization should keep that same boundary. The SDK should define and
verify signed protocol objects. Applications should decide how those objects are
requested, stored, transported, displayed, and accepted.

## Existing Types To Preserve

The current library is the source of truth for existing protocol shapes:

```ts
interface SignedCredential {
  readonly version: 1;
  readonly credential: Credential;
  readonly proof: CredentialProof;
}

interface Credential {
  readonly issuer_id_pubkey: string;
  readonly info: JsonValue;
  readonly blind_msg: JsonValue;
}

interface IssuerAuthority {
  readonly version: 1;
  readonly issuer: Issuer;
  readonly proof: SchnorrSignatureProof;
}

interface SchnorrSignatureProof {
  readonly signature: string;
}
```

Important consequences:

- `Credential.blind_msg` is arbitrary JSON. The SDK does not currently define a
  protocol-level holder field inside a credential.
- The current Fedi/Nostr use case often places a holder public key in
  `blind_msg`, but that is application schema data.
- `Credential::digest()` hashes the canonical `Credential` payload and excludes
  `CredentialProof`.
- Verifiers currently trust issuer authorities, ingest revocations, and verify
  credentials through `VerificationContext`.

Holder authorization must be designed around these facts rather than inventing
new fields on existing credential types.

## Actors

- **Holder wallet**: controls the holder key and stores credentials.
- **External application**: controls a separate subject key and wants permission
  to present selected holder credentials.
- **Verifier**: receives a credential presentation and applies local policy.
- **Issuer**: signs credentials. Issuers are not involved in holder
  authorization.

## Goals

- Avoid sharing the holder wallet's secret key with external applications.
- Bind a holder authorization to concrete credential digests.
- Bind a holder authorization to a concrete external subject key.
- Include authorization time bounds in v1.
- Keep holder authorization close to existing signed SDK object shapes:
  `{ version, authorization, proof }`.
- Reuse `ProtocolV1`, Nostr public key encoding, and `SchnorrSignatureProof`.
- Keep transport and discovery out of the SDK.
- Avoid rebuilding verifier-specific access management or KMS-style scoping in
  the SDK. Credential schemas should be narrow enough for applications to apply
  purpose-specific policy outside the authorization object.

## Non-Goals

- Holder authorizations are not issuer-issued credentials.
- Holder authorizations do not replace `SignedCredential`.
- Holder authorizations do not decide verifier policy.
- Holder authorizations do not add selective disclosure.
- Holder authorizations do not make Nostr publication mandatory.
- Holder authorizations do not require the SDK to manage external application
  key storage.
- Holder authorizations do not define a separate SDK presentation signature in
  the MVP.
- Holder authorization revocation is not in the MVP. An authorization remains
  valid while the credential itself remains valid.

## Holder Authorization Creation And Wire Shape

The SDK-native holder authorization should be a direct Schnorr-signed holder
statement. Applications should not calculate credential digests or build
the credential digest when creating an authorization; the request identifies
the subject key, and the holder passes the selected `SignedCredential` value to
the holder context when signing.

```ts
interface HolderAuthorizationRequest {
  readonly subject_pubkey: string;
}

interface HolderAuthorization {
  readonly version: 1;
  readonly authorization: HolderAuthorizationStatement;
  readonly proof: SchnorrSignatureProof;
}

interface HolderAuthorizationStatement {
  readonly holder_id_pubkey: string;
  readonly subject_pubkey: string;
  readonly credential_digest: CredentialDigest;
  readonly issued_at: Timestamp;
}

type CredentialDigest = string;
type Timestamp = number;
```

Field notes:

- `HolderAuthorizationRequest` names the external subject key asking to act
  under the holder identity. The holder selects exactly one signed credential
  separately when signing. The SDK derives the signed `credential_digest` from
  that credential.
- The SDK sets `issued_at` when signing.
- `holder_id_pubkey` is derived by `HolderContext` from the holder identity key.
  It uses the same Nostr public key string encoding returned by
  `HolderContext.publicKey`.
- `subject_pubkey` is the external application's public key. It should use the
  same Nostr public key representation unless a future version explicitly adds
  multi-key support.
- `credential_digest` is not a free-form badge name. It is the
  base64url-unpadded SHA-256 digest produced from `Credential::digest()`, which
  is the same canonical credential id already used by
  `Revocation.credential_digest`. This digest commits to the credential's
  `issuer_id_pubkey`, so the authorization does not repeat the issuer id. This
  id is generated by the SDK during authorization creation.
- `issued_at` is a Unix timestamp in seconds. Rust exposes this as
  `Timestamp`; TypeScript exposes `Timestamp` as a number alias.

The earlier free-form `trust_badge` concept should not be a v1 SDK protocol
field. A verifier can derive badge or schema meaning from the verified
credential's `info` field according to application policy. The SDK-level
`CredentialDigest` is exposed in the returned wire authorization for verifiers,
not as standalone WASM digest plumbing for wallet applications.

## Credential Binding

A holder authorization is only meaningful when checked against a real
`SignedCredential`.

Verification must prove:

- The credential verifies against trusted issuer authorities and known
  revocations.
- The credential digest matches `authorization.credential_digest`.
- The holder key in the authorization is bound to the credential holder.

Application policy must separately prove:

- The current external application controls `authorization.subject_pubkey`.
- The credential schema and `credential.info` are appropriate for the verifier's
  expected purpose.

The remaining holder-binding assumption is credential schema shape. Because
`Credential.blind_msg` is arbitrary JSON, V1 uses this boundary:

- Applications choose and document their credential schema.
- The SDK extracts the holder public key from the common `blind_msg` string
  shape used by the issuance guide.
- The SDK verifies that the extracted key equals
  `authorization.holder_id_pubkey`.

This keeps schema parsing and policy outside the SDK while still letting the SDK
verify the cryptographic binding once the holder key is supplied.

## Subject Possession

The holder authorization says that `subject_pubkey` is allowed to present the
referenced credential. It does not by itself prove that the current caller
controls that subject key.

For MVP, the SDK does not define a separate authorized-presentation object or
challenge signature. Consuming applications should use their existing
authentication, Nostr event signature, request signature, session binding, or
transport-level proof to establish the external application's subject key. The
application can then compare that expected subject key to
`authorization.subject_pubkey`.

## Verifier Algorithm

Given:

- `SignedCredential`
- `HolderAuthorization`
- trusted issuer authorities and credential revocations
- local verifier policy

The verifier should:

1. Verify the `SignedCredential` with `VerificationContext`.
2. Compute `Credential::digest()`.
3. Verify the holder authorization Schnorr proof with
   `authorization.holder_id_pubkey`.
4. Check authorization `issued_at`.
5. Check the computed credential digest matches the signed credential digest.
6. Extract the holder public key from `credential.blind_msg` and check it equals
   `authorization.holder_id_pubkey`.
7. Apply local policy to issuer, credential schema and `info`, holder, subject,
   and freshness.

SDK verifier API shape:

```rust
VerificationContext::verify_credential_authorization(
    credential,
    authorization,
)
```

The WASM binding exposes the same check as `verifyCredentialAuthorization`.
It accepts the same two inputs as the Rust API.

## Authorization Lifetime

Holder authorization revocation is intentionally out of scope for the MVP. A
holder authorization is accepted while:

- Its holder signature verifies.
- Its `issued_at` is accepted by verifier policy.
- The referenced credential is still valid and not revoked by its issuer.

A future protocol version can add holder-signed authorization revocations if
credential revocation alone is not enough.

## Canonicalization And Signatures

Holder authorization signatures should follow the SDK's existing pattern:
canonical JSON with a type string, protocol version, and domain-separated
SHA-256 digest before Schnorr signing.

Recommended holder authorization digest:

```text
SHA256(
  "fedi-credential/holder-authorization-signature/v1\0" ||
  JCS({
    "type": "fedibtc.credentials.holder-authorization",
    "version": 1,
    "authorization": <HolderAuthorizationStatement>
  })
)
```

Do not sign raw nested JSON without type and version context.

## Nostr And Other Delivery

Nostr can be useful for discovery, but it is not a protocol requirement.

If an application publishes holder authorizations over Nostr:

- Use an event authored by `holder_id_pubkey`.
- Use a `p` tag for `subject_pubkey` as an index.
- Treat all tags as lookup hints only.
- Put canonical JSON for `HolderAuthorization` in event content.
- Verify the Nostr event signature.
- Verify `event.pubkey == authorization.holder_id_pubkey`.
- Verify the holder authorization proof independently.

For private wallet-to-app authorization, direct setup-channel delivery, encrypted
transport, deep links, or QR-encoded payloads may be more appropriate. Those
transport choices remain application-owned.

## Relationship To FMan

The FMan flow is one instance of the general pattern:

- FMan generates its own service identity key.
- Holder wallet authorizes that FMan subject key to present a selected
  credential.
- FMan advertisements or credential bundles carry a holder authorization.
- FI verification checks FMan subject key possession, holder authorization,
  credential validity, and local policy together.

Any FMan spec that currently assumes the FMan service identity is always the
direct credential holder must be updated.

## Open Questions

- Whether a future protocol version should support multi-credential
  authorizations.
- Whether any SDK guide should recommend a conventional holder key path inside
  `credential.blind_msg`.
