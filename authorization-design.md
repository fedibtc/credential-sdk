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
application permission to use selected credentials without sharing the wallet's
long-lived holder secret key.

The core pattern is auxiliary identity authorization:

```text
<holder key> authorizes <external app key> to present <selected credential>
```

The external application controls its own key. The holder wallet signs an
authorization that links that external key to specific credential use. In the
MVP, the SDK verifies that signed authorization, its expiry, and its binding to
the credential. Any live proof that the external application currently controls
the subject key remains part of the consuming application's authentication or
transport protocol.

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
- Which issuers, schemas, audiences, or holders a verifier trusts.
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
- Include audience and time bounds in v1.
- Keep holder authorization close to existing signed SDK object shapes:
  `{ version, authorization, proof }`.
- Reuse `ProtocolV1`, Nostr public key encoding, and `SchnorrSignatureProof`.
- Keep transport and discovery out of the SDK.

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
- Holder authorization revocation is not in the MVP. An authorization is valid
  until `expires_at`, assuming the credential itself remains valid.

## Holder Authorization Wire Shape

The SDK-native holder authorization should be a direct Schnorr-signed holder
statement:

```ts
interface HolderAuthorization {
  readonly version: 1;
  readonly authorization: HolderAuthorizationStatement;
  readonly proof: SchnorrSignatureProof;
}

interface HolderAuthorizationStatement {
  readonly holder_id_pubkey: string;
  readonly subject_pubkey: string;
  readonly audience: string;
  readonly credential_refs: readonly CredentialRef[];
  readonly scope: readonly HolderAuthorizationScope[];
  readonly issued_at: number;
  readonly expires_at: number;
  readonly authorization_id: string;
}

interface CredentialRef {
  readonly issuer_id_pubkey: string;
  readonly trust_badge_id: TrustBadgeId;
}

type TrustBadgeId = string;
type HolderAuthorizationScope = "present";
```

Field notes:

- `holder_id_pubkey` uses the same Nostr public key string encoding returned by
  `HolderContext.publicKey`.
- `subject_pubkey` is the external application's public key. It should use the
  same Nostr public key representation unless a future version explicitly adds
  multi-key support.
- `audience` is an opaque string to the SDK. Applications decide its naming
  scheme and policy meaning.
- `credential_refs[].issuer_id_pubkey` uses the same encoding as
  `SignedCredential.credential.issuer_id_pubkey`.
- `credential_refs[].trust_badge_id` is not a free-form badge name. It is the
  base64url-unpadded SHA-256 digest produced from `Credential::digest()`, which
  is the same canonical credential id already used by
  `Revocation.credential_digest`.
- `scope` is a future-proof field. The only defined MVP value is `present`; MVP
  verification signs and preserves this field but does not apply scope-specific
  policy.
- `issued_at` and `expires_at` are Unix timestamps in seconds.
- `authorization_id` is a future-proof application-chosen identifier. The MVP
  signs and preserves this field but does not use it for replacement, replay
  tracking, or revocation.

The earlier free-form `trust_badge` concept should not be a v1 SDK protocol
field. A verifier can derive badge or schema meaning from the verified
credential's `info` field according to application policy. The SDK-level
`TrustBadgeId` should be the credential digest, not a separate badge-name
string.

## Credential Binding

A holder authorization is only meaningful when checked against a real
`SignedCredential`.

Verification must prove:

- The credential verifies against trusted issuer authorities and known
  revocations.
- The credential digest matches one of
  `authorization.credential_refs[].trust_badge_id`.
- The credential issuer matches that credential ref's `issuer_id_pubkey`.
- The holder key in the authorization is bound to the credential holder.
- The expected external application key equals `authorization.subject_pubkey`.

The only unresolved generic piece is holder binding. Because `Credential.blind_msg`
is arbitrary JSON, the SDK cannot always extract the holder key itself. V1 should
use this boundary:

- Applications choose and document their credential schema.
- Applications extract the holder public key from `credential.blind_msg`.
- The SDK accepts the extracted holder public key as an argument when checking a
  holder authorization against a credential.
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
SDK can then compare that expected subject key to
`authorization.subject_pubkey`.

## Verifier Algorithm

Given:

- `SignedCredential`
- holder public key extracted by the application from `credential.blind_msg`
- `HolderAuthorization`
- expected external application subject public key
- trusted issuer authorities and credential revocations
- local verifier policy

The verifier should:

1. Verify the `SignedCredential` with `VerificationContext`.
2. Compute `Credential::digest()`.
3. Verify the holder authorization Schnorr proof with
   `authorization.holder_id_pubkey`.
4. Check authorization `issued_at`, `expires_at`, and `audience`.
5. Check the computed credential digest and issuer id match a credential ref.
6. Check the extracted holder public key equals `authorization.holder_id_pubkey`.
7. Check the expected external application subject key equals
   `authorization.subject_pubkey`.
8. Preserve `scope` and `authorization_id` but do not apply MVP verifier policy
   to them.
9. Apply local policy to issuer, credential `info`, holder, subject, audience,
   and freshness.

## Authorization Lifetime

Holder authorization revocation is intentionally out of scope for the MVP. A
holder authorization is accepted while:

- Its holder signature verifies.
- Its `issued_at` and `expires_at` are accepted by verifier policy.
- The referenced credential is still valid and not revoked by its issuer.

Wallets should issue short-lived authorizations when fast permission rollback is
important. A future protocol version can add holder-signed authorization
revocations if expiration alone is not enough.

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
- Holder wallet authorizes that FMan subject key to present selected
  credentials.
- FMan advertisements or credential bundles carry a holder authorization.
- FI verification checks FMan subject key possession, holder authorization,
  credential validity, and local policy together.

Any FMan spec that currently assumes the FMan service identity is always the
direct credential holder must be updated.

## Open Questions

- Exact `audience` string format.
- Whether one holder authorization can reference multiple credentials.
- Whether any SDK guide should recommend a conventional holder key path inside
  `credential.blind_msg`.
