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
authorization that links that external key to specific credential use. During
verification, the external application must prove possession of its key, so a
copied holder authorization alone is not sufficient.

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
- Require proof that the external subject key is live in the presentation.
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
- `scope` starts with only `present`. Future scopes should be versioned protocol
  extensions.
- `issued_at` and `expires_at` are Unix timestamps in seconds.
- `authorization_id` is a random or deterministic application-chosen identifier
  used for replacement and revocation.

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
- The subject key in the authorization proves possession for the current
  presentation.

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

## Subject Presentation Proof

The holder authorization says that a subject key may present a credential. It
does not by itself prove that the external application currently controls that
subject key.

A verifier should issue or provide a challenge. The external application should
sign a presentation statement with its subject key:

```ts
interface AuthorizedPresentation {
  readonly version: 1;
  readonly presentation: AuthorizedPresentationStatement;
  readonly proof: SchnorrSignatureProof;
}

interface AuthorizedPresentationStatement {
  readonly subject_pubkey: string;
  readonly authorization_id: string;
  readonly trust_badge_id: TrustBadgeId;
  readonly audience: string;
  readonly challenge: string;
  readonly issued_at: number;
}
```

Applications may carry the credential, holder authorization, and subject
presentation in whatever envelope or transport they need. The signed
presentation statement is the protocol-sensitive part.

## Verifier Algorithm

Given:

- `SignedCredential`
- holder public key extracted by the application from `credential.blind_msg`
- `HolderAuthorization`
- `AuthorizedPresentation`
- trusted issuer authorities and credential revocations
- optional holder authorization revocations
- local verifier policy

The verifier should:

1. Verify the `SignedCredential` with `VerificationContext`.
2. Compute `Credential::digest()`.
3. Verify the holder authorization Schnorr proof with
   `authorization.holder_id_pubkey`.
4. Check authorization `issued_at`, `expires_at`, `audience`, and `scope`.
5. Check the computed credential digest and issuer id match a credential ref.
6. Check the extracted holder public key equals `authorization.holder_id_pubkey`.
7. Verify the subject presentation proof with `presentation.subject_pubkey`.
8. Check `presentation.subject_pubkey == authorization.subject_pubkey`.
9. Check `presentation.authorization_id == authorization.authorization_id`.
10. Check `presentation.trust_badge_id` equals the computed credential digest.
11. Check `presentation.audience`, `challenge`, and `issued_at`.
12. Reject if a valid holder authorization revocation applies.
13. Apply local policy to issuer, credential `info`, holder, subject, audience,
    and freshness.

## Holder Authorization Revocation

Credential revocation is already a signed SDK object whose transport is
application-owned. Holder authorization revocation should follow the same
boundary.

Recommended wire shape:

```ts
interface HolderAuthorizationRevocation {
  readonly version: 1;
  readonly revocation: HolderAuthorizationRevocationStatement;
  readonly proof: SchnorrSignatureProof;
}

interface HolderAuthorizationRevocationStatement {
  readonly holder_id_pubkey: string;
  readonly authorization_id: string;
  readonly revoked_at: number;
}
```

The SDK should define, sign, and verify this object. Applications decide where
revocations are published, how often to refresh them, and whether short
authorization lifetimes are enough for their deployment.

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

Recommended subject presentation digest:

```text
SHA256(
  "fedi-credential/authorized-presentation-signature/v1\0" ||
  JCS({
    "type": "fedibtc.credentials.authorized-presentation",
    "version": 1,
    "presentation": <AuthorizedPresentationStatement>
  })
)
```

Recommended holder authorization revocation digest:

```text
SHA256(
  "fedi-credential/holder-authorization-revocation-signature/v1\0" ||
  JCS({
    "type": "fedibtc.credentials.holder-authorization-revocation",
    "version": 1,
    "revocation": <HolderAuthorizationRevocationStatement>
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
- FMan advertisements or credential bundles carry a holder authorization and
  subject presentation proof.
- FI verification checks FMan subject key possession, holder authorization,
  credential validity, and local policy together.

Any FMan spec that currently assumes the FMan service identity is always the
direct credential holder must be updated.

## Open Questions

- Exact `audience` string format.
- Whether `scope` needs values beyond `present` in v1.
- Whether one holder authorization can reference multiple credentials.
- Whether holder authorization revocation is required in the first SDK release
  or can be deferred in favor of short expirations.
- Whether the SDK should expose subject presentation signing helpers or only
  digest and verification helpers.
- Whether any SDK guide should recommend a conventional holder key path inside
  `credential.blind_msg`.
