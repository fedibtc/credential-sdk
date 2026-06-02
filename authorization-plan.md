# Holder Authorization Plan

## Status

Draft plan for adding holder-authorized credential use to the credential SDK.

This document is adapted from the holder authorization design in
`fedibtc/decentralized-federations` PR 11, with SDK-specific integration notes
and review findings folded in.

## Motivation

Users may receive credentials in one application or wallet and use them in a
different external application. The wallet should be able to grant that external
application permission to use selected credentials without sharing the wallet's
long-lived holder secret key.

The core idea is auxiliary identity authorization:

```text
<holder key> authorizes <external app or service key> to use <selected credential>
```

This keeps the wallet and external application key-custody boundaries separate.
The external application controls its own key and proves possession of that key
when presenting. The holder wallet signs an authorization that links that
external key to specific credential use.

## SDK Boundary

The SDK should own protocol-sensitive pieces:

- Canonical holder authorization wire types.
- Holder authorization signing and verification.
- Domain-separated digest construction.
- WASM and TypeScript bindings for the protocol objects.
- Test vectors for signatures and canonicalization.

Applications still own:

- Wallet UI and consent.
- Transport between wallet, external app, verifier, and Nostr relays.
- Secure storage of holder keys and external app keys.
- Verifier policy.
- Revocation freshness requirements.
- Which credential schemas are accepted.

## Design Goals

- Do not require the external application to use the holder wallet's key.
- Bind an authorization to a concrete credential or credential selector.
- Bind an authorization to a concrete external subject key.
- Support verifier challenge or presentation signatures so copied
  authorizations are not enough by themselves.
- Include scope, audience, and lifetime in v1.
- Keep the authorization shape close to existing signed SDK objects:
  `{ version, authorization, proof }`.
- Reuse the SDK's Nostr public key representation and Schnorr signature proof
  shape.
- Keep Nostr publication optional. Direct or private setup-channel delivery
  should be the default for wallet-to-application permission grants.

## Non-Goals

- Holder authorizations are not issuer credentials.
- Holder authorizations do not replace attester-issued credentials.
- Holder authorizations do not decide verifier policy.
- Holder authorizations do not add selective disclosure to the SDK.
- Holder authorizations do not make public Nostr publication mandatory.

## Proposed Wire Shape

The first SDK-native type should be a holder-signed statement:

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
  readonly scope: readonly AuthorizationScope[];
  readonly issued_at: number;
  readonly expires_at: number;
  readonly authorization_id: string;
}

interface CredentialRef {
  readonly issuer_id_pubkey: string;
  readonly credential_digest: string;
  readonly schema?: string;
}

type AuthorizationScope = "present";
```

Notes:

- `holder_id_pubkey` is the wallet holder key signing the authorization.
- `subject_pubkey` is the external application or service identity key.
- `audience` identifies the verifier, relying party, or application context that
  may accept the authorization.
- `credential_refs` should prefer credential digests over a free-form
  `trust_badge` string. If broader badge semantics are needed later, model them
  as explicit credential selectors and require a matching verified credential.
- `scope` starts narrow. `present` means the subject may present the referenced
  credential. Future scopes should be versioned extensions.
- `issued_at` and `expires_at` prevent indefinite bearer delegation.
- `authorization_id` gives revocation and replacement schemes a stable target.

## Credential Binding

The authorization must be checked against an actual `SignedCredential`.

Verification must prove all of the following:

- The credential verifies against trusted issuer authorities and current
  revocations.
- The credential digest matches one of
  `authorization.credential_refs[].credential_digest`.
- The credential issuer matches the corresponding
  `authorization.credential_refs[].issuer_id_pubkey`.
- The holder public key in the authorization is bound to the credential holder.
- The external subject proves possession of `subject_pubkey` for this
  presentation.

The current SDK treats `credential.blind_msg` as arbitrary JSON. For a generic
SDK API, v1 must choose one of these approaches:

- Standardize a holder-bound credential schema where `blind_msg` contains a
  holder pubkey at a known path.
- Require callers to pass the holder pubkey they extracted from credential
  application data, then have the SDK verify that it equals
  `authorization.holder_id_pubkey`.

Do not accept a holder authorization by only checking that the signed
`trust_badge` or schema name is supported by verifier policy. That would let any
holder key claim any badge without proving control of a matching credential.

## Presentation Shape

Applications need a presentation object that carries the pieces verifiers must
check together:

```ts
interface AuthorizedCredentialPresentation {
  readonly version: 1;
  readonly subject_pubkey: string;
  readonly credential: SignedCredential;
  readonly holder_authorization: HolderAuthorization;
  readonly challenge: string;
  readonly audience: string;
  readonly proof: SchnorrSignatureProof;
}
```

The presentation proof should be signed by `subject_pubkey` over a
domain-separated digest of:

- `subject_pubkey`
- credential digest
- holder authorization digest or `authorization_id`
- challenge
- audience
- presentation version

This proves that the external application key named in the holder authorization
is actively participating in the current presentation. A copied holder
authorization alone should not be sufficient.

## Verification Algorithm

For a verifier:

1. Parse the presentation.
2. Verify the subject presentation proof with `subject_pubkey`.
3. Verify the holder authorization signature with
   `holder_authorization.authorization.holder_id_pubkey`.
4. Check authorization time bounds.
5. Check authorization audience matches the presentation audience.
6. Check presentation `subject_pubkey` equals
   `holder_authorization.authorization.subject_pubkey`.
7. Verify the presented credential with `VerificationContext`.
8. Compute the credential digest and match it to a credential ref.
9. Check holder binding between the credential and
   `holder_authorization.authorization.holder_id_pubkey`.
10. Apply local verifier policy to issuer, schema, scope, audience, holder, and
    credential data.
11. Check authorization revocation or replacement state if the deployment uses
    one.

## Canonicalization And Signatures

Add holder authorization canonicalization to `fedi-credential-sdk-protocol`.

Recommended digest construction:

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

Do not sign raw `authorization` JSON without type and version context.

Add a separate presentation domain separator:

```text
fedi-credential/authorized-presentation-signature/v1\0
```

## SDK API Plan

Rust protocol crate:

- Add `HolderId`, `SubjectPubkey`, `CredentialRef`,
  `HolderAuthorizationStatement`, `HolderAuthorization`, and presentation types.
- Reuse `ProtocolV1` and `SchnorrSignatureProof`.
- Add `canonicalize_holder_authorization`.
- Add holder authorization and authorized presentation domain separators.
- Add holder authorization digest and verification methods.
- Add presentation digest and verification helpers.
- Extract a generic Nostr identity signature verification helper so it is not
  tied to `IssuerId`.
- Add test vectors for canonical JSON, signatures, tampering, expiry, wrong
  audience, wrong subject, wrong credential digest, and wrong holder binding.

Holder API:

- Add `HolderContext.authorizeCredentialUse(...)`.
- The API should sign only after the caller supplies credential refs, audience,
  scope, and expiration.

Verifier API:

- Add `VerificationContext.verifyHolderAuthorization(...)` for the pure holder
  authorization signature and lifetime checks.
- Add `VerificationContext.verifyAuthorizedPresentation(...)` only if the SDK can
  receive enough holder-binding information generically.
- Otherwise expose lower-level helpers and document the app-owned holder-binding
  check clearly.

WASM and TypeScript:

- Add TS interfaces for all new wire objects.
- Expose holder authorization creation and verification methods.
- Preserve JSON-compatible serialization with base64url-unpadded signatures.

## Nostr Delivery

Nostr can be used for discovery, but should not be required for wallet-to-app
authorization.

If published over Nostr:

- Use an event authored by `holder_id_pubkey`.
- Use a `p` tag for `subject_pubkey` as an index.
- Treat all tags as lookup hints only.
- Put canonical JSON for `HolderAuthorization` in event content.
- Verify the Nostr event signature.
- Verify `event.pubkey == authorization.holder_id_pubkey`.
- Verify the holder authorization proof independently.

Public Nostr publication links the holder, external subject, and credential use.
That may be acceptable for public FMan discovery, but it is likely wrong as the
default for private wallet-to-application authorization.

## Relationship To FMan

The FMan flow is one instance of the general pattern:

- FMan generates its own service identity key.
- Holder wallet authorizes that FMan subject key to present a selected
  credential or trust badge.
- FMan advertisements or credential bundles carry the holder authorization or an
  authorized presentation.
- FI verification checks the FMan subject key, holder authorization, credential,
  and local policy together.

Any existing FMan verification spec must be updated so it no longer assumes the
FMan service identity is always the direct credential holder.

## Open Questions

- Exact `audience` format.
- Whether `scope` needs values beyond `present` in v1.
- Whether v1 supports one credential ref or many.
- Authorization revocation mechanism and publication location.
- Whether authorization replacement uses Nostr addressable events,
  `authorization_id`, explicit signed revocations, or short expirations only.
- Whether the SDK should standardize holder binding inside `blind_msg`.
- Whether authorized presentations should be a first-class SDK object or an
  application-level object assembled from lower-level SDK helpers.
- Minimum and maximum expiration windows for wallet-granted authorizations.
