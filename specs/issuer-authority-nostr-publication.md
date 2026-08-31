# DRAFT: Issuer Authority Publication over Nostr (v1)

Status: draft, local only. Not merged, not published. Tracks issue #44
(Signer-authority publication); feeds #46 (discovery and chain walk).

## 1. Scope and layering

This spec defines how a signed `IssuerAuthority` is published as a Nostr event
so that a verifier holding only the issuer identity public key can discover,
fetch, and verify the authority.

Layering follows the SDK's existing pattern for holder authorizations and
revocations: **the SDK owns transport-agnostic payloads and trust rules; the
application owns envelopes and transport.**

SDK/protocol crate (normative surface):

- The `IssuerAuthority` payload (already exists, unchanged).
- The **author-binding rule** and a primitive that enforces it:
  `VerificationContext::add_issuer_authority_from_author`.

Application (normative rules defined here, implemented app-side, alongside
the existing authorization-event publication code):

- Building, signing, publishing, and fetching the Nostr event (§3–§4).
- Envelope verification steps of §5, feeding the SDK primitive.

Out of scope entirely: badge publication (#45), chain walk (#46), revocation
semantics for signer authorities (#43).

## 2. Terms

- **Issuer identity key**: the secp256k1 Schnorr keypair inside
  `IssuerContext`. Its x-only public key is `Issuer.issuer_id_pubkey` (hex),
  which is also a valid Nostr pubkey. The secret key is exportable as
  `IssuerSecretKeys.issuer_id_secret_key` (a Nostr secret key), which is how
  the application signs the publication envelope.
- **Authority payload**: the existing `IssuerAuthority` wire object
  (`version`, `issuer`, `proof`), self-signed over JCS canonical bytes with
  domain separator `fedi-credential/issuer-authority-signature/v1\0`.
  This spec does not change the payload.

## 3. Event format

A published issuer authority is a Nostr **addressable event** (NIP-01
kind range 30000–39999) authored by the issuer identity key.

| Field        | Value                                                        |
| ------------ | ------------------------------------------------------------ |
| `kind`       | `38173`                                                      |
| `pubkey`     | issuer identity public key (hex). MUST equal `content.issuer.issuer_id_pubkey`. |
| `created_at` | publication time (unix seconds). Governs supersession.       |
| `tags`       | MUST include `["d", "fedibtc.credentials.issuer-authority.v1"]`. MAY include `["alt", ...]` (NIP-31). Verifiers MUST ignore unknown tags. |
| `content`    | the `IssuerAuthority` object serialized as JSON (the same serde wire encoding used everywhere else in this SDK). |
| `id`, `sig`  | standard NIP-01 event id and Schnorr signature by `pubkey`.  |

The kind number and `d` value are **normative constants of this spec**. They
are deliberately not exported from the SDK: the SDK has no Nostr-envelope
vocabulary (see §7), and the publishing application is the single owner of
event construction, as it already is for authorization events.

Design notes:

- **Addressable, not plain-replaceable.** The fixed `d` tag pins one slot per
  `(pubkey, kind, d)`. A future payload v2 gets a new `d` value and can coexist
  with v1 during migration instead of clobbering the slot for v1-only
  verifiers.
- **Kind 38173** has no known registered NIP usage. The `d` tag namespaces the
  slot regardless, so an accidental kind collision cannot alias our slot.
- **Content is plain serde JSON, not JCS.** The inner `proof` already covers
  the JCS canonical bytes of the issuer metadata; the event `sig` covers the
  literal content string. No second canonicalization layer is needed.

## 4. Location rule (key → event)

Given an issuer identity public key `pk`, the authority event is found with
the NIP-01 filter:

```json
{ "kinds": [38173], "authors": ["<pk hex>"], "#d": ["fedibtc.credentials.issuer-authority.v1"] }
```

- Relays enforce addressable-event semantics: at most one stored event per
  `(pubkey, kind, d)`.
- A verifier SHOULD query more than one relay and reconcile results itself
  (see §6); relay storage semantics are an optimization, not a trust anchor.
- Which relays to query is an application policy. This spec deliberately does
  not define a relay-discovery rule; NIP-65 relay lists of the issuer identity
  key are a reasonable application default.

## 5. Verification algorithm

A verifier processing a fetched event MUST perform, in order:

1. `event.kind == 38173`, else reject.
2. The `d` tag equals `fedibtc.credentials.issuer-authority.v1`, else reject.
3. The event id is correctly computed and `sig` is a valid Schnorr signature
   by `event.pubkey` (NIP-01), else reject.
4. `content` parses as an `IssuerAuthority`, else reject.
5. **Author binding**: `event.pubkey == authority.issuer.issuer_id_pubkey`,
   else reject.
6. The `IssuerAuthority::verify()` identity proof succeeds (including
   revocation-location validation).

Steps 1–4 are envelope checks and belong to the application's Nostr layer
(steps 3–4 are what generic Nostr tooling already does). Steps 5–6 are
protocol trust rules and MUST be delegated to the SDK in one call:

```
verifier.add_issuer_authority_from_author(&authority, event.pubkey)
```

Step 5 is load-bearing: without it, any key can republish another issuer's
(validly self-signed) authority under its own discovery slot and poison
key→authority lookup for the chain walk (#46). Applications MUST NOT call
plain `add_issuer_authority` on events fetched by author — the
`_from_author` variant exists so the binding check cannot be forgotten.

## 6. Supersession and freshness

- Between two valid authority events for the same `(pubkey, kind, d)`, the one
  with the greater `created_at` supersedes; ties break to the lexically lower
  event `id` (NIP-01 replaceable rules).
- Supersession selects among events **the verifier has seen**. An old event
  replayed from a stale relay is valid but superseded; verifiers SHOULD query
  multiple relays before treating a result as current.
- Absence of an event is not a revocation statement. Compromise and
  end-of-life semantics for signer authorities are defined by #43, not by
  event deletion.
- `IssuerAuthority` itself carries no timestamp; `created_at` is the only
  freshness signal and is attested by the event signature.

## 7. SDK API surface

One addition. No `nostr::Event`, `nostr::Filter`, event builders, kinds, or
tags enter the SDK — the crate keeps zero Nostr-envelope vocabulary, exactly
as it has none for authorization or revocation transport today.

### Rust (`fedi-credential-sdk-protocol`)

```rust
impl VerificationContext {
    /// Verify a published issuer authority against the key that published
    /// it (for Nostr, the event `pubkey`), then trust it for subsequent
    /// credential checks. Rejects with
    /// `CredentialsError::AuthorityAuthorMismatch` when the claimed author
    /// is not the embedded issuer identity key.
    pub fn add_issuer_authority_from_author(
        &mut self,
        authority: &IssuerAuthority,
        claimed_author: &IssuerId,
    ) -> Result<(), CredentialsError>;
}
```

New `CredentialsError` variant: `AuthorityAuthorMismatch`.

### WASM / TypeScript (`@fedibtc/fedi-credential-sdk-wasm`)

```ts
interface VerificationContext {
  /**
   * Verify a published issuer authority against the key that published it
   * (for Nostr, the event `pubkey` in hex), then trust it.
   */
  addIssuerAuthorityFromAuthor(
    issuerAuthority: IssuerAuthority,
    claimedAuthorPubkey: string,
  ): void;
}
```

### Application sketch (event side, lives in the credential app)

```ts
// Publish: sign the envelope with the exported issuer identity key,
// exactly like other credential-app event types.
const event = finalizeEvent(
  {
    kind: 38173,
    created_at: now(),
    tags: [["d", "fedibtc.credentials.issuer-authority.v1"]],
    content: JSON.stringify(issuer.issuerAuthority(revocationLocations)),
  },
  issuerIdSecretKey,
);

// Fetch + verify: envelope checks via the app's Nostr tooling (§5 steps
// 1–4), then trust rules via the SDK (§5 steps 5–6).
const authority = JSON.parse(event.content);
verifier.addIssuerAuthorityFromAuthor(authority, event.pubkey);
```

## 8. Security considerations

- **Author binding** (§5 step 5) prevents authority-slot squatting. It is
  enforced inside the SDK so no application copy of the check can drift.
- **Two signatures, two roles.** The event `sig` authenticates *publication*
  (this key placed this payload in its slot at this time); the embedded
  `proof` authenticates the *payload* independent of transport. Verifying only
  one is insufficient: content alone has no freshness; the envelope alone does
  not bind the issuance key.
- **Relays are untrusted.** They can withhold or serve stale events; they
  cannot forge or mutate one. Multi-relay querying mitigates withholding.
- **No deletion semantics.** NIP-09 deletion of an authority event MUST NOT be
  interpreted as revocation of the authority (#43 owns that).
- **Envelope key custody.** Publishing requires the issuer identity secret
  key app-side (exported `issuer_id_secret_key`). This matches the app's
  existing custody model for event signing; no new key-handling surface is
  introduced in the SDK.

## 9. Test requirements

SDK (this repo):

- `add_issuer_authority_from_author` with the genuine author trusts the
  issuer and a subsequently issued credential verifies.
- With a different (valid) author key it fails with
  `AuthorityAuthorMismatch` and the issuer is **not** trusted afterwards.
- WASM mirror of both, plus rejection of a malformed author key string.

Application (credential app repo, with the event implementation):

- Round trip: build → sign → §5 verify → authority accepted.
- Each §5 envelope failure: wrong kind, missing/wrong `d`, tampered content,
  malformed content JSON.
- The author-mismatch attack: an event validly signed by key B whose content
  embeds issuer A's authority is rejected by the SDK primitive.
