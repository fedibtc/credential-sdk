---
title: Architecture
---

# Architecture

The SDK exposes a small runtime API around three verifiable credential roles:
issuer, holder, and verifier.

![Issuer, holder, and verifier credential architecture](https://upload.wikimedia.org/wikipedia/commons/thumb/5/51/VC_triangle_of_Trust.svg/1280px-VC_triangle_of_Trust.svg.png)

## Roles

- **Issuer**: creates signed issuer metadata, signs holder issuance requests, and
  signs revocations for credentials it issued.
- **Holder**: creates an issuance request that hides `blind_msg` from the issuer
  during signing, finalizes the issuer response into a credential, and can
  authorize external application keys to use a selected credential.
- **Verifier**: trusts issuer authorities, ingests signed revocations, and verifies
  finalized credentials and holder authorizations against both.

## Main Objects

- `IssuerAuthority`: signed public issuer metadata. It binds the issuer identity
  public key, issuance public key, and revocation locations.
- `IssuanceRequest`: holder-created blinded request sent to the issuer.
- `IssuanceResponse`: issuer-created blind signature response bound to visible
  credential `info`.
- `SignedCredential`: finalized holder credential containing visible `info`,
  disclosed `blind_msg`, and an unblinded proof signature.
- `HolderAuthorization`: holder-signed authorization that lets an external
  application subject key use a selected credential.
- `SignedRevocation`: issuer-signed credential digest used by verifiers to reject
  revoked credentials.

## SDK Boundary

The core protocol deliberately does not fetch issuer authorities, publish
revocations, scan QR codes, store pending issuance state, choose trusted
issuers, or decide what application-specific credential fields mean. It also
does not transport holder authorizations, manage external application subject
keys, or decide verifier credential-schema policy.

The `fedi-credential-sdk-nostr` crate defines one open publication profile for
`IssuerAuthority` and `SignedRevocation`: event envelopes, wire identifiers, and
complete event admission. It does not perform relay I/O or impose consumer
trust policy. Applications can use other transports without changing the core
credential documents.

Applications should preserve protocol objects exactly as returned unless they
know the wire format rules.
