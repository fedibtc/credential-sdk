---
title: Architecture
---

# Architecture

The SDK exposes a small runtime API around three verifiable credential roles:
issuer, holder, and verifier.

## Roles

- **Issuer**: creates signed issuer metadata, signs holder issuance requests, and
  signs revocations for credentials it issued.
- **Holder**: creates an issuance request that hides `blind_msg` from the issuer
  during signing, then finalizes the issuer response into a credential.
- **Verifier**: trusts issuer bundles, ingests signed revocations, and verifies
  finalized credentials against both.

## Main Objects

- `IssuerBundle`: signed public issuer metadata. It binds the issuer identity
  public key, issuance public key, and revocation locations.
- `IssuanceRequest`: holder-created blinded request sent to the issuer.
- `IssuanceResponse`: issuer-created blind signature response bound to visible
  credential `info`.
- `SignedCredential`: finalized holder credential containing visible `info`,
  disclosed `blind_msg`, and an unblinded proof signature.
- `SignedRevocation`: issuer-signed credential digest used by verifiers to reject
  revoked credentials.

## SDK Boundary

The SDK deliberately does not fetch issuer bundles, publish revocations, scan QR
codes, store pending issuance state, choose which issuers are trusted, or decide
what application-specific credential fields mean.

Applications should treat every protocol object as transportable JSON, but they
should preserve it exactly as returned unless they know the wire format rules.
