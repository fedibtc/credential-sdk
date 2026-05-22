---
title: Protocol Flow
---

# Protocol Flow

The issuance protocol separates issuer-visible credential information from the
holder-hidden value that is blinded during signing.

## Issuance

```mermaid
sequenceDiagram
  participant I as Issuer
  participant H as Holder

  I->>I: Generate issuer keys
  I->>H: Share signed IssuerBundle
  H->>H: Choose blind_msg and credential info
  H->>H: Create IssuanceRequest and PendingIssuance
  H->>I: Send IssuanceRequest
  I->>I: Bind visible info and blind-sign request
  I->>H: Send IssuanceResponse
  H->>H: Finalize response into SignedCredential
```

## Verification

```mermaid
sequenceDiagram
  participant V as Verifier
  participant I as Issuer
  participant H as Holder

  I->>V: Share trusted IssuerBundle
  H->>V: Present SignedCredential
  V->>V: Verify issuer is trusted
  V->>V: Verify credential signature
  V->>V: Check ingested revocations
```

## Revocation

```mermaid
sequenceDiagram
  participant I as Issuer
  participant V as Verifier

  I->>I: Compute credential digest
  I->>I: Sign SignedRevocation
  I->>V: Publish or transport revocation
  V->>V: Verify revocation issuer signature
  V->>V: Reject matching credential digest
```

`credential.info` is visible to the issuer during signing. `credential.blind_msg`
is hidden from the issuer during signing and disclosed in the final credential.
