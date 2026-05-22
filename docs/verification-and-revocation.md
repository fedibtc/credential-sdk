---
title: Verification And Revocation
---

# Verification And Revocation

Verification is stateful. A verifier must first trust one or more issuer bundles
before it can accept credentials from those issuers.

```ts
const verifier = new VerificationContext();

verifier.addIssuerBundle(issuerBundle);
verifier.verifyCredential(credential); // true
```

If the issuer is unknown, verification throws an error.

```ts
const verifier = new VerificationContext();

verifier.verifyCredential(credential); // throws: unknown issuer
```

## Revocations

Issuers revoke credentials by signing the digest of a finalized credential.
Transport and publication are application concerns.

```ts
const signedRevocation = issuer.revokeCredential(credential);

verifier.addIssuerBundle(issuerBundle);
verifier.addRevocation(signedRevocation);
verifier.verifyCredential(credential); // throws: credential has been revoked
```

Verifiers should ingest revocations from every location they trust for an issuer
before presenting a credential as accepted.

## Current Error Model

The WASM API currently reports validation and verification failures as thrown
JavaScript errors. Machine-readable result codes are still a planned API
improvement.
