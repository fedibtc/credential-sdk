---
title: Verify A Credential
---

# Verify A Credential

Verification is stateful. A verifier must trust an issuer authority before it can
accept credentials from that issuer.

```ts
import { VerificationContext } from "@fedibtc/fedi-credential-sdk-wasm";

const verifier = new VerificationContext();
verifier.addIssuerAuthority(issuerAuthority);

const accepted = verifier.verifyCredential(credential);
console.log(accepted); // true
```

## Trust Issuer Authorities First

`addIssuerAuthority()` verifies the issuer authority signature and stores the issuer's
identity and issuance public key in the verification context.

```ts
const verifier = new VerificationContext();

try {
  verifier.addIssuerAuthority(issuerAuthority);
} catch (error) {
  // The authority is malformed or its proof does not verify.
}
```

If the credential's issuer is unknown, `verifyCredential()` throws.

```ts
const verifier = new VerificationContext();

verifier.verifyCredential(credential); // throws: unknown issuer
```

## Verify Presented Credentials

```ts
verifier.addIssuerAuthority(issuerAuthority);
verifier.verifyCredential(credential); // true
```

Verification checks that:

- The credential references a trusted issuer.
- The credential proof verifies against that issuer's issuance public key.
- The credential does not match any ingested revocation.

## Verifier Policy

The SDK only answers whether the credential is cryptographically valid for the
trusted issuer authorities and revocations you loaded. Your application still
decides which issuers to trust, how fresh revocation data must be, and what
credential `info` values satisfy the verifier's policy.
