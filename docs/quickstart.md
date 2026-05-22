---
title: Quickstart
---

# Quickstart

This guide shows the smallest useful TypeScript flow: create an issuer bundle,
create a holder issuance request, issue a blind signature, finalize a
credential, verify it, and then revoke it.

```ts
import type { JsonValue, RevocationLocation } from "@fedibtc/fedi-credential-sdk-wasm";
import {
  HolderContext,
  IssuerContext,
  PendingIssuance,
  VerificationContext,
} from "@fedibtc/fedi-credential-sdk-wasm";

const credentialInfo = {
  schema: "fedi-trust-score-v1.0",
  trust_level: 7,
} satisfies JsonValue;

const revocationLocations = [
  {
    protocol: "nostr",
    location: "wss://relay.example.com",
  },
] satisfies readonly RevocationLocation[];

const issuer = IssuerContext.generate();
const issuerBundle = issuer.issuerBundle(revocationLocations);

const holder = HolderContext.generate();
const blindMsg = holder.publicKey;
const { request, pending } = PendingIssuance.createRequest(
  issuerBundle,
  credentialInfo,
  blindMsg,
);

const response = issuer.issueCredential(credentialInfo, request);
const credential = pending.finalize(issuerBundle, response);

const verifier = new VerificationContext();
verifier.addIssuerBundle(issuerBundle);
verifier.verifyCredential(credential); // true

const signedRevocation = issuer.revokeCredential(credential);
verifier.addRevocation(signedRevocation);
verifier.verifyCredential(credential); // throws: credential has been revoked
```

## What The SDK Owns

The SDK owns protocol-sensitive operations: key generation, issuer bundle
signing, holder blinding, issuer signing, holder finalization, credential
verification, revocation signing, revocation verification, and canonical JSON
encoding.

## What Your App Owns

Your app still owns storage, QR codes, relay or HTTP transport, file downloads,
UI state, verifier trust-list policy, and revocation refresh jobs.

## Source Of Truth

The quickstart mirrors the tested flow in `test/full-issuance-flow.test.ts`.
Future examples should stay close to that test or be compiled directly in CI.
