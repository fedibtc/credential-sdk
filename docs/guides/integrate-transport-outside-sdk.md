---
title: Integrate Transport Outside The SDK
---

# Integrate Transport Outside The SDK

The SDK returns transportable JSON objects. Your application chooses how to move
those objects between issuers, holders, and verifiers.

The core protocol and WASM package do not fetch, publish, encrypt, store, scan,
or display protocol objects. Rust applications that publish through Nostr can
use the companion `fedi-credential-sdk-nostr` profile to build and admit events;
relay I/O and application policy still remain outside the SDK.

## Issuance Transport

The holder sends an `IssuanceRequest` to the issuer and keeps
`PendingIssuance` local.

```ts
const { request, pending } = PendingIssuance.createRequest(
  issuerAuthority,
  credentialInfo,
  blindMsg,
);

await appStorage.set("pending-issuance", pending.exportState());
await sendToIssuer(JSON.stringify(request));
```

The issuer sends an `IssuanceResponse` back.

```ts
const request = JSON.parse(await receiveFromHolder());
const response = issuer.issueCredential(credentialInfo, request);

await sendToHolder(JSON.stringify(response));
```

The holder parses the response and finalizes locally.

```ts
const pending = PendingIssuance.importState(
  await appStorage.get("pending-issuance"),
);
const response = JSON.parse(await receiveFromIssuer());
const credential = pending.finalize(issuerAuthority, response);
```

## Holder Authorization Transport

A holder wallet can authorize an external application subject key to use a
selected credential. The authorization is a transportable JSON object like the
other protocol objects.

```ts
const holderAuthorization = holder.authorizeCredentialUse(
  {
    subject_pubkey: subjectPubkey,
  },
  credential,
);

await sendToExternalApp(JSON.stringify(holderAuthorization));
```

The external app presents the credential and holder authorization together.

```ts
const holderAuthorization = JSON.parse(await receiveFromExternalApp());

verifier.addIssuerAuthority(issuerAuthority);
verifier.verifyCredentialAuthorization(credential, holderAuthorization);
```

The SDK does not choose the authorization transport, store the authorization, or
authenticate the external application's subject key.

## Revocation Transport

Issuers can publish signed revocations anywhere their issuer authority advertises.

```ts
const issuerAuthority = issuer.issuerAuthority([
  {
    protocol: "nostr",
    location: "wss://relay.example.com",
  },
]);

const signedRevocation = issuer.revokeCredential(credential);
await publishRevocation(JSON.stringify(signedRevocation));
```

Verifiers fetch, parse, and ingest revocations before accepting credentials.

```ts
const verifier = new VerificationContext();
verifier.addIssuerAuthority(issuerAuthority);

for (const revocationJson of await fetchRevocations(issuerAuthority)) {
  verifier.addRevocation(JSON.parse(revocationJson));
}

verifier.verifyCredential(credential);
```

## Preserve JSON Objects

Protocol objects should be preserved exactly as returned unless your application
understands the wire format. Do not rename fields, drop `version`, rewrite
base64url strings, or reorder data through a custom serializer that changes JSON
values.

QR codes, HTTP APIs, files, browser storage, and application-defined transports
can carry the same JSON objects. Nostr publication of issuer authorities and
credential revocations has an open wire profile in
[`crates/nostr`](../../crates/nostr); use that profile rather than assigning an
application-specific event kind.

## Transport Examples

QR code transport usually means serializing one protocol object and scanning it
on another device.

```ts
const qrPayload = JSON.stringify(request);
await showQrCode(qrPayload);

const scannedRequest = JSON.parse(await scanQrCode());
```

HTTP transport can carry the same JSON object in a request or response body.

```ts
const issueResponse = await fetch("/credentials/issue", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(request),
});

const response = await issueResponse.json();
```

The Nostr profile maps `IssuerAuthority` and `SignedRevocation` documents to
their shared addressable event kinds and tags. It authenticates received events
without selecting relays or deciding which issuers an application trusts.

Browser storage can keep holder-local state while the request is in flight.

```ts
localStorage.setItem("pending-issuance", pending.exportState());

const pendingState = localStorage.getItem("pending-issuance");

if (!pendingState) {
  throw new Error("missing pending issuance state");
}

const pending = PendingIssuance.importState(pendingState);
```
