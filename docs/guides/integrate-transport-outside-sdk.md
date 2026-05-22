---
title: Integrate Transport Outside The SDK
---

# Integrate Transport Outside The SDK

The SDK returns transportable JSON objects. Your application chooses how to move
those objects between issuers, holders, and verifiers.

The SDK does not fetch, publish, encrypt, store, scan, or display protocol
objects.

## Issuance Transport

The holder sends an `IssuanceRequest` to the issuer and keeps
`PendingIssuance` local.

```ts
const { request, pending } = PendingIssuance.createRequest(
  issuerBundle,
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
const credential = pending.finalize(issuerBundle, response);
```

## Revocation Transport

Issuers can publish signed revocations anywhere their issuer bundle advertises.

```ts
const issuerBundle = issuer.issuerBundle([
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
verifier.addIssuerBundle(issuerBundle);

for (const revocationJson of await fetchRevocations(issuerBundle)) {
  verifier.addRevocation(JSON.parse(revocationJson));
}

verifier.verifyCredential(credential);
```

## Preserve JSON Objects

Protocol objects should be preserved exactly as returned unless your application
understands the wire format. Do not rename fields, drop `version`, rewrite
base64url strings, or reorder data through a custom serializer that changes JSON
values.

QR codes, Nostr events, HTTP APIs, files, and browser storage are all valid
application transports as long as the same JSON objects reach the next SDK call.

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

Nostr or another relay can carry the JSON string as event content.

```ts
await publishRelayEvent({
  kind: 30078,
  content: JSON.stringify(signedRevocation),
});
```

Browser storage can keep holder-local state while the request is in flight.

```ts
localStorage.setItem("pending-issuance", pending.exportState());

const pendingState = localStorage.getItem("pending-issuance");

if (!pendingState) {
  throw new Error("missing pending issuance state");
}

const pending = PendingIssuance.importState(pendingState);
```
