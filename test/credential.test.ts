import { describe, expect, it } from "vitest";

import {
  IssuerContext,
  PbrsaPublicKey,
  PendingIssuance,
} from "../pkg/fedi_credential_sdk_wasm.js";
import type {
  IssuerBundle,
  IssuanceResponse,
  PendingIssuanceResult,
  SignedCredential,
} from "../pkg/fedi_credential_sdk_wasm.js";

const otherIssuerId = "22".repeat(32);
const revocationLocations = [
  {
    location: "wss://relay.example.com",
    protocol: "nostr",
  },
];

const credentialInfo = {
  schema: "fedi-trust-score-v1.0",
  trust_level: 7,
};

const blindMessage = "anonymous-holder-public-key";

function createPendingIssuance(
  issuer = IssuerContext.generate(),
): {
  issuer: IssuerContext;
  issuerBundle: IssuerBundle;
  request: PendingIssuanceResult["request"];
  pending: PendingIssuanceResult["pending"];
} {
  const issuerBundle = issuer.issuerBundle(revocationLocations) as IssuerBundle;
  const result = PendingIssuance.createRequest(
    issuerBundle,
    credentialInfo,
    blindMessage,
  ) as PendingIssuanceResult;

  return {
    issuer,
    issuerBundle,
    request: result.request,
    pending: result.pending,
  };
}

describe("credential issuance protocol", () => {
  it("round trips holder request, issuer response, holder finalization, and verification", () => {
    const { issuer, issuerBundle, request, pending } = createPendingIssuance();
    const issuerId = issuerBundle.issuer.issuer_id_pubkey;

    expect(request.version).toBe(1);
    expect(request.blinded_message.length).toBeGreaterThan(0);
    expect(request.blinded_message).not.toContain(blindMessage);

    const response = issuer.issueCredential(
      credentialInfo,
      request,
    ) as IssuanceResponse;
    expect(response).toMatchObject({
      version: 1,
      issuer_id: issuerId,
      info: credentialInfo,
    });
    expect(response.blind_signature.length).toBeGreaterThan(0);

    const credential = pending.finalize(
      issuerBundle,
      response,
    ) as SignedCredential;
    expect(credential).toMatchObject({
      version: 1,
      credential: {
        issuer_id_pubkey: issuerId,
        info: credentialInfo,
        blind_msg: blindMessage,
      },
    });
    expect(credential.credential.message_randomizer.length).toBeGreaterThan(0);
    expect(credential.proof.signature.length).toBeGreaterThan(0);
  });

  it("imports issuer secret keys and public keys from DER", () => {
    const issuer = IssuerContext.generate();
    const issuerBundle = issuer.issuerBundle(revocationLocations) as IssuerBundle;
    const importedIssuer = IssuerContext.importSecretKey(issuer.exportSecretKey());
    const importedBundle = importedIssuer.issuerBundle(revocationLocations) as IssuerBundle;

    expect(importedBundle.issuer.issuer_id_pubkey).toBe(
      issuerBundle.issuer.issuer_id_pubkey,
    );
    expect(importedBundle.issuer.issuance_key).toBe(
      issuerBundle.issuer.issuance_key,
    );

    const { request, pending } = createPendingIssuance(importedIssuer);
    const response = importedIssuer.issueCredential(
      credentialInfo,
      request,
    ) as IssuanceResponse;
    expect(pending.finalize(importedBundle, response) as SignedCredential).toMatchObject({
      credential: {
        issuer_id_pubkey: issuerBundle.issuer.issuer_id_pubkey,
        info: credentialInfo,
        blind_msg: blindMessage,
      },
    });
  });

  it("rejects malformed issuer and public key inputs", () => {
    expect(() =>
      IssuerContext.importSecretKey({
        issuer_id_secret_key: "not-a-hex-key",
        issuance_secret_key: "AQID",
      }),
    ).toThrow();
    expect(() => PbrsaPublicKey.fromDer(new Uint8Array([1, 2, 3]))).toThrow();
  });

  it("rejects finalization with mismatched issuer responses", () => {
    const { issuer, issuerBundle, request, pending } = createPendingIssuance();
    const response = issuer.issueCredential(
      credentialInfo,
      request,
    ) as IssuanceResponse;

    expect(() =>
      pending.finalize(issuerBundle, {
        ...response,
        issuer_id: otherIssuerId,
      }),
    ).toThrow();
    expect(() =>
      pending.finalize(issuerBundle, {
        ...response,
        info: {
          ...credentialInfo,
          trust_level: 8,
        },
      }),
    ).toThrow();
    expect(() =>
      pending.finalize(
        IssuerContext.generate().issuerBundle(revocationLocations) as IssuerBundle,
        response,
      ),
    ).toThrow();
  });

  it("rejects tampered finalized credentials during finalization checks", () => {
    const { issuer, issuerBundle, request, pending } = createPendingIssuance();
    const response = issuer.issueCredential(
      credentialInfo,
      request,
    ) as IssuanceResponse;
    expect(() =>
      pending.finalize(issuerBundle, {
        ...response,
        blind_signature: response.blind_signature.slice(1),
      }),
    ).toThrow();
  });
});
