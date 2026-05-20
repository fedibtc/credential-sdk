import { describe, expect, it } from "vitest";

import {
  IssuerContext,
  PbrsaPublicKey,
  PendingIssuance,
} from "../pkg/fedi_credential_sdk_wasm.js";
import type {
  Credential,
  IssuanceResponse,
  PendingIssuanceResult,
} from "../pkg/fedi_credential_sdk_wasm.js";

const issuerId = "11".repeat(32);
const otherIssuerId = "22".repeat(32);

const credentialInfo = {
  schema: "fedi-trust-score-v1.0",
  trust_level: 7,
};

const blindMessage = "anonymous-holder-public-key";

function createPendingIssuance(
  issuer = IssuerContext.generate(1024),
): {
  issuer: IssuerContext;
  request: PendingIssuanceResult["request"];
  pending: PendingIssuanceResult["pending"];
} {
  const result = PendingIssuance.createRequest(
    issuer.publicKey,
    issuer.issuerId,
    credentialInfo,
    blindMessage,
  ) as PendingIssuanceResult;

  return {
    issuer,
    request: result.request,
    pending: result.pending,
  };
}

describe("credential issuance protocol", () => {
  it("round trips holder request, issuer response, holder finalization, and verification", () => {
    const { issuer, request, pending } = createPendingIssuance();
    const issuerId = issuer.issuerId;

    expect(issuer.issuerId).toBe(issuerId);
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
      issuer.publicKey,
      response,
    ) as Credential;
    expect(credential).toMatchObject({
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
    const issuer = IssuerContext.generate(1024);
    const importedIssuer = IssuerContext.fromSecretKeyDer(
      issuer.nostrSecretKey(),
      issuer.secretKeyDer(),
    );
    const importedPublicKey = PbrsaPublicKey.fromDer(issuer.publicKey.toDer());

    expect(importedIssuer.issuerId).toBe(issuer.issuerId);
    expect(Array.from(importedIssuer.publicKey.toDer())).toEqual(
      Array.from(issuer.publicKey.toDer()),
    );
    expect(Array.from(importedPublicKey.toDer())).toEqual(
      Array.from(issuer.publicKey.toDer()),
    );

    const { request, pending } = createPendingIssuance(importedIssuer);
    const response = importedIssuer.issueCredential(
      credentialInfo,
      request,
    ) as IssuanceResponse;
    expect(pending.finalize(importedPublicKey, response) as Credential).toMatchObject({
      credential: {
        issuer_id_pubkey: issuer.issuerId,
        info: credentialInfo,
        blind_msg: blindMessage,
      },
    });
  });

  it("rejects malformed issuer and public key inputs", () => {
    expect(() =>
      IssuerContext.fromSecretKeyDer("not-a-hex-key", new Uint8Array([1, 2, 3])),
    ).toThrow();
    expect(() => PbrsaPublicKey.fromDer(new Uint8Array([1, 2, 3]))).toThrow();
  });

  it("rejects finalization with mismatched issuer responses", () => {
    const { issuer, request, pending } = createPendingIssuance();
    const response = issuer.issueCredential(
      credentialInfo,
      request,
    ) as IssuanceResponse;

    expect(() =>
      pending.finalize(issuer.publicKey, {
        ...response,
        issuer_id: otherIssuerId,
      }),
    ).toThrow();
    expect(() =>
      pending.finalize(issuer.publicKey, {
        ...response,
        info: {
          ...credentialInfo,
          trust_level: 8,
        },
      }),
    ).toThrow();
    expect(() =>
      pending.finalize(
        IssuerContext.generate(1024).publicKey,
        response,
      ),
    ).toThrow();
  });

  it("rejects tampered finalized credentials during finalization checks", () => {
    const { issuer, request, pending } = createPendingIssuance();
    const response = issuer.issueCredential(
      credentialInfo,
      request,
    ) as IssuanceResponse;
    expect(() =>
      pending.finalize(issuer.publicKey, {
        ...response,
        blind_signature: response.blind_signature.slice(1),
      }),
    ).toThrow();
  });
});
