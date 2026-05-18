import { describe, expect, it } from "vitest";

import {
  IssuerContext,
  PbrsaPublicKey,
  PendingIssuance,
  verifyCredential,
} from "../pkg/blind_rsa_signatures_wasm_next.js";
import type {
  Credential,
  IssuanceResponse,
  PendingIssuanceResult,
} from "../pkg/blind_rsa_signatures_wasm_next.js";

const issuerId = "11".repeat(32);
const otherIssuerId = "22".repeat(32);
const issuerNpub =
  "npub1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygse4sl3h";

const credentialInfo = {
  schema: "trust-score-v1",
  issuer_id_pubkey: issuerId,
  score: 7,
  verified: true,
};

const blindMessage = {
  holder_pubkey: "holder-pubkey",
  nonce: 7,
};

function createPendingIssuance(
  issuer = IssuerContext.generate(issuerId, 1024),
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

function tamperEncoded(value: string): string {
  const first = value[0] === "A" ? "B" : "A";
  return `${first}${value.slice(1)}`;
}

describe("credential issuance protocol", () => {
  it("round trips holder request, issuer response, holder finalization, and verification", () => {
    const { issuer, request, pending } = createPendingIssuance();

    expect(issuer.issuerId).toBe(issuerId);
    expect(request.version).toBe(1);
    expect(request.blinded_message.length).toBeGreaterThan(0);
    expect(request.blinded_message).not.toContain(blindMessage.holder_pubkey);

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
      version: 1,
      issuer_id: issuerId,
      info: credentialInfo,
      blind_msg: blindMessage,
    });
    expect(credential.message_randomizer.length).toBeGreaterThan(0);
    expect(credential.signature.length).toBeGreaterThan(0);
    expect(verifyCredential(issuer.publicKey, credential)).toBe(true);
  });

  it("imports issuer secret keys and public keys from DER", () => {
    const issuer = IssuerContext.generate(issuerId, 1024);
    const importedIssuer = IssuerContext.fromSecretKeyDer(
      `nostr:${issuerNpub}`,
      issuer.secretKeyDer(),
    );
    const importedPublicKey = PbrsaPublicKey.fromDer(issuer.publicKey.toDer());

    expect(importedIssuer.issuerId).toBe(issuerId);
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
    const credential = pending.finalize(
      importedPublicKey,
      response,
    ) as Credential;

    expect(verifyCredential(importedPublicKey, credential)).toBe(true);
  });

  it("rejects malformed issuer and public key inputs", () => {
    expect(() => IssuerContext.generate("not-a-hex-key", 1024)).toThrow();
    expect(() => IssuerContext.generate("00", 1024)).toThrow();
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
          score: 8,
        },
      }),
    ).toThrow();
    expect(() =>
      pending.finalize(
        IssuerContext.generate(otherIssuerId, 1024).publicKey,
        response,
      ),
    ).toThrow();
  });

  it("rejects tampered finalized credentials during verification", () => {
    const { issuer, request, pending } = createPendingIssuance();
    const response = issuer.issueCredential(
      credentialInfo,
      request,
    ) as IssuanceResponse;
    const credential = pending.finalize(
      issuer.publicKey,
      response,
    ) as Credential;

    expect(() =>
      verifyCredential(issuer.publicKey, {
        ...credential,
        info: {
          ...credentialInfo,
          score: 8,
        },
      }),
    ).toThrow();
    expect(() =>
      verifyCredential(issuer.publicKey, {
        ...credential,
        blind_msg: {
          ...blindMessage,
          holder_pubkey: "mallory",
        },
      }),
    ).toThrow();
    expect(() =>
      verifyCredential(issuer.publicKey, {
        ...credential,
        signature: tamperEncoded(credential.signature),
      }),
    ).toThrow();
    expect(() =>
      verifyCredential(
        IssuerContext.generate(otherIssuerId, 1024).publicKey,
        credential,
      ),
    ).toThrow();
  });
});
