import { describe, expect, it } from "vitest";
import type {
  IssuerBundle,
  JsonValue,
  RevocationLocation,
  SignedCredential,
} from "../pkg/fedi_credential_sdk_wasm.js";
import {
  HolderContext,
  IssuerContext,
  PendingIssuance,
  VerificationContext,
} from "../pkg/fedi_credential_sdk_wasm.js";
import { createTestIssuer } from "./fixtures.js";

const credentialInfo = {
  schema: "fedi-trust-score-v1.0",
  trust_level: 7,
} satisfies JsonValue;

const revocationLocations = [
  {
    location: "wss://relay.example.com",
    protocol: "nostr",
  },
] satisfies readonly RevocationLocation[];
const otherIssuerId = "22".repeat(32);

describe("full credential issuance flow", () => {
  it("issues, verifies, revokes, imports issuer keys, and rejects tampering", () => {
    const issuer = createTestIssuer();
    const issuerBundle = issuer.issuerBundle(revocationLocations);
    const issuerId = issuerBundle.issuer.issuer_id_pubkey;

    expect(issuerBundle).toMatchObject({
      version: 1,
      issuer: {
        issuer_id_pubkey: issuerId,
        revocation: revocationLocations,
      },
      proof: {
        signature: expect.any(String),
      },
    });
    expect(issuerBundle.issuer.issuance_key.length).toBeGreaterThan(0);
    const issuerBundleVerifier = new VerificationContext();
    expect(issuerBundleVerifier.addIssuerBundle(issuerBundle)).toBeUndefined();

    const holder = HolderContext.generate();
    const blindMsg = holder.publicKey;
    const result = PendingIssuance.createRequest(
      issuerBundle,
      credentialInfo,
      blindMsg,
    );

    expect(result.request).toMatchObject({
      version: 1,
      blinded_message: expect.any(String),
    });
    expect(result.request.blinded_message.length).toBeGreaterThan(0);
    expect(result.request.blinded_message).not.toBe(blindMsg);
    expect(result.request.blinded_message).not.toContain(blindMsg);

    const response = issuer.issueCredential(credentialInfo, result.request);

    expect(response).toMatchObject({
      version: 1,
      issuer_id: issuerId,
      info: credentialInfo,
      blind_signature: expect.any(String),
    });
    expect(response.blind_signature.length).toBeGreaterThan(0);

    const credential = result.pending.finalize(issuerBundle, response);

    expect(credential).toMatchObject({
      version: 1,
      credential: {
        issuer_id_pubkey: issuerId,
        info: credentialInfo,
        blind_msg: blindMsg,
      },
      proof: {
        signature: expect.any(String),
      },
    });
    expect(credential.proof.signature.length).toBeGreaterThan(0);

    const signedRevocation = issuer.revokeCredential(credential);

    expect(signedRevocation).toMatchObject({
      version: 1,
      revocation: {
        credential_digest: expect.any(String),
      },
      proof: {
        issuer_id_pubkey: issuerId,
        signature: expect.any(String),
      },
    });
    expect(
      signedRevocation.revocation.credential_digest.length,
    ).toBeGreaterThan(0);
    const revocationVerifier = new VerificationContext();
    expect(revocationVerifier.addIssuerBundle(issuerBundle)).toBeUndefined();
    expect(revocationVerifier.addRevocation(signedRevocation)).toBeUndefined();

    const verifier = new VerificationContext();
    expect(() => verifier.verifyCredential(credential)).toThrow(
      /unknown issuer/,
    );
    expect(verifier.addIssuerBundle(issuerBundle)).toBeUndefined();
    expect(verifier.verifyCredential(credential)).toBe(true);
    expect(verifier.addRevocation(signedRevocation)).toBeUndefined();
    expect(() => verifier.verifyCredential(credential)).toThrow(
      /credential has been revoked/,
    );

    const importedIssuer = IssuerContext.importSecretKey(
      issuer.exportSecretKey(),
    );
    const importedBundle = importedIssuer.issuerBundle([]);

    expect(importedBundle.issuer.issuer_id_pubkey).toBe(issuerId);
    expect(importedBundle.issuer.issuance_key).toBe(
      issuerBundle.issuer.issuance_key,
    );

    const tamperedBundle = {
      ...issuerBundle,
      issuer: {
        ...issuerBundle.issuer,
        revocation: [
          {
            location: "wss://evil.example.com",
            protocol: "nostr",
          },
        ],
      },
    } satisfies IssuerBundle;
    const tamperedCredential = {
      ...credential,
      credential: {
        ...credential.credential,
        blind_msg: "mallory-public-key",
      },
    } satisfies SignedCredential;
    const wrongIssuerCredential = {
      ...credential,
      credential: {
        ...credential.credential,
        issuer_id_pubkey: otherIssuerId,
      },
    } satisfies SignedCredential;
    const tamperVerifier = new VerificationContext();

    expect(() =>
      new VerificationContext().addIssuerBundle(tamperedBundle),
    ).toThrow(/verification failed/);
    expect(tamperVerifier.addIssuerBundle(issuerBundle)).toBeUndefined();
    expect(() => tamperVerifier.verifyCredential(tamperedCredential)).toThrow(
      /Verification failed|blind RSA operation failed/,
    );
    expect(() => issuer.revokeCredential(wrongIssuerCredential)).toThrow(
      /issuer_id does not match/,
    );
  }, 60_000);
});
