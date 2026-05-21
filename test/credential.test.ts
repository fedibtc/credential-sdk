import { describe, expect, it } from "vitest";
import type {
  IssuerBundle,
  JsonValue,
  RevocationLocation,
} from "../pkg/fedi_credential_sdk_wasm.js";
import {
  IssuerContext,
  PendingIssuance,
} from "../pkg/fedi_credential_sdk_wasm.js";
import { createTestIssuer } from "./fixtures.js";

const otherIssuerId = "22".repeat(32);
const wrongIssuanceKey =
  "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHqlcEXhOsb7YTTOFty0DtofgEZMxIXHDGgfjef6dL7wNZ6EBqknxMfT3s40XP32uKbuen2AzFSOC_ml41YiiZSkMh-PLyrmo9LxtpCDh2SIzRDPFb9PiCMmC0uDtebIh6wffxYon4OGlQghC0cE_GavsswisZVlQoNM9OkfSTetAgMBAAE";
const revocationLocations = [
  {
    location: "wss://relay.example.com",
    protocol: "nostr",
  },
] satisfies readonly RevocationLocation[];

const credentialInfo = {
  schema: "fedi-trust-score-v1.0",
  trust_level: 7,
} satisfies JsonValue;

const blindMessage = "anonymous-holder-public-key";

describe("credential issuance protocol", () => {
  it("round trips holder request, issuer response, holder finalization, and verification", () => {
    const issuer = createTestIssuer();
    const issuerBundle = issuer.issuerBundle(revocationLocations);
    const result = PendingIssuance.createRequest(
      issuerBundle,
      credentialInfo,
      blindMessage,
    );
    const issuerId = issuerBundle.issuer.issuer_id_pubkey;

    expect(result.request.version).toBe(1);
    expect(result.request.blinded_message.length).toBeGreaterThan(0);
    expect(result.request.blinded_message).not.toContain(blindMessage);

    const response = issuer.issueCredential(credentialInfo, result.request);
    expect(response).toMatchObject({
      version: 1,
      issuer_id: issuerId,
      info: credentialInfo,
    });
    expect(response.blind_signature.length).toBeGreaterThan(0);

    const credential = result.pending.finalize(issuerBundle, response);
    expect(credential).toMatchObject({
      version: 1,
      credential: {
        issuer_id_pubkey: issuerId,
        info: credentialInfo,
        blind_msg: blindMessage,
      },
    });
    expect(credential.proof.signature.length).toBeGreaterThan(0);
  });

  it("imports issuer secret keys and public keys from DER", () => {
    const issuer = createTestIssuer();
    const issuerBundle = issuer.issuerBundle(revocationLocations);
    const importedIssuer = IssuerContext.importSecretKey(
      issuer.exportSecretKey(),
    );
    const importedBundle = importedIssuer.issuerBundle(revocationLocations);

    expect(importedBundle.issuer.issuer_id_pubkey).toBe(
      issuerBundle.issuer.issuer_id_pubkey,
    );
    expect(importedBundle.issuer.issuance_key).toBe(
      issuerBundle.issuer.issuance_key,
    );

    const result = PendingIssuance.createRequest(
      importedBundle,
      credentialInfo,
      blindMessage,
    );
    const response = importedIssuer.issueCredential(
      credentialInfo,
      result.request,
    );
    expect(result.pending.finalize(importedBundle, response)).toMatchObject({
      credential: {
        issuer_id_pubkey: issuerBundle.issuer.issuer_id_pubkey,
        info: credentialInfo,
        blind_msg: blindMessage,
      },
    });
  });

  it("rejects malformed issuer secret key inputs", () => {
    expect(() =>
      IssuerContext.importSecretKey({
        issuer_id_secret_key: "not-a-hex-key",
        issuance_secret_key: "AQID",
      }),
    ).toThrow();
  });

  it("rejects finalization with mismatched issuer responses", () => {
    const issuer = createTestIssuer();
    const issuerBundle = issuer.issuerBundle(revocationLocations);
    const result = PendingIssuance.createRequest(
      issuerBundle,
      credentialInfo,
      blindMessage,
    );
    const response = issuer.issueCredential(credentialInfo, result.request);
    const wrongIssuerBundle = {
      ...issuerBundle,
      issuer: {
        ...issuerBundle.issuer,
        issuance_key: wrongIssuanceKey,
      },
    } satisfies IssuerBundle;

    expect(() =>
      result.pending.finalize(issuerBundle, {
        ...response,
        issuer_id: otherIssuerId,
      }),
    ).toThrow();
    expect(() =>
      result.pending.finalize(issuerBundle, {
        ...response,
        info: {
          ...credentialInfo,
          trust_level: 8,
        },
      }),
    ).toThrow();
    expect(() =>
      result.pending.finalize(wrongIssuerBundle, response),
    ).toThrow();
  });

  it("rejects tampered finalized credentials during finalization checks", () => {
    const issuer = createTestIssuer();
    const issuerBundle = issuer.issuerBundle(revocationLocations);
    const result = PendingIssuance.createRequest(
      issuerBundle,
      credentialInfo,
      blindMessage,
    );
    const response = issuer.issueCredential(credentialInfo, result.request);
    expect(() =>
      result.pending.finalize(issuerBundle, {
        ...response,
        blind_signature: response.blind_signature.slice(1),
      }),
    ).toThrow();
  });
});
