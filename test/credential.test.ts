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

function decodePendingState(state: string): Record<string, unknown> {
  return JSON.parse(state) as Record<string, unknown>;
}

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

  it("exports and imports pending issuance state across reload", () => {
    const issuer = createTestIssuer();
    const issuerBundle = issuer.issuerBundle(revocationLocations);
    const result = PendingIssuance.createRequest(
      issuerBundle,
      credentialInfo,
      blindMessage,
    );
    const pendingState = result.pending.exportState();

    expect(typeof pendingState).toBe("string");
    expect(pendingState.length).toBeGreaterThan(0);
    expect(decodePendingState(pendingState)).toMatchObject({
      version: 1,
      step: "waiting_for_issuer_response",
    });

    const response = issuer.issueCredential(credentialInfo, result.request);
    const importedPending = PendingIssuance.importState(pendingState);
    const credential = importedPending.finalize(issuerBundle, response);

    expect(credential).toMatchObject({
      version: 1,
      credential: {
        issuer_id_pubkey: issuerBundle.issuer.issuer_id_pubkey,
        info: credentialInfo,
        blind_msg: blindMessage,
      },
    });
  });

  it("rejects imported pending finalization with wrong issuer bundle or mismatched responses", () => {
    const issuer = createTestIssuer();
    const issuerBundle = issuer.issuerBundle(revocationLocations);
    const wrongIssuerBundle = {
      ...issuerBundle,
      issuer: {
        ...issuerBundle.issuer,
        issuance_key: wrongIssuanceKey,
      },
    } satisfies IssuerBundle;
    const wrongIssuerIdBundle = {
      ...issuerBundle,
      issuer: {
        ...issuerBundle.issuer,
        issuer_id_pubkey: otherIssuerId,
      },
    } satisfies IssuerBundle;

    const wrongIssuerResult = PendingIssuance.createRequest(
      issuerBundle,
      credentialInfo,
      blindMessage,
    );
    const wrongIssuerResponse = issuer.issueCredential(
      credentialInfo,
      wrongIssuerResult.request,
    );
    expect(() =>
      PendingIssuance.importState(
        wrongIssuerResult.pending.exportState(),
      ).finalize(wrongIssuerBundle, wrongIssuerResponse),
    ).toThrow(/blind RSA operation failed/);
    expect(() =>
      PendingIssuance.importState(
        wrongIssuerResult.pending.exportState(),
      ).finalize(wrongIssuerIdBundle, wrongIssuerResponse),
    ).toThrow(/issuer_id does not match/);

    const differentInfo = {
      ...credentialInfo,
      trust_level: 8,
    } satisfies JsonValue;
    const infoResult = PendingIssuance.createRequest(
      issuerBundle,
      credentialInfo,
      blindMessage,
    );
    const infoResponse = issuer.issueCredential(
      differentInfo,
      infoResult.request,
    );
    expect(() =>
      PendingIssuance.importState(infoResult.pending.exportState()).finalize(
        issuerBundle,
        infoResponse,
      ),
    ).toThrow(/issuance response info does not match/);

    const firstResult = PendingIssuance.createRequest(
      issuerBundle,
      credentialInfo,
      blindMessage,
    );
    const secondResult = PendingIssuance.createRequest(
      issuerBundle,
      credentialInfo,
      blindMessage,
    );
    const secondResponse = issuer.issueCredential(
      credentialInfo,
      secondResult.request,
    );
    expect(() =>
      PendingIssuance.importState(firstResult.pending.exportState()).finalize(
        issuerBundle,
        secondResponse,
      ),
    ).toThrow();
  });

  it("rejects malformed and unknown-version pending issuance state", () => {
    const issuer = createTestIssuer();
    const issuerBundle = issuer.issuerBundle(revocationLocations);
    const result = PendingIssuance.createRequest(
      issuerBundle,
      credentialInfo,
      blindMessage,
    );
    const pendingState = result.pending.exportState();
    const unknownVersionState = JSON.stringify({
      ...decodePendingState(pendingState),
      version: 2,
    });

    expect(() => PendingIssuance.importState(unknownVersionState)).toThrow(
      /unsupported protocol version/,
    );
    expect(() => PendingIssuance.importState("not-json")).toThrow(
      /invalid pending issuance state/,
    );
  });

  it("keeps imported pending issuance objects freeable and single-use", () => {
    const issuer = createTestIssuer();
    const issuerBundle = issuer.issuerBundle(revocationLocations);
    const result = PendingIssuance.createRequest(
      issuerBundle,
      credentialInfo,
      blindMessage,
    );
    const pendingState = result.pending.exportState();
    const response = issuer.issueCredential(credentialInfo, result.request);

    const freedPending = PendingIssuance.importState(pendingState);
    freedPending.free();
    expect(() => freedPending.finalize(issuerBundle, response)).toThrow();

    const singleUsePending = PendingIssuance.importState(pendingState);
    expect(singleUsePending.finalize(issuerBundle, response)).toMatchObject({
      credential: {
        issuer_id_pubkey: issuerBundle.issuer.issuer_id_pubkey,
        info: credentialInfo,
        blind_msg: blindMessage,
      },
    });
    expect(() => singleUsePending.finalize(issuerBundle, response)).toThrow();
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
