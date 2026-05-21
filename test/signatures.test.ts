import { describe, expect, it } from "vitest";

import type {
  IssuanceRequest,
  IssuanceResponse,
  JsonValue,
  PendingIssuanceResult,
  SignedCredential,
} from "../pkg/fedi_credential_sdk_wasm.js";

describe("protocol types", () => {
  it("typechecks issuance request, response, and credential envelopes", () => {
    const info = {
      schema: "trust-score-v1",
      issuer_id_pubkey:
        "1111111111111111111111111111111111111111111111111111111111111111",
      trust_level: 7,
    } satisfies JsonValue;
    const request = {
      version: 1,
      blinded_message: "base64url-blinded-message",
    } satisfies IssuanceRequest;
    const response = {
      version: 1,
      issuer_id:
        "1111111111111111111111111111111111111111111111111111111111111111",
      info,
      blind_signature: "base64url-blind-signature",
    } satisfies IssuanceResponse;
    const credential = {
      version: 1,
      credential: {
        issuer_id_pubkey:
          "1111111111111111111111111111111111111111111111111111111111111111",
        info,
        blind_msg: "anonymous-holder-public-key",
        message_randomizer: "base64url-message-randomizer",
      },
      proof: {
        signature: "base64url-signature",
      },
    } satisfies SignedCredential;
    const pendingIssuance = {
      request,
      pending: null as never,
    } satisfies PendingIssuanceResult;

    expect(response.info).toBe(info);
    expect(credential.credential.blind_msg).toBe("anonymous-holder-public-key");
    expect(pendingIssuance.request.blinded_message).toBe(
      "base64url-blinded-message",
    );
  });
});
