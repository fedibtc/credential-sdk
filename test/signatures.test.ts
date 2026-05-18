import { describe, expect, it } from "vitest";

import type {
  Credential,
  IssuanceRequest,
  IssuanceResponse,
  JsonValue,
  PendingIssuanceResult,
} from "../pkg/blind_rsa_signatures_wasm_next.js";

describe("protocol types", () => {
  it("typechecks issuance request, response, and credential envelopes", () => {
    const info = {
      schema: "trust-score-v1",
      issuer_id_pubkey:
        "1111111111111111111111111111111111111111111111111111111111111111",
      score: 7,
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
      issuer_id:
        "1111111111111111111111111111111111111111111111111111111111111111",
      info,
      blind_msg: {
        holder_pubkey: "holder-pubkey",
      },
      message_randomizer: "base64url-message-randomizer",
      signature: "base64url-signature",
    } satisfies Credential;
    const pendingIssuance = {
      request,
      pending: null as never,
    } satisfies PendingIssuanceResult;

    expect(response.info).toBe(info);
    expect(credential.blind_msg).toEqual({ holder_pubkey: "holder-pubkey" });
    expect(pendingIssuance.request.blinded_message).toBe(
      "base64url-blinded-message",
    );
  });
});
