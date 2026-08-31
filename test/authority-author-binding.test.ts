import { beforeAll, describe, expect, it } from "vitest";
import type {
  IssuerAuthority,
  JsonValue,
  SignedCredential,
} from "../pkg/fedi_credential_sdk_wasm.js";
import {
  PendingIssuance,
  VerificationContext,
} from "../pkg/fedi_credential_sdk_wasm.js";
import { createTestIssuer } from "./fixtures.js";

const credentialInfo = {
  schema: "example-membership-v1.0",
  trust_level: 7,
} satisfies JsonValue;

const blindMessage = "anonymous-holder-public-key";

// A valid x-only public key that is not the test issuer identity key
// (issuer_id_pubkey from crates/schemas/fixtures/trust-score-v1.json).
const squatterPubkey =
  "8df31bee16d9ad0701514cbf2a6cb5c5cc9ebc2d70fed74fea8adaef599a9fcf";

let issuerAuthority: IssuerAuthority;
let credential: SignedCredential;

beforeAll(() => {
  const issuer = createTestIssuer();
  issuerAuthority = issuer.issuerAuthority([]);
  const result = PendingIssuance.createRequest(
    issuerAuthority,
    credentialInfo,
    blindMessage,
  );
  const response = issuer.issueCredential(credentialInfo, result.request);
  credential = result.pending.finalize(issuerAuthority, response);
});

describe("issuer authority author binding", () => {
  it("accepts an authority published by its own issuer identity key", () => {
    const verifier = new VerificationContext();
    verifier.addIssuerAuthorityFromAuthor(
      issuerAuthority,
      issuerAuthority.issuer.issuer_id_pubkey,
    );
    expect(verifier.verifyCredential(credential)).toBe(true);
  });

  it("rejects an authority published by a different author key", () => {
    const verifier = new VerificationContext();
    expect(() =>
      verifier.addIssuerAuthorityFromAuthor(issuerAuthority, squatterPubkey),
    ).toThrow(/author does not match/);
    // The rejected authority must not have been trusted.
    expect(() => verifier.verifyCredential(credential)).toThrow();
  });

  it("rejects a malformed author key", () => {
    const verifier = new VerificationContext();
    expect(() =>
      verifier.addIssuerAuthorityFromAuthor(issuerAuthority, "not-a-pubkey"),
    ).toThrow();
  });
});
