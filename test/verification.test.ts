import { beforeAll, describe, expect, it } from "vitest";
import type {
  IssuerBundle,
  JsonValue,
  RevocationLocation,
  SignedRevocation,
} from "../pkg/fedi_credential_sdk_wasm.js";
import {
  PendingIssuance,
  VerificationContext,
} from "../pkg/fedi_credential_sdk_wasm.js";
import { createTestIssuer } from "./fixtures.js";

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

let issuerBundle: IssuerBundle;
let signedRevocation: SignedRevocation;

beforeAll(() => {
  const issuer = createTestIssuer();
  issuerBundle = issuer.issuerBundle(revocationLocations);
  const result = PendingIssuance.createRequest(
    issuerBundle,
    credentialInfo,
    blindMessage,
  );
  const response = issuer.issueCredential(credentialInfo, result.request);
  const credential = result.pending.finalize(issuerBundle, response);
  signedRevocation = issuer.revokeCredential(credential);
});

describe("issuer bundle verification", () => {
  it("accepts a signed issuer bundle", () => {
    const context = new VerificationContext();

    expect(context.addIssuerBundle(issuerBundle)).toBeUndefined();
  });

  it("rejects tampered issuer bundle metadata", () => {
    const context = new VerificationContext();

    expect(() =>
      context.addIssuerBundle({
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
      }),
    ).toThrow();
  });
});

describe("revocation verification", () => {
  it("accepts a signed revocation", () => {
    const context = new VerificationContext();

    context.addIssuerBundle(issuerBundle);
    expect(context.addRevocation(signedRevocation)).toBeUndefined();
  });

  it("rejects tampered revocation data", () => {
    const context = new VerificationContext();

    context.addIssuerBundle(issuerBundle);

    expect(() =>
      context.addRevocation({
        ...signedRevocation,
        revocation: {
          ...signedRevocation.revocation,
          credential_digest: "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg",
        },
      }),
    ).toThrow();
  });
});

describe("verification context", () => {
  it("accepts trusted issuer bundles and their revocations", () => {
    const context = new VerificationContext();

    expect(context.addIssuerBundle(issuerBundle)).toBeUndefined();
    expect(context.addRevocation(signedRevocation)).toBeUndefined();
  });

  it("rejects revocations from unknown issuers", () => {
    const context = new VerificationContext();

    expect(() => context.addRevocation(signedRevocation)).toThrow();
  });
});
