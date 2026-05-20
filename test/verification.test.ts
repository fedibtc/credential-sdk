import { describe, expect, it } from "vitest";

import {
  IssuerContext,
  PendingIssuance,
  VerificationContext,
  verifyIssuerBundle,
  verifyRevocation,
} from "../pkg/fedi_credential_sdk_wasm.js";
import type {
  Credential,
  IssuerBundle,
  PendingIssuanceResult,
  SignedRevocation,
} from "../pkg/fedi_credential_sdk_wasm.js";

const revocationLocations = [
  {
    location: "wss://relay.example.com",
    protocol: "nostr",
  },
];

function credentialFixture(): {
  issuer: IssuerContext;
  issuerBundle: IssuerBundle;
  signedRevocation: SignedRevocation;
  credential: Credential;
} {
  const issuer = IssuerContext.generate(1024);
  const info = { schema: "fedi-trust-score-v1.0", trust_level: 7 };
  const blindMsg = "anonymous-holder-public-key";
  const result = PendingIssuance.createRequest(
    issuer.publicKey,
    issuer.issuerId,
    info,
    blindMsg,
  ) as PendingIssuanceResult;
  const response = issuer.issueCredential(info, result.request);
  const credential = result.pending.finalize(
    issuer.publicKey,
    response,
  ) as Credential;

  return {
    issuer,
    issuerBundle: issuer.issuerBundle(revocationLocations) as IssuerBundle,
    signedRevocation: issuer.revokeCredential(credential) as SignedRevocation,
    credential,
  };
}

describe("issuer bundle verification", () => {
  it("accepts a signed issuer bundle", () => {
    const { issuerBundle } = credentialFixture();

    expect(verifyIssuerBundle(issuerBundle)).toBe(true);
  });

  it("rejects tampered issuer bundle metadata", () => {
    const { issuerBundle } = credentialFixture();

    expect(() =>
      verifyIssuerBundle({
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
    const { signedRevocation } = credentialFixture();

    expect(verifyRevocation(signedRevocation)).toBe(true);
  });

  it("rejects tampered revocation data", () => {
    const { signedRevocation } = credentialFixture();

    expect(() =>
      verifyRevocation({
        ...signedRevocation,
        revocation: {
          ...signedRevocation.revocation,
          credential_digest:
            "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg",
        },
      }),
    ).toThrow();
  });
});

describe("verification context", () => {
  it("accepts trusted issuer bundles and their revocations", () => {
    const { issuerBundle, signedRevocation } = credentialFixture();
    const context = new VerificationContext();

    expect(context.addIssuerBundle(issuerBundle)).toBeUndefined();
    expect(context.addRevocation(signedRevocation)).toBeUndefined();
  });

  it("rejects revocations from unknown issuers", () => {
    const { signedRevocation } = credentialFixture();
    const context = new VerificationContext();

    expect(() => context.addRevocation(signedRevocation)).toThrow();
  });
});
