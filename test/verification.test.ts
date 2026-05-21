import { describe, expect, it } from "vitest";
import type {
  IssuerBundle,
  PendingIssuanceResult,
  SignedCredential,
  SignedRevocation,
} from "../pkg/fedi_credential_sdk_wasm.js";
import {
  IssuerContext,
  PendingIssuance,
  VerificationContext,
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
  credential: SignedCredential;
} {
  const issuer = IssuerContext.generate();
  const issuerBundle = issuer.issuerBundle(revocationLocations) as IssuerBundle;
  const info = { schema: "fedi-trust-score-v1.0", trust_level: 7 };
  const blindMsg = "anonymous-holder-public-key";
  const result = PendingIssuance.createRequest(
    issuerBundle,
    info,
    blindMsg,
  ) as PendingIssuanceResult;
  const response = issuer.issueCredential(info, result.request);
  const credential = result.pending.finalize(
    issuerBundle,
    response,
  ) as SignedCredential;

  return {
    issuer,
    issuerBundle,
    signedRevocation: issuer.revokeCredential(credential) as SignedRevocation,
    credential,
  };
}

describe("issuer bundle verification", () => {
  it("accepts a signed issuer bundle", () => {
    const { issuerBundle } = credentialFixture();
    const context = new VerificationContext();

    expect(context.addIssuerBundle(issuerBundle)).toBeUndefined();
  });

  it("rejects tampered issuer bundle metadata", () => {
    const { issuerBundle } = credentialFixture();
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
    const { issuerBundle, signedRevocation } = credentialFixture();
    const context = new VerificationContext();

    context.addIssuerBundle(issuerBundle);
    expect(context.addRevocation(signedRevocation)).toBeUndefined();
  });

  it("rejects tampered revocation data", () => {
    const { issuerBundle, signedRevocation } = credentialFixture();
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
