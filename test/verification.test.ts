import { describe, expect, it } from "vitest";

import {
  verifyIssuerBundle,
  verifyRevocation,
} from "../pkg/fedi_credential_sdk_wasm.js";
import type {
  IssuerBundle,
  SignedRevocation,
} from "../pkg/fedi_credential_sdk_wasm.js";

const issuerBundle = {
  issuer: {
    issuance_key:
      "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgG4kMHJsker93DRQ4R8vFndLqYCWHD_QSt351YYFjYnin8oFvNjV4hNLlibXrJiCg1Dl4dnVOCaQV7hjjp9QxsYQI9k5wHXJI44xSn9BHzWs5Cep3jEN0rzqPr72aKfyu9fnjVFM3evuALIZDWuqtC-H5D3qCGxr-amJHx1XFGWVAgMBAAE",
    issuer_id_pubkey:
      "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
    revocation: [
      {
        location: "wss://relay.example.com",
        protocol: "nostr",
      },
    ],
  },
  proof: {
    signature:
      "96f800fa5e8dd9198b1ce92a46b0ddb2c5b2245949e1198a2147bd1714ecccc490203d71a33ec75f38274129c9ffee3ed7c66ec92933f6fd3a3c18e009ca4c88",
  },
} satisfies IssuerBundle;

const signedRevocation = {
  proof: {
    issuer_id_pubkey:
      "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
    signature:
      "ee9d501b2ebb13671649fcfead294b19f7abd3885b516f119297c645caaabcdc9e0ffadaf015db7d9baede461a81adacaab4cf873cc84a676c04a41054a11f45",
  },
  revocation: {
    credential_digest:
      "0707070707070707070707070707070707070707070707070707070707070707",
  },
} satisfies SignedRevocation;

describe("issuer bundle verification", () => {
  it("accepts a signed issuer bundle", () => {
    expect(verifyIssuerBundle(issuerBundle)).toBe(true);
  });

  it("rejects tampered issuer bundle metadata", () => {
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
    expect(verifyRevocation(signedRevocation)).toBe(true);
  });

  it("rejects tampered revocation data", () => {
    expect(() =>
      verifyRevocation({
        ...signedRevocation,
        revocation: {
          credential_digest:
            "0808080808080808080808080808080808080808080808080808080808080808",
        },
      }),
    ).toThrow();
  });
});
