import { describe, expect, it } from "vitest";
import vector from "../crates/schemas/fixtures/trust-score-v1.json";
import type { SignedCredential } from "../pkg/fedi_credential_sdk_wasm.js";
import { credentialDigest } from "../pkg/fedi_credential_sdk_wasm.js";

const goldenDigest = "QK-voxaw9juOY7kZRJVcpWqi7hJP_Q33pAeto-Kg8NM";
const credential: SignedCredential = {
  ...vector.signed_credential,
  version: 1,
};

describe("credentialDigest", () => {
  it("matches the Rust credential digest golden vector", () => {
    expect(credentialDigest(credential)).toBe(goldenDigest);
  });

  it("excludes the proof from the digest", () => {
    const changedProof = {
      ...credential,
      proof: { signature: "AQIDBA" },
    } satisfies SignedCredential;
    expect(credentialDigest(changedProof)).toBe(goldenDigest);
  });
});
