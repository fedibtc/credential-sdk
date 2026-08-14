import { describe, expect, it } from "vitest";
import vector from "../crates/schemas/fixtures/trust-score-v1.json";
import type {
  NostrEvent,
  SignedCredential,
} from "../pkg/fedi_credential_sdk_wasm.js";
import {
  credentialDigest,
  prepareStandaloneCredentialEvent,
  selectNewestStandaloneCredentialEvent,
} from "../pkg/fedi_credential_sdk_wasm.js";

const goldenDigest = "QK-voxaw9juOY7kZRJVcpWqi7hJP_Q33pAeto-Kg8NM";
const holderPubkey = vector.signed_credential.credential.blind_msg;
const credential: SignedCredential = {
  ...vector.signed_credential,
  version: 1,
};

describe("standalone holder credential events", () => {
  it("matches the Rust credential digest golden vector", () => {
    expect(credentialDigest(credential)).toBe(goldenDigest);

    const changedProof = {
      ...credential,
      proof: { signature: "AQIDBA" },
    } satisfies SignedCredential;
    expect(credentialDigest(changedProof)).toBe(goldenDigest);
  });

  it("keeps the draft event shape and uses ordinary JSON content", () => {
    expect(
      prepareStandaloneCredentialEvent(holderPubkey, credential, 1_755_000_000),
    ).toEqual({
      pubkey: holderPubkey,
      created_at: 1_755_000_000,
      kind: 37_702,
      tags: [
        ["d", `credential:${goldenDigest}`],
        ["t", "fedi-credential"],
        ["p", holderPubkey],
      ],
      content: JSON.stringify(credential),
    });
  });

  it("skips a structurally malformed relay candidate", () => {
    const malformedCandidates = [
      { id: "not-a-nostr-event" },
    ] as unknown as readonly NostrEvent[];

    expect(
      selectNewestStandaloneCredentialEvent(holderPubkey, malformedCandidates),
    ).toBeUndefined();
  });
});
