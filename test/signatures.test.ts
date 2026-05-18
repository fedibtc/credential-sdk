import { describe, expect, it } from "vitest";

import type {
  IssuerBundle,
  Revocation,
  SchemaDefinition,
} from "../pkg/fedi_credential_sdk.js";

describe("protocol types", () => {
  it("typechecks MVP protocol envelopes", () => {
    const issuerBundle = {
      issuer: {
        issuer_id_pubkey: "issuer-id-pubkey",
        issuance_key: "rsa-pubkey-for-credential-issuance",
        revocation: [
          {
            protocol: "https",
            location: "https://example.com/revocations",
          },
        ],
      },
      proof: {
        signature: "issuer-signature",
      },
    } satisfies IssuerBundle;
    const schemaDefinition = {
      schema: {
        id: "fedi-trust-score",
        version: "1.0.0",
        digest: "base64url-digest",
        fields: {
          info: {
            schema: "string",
            issuer_id_pubkey: "string",
            score: "number",
          },
          blind_msg: "string",
        },
      },
    } satisfies SchemaDefinition;
    const revocation = {
      revocation: {
        credential_digest: "SHA256(canonical_credential)",
      },
      proof: {
        issuer_id_pubkey: "id-public-key",
        signature: "partially-blinded-signature",
      },
    } satisfies Revocation;

    expect(issuerBundle.issuer.revocation[0].protocol).toBe("https");
    expect(schemaDefinition.schema.fields.blind_msg).toBe("string");
    expect(revocation.proof.issuer_id_pubkey).toBe("id-public-key");
  });
});
