import { describe, expect, it } from "vitest";

import {
  BrsaKeyPair,
  PbrsaKeyPair,
} from "../pkg/blind_rsa_signatures_wasm.js";
import type {
  IssuerBundle,
  LegacyVerifiableCredential,
  Revocation,
  SchemaDefinition,
} from "../pkg/blind_rsa_signatures_wasm.js";

const encoder = new TextEncoder();

describe("blind RSA signatures", () => {
  it("blinds, signs, finalizes, and verifies a BRSA message", () => {
    const message = encoder.encode("vitest-brsa-message");
    const keyPair = BrsaKeyPair.generate(2048);

    const blinded = keyPair.publicKey.blind(message);
    const blindSignature = keyPair.secretKey.blindSign(blinded.blindMessage);
    const signature = keyPair.publicKey.finalize(
      blindSignature,
      blinded,
      message,
    );

    expect(
      keyPair.publicKey.verify(
        signature,
        blinded.messageRandomizer,
        message,
      ),
    ).toBe(true);
  });

  it("derives metadata-bound keys and verifies a PBRSA message", () => {
    const message = encoder.encode("vitest-pbrsa-message");
    const metadata = encoder.encode("vitest-pbrsa-metadata");
    const masterKeyPair = PbrsaKeyPair.generate(1024);
    const keyPair = masterKeyPair.deriveForMetadata(metadata);

    const blinded = keyPair.publicKey.blind(message, metadata);
    const blindSignature = keyPair.secretKey.blindSign(blinded.blindMessage);
    const signature = keyPair.publicKey.finalize(
      blindSignature,
      blinded,
      message,
      metadata,
    );

    expect(
      keyPair.publicKey.verify(
        signature,
        blinded.messageRandomizer,
        message,
        metadata,
      ),
    ).toBe(true);
  });
});

describe("protocol types", () => {
  it("typechecks MVP protocol envelopes", () => {
    const verifiableCredential = {
      credential: {
        info: {
          schema: "base64url-digest",
          issuer_id_pubkey: "issuer-id-pubkey",
          score: 7,
        },
        blind_msg: "anonymous-holder-public-key",
      },
      proof: {
        signature: "RSA-signature",
      },
    } satisfies LegacyVerifiableCredential;
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

    expect(verifiableCredential.credential.info.score).toBe(7);
    expect(issuerBundle.issuer.revocation[0].protocol).toBe("https");
    expect(schemaDefinition.schema.fields.blind_msg).toBe("string");
    expect(revocation.proof.issuer_id_pubkey).toBe("id-public-key");
  });
});
