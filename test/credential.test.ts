import { describe, expect, it } from "vitest";

import {
  blind,
  blindSignCredential,
  createCredential,
  createSchema,
  finalizeCredential,
  generateIssuerKeys,
  schemaDigest,
} from "../pkg/fedi_credential_sdk.js";
import type {
  BlindedPayload,
  VerifiableCredential,
} from "../pkg/fedi_credential_sdk.js";

type TrustScoreVisibleData = {
  issuer_id_pubkey: string;
  score: number;
};

describe("dynamic credential schemas", () => {
  it("creates a schema with blinded and visible fields from field lists", () => {
    const schema = createSchema(
      [{ name: "holder_pubkey", type: "string" }],
      [
        { name: "issuer_id_pubkey", type: "string" },
        { name: "score", type: "number" },
      ],
    );

    expect(schema).toMatchObject({
      id: "dynamic-credential",
      version: "1.0.0",
      fields: {
        blinded: {
          holder_pubkey: "string",
        },
        visible: {
          issuer_id_pubkey: "string",
          score: "number",
        },
      },
    });
    expect(schema.fields.blinded.holder_pubkey).toBe("string");
    expect(schema.fields.visible.score).toBe("number");
    expect(schema.digest).toBe(schemaDigest(schema));
  });

  it("produces the same digest regardless of object field order", () => {
    const first = createSchema(
      [{ name: "holder_pubkey", type: "string" }],
      [
        { name: "issuer_id_pubkey", type: "string" },
        { name: "score", type: "number" },
      ],
    );
    const second = createSchema(
      [{ name: "holder_pubkey", type: "string" }],
      [
        { name: "score", type: "number" },
        { name: "issuer_id_pubkey", type: "string" },
      ],
    );

    expect(first.digest).toBe(second.digest);
  });

  it("creates credentials that carry schema digest and dynamic data", () => {
    const schema = createSchema(
      [{ name: "holder_pubkey", type: "string" }],
      [
        { name: "issuer_id_pubkey", type: "string" },
        { name: "score", type: "number" },
        { name: "verified", type: "boolean" },
      ],
    );
    const blindedPayload = blind(schema, {
      holder_pubkey: "holder-pubkey",
    });
    const credential = createCredential(schema, blindedPayload, {
      issuer_id_pubkey: "issuer-id-pubkey",
      score: 7,
      verified: true,
    });

    expect(credential).toEqual({
      credential: {
        info: {
          schema: schema.digest,
          issuer_id_pubkey: "issuer-id-pubkey",
          score: 7,
          verified: true,
        },
        blind_msg: {
          holder_pubkey: "holder-pubkey",
        },
      },
    });
    expect(blindedPayload.schema).toBe(schema.digest);
    expect(credential.credential.info.schema).toBe(schema.digest);
    expect(credential.credential.info.score).toBe(7);
  });

  it("blind signs a credential template with a PBRSA key pair", () => {
    const schema = createSchema(
      [{ name: "holder_pubkey", type: "string" }],
      [
        { name: "issuer_id_pubkey", type: "string" },
        { name: "score", type: "number" },
      ],
    );
    const blindedPayload = blind(schema, {
      holder_pubkey: "holder-pubkey",
    });
    const keyPair = generateIssuerKeys(1024);
    const signedCredential = blindSignCredential(
      schema,
      blindedPayload,
      {
        issuer_id_pubkey: "issuer-id-pubkey",
        score: 7,
      },
      keyPair,
    );
    const publicKey = keyPair.publicKey;
    const credential = finalizeCredential(signedCredential, publicKey);

    expect(signedCredential.credential.info.schema).toBe(schema.digest);
    expect(signedCredential.credential.info.score).toBe(7);
    expect(signedCredential.credential.blind_msg.length).toBeGreaterThan(0);
    expect(signedCredential.proof.signature.length).toBeGreaterThan(0);
    expect(signedCredential.proof.blinded_msg.length).toBeGreaterThan(0);
    expect(signedCredential.proof.info.length).toBeGreaterThan(0);
    expect(signedCredential.proof.blind_msg.length).toBeGreaterThan(0);
    expect(credential).toEqual({
      credential: {
        info: {
          schema: schema.digest,
          issuer_id_pubkey: "issuer-id-pubkey",
          score: 7,
        },
        blind_msg: {
          holder_pubkey: "holder-pubkey",
        },
      },
      proof: {
        signature: credential.proof.signature,
      },
    });
    expect(credential.proof.signature.length).toBeGreaterThan(0);
    expect(
      publicKey.verify(
        Uint8Array.from(credential.proof.signature),
        Uint8Array.from(signedCredential.proof.messageRandomizer),
        Uint8Array.from(signedCredential.proof.blind_msg),
        Uint8Array.from(signedCredential.proof.info),
      ),
    ).toBe(true);
    expect(credential satisfies VerifiableCredential<typeof schema>).toBe(
      credential,
    );
  });

  it("rejects finalizing tampered or mismatched blind signed credentials", () => {
    const schema = createSchema(
      [{ name: "holder_pubkey", type: "string" }],
      [
        { name: "issuer_id_pubkey", type: "string" },
        { name: "score", type: "number" },
      ],
    );
    const blindedPayload = blind(schema, {
      holder_pubkey: "holder-pubkey",
    });
    const keyPair = generateIssuerKeys(1024);
    const signedCredential = blindSignCredential(
      schema,
      blindedPayload,
      {
        issuer_id_pubkey: "issuer-id-pubkey",
        score: 7,
      },
      keyPair,
    );
    const publicKey = keyPair.publicKey;

    expect(() =>
      finalizeCredential(
        {
          ...signedCredential,
          credential: {
            ...signedCredential.credential,
            info: {
              ...signedCredential.credential.info,
              score: 8,
            },
          },
        },
        publicKey,
      ),
    ).toThrow();
    expect(() =>
      finalizeCredential(
        {
          ...signedCredential,
          credential: {
            ...signedCredential.credential,
            blind_msg: signedCredential.credential.blind_msg.map(
              (byte, index) => (index === 0 ? byte ^ 1 : byte),
            ),
          },
        },
        publicKey,
      ),
    ).toThrow();
    expect(() =>
      finalizeCredential(signedCredential, generateIssuerKeys(1024).publicKey),
    ).toThrow();
  });

  it("rejects blind signing when visible data does not match the schema", () => {
    const schema = createSchema(
      [{ name: "holder_pubkey", type: "string" }],
      [
        { name: "issuer_id_pubkey", type: "string" },
        { name: "score", type: "number" },
      ],
    );
    const blindedPayload = blind(schema, {
      holder_pubkey: "holder-pubkey",
    });
    const keys = generateIssuerKeys(1024);

    expect(() =>
      blindSignCredential(
        schema,
        blindedPayload,
        {
          issuer_id_pubkey: "issuer-id-pubkey",
        } as TrustScoreVisibleData,
        keys,
      ),
    ).toThrow();
    expect(() =>
      blindSignCredential(
        schema,
        blindedPayload,
        {
          issuer_id_pubkey: "issuer-id-pubkey",
          score: 7,
          unexpected: true,
        } as TrustScoreVisibleData,
        keys,
      ),
    ).toThrow();
    expect(() =>
      blindSignCredential(
        schema,
        blindedPayload,
        {
          issuer_id_pubkey: "issuer-id-pubkey",
          score: "7",
        } as unknown as TrustScoreVisibleData,
        keys,
      ),
    ).toThrow();
  });

  it("rejects blind signing when the blinded payload does not match the schema", () => {
    const schema = createSchema(
      [{ name: "holder_pubkey", type: "string" }],
      [{ name: "score", type: "number" }],
    );
    const otherSchema = createSchema(
      [{ name: "other_pubkey", type: "string" }],
      [{ name: "score", type: "number" }],
    );
    const visibleData = { score: 7 };
    const keys = generateIssuerKeys(1024);

    expect(() =>
      blindSignCredential(
        schema,
        blind(otherSchema, { other_pubkey: "other" }) as unknown as ReturnType<
          typeof blind<typeof schema>
        >,
        visibleData,
        keys,
      ),
    ).toThrow();
    expect(() =>
      blindSignCredential(
        schema,
        {
          schema: schema.digest,
          payload: {},
        } as BlindedPayload<typeof schema>,
        visibleData,
        keys,
      ),
    ).toThrow();
    expect(() =>
      blindSignCredential(
        schema,
        {
          schema: schema.digest,
          payload: {
            holder_pubkey: 7,
          },
        } as unknown as BlindedPayload<typeof schema>,
        visibleData,
        keys,
      ),
    ).toThrow();
  });

  it("validates nested credential data against nested schema fields", () => {
    const schema = createSchema(
      [{ name: "holder_pubkey", type: "string" }],
      [
        { name: "issuer_id_pubkey", type: "string" },
        {
          name: "profile",
          fields: [
            { name: "display_name", type: "string" },
            { name: "rank", type: "integer" },
          ],
        },
      ],
    );
    const blindedPayload = blind(schema, {
      holder_pubkey: "holder-pubkey",
    });
    const credential = createCredential(schema, blindedPayload, {
      issuer_id_pubkey: "issuer-id-pubkey",
      profile: {
        display_name: "Alice",
        rank: 3,
      },
    });

    expect(credential.credential.info.profile.display_name).toBe("Alice");
    expect(credential.credential.info.profile.rank).toBe(3);
  });

  it("rejects data with missing, extra, or wrong-typed fields", () => {
    const schema = createSchema(
      [{ name: "holder_pubkey", type: "string" }],
      [
        { name: "issuer_id_pubkey", type: "string" },
        { name: "score", type: "number" },
      ],
    );
    const blindedPayload = blind(schema, {
      holder_pubkey: "holder-pubkey",
    });

    expect(() =>
      createCredential(schema, blindedPayload, {
        issuer_id_pubkey: "issuer-id-pubkey",
      } as TrustScoreVisibleData),
    ).toThrow();
    expect(() =>
      createCredential(schema, blindedPayload, {
        issuer_id_pubkey: "issuer-id-pubkey",
        score: 7,
        unexpected: true,
      } as TrustScoreVisibleData),
    ).toThrow();
    expect(() =>
      createCredential(schema, blindedPayload, {
        issuer_id_pubkey: "issuer-id-pubkey",
        score: "7", // should be a number
      } as unknown as TrustScoreVisibleData),
    ).toThrow();
  });

  it("propagates schema type parameters into createCredential", () => {
    const schema = createSchema(
      [{ name: "holder_pubkey", type: "string" }],
      [
        { name: "issuer_id_pubkey", type: "string" },
        { name: "score", type: "number" },
      ],
    );
    const blindedPayload = blind(schema, {
      holder_pubkey: "holder-pubkey",
    });

    expect(() => {
      blind(
        schema,
        // @ts-expect-error blinded data must include holder_pubkey.
        {},
      );
    }).toThrow();
    expect(() => {
      createCredential(schema, blindedPayload, {
        issuer_id_pubkey: "issuer-id-pubkey",
        // @ts-expect-error score must be a number for this schema.
        score: "7",
      });
    }).toThrow();
    expect(() => {
      createCredential(
        schema,
        // @ts-expect-error blinded payload must come from the same schema.
        blind(
          createSchema(
            [{ name: "other", type: "string" }],
            [{ name: "score", type: "number" }],
          ),
          { other: "value" },
        ),
        {
          issuer_id_pubkey: "issuer-id-pubkey",
          score: 7,
        },
      );
    }).toThrow();
    expect(() => {
      blindSignCredential(
        schema,
        blindedPayload,
        {
          issuer_id_pubkey: "issuer-id-pubkey",
          // @ts-expect-error score must be a number for this schema.
          score: "7",
        },
        generateIssuerKeys(1024),
      );
    }).toThrow();

    expect(schema.digest).toBe(schemaDigest(schema));
  });
});
