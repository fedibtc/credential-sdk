import { describe, expect, it } from "vitest";

import {
  blind,
  blindSignCredential,
  createCredential,
  createSchema,
  PbrsaKeyPair,
  schemaDigest,
} from "../pkg/blind_rsa_signatures_wasm.js";
import type { BlindedPayload } from "../pkg/blind_rsa_signatures_wasm.js";

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
      schema: schema.digest,
      data: {
        blinded: {
          schema: schema.digest,
          payload: {
            holder_pubkey: "holder-pubkey",
          },
        },
        visible: {
          issuer_id_pubkey: "issuer-id-pubkey",
          score: 7,
          verified: true,
        },
      },
    });
    expect(credential.schema).toBe(schema.digest);
    expect(blindedPayload.schema).toBe(schema.digest);
    expect(credential.schema).toBe(schema.digest);
    expect(credential.data.visible.score).toBe(7);
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
    const signedCredential = blindSignCredential(
      schema,
      blindedPayload,
      {
        issuer_id_pubkey: "issuer-id-pubkey",
        score: 7,
      },
      PbrsaKeyPair.generate(1024),
    );

    expect(signedCredential.schema).toBe(schema.digest);
    expect(signedCredential.credentialTemplate.schema).toBe(schema.digest);
    expect(signedCredential.proof.blindSignature.length).toBeGreaterThan(0);
    expect(signedCredential.proof.blindMessage.length).toBeGreaterThan(0);
    expect(signedCredential.proof.metadata.length).toBeGreaterThan(0);
    expect(signedCredential.proof.message.length).toBeGreaterThan(0);
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
    const keys = PbrsaKeyPair.generate(1024);

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
    const keys = PbrsaKeyPair.generate(1024);

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

    expect(credential.data.visible.profile.display_name).toBe("Alice");
    expect(credential.data.visible.profile.rank).toBe(3);
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
      createCredential(
        schema,
        blindedPayload,
        {
          issuer_id_pubkey: "issuer-id-pubkey",
        } as TrustScoreVisibleData,
      ),
    ).toThrow();
    expect(() =>
      createCredential(
        schema,
        blindedPayload,
        {
          issuer_id_pubkey: "issuer-id-pubkey",
          score: 7,
          unexpected: true,
        } as TrustScoreVisibleData,
      ),
    ).toThrow();
    expect(() =>
      createCredential(
        schema,
        blindedPayload,
        {
          issuer_id_pubkey: "issuer-id-pubkey",
          score: "7", // should be a number
        } as unknown as TrustScoreVisibleData,
      ),
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
      createCredential(
        schema,
        blindedPayload,
        {
          issuer_id_pubkey: "issuer-id-pubkey",
          // @ts-expect-error score must be a number for this schema.
          score: "7",
        },
      );
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
        PbrsaKeyPair.generate(1024),
      );
    }).toThrow();

    expect(schema.digest).toBe(schemaDigest(schema));
  });
});
