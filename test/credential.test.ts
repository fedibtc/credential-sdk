import { describe, expect, it } from "vitest";

import {
  createCredential,
  createSchema,
  schemaDigest,
} from "../pkg/blind_rsa_signatures_wasm.js";
import type { CredentialTemplate } from "../pkg/blind_rsa_signatures_wasm.js";

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
    const credential = createCredential(
      schema,
      {
        holder_pubkey: "holder-pubkey",
      },
      {
        issuer_id_pubkey: "issuer-id-pubkey",
        score: 7,
        verified: true,
      },
    );

    expect(credential).toEqual({
      schema: schema.digest,
      data: {
        blinded: {
          holder_pubkey: "holder-pubkey",
        },
        visible: {
          issuer_id_pubkey: "issuer-id-pubkey",
          score: 7,
          verified: true,
        },
      },
    });
    expect(credential.schema).toBe(schema.digest);
    expect(credential.data.visible.score).toBe(7);
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
    const credential = createCredential(
      schema,
      {
        holder_pubkey: "holder-pubkey",
      },
      {
        issuer_id_pubkey: "issuer-id-pubkey",
        profile: {
          display_name: "Alice",
          rank: 3,
        },
      },
    );

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

    expect(() =>
      createCredential(
        schema,
        {
          holder_pubkey: "holder-pubkey",
        },
        {
          issuer_id_pubkey: "issuer-id-pubkey",
        } as TrustScoreVisibleData,
      ),
    ).toThrow();
    expect(() =>
      createCredential(
        schema,
        {
          holder_pubkey: "holder-pubkey",
        },
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
        {
          holder_pubkey: "holder-pubkey",
        },
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

    if (false) {
      createCredential(
        schema,
        {
          holder_pubkey: "holder-pubkey",
        },
        {
          issuer_id_pubkey: "issuer-id-pubkey",
          // @ts-expect-error score must be a number for this schema.
          score: "7",
        },
      );
      createCredential(
        schema,
        // @ts-expect-error blinded data must include holder_pubkey.
        {},
        {
          issuer_id_pubkey: "issuer-id-pubkey",
          score: 7,
        },
      );
    }

    expect(schema.digest).toBe(schemaDigest(schema));
  });
});
