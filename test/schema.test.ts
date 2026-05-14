import { describe, expect, it } from "vitest";

import {
  createCredential,
  createSchema,
  schemaDigest,
} from "../pkg/blind_rsa_signatures_wasm.js";
import type {
  CredentialSchema,
  DynamicCredential,
} from "../pkg/blind_rsa_signatures_wasm.js";

type HolderBlindData = {
  holder_pubkey: string;
};

type TrustScoreVisibleData = {
  issuer_id_pubkey: string;
  score: number;
};

describe("dynamic credential schemas", () => {
  it("creates a schema with blinded and visible fields from field lists", () => {
    const schema = createSchema<HolderBlindData, TrustScoreVisibleData>(
      [{ name: "holder_pubkey", type: "string" }],
      [
        { name: "issuer_id_pubkey", type: "string" },
        { name: "score", type: "number" },
      ],
    );
    const typedSchema: CredentialSchema<
      HolderBlindData,
      TrustScoreVisibleData
    > = schema;

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
    expect(typedSchema.digest).toBe(schema.digest);
    expect(schema.digest).toBe(schemaDigest(schema));
  });

  it("produces the same digest regardless of object field order", () => {
    const first = createSchema<HolderBlindData, TrustScoreVisibleData>(
      {
        holder_pubkey: "string",
      },
      {
        issuer_id_pubkey: "string",
        score: "number",
      },
    );
    const second = createSchema<HolderBlindData, TrustScoreVisibleData>(
      {
        holder_pubkey: "string",
      },
      {
        score: "number",
        issuer_id_pubkey: "string",
      },
    );

    expect(first.digest).toBe(second.digest);
  });

  it("creates credentials that carry schema digest and dynamic data", () => {
    type VisibleData = TrustScoreVisibleData & {
      verified: boolean;
    };
    const schema = createSchema<HolderBlindData, VisibleData>(
      {
        holder_pubkey: "string",
      },
      {
        issuer_id_pubkey: "string",
        score: "number",
        verified: "boolean",
      },
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
    const typedCredential: DynamicCredential<HolderBlindData, VisibleData> =
      credential;

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
    expect(typedCredential.data.visible.score).toBe(7);
  });

  it("validates nested credential data against nested schema fields", () => {
    type VisibleData = {
      issuer_id_pubkey: string;
      profile: {
        display_name: string;
        rank: number;
      };
    };
    const schema = createSchema<HolderBlindData, VisibleData>(
      {
        holder_pubkey: "string",
      },
      {
        issuer_id_pubkey: "string",
        profile: {
          display_name: "string",
          rank: "integer",
        },
      },
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
    const schema = createSchema<HolderBlindData, TrustScoreVisibleData>(
      {
        holder_pubkey: "string",
      },
      {
        issuer_id_pubkey: "string",
        score: "number",
      },
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
    const schema = createSchema<HolderBlindData, TrustScoreVisibleData>(
      {
        holder_pubkey: "string",
      },
      {
        issuer_id_pubkey: "string",
        score: "number",
      },
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
