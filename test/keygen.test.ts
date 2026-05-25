import { describe, expect, it } from "vitest";
import type { JsonValue } from "../pkg/fedi_credential_sdk_wasm.js";
import {
  HolderContext,
  IssuerContext,
  PendingIssuance,
  VerificationContext,
} from "../pkg/fedi_credential_sdk_wasm.js";

const runSlowKeygen =
  (globalThis as { process?: { env?: Record<string, string | undefined> } })
    .process?.env?.RUN_RSA_KEYGEN_TESTS === "1";

const slowKeygenTimeoutMs = 1_200_000;

const credentialInfo = {
  schema: "rsa-keygen-smoke-v1",
  trust_level: 1,
} satisfies JsonValue;

function writeTiming(message: string) {
  const stdout = (
    globalThis as {
      process?: { stdout?: { write: (value: string) => void } };
    }
  ).process?.stdout;

  if (stdout) {
    stdout.write(`${message}\n`);
  } else {
    console.info(message);
  }
}

function reportsRsaKeygenTiming() {
  const started = Date.now();
  const issuer = IssuerContext.generate();
  const keygenElapsedMs = Date.now() - started;

  writeTiming(
    `IssuerContext.generate() wasm RSA keygen completed in ${(
      keygenElapsedMs / 1000
    ).toFixed(3)}s`,
  );

  const exported = issuer.exportSecretKey();
  expect(exported.issuer_id_secret_key).toMatch(/^[0-9a-f]+$/);
  expect(exported.issuance_secret_key.length).toBeGreaterThan(0);

  const issuerBundle = issuer.issuerBundle([]);
  expect(issuerBundle.issuer.issuer_id_pubkey.length).toBeGreaterThan(0);
  expect(issuerBundle.issuer.issuance_key.length).toBeGreaterThan(0);

  const holder = HolderContext.generate();
  const result = PendingIssuance.createRequest(
    issuerBundle,
    credentialInfo,
    holder.publicKey,
  );
  const response = issuer.issueCredential(credentialInfo, result.request);
  const credential = result.pending.finalize(issuerBundle, response);

  const verifier = new VerificationContext();
  expect(verifier.addIssuerBundle(issuerBundle)).toBeUndefined();
  expect(verifier.verifyCredential(credential)).toBe(true);
}

describe("RSA issuer key generation", () => {
  if (runSlowKeygen) {
    it(
      "generates issuer keys and reports timing",
      reportsRsaKeygenTiming,
      slowKeygenTimeoutMs,
    );
  } else {
    it.skip(
      "generates issuer keys and reports timing",
      reportsRsaKeygenTiming,
      slowKeygenTimeoutMs,
    );
  }
});
