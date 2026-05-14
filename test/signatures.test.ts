import { describe, expect, it } from "vitest";

import { brsa, pbrsa } from "../dist/index.js";

const encoder = new TextEncoder();

describe("blind RSA signatures", () => {
  it("blinds, signs, finalizes, and verifies a BRSA message", () => {
    const message = encoder.encode("vitest-brsa-message");
    const keyPair = brsa.KeyPair.generate(2048);

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
    const masterKeyPair = pbrsa.KeyPair.generate(1024);
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
