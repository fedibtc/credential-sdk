import { brsa, pbrsa } from "../dist/index.js";

const status = document.querySelector("#status");
const encoder = new TextEncoder();

if (!(status instanceof HTMLOutputElement)) {
  throw new Error("Missing status output");
}

try {
  const message = encoder.encode("browser-smoke-message");

  const brsaKeys = brsa.generateKeyPair();
  const brsaPublicKey = brsaKeys.publicKey;
  const brsaSecretKey = brsaKeys.secretKey;
  const brsaBlinded = brsaPublicKey.blind(message);
  const brsaBlindSignature = brsaSecretKey.blindSign(brsaBlinded.blindMessage);
  const brsaSignature = brsaPublicKey.finalize(
    brsaBlindSignature,
    brsaBlinded,
    message,
  );

  if (!brsaPublicKey.verify(brsaSignature, brsaBlinded.messageRandomizer, message)) {
    throw new Error("BRSA verification failed");
  }

  const metadata = encoder.encode("browser-smoke-metadata");
  const pbrsaKeys = pbrsa.generateKeyPair({ modulusBits: 1024 });
  const derivedKeys = pbrsaKeys.deriveForMetadata(metadata);
  const pbrsaPublicKey = derivedKeys.publicKey;
  const pbrsaSecretKey = derivedKeys.secretKey;
  const pbrsaBlinded = pbrsaPublicKey.blind(message, metadata);
  const pbrsaBlindSignature = pbrsaSecretKey.blindSign(pbrsaBlinded.blindMessage);
  const pbrsaSignature = pbrsaPublicKey.finalize(
    pbrsaBlindSignature,
    pbrsaBlinded,
    message,
    metadata,
  );

  if (
    !pbrsaPublicKey.verify(
      pbrsaSignature,
      pbrsaBlinded.messageRandomizer,
      message,
      metadata,
    )
  ) {
    throw new Error("PBRSA verification failed");
  }

  status.textContent = "ok brsa pbrsa";
} catch (error) {
  console.error(error);
  status.textContent = `error ${error instanceof Error ? error.message : String(error)}`;
}
