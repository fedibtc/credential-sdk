import { brsa, pbrsa } from "../dist/index.js";

const status = document.querySelector("#status");
const encoder = new TextEncoder();

if (!(status instanceof HTMLOutputElement)) {
  throw new Error("Missing status output");
}

try {
  const message = encoder.encode("browser-smoke-message");

  const brsaKeys = brsa.KeyPair.generate(2048);
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
  const pbrsaKeys = pbrsa.KeyPair.generate(1024);
  console.log("pbrsaKeys", pbrsaKeys);
  const derivedKeys = pbrsaKeys.deriveForMetadata(metadata);
  console.log("derivedKeys", derivedKeys);
  const pbrsaPublicKey = derivedKeys.publicKey;
  const pbrsaSecretKey = derivedKeys.secretKey;
  console.log("pbrsaPublicKey", pbrsaPublicKey);
  console.log("pbrsaSecretKey", pbrsaSecretKey);
  const pbrsaBlinded = pbrsaPublicKey.blind(message, metadata);
  console.log("pbrsaBlinded", pbrsaBlinded);
  const pbrsaBlindSignature = pbrsaSecretKey.blindSign(pbrsaBlinded.blindMessage);
  console.log("pbrsaBlindSignature", pbrsaBlindSignature);
  const pbrsaSignature = pbrsaPublicKey.finalize(
    pbrsaBlindSignature,
    pbrsaBlinded,
    message,
    metadata,
  );
  console.log("pbrsaSignature (unblinded)", pbrsaSignature);

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
