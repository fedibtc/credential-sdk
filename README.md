# @fedi/blind-rsa-signatures-wasm

WebAssembly bindings for the Rust [`blind-rsa-signatures`](https://crates.io/crates/blind-rsa-signatures) crate.

This package exposes the recommended SHA-384/PSS/randomized configuration for:

- regular blind RSA signatures (`brsa`)
- partially blind RSA signatures with metadata (`pbrsa`)

## Development

```sh
devenv shell
npm install
npm run build
```

`npm run build` uses `wasm-pack build --target bundler --out-dir pkg`, then compiles the TypeScript wrapper into `dist/`.

## Regular Blind RSA

```ts
import { brsa } from "@fedi/blind-rsa-signatures-wasm";

const keys = brsa.KeyPair.generate(2048);
const message = new TextEncoder().encode("token");

const publicKey = keys.publicKey;
const secretKey = keys.secretKey;

const blinded = publicKey.blind(message);
const blindSignature = secretKey.blindSign(blinded.blindMessage);
const signature = publicKey.finalize(blindSignature, blinded, message);

console.log(publicKey.verify(signature, blinded.messageRandomizer, message));
```

## Partially Blind RSA

```ts
import { pbrsa } from "@fedi/blind-rsa-signatures-wasm";

const masterKeys = pbrsa.KeyPair.generate(2048);
const metadata = new TextEncoder().encode("2026-05-11");
const message = new TextEncoder().encode("token");

const derivedKeys = masterKeys.deriveForMetadata(metadata);
const publicKey = derivedKeys.publicKey;
const secretKey = derivedKeys.secretKey;

const blinded = publicKey.blind(message, metadata);
const blindSignature = secretKey.blindSign(blinded.blindMessage);
const signature = publicKey.finalize(blindSignature, blinded, message, metadata);

console.log(
  publicKey.verify(signature, blinded.messageRandomizer, message, metadata),
);
```

Byte inputs are `Uint8Array`. Metadata is byte-exact.

Derived PBRSA keys are Rust-backed WebAssembly objects. They are not serialized as DER or PEM because the underlying Rust crate does not serialize derived keys to standard key formats.
