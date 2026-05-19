# @fedibtc/blind-rsa-signatures-wasm

WebAssembly bindings for a partially blind RSA verifiable credential protocol.

The library is intended to own the protocol-sensitive pieces of credential issuance and verification: holder blinding, issuer partial blind signing, holder finalization, runtime validation, and the WASM/TypeScript API surface around those operations.

It deliberately does not own app concerns such as browser storage, QR codes, Nostr relay I/O, HTTP fetching, UI state, verifier policy, or revocation list refresh jobs.

## Credential Flow

The current protocol shape separates issuer-visible data from holder-hidden data:

```ts
{
  credential: {
    info: {
      schema: "trust-score-v1",
      issuer_id_pubkey: "issuer-id-pubkey",
      score: 7,
    },
    blind_msg: "anonymous-holder-public-key",
  },
  proof: {
    signature: "RSA-signature",
  },
}
```

During issuance, `credential.info` is public and `credential.blind_msg` is blinded. The issuer partially blind-signs both pieces together: `blind_msg` is the hidden payload, and `info` is the visible credential data. During finalization, the holder unblinds the signature and gets the final verifiable credential shape above.

## Public API

The current high-level API is:

- `generateIssuerKeys(modulusBits)`
- `createCredential(blindedData, visibleData)`
- `blindSignCredential(blindedData, visibleData, issuerKeys)`
- `finalizeCredential(blindSignedCredential, issuerPublicKey)`

The low-level key surface is intentionally small:

- `PbrsaPublicKey.blind(blind_msg, info)`
- `PbrsaSecretKey.blindSign(blind_msg, info)`
- `PbrsaPublicKey.verify(signature, messageRandomizer, blind_msg, info)`

## Status

This checklist is intentionally shorter than [docs/library-todos.md](docs/library-todos.md). It tracks the major pieces needed before this can be treated as a complete reusable protocol library.

- [x] Rust/WASM build wired through `wasm-pack`
- [x] pnpm, TypeScript, Vitest, and Rust test workflows
- [x] Minimal public pbRSA key API for issuer key generation, blinding, partial blind signing, and verification
- [x] Holder blinding flow with retained unblinding state
- [x] Credential template construction in the protocol credential shape
- [x] Partial blind signing over hidden `blind_msg` plus visible `credential.info`
- [x] Holder finalization into a verifiable credential with an unblinded signature
- [x] Tamper and mismatch tests for blind-signed credentials and finalization
- [x] Initial canonical protocol structs for issuer bundles, credentials, and revocation objects
- [ ] Implement issuer bundle creation and verification
- [ ] Replace issuer issuance stubs with finalized request/response helpers
- [ ] Implement full `verifyCredential`
- [ ] Implement credential digesting and revocation creation/verification
- [ ] Specify canonical JSON encoding formally rather than relying on the current internal canonicalizer
- [ ] Add typed, machine-readable errors
- [ ] Add deterministic fixtures and stable test vectors
- [ ] Add encode/decode helpers for all protocol messages
- [ ] Complete a security review of domain separation, randomness, key handling, replay risk, and malformed input behavior

## Development

```sh
devenv shell
pnpm install
pnpm run build
pnpm test
```

`pnpm run build` runs `wasm-pack build crates/wasm --scope fedibtc --target bundler --out-dir ../../pkg --no-opt`. Run it inside `devenv shell` so `secp256k1-sys` uses Nix LLVM clang for wasm32 C code.

Useful scripts:

- `pnpm run docs` rebuilds the WASM package and generates the TypeDoc API reference in `dist/docs/api`; run it inside `devenv shell`.
- `pnpm run docs:serve` rebuilds the API reference and serves it locally with Vite; run it inside `devenv shell`.
- `pnpm run test:rust` runs Rust unit tests for the full workspace.
- `pnpm run test:ts` rebuilds the WASM package, typechecks TypeScript, and runs Vitest.
- `pnpm run check` runs typecheck and the full test suite.
- `pnpm run publish:dry-run` builds and validates the generated package before publishing.
