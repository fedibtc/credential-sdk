# @fedibtc/credential-sdk

WebAssembly bindings for a partially blind RSA verifiable credential protocol.

The library is intended to own the protocol-sensitive pieces of credential issuance and verification: holder blinding, issuer partial blind signing, holder finalization, runtime validation, and the WASM/TypeScript API surface around those operations.

It deliberately does not own app concerns such as browser storage, QR codes, Nostr relay I/O, HTTP fetching, UI state, verifier policy, or revocation list refresh jobs.

## Credential Flow

The current protocol shape separates issuer-visible data from holder-hidden data:

```ts
{
  version: 1,
  credential: {
    issuer_id_pubkey: "issuer-id-pubkey",
    info: {
      schema: "trust-score-v1",
      trust_level: 7,
    },
    blind_msg: "anonymous-holder-public-key",
  },
  proof: {
    signature: "base64url-rsa-signature",
  },
}
```

During issuance, `credential.info` is public and `credential.blind_msg` is blinded. The holder creates an `IssuanceRequest` plus local pending state, the issuer returns an `IssuanceResponse`, and the holder finalizes that response into the verifiable credential shape above. The issuer partially blind-signs both pieces together: `blind_msg` is the hidden payload, and `info` is the visible credential data.

`PendingIssuance` can be exported as a versioned string and imported again after a browser reload:

```ts
const { request, pending } = PendingIssuance.createRequest(
  issuerBundle,
  info,
  blindMsg,
);
const pendingState = pending.exportState();

// Store request and pendingState in application storage while issuance is pending.
const importedPending = PendingIssuance.importState(pendingState);
const credential = importedPending.finalize(issuerBundle, response);
```

The exported pending issuance state is sensitive holder-side issuance material. It is not a long-term holder private key, but it is required to unblind and finalize the issuer response, so applications should avoid logging or sharing it.

## Public API

The current high-level API is organized around runtime contexts:

- `IssuerContext`: generate/import/export issuer keys, create signed issuer bundles, issue credentials, and create signed revocations
- `PendingIssuance`: create holder issuance requests and finalize issuer responses
- `HolderContext`: generate/import/export holder identity keys
- `VerificationContext`: trust issuer bundles, ingest revocations, and verify credentials

## Status

This checklist is intentionally shorter than [docs/library-todos.md](docs/library-todos.md). It tracks coarse reusable-library readiness rather than every implementation detail.

- [x] Rust/WASM build and TypeScript/Rust test workflows
- [x] Runtime issuer, holder, and verifier contexts exposed through WASM/TypeScript
- [x] Signed issuer bundle creation and verification
- [x] Holder issuance request flow with retained pending unblinding state
- [x] Issuer issuance response flow with partially blind signing over hidden `blind_msg` plus visible `credential.info`
- [x] Holder finalization into a verifiable credential with an unblinded signature
- [x] Credential verification against trusted issuer bundles
- [x] Credential digesting plus signed revocation creation and verification
- [x] Revocation-aware credential verification
- [x] RFC 8785/JCS canonical JSON encoding with domain-separated credential, issuer bundle, and revocation digests/signatures
- [x] Deterministic protocol snapshots for issuer bundles, issuance messages, credentials, revocations, and verifier outcomes
- [ ] Expose machine-readable error or verification result codes across the WASM boundary
- [ ] Complete a security review of the pbRSA suite, domain separation, randomness, key handling, replay risk, and malformed input behavior

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
