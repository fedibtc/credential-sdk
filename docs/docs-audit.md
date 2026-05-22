# Documentation Audit

This internal audit records the result of the first documentation cleanup pass.
It is intentionally not included in TypeDoc `projectDocuments`.

## README.md

Status: current enough to remain the docs landing page.

Findings:

- The main issuance example matches the high-level flow in
  `test/full-issuance-flow.test.ts`.
- The API summary matches the exported WASM classes in `crates/wasm/src/lib.rs`.
- The docs script description needed updating because `pnpm run docs` now builds
  TypeDoc and rustdoc.
- Remaining gap: README is doing too much. The new top-level docs pages should
  gradually take over quickstart, architecture, protocol flow, and
  verification/revocation detail.

## docs/mvp-design.md

Status: historical product and protocol design notes.

Current protocol facts worth preserving:

- The actor model is issuer, holder, verifier.
- Issuer bundles bind issuer identity, issuance key, and revocation locations.
- Credentials separate issuer-visible `info` from holder-hidden `blind_msg`
  during issuance.
- Revocations are signed by issuer identity keys and refer to credential
  digests.
- QR, Nostr relay, HTTP, browser storage, and UI concerns are application-owned.

Historical or stale material:

- "Fedi Blue Check", "Masters/Knights", mini-app UX, and tabbed web app flows are
  product/MVP context, not SDK usage guidance.
- Schema definition publication is exploratory and not implemented as an SDK API.
- Several example JSON snippets predate the current exact wire formats.
- The text says revocation locations must be scanned by verifiers. The SDK can
  verify ingested revocations, but fetching/scanning is application-owned.

Decision: keep this file in the repository as historical notes, but do not
include it in TypeDoc project documents.

## docs/library-todos.md

Status: internal implementation tracker.

Findings:

- It remains useful for library engineering work.
- Some checklist names no longer match the high-level public WASM API exactly.
- It should not be presented as public integration documentation.

Decision: keep this file in the repository, but do not include it in TypeDoc
project documents.

## Tests

Canonical example sources:

- `test/full-issuance-flow.test.ts`: best end-to-end source for the quickstart.
- `test/credential.test.ts`: best source for pending issuance persistence,
  import/export, and mismatch failure examples.
- `test/verification.test.ts`: best source for issuer bundle and revocation
  verification examples.

Decision: future public examples should either be extracted from tests or kept
close enough to these tests that drift is easy to catch.

## Public TypeDoc Documents

The generated docs site should use an explicit ordered `projectDocuments` list:

- `docs/quickstart.md`
- `docs/architecture.md`
- `docs/protocol-flow.md`
- `docs/verification-and-revocation.md`
- `docs/rust-api.md`

This excludes internal planning files and historical notes from the public docs
navigation while keeping them available in the repository.
