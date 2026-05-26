# RSA Keygen Performance Notes

Last updated: 2026-05-26

This is the synced record for issuer RSA safe-prime key generation performance
testing. The browser tests use Vitest Browser Mode with Playwright-managed
headless Chromium, real Web Workers, and the real WASM package from `pkg/`.
The keygen path is not mocked.

## Variables

| Variable | Values tested | Notes |
|---|---|---|
| RNG strategy | `thread_rng`, `system_rng` | `thread_rng` uses `rand::rng()` in WASM. `system_rng` uses direct `SysRng`, which maps to `globalThis.crypto.getRandomValues` in the worker. |
| Build profile | normal, speed | Normal uses `pnpm run build` with release `opt-level = "s"`. Speed uses `pnpm run build:wasm:speed` with `opt-level = 3`, fat LTO, one codegen unit, `panic = "abort"`, and `wasm-opt -O3`. |
| Concurrent workers | 1, 4, 10 per strategy | Each worker runs one isolated keygen attempt. Current benchmark methodology ends each setup when the first worker succeeds, terminates the remaining workers, repeats the setup five times sequentially, and aggregates those first-success samples. |

## Commands

| Purpose | Command |
|---|---|
| Normal WASM build | `devenv shell pnpm run build` |
| Speed WASM build with default thread RNG | `devenv shell pnpm run build:wasm:speed:thread-rng` |
| Speed WASM build with default system RNG | `devenv shell pnpm run build:wasm:speed:system-rng` |
| Browser worker benchmark | `VITE_RSA_KEYGEN_RUNS=<workers> VITE_RSA_KEYGEN_REPEATS=5 VITE_RSA_KEYGEN_TIMEOUT_MS=3600000 pnpm exec vitest --config vitest.browser.config.ts run test/keygen.browser.test.ts --testTimeout 3600000 --reporter verbose` |

## Benchmark Strategy

| Step | Behavior |
|---|---|
| Start | Launch `Concurrent workers` isolated Web Workers for one RNG strategy. |
| Finish condition | Record the first worker that produces a valid keygen result. |
| Cleanup | Terminate the remaining workers immediately after the first valid result. |
| Repetition | Run the same setup five times sequentially per RNG strategy. |
| Report | Aggregate the five first-success timings per build profile, concurrent worker count, and RNG strategy. |

## Per-Strategy Results

The previous wait-for-all worker measurements are intentionally excluded from
this table. Results below should use the race-to-first strategy above.

| Build | Concurrent workers | Strategy | Repetitions | Fastest first success | Slowest first success | Average first success | Median first success |
|---|---:|---|---:|---:|---:|---:|---:|
| speed | 4 | `thread_rng` | 5 | TBD | TBD | TBD | TBD |
| speed | 4 | `system_rng` | 5 | TBD | TBD | TBD | TBD |

## Current Observations

| Observation | Evidence | Implication |
|---|---|---|
| Previous results need reruns. | Earlier browser-worker benchmarks waited for every worker to finish. | Production-relevant measurements should use race-to-first-success timing. |
| Build profile should be controlled. | Speed and normal WASM builds use different optimization settings. | Compare RNG strategies only within the same build profile. |
| Safe-prime search variance is large. | Earlier batches showed wide timing spreads between workers. | Race-to-first-success should better model concurrent keygen attempts. |
