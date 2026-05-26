# RSA Keygen Performance Notes

Last updated: 2026-05-26

This is the synced record for issuer RSA safe-prime key generation performance
testing. The browser tests use Vitest Browser Mode with Playwright-managed
headless Chromium, real Web Workers, and the real WASM package from `pkg/`.
The keygen path is not mocked.

## Variables

| Variable | Values tested | Notes |
|---|---|---|
| RNG strategy | `thread_rng`, `system_rng` | `thread_rng` uses `rand::rng()` in WASM. `system_rng` uses direct `SysRng`, which maps to `globalThis.crypto.getRandomValues` in the worker. Use `VITE_RSA_KEYGEN_STRATEGIES=thread_rng` to run only one strategy. |
| Build profile | speed | `pnpm run build` and `pnpm run build:wasm:speed` use `opt-level = 3`, fat LTO, one codegen unit, `panic = "abort"`, and `wasm-opt -O3`. |
| Concurrent workers | 1, 4, 6, 8, 10 per strategy | Each worker runs one isolated keygen attempt. Current benchmark methodology ends each setup when the first worker succeeds, terminates the remaining workers, repeats the setup five times sequentially, and aggregates those first-success samples. |
| CPU throttle rate | unset, `1`, `4`, etc. | Optional Chromium DevTools Protocol CPU throttling for browser-worker benchmarks. Use `VITE_RSA_KEYGEN_CPU_THROTTLE_RATE=<rate>`; unset or `1` means unthrottled. |

## Commands

| Purpose | Command |
|---|---|
| Speed WASM build with default thread RNG | `devenv shell pnpm run build` |
| Speed WASM build with system RNG | `devenv shell pnpm run build:wasm:sys-rng` |
| Browser worker benchmark | `VITE_RSA_KEYGEN_STRATEGIES=<strategy> VITE_RSA_KEYGEN_CONCURRENT_WORKERS=<workers> VITE_RSA_KEYGEN_REPEATS=5 VITE_RSA_KEYGEN_TIMEOUT_MS=3600000 pnpm exec vitest --config vitest.browser.config.ts run test/keygen.browser.test.ts --testTimeout 3600000 --reporter verbose` |
| Browser worker benchmark with CPU throttle | `VITE_RSA_KEYGEN_CPU_THROTTLE_RATE=<rate> VITE_RSA_KEYGEN_STRATEGIES=<strategy> VITE_RSA_KEYGEN_CONCURRENT_WORKERS=<workers> VITE_RSA_KEYGEN_REPEATS=5 VITE_RSA_KEYGEN_TIMEOUT_MS=3600000 pnpm exec vitest --config vitest.browser.config.ts run test/keygen.browser.test.ts --testTimeout 3600000 --reporter verbose` |

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

| Build | Concurrent workers | CPU throttle rate | Strategy | Repetitions | Fastest first success | Slowest first success | Average first success | Median first success |
|---|---:|---:|---|---:|---:|---:|---:|---:|
| speed | 1 | 4 | `thread_rng` | 5 | 27.935s | 129.064s | 85.383s | 86.787s |
| speed | 4 | 4 | `thread_rng` | 5 | 10.677s | 39.096s | 27.116s | 29.451s |
| speed | 6 | 4 | `thread_rng` | 5 | 3.781s | 41.572s | 17.280s | 11.764s |
| speed | 8 | 4 | `thread_rng` | 5 | 26.922s | 68.052s | 39.306s | 31.053s |

## Current Observations

| Observation | Evidence | Implication |
|---|---|---|
| Previous results need reruns. | Earlier browser-worker benchmarks waited for every worker to finish. | Production-relevant measurements should use race-to-first-success timing. |
| Build profile should be controlled. | Speed and normal WASM builds use different optimization settings. | Compare RNG strategies only within the same build profile. |
| CPU throttle should be controlled. | Chromium CPU throttling is optional and changes execution timing. | Compare runs only within the same throttle rate. |
| Safe-prime search variance is large. | Earlier batches showed wide timing spreads between workers. | Race-to-first-success should better model concurrent keygen attempts. |
| More workers can still regress. | In the speed/thread-RNG/4x-throttle run, 6 workers had the best median and average, while 8 workers was slower. | Worker count needs tuning instead of assuming more concurrent attempts is always better. |
