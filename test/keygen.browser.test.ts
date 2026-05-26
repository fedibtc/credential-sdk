import { describe, it } from "vitest";
import KeygenBrowserWorker from "./keygen.browser.worker.ts?worker";

type KeygenTiming = {
  readonly run: number;
  readonly elapsedMs: number;
};

type KeygenWorkerResponse =
  | {
      readonly type: "progress";
      readonly run: number;
      readonly message: string;
    }
  | {
      readonly type: "timing";
      readonly timing: KeygenTiming;
    }
  | {
      readonly type: "error";
      readonly message: string;
      readonly stack?: string;
    };

function envValue(name: string): string | undefined {
  const value = import.meta.env?.[name];
  return typeof value === "string" ? value : undefined;
}

function envBool(name: string): boolean {
  const value = envValue(name);
  return (
    value === "1" ||
    value === "true" ||
    value === "TRUE" ||
    value === "yes" ||
    value === "YES" ||
    value === "on" ||
    value === "ON"
  );
}

function envNumber(name: string, defaultValue: number): number {
  const parsed = Number(envValue(name));
  return Number.isInteger(parsed) && parsed > 0 ? parsed : defaultValue;
}

const keygenRuns = envNumber("VITE_RSA_KEYGEN_RUNS", 1);
const runKeygensConcurrently =
  envBool("VITE_RSA_KEYGEN_CONCURRENT") && keygenRuns > 1;
const slowKeygenTimeoutMs = envNumber("VITE_RSA_KEYGEN_TIMEOUT_MS", 1_200_000);

function writeTiming(message: string) {
  console.info(message);
}

function writeRunTiming(timing: KeygenTiming, runCount: number) {
  writeTiming(
    `IssuerContext.generate() browser Worker WASM RSA keygen run ${
      timing.run
    }/${runCount} completed in ${(timing.elapsedMs / 1000).toFixed(3)}s`,
  );
}

function median(values: readonly number[]): number {
  const mid = Math.floor(values.length / 2);
  return values.length % 2 === 0
    ? (values[mid - 1] + values[mid]) / 2
    : values[mid];
}

function reportKeygenStats(
  timings: readonly KeygenTiming[],
  wallElapsedMs: number,
  concurrent: boolean,
) {
  const sortedByElapsed = [...timings].sort(
    (a, b) => a.elapsedMs - b.elapsedMs,
  );
  const sortedSeconds = sortedByElapsed.map(
    (timing) => timing.elapsedMs / 1000,
  );
  const average =
    sortedSeconds.reduce((total, value) => total + value, 0) /
    sortedSeconds.length;
  const fastest = sortedByElapsed[0];
  const slowest = sortedByElapsed[sortedByElapsed.length - 1];

  writeTiming(
    `IssuerContext.generate() browser Worker WASM RSA keygen summary: runs=${
      timings.length
    }, concurrent=${concurrent}, wall=${(wallElapsedMs / 1000).toFixed(
      3,
    )}s, fastest=${(fastest.elapsedMs / 1000).toFixed(3)}s (run ${
      fastest.run
    }), slowest=${(slowest.elapsedMs / 1000).toFixed(3)}s (run ${
      slowest.run
    }), average=${average.toFixed(3)}s, median=${median(sortedSeconds).toFixed(
      3,
    )}s`,
  );

  for (const timing of [...timings].sort((a, b) => a.run - b.run)) {
    writeTiming(
      `IssuerContext.generate() browser Worker WASM RSA keygen sample ${
        timing.run
      }: ${(timing.elapsedMs / 1000).toFixed(3)}s`,
    );
  }
}

function isKeygenWorkerResponse(value: unknown): value is KeygenWorkerResponse {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const response = value as KeygenWorkerResponse;
  return (
    (response.type === "progress" &&
      typeof response.run === "number" &&
      typeof response.message === "string") ||
    (response.type === "timing" &&
      typeof response.timing?.run === "number" &&
      typeof response.timing.elapsedMs === "number") ||
    (response.type === "error" && typeof response.message === "string")
  );
}

function runBrowserWorkerKeygen(
  run: number,
  runCount: number,
): Promise<KeygenTiming> {
  const worker = new KeygenBrowserWorker();

  return new Promise((resolve, reject) => {
    function cleanup() {
      worker.terminate();
    }

    worker.addEventListener("message", (event: MessageEvent<unknown>) => {
      if (!isKeygenWorkerResponse(event.data)) {
        cleanup();
        reject(
          new Error("RSA keygen browser Worker returned an invalid message"),
        );
        return;
      }

      if (event.data.type === "error") {
        cleanup();
        reject(new Error(event.data.stack ?? event.data.message));
        return;
      }

      if (event.data.type === "progress") {
        writeTiming(
          `IssuerContext.generate() browser Worker WASM RSA keygen run ${
            event.data.run
          }/${runCount}: ${event.data.message}`,
        );
        return;
      }

      writeRunTiming(event.data.timing, runCount);
      cleanup();
      resolve(event.data.timing);
    });

    worker.addEventListener("error", (event) => {
      cleanup();
      reject(
        new Error(
          event.message ||
            "RSA keygen browser Worker failed before returning timing",
        ),
      );
    });

    worker.postMessage({ run, runCount });
  });
}

async function runBrowserWorkerKeygens(
  runCount: number,
  concurrent: boolean,
): Promise<KeygenTiming[]> {
  if (concurrent) {
    return Promise.all(
      Array.from({ length: runCount }, (_, index) =>
        runBrowserWorkerKeygen(index + 1, runCount),
      ),
    );
  }

  const timings: KeygenTiming[] = [];
  for (let index = 0; index < runCount; index += 1) {
    timings.push(await runBrowserWorkerKeygen(index + 1, runCount));
  }
  return timings;
}

describe("RSA issuer key generation in a browser Worker", () => {
  it(
    "generates issuer keys and reports timing",
    async () => {
      const wallStarted = performance.now();
      const timings = await runBrowserWorkerKeygens(
        keygenRuns,
        runKeygensConcurrently,
      );

      reportKeygenStats(
        timings,
        performance.now() - wallStarted,
        runKeygensConcurrently,
      );
    },
    slowKeygenTimeoutMs,
  );
});
