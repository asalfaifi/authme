import { performance } from 'node:perf_hooks';

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export async function monitorAvailability({ probe, operation, intervalMs = 250 }) {
  if (typeof probe !== 'function' || typeof operation !== 'function') throw new TypeError('probe and operation functions are required');
  if (!Number.isFinite(intervalMs) || intervalMs < 1) throw new TypeError('intervalMs must be a positive number');
  const samples = [];
  let running = true;
  const monitor = (async () => {
    while (running) {
      const started = performance.now();
      try {
        await probe();
        samples.push({ at: new Date().toISOString(), ok: true, latencyMs: Number((performance.now() - started).toFixed(2)) });
      } catch (error) {
        samples.push({
          at: new Date().toISOString(), ok: false,
          latencyMs: Number((performance.now() - started).toFixed(2)),
          error: error instanceof Error ? error.message : String(error),
        });
      }
      if (running) await delay(intervalMs);
    }
  })();
  let operationError;
  const operationStarted = performance.now();
  try {
    await operation();
  } catch (error) {
    operationError = error;
  } finally {
    running = false;
    await monitor;
  }
  const failures = samples.filter((sample) => !sample.ok);
  const latencies = samples.map((sample) => sample.latencyMs);
  return {
    report: {
      intervalMs,
      durationMs: Number((performance.now() - operationStarted).toFixed(2)),
      samples: samples.length,
      failures: failures.length,
      maxLatencyMs: latencies.length ? Math.max(...latencies) : null,
      failureSamples: failures.slice(0, 20),
    },
    operationError,
  };
}
