import { performance } from 'node:perf_hooks';

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export async function probeRealmAvailability({ origin, realm, fetch: fetchImpl = globalThis.fetch }) {
  const normalizedOrigin = new URL(origin).origin;
  if (typeof realm !== 'string' || !/^[a-z][a-z0-9-]{0,62}$/u.test(realm)) throw new TypeError('A valid realm is required');
  const request = async (path) => {
    const response = await fetchImpl(`${normalizedOrigin}${path}`, {
      cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error(`${path} returned HTTP ${response.status}`);
    return response.json();
  };
  const realmPath = `/realms/${encodeURIComponent(realm)}`;
  const [ready, discovery] = await Promise.all([
    request('/health/ready'),
    request(`${realmPath}/.well-known/openid-configuration`),
  ]);
  const issuer = `${normalizedOrigin}${realmPath}`;
  const expectedEndpoints = {
    authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
    token_endpoint: `${issuer}/protocol/openid-connect/token`,
    jwks_uri: `${issuer}/protocol/openid-connect/certs`,
  };
  if (ready.status !== 'ready') throw new Error('Readiness response was not ready');
  if (discovery.issuer !== issuer
    || Object.entries(expectedEndpoints).some(([name, value]) => discovery[name] !== value)) {
    throw new Error('Realm discovery response is incomplete or has the wrong issuer');
  }
  return { ready: ready.status, issuer: discovery.issuer };
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
