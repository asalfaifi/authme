#!/usr/bin/env node
import { performance } from 'node:perf_hooks';

function option(name, fallback) { const index = process.argv.indexOf(name); return index === -1 ? fallback : process.argv[index + 1]; }
const baseUrl = option('--base-url');
const requests = Number(option('--requests', '500'));
const concurrency = Number(option('--concurrency', '25'));
const p95TargetMs = Number(option('--p95-ms', '500'));
if (!baseUrl || !Number.isSafeInteger(requests) || requests < 1 || !Number.isSafeInteger(concurrency) || concurrency < 1) {
  throw new Error('Usage: npm run perf:rehearse -- --base-url https://auth.example.com [--requests 500 --concurrency 25 --p95-ms 500]');
}
const endpoint = new URL('/realms/master/.well-known/openid-configuration', baseUrl);
const durations = [];
let failures = 0;
let next = 0;
async function worker() {
  while (next < requests) {
    next += 1;
    const started = performance.now();
    try {
      const response = await fetch(endpoint, { cache: 'no-store', signal: AbortSignal.timeout(10_000) });
      if (!response.ok) failures += 1;
      await response.arrayBuffer();
    } catch { failures += 1; }
    durations.push(performance.now() - started);
  }
}
const started = performance.now();
await Promise.all(Array.from({ length: Math.min(concurrency, requests) }, worker));
durations.sort((left, right) => left - right);
const elapsed = performance.now() - started;
const percentile = (value) => durations[Math.min(durations.length - 1, Math.ceil(durations.length * value) - 1)];
const report = {
  endpoint: endpoint.href, requests, concurrency, failures,
  throughputPerSecond: Number((requests / (elapsed / 1000)).toFixed(2)),
  latencyMs: { p50: Number(percentile(0.5).toFixed(2)), p95: Number(percentile(0.95).toFixed(2)), p99: Number(percentile(0.99).toFixed(2)) },
  target: { failures: 0, p95Ms: p95TargetMs },
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (failures || report.latencyMs.p95 > p95TargetMs) process.exitCode = 1;
