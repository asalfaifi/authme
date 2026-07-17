#!/usr/bin/env node
import { performance } from 'node:perf_hooks';
import { authorizationCodeRoundTrip } from '../src/operations/authorization-code-rehearsal.js';

function option(name, fallback) { const index = process.argv.indexOf(name); return index === -1 ? fallback : process.argv[index + 1]; }
const baseUrl = option('--base-url');
const requests = Number(option('--requests', '500'));
const concurrency = Number(option('--concurrency', '25'));
const p95TargetMs = Number(option('--p95-ms', '500'));
const scenario = option('--scenario', 'discovery');
const realm = process.env.AUTHME_PERF_REALM ?? 'master';
if (!baseUrl || !Number.isSafeInteger(requests) || requests < 1 || !Number.isSafeInteger(concurrency) || concurrency < 1
  || !Number.isFinite(p95TargetMs) || p95TargetMs <= 0 || !/^[a-z][a-z0-9-]{0,62}$/u.test(realm)) {
  throw new Error('Usage: npm run perf:rehearse -- --base-url https://auth.example.com [--scenario discovery|authorization-code --requests 500 --concurrency 25 --p95-ms 500]');
}
if (!['discovery', 'authorization-code'].includes(scenario)) throw new Error('--scenario must be discovery or authorization-code');
const endpoint = new URL(`/realms/${encodeURIComponent(realm)}/.well-known/openid-configuration`, baseUrl);
const durations = [];
let failures = 0;
let next = 0;
async function worker() {
  while (next < requests) {
    next += 1;
    const started = performance.now();
    try {
      if (scenario === 'authorization-code') {
        await authorizationCodeRoundTrip({
          baseUrl,
          realm,
          clientId: process.env.AUTHME_PERF_CLIENT_ID,
          clientSecret: process.env.AUTHME_PERF_CLIENT_SECRET,
          redirectUri: process.env.AUTHME_PERF_REDIRECT_URI,
          username: process.env.AUTHME_PERF_USERNAME,
          password: process.env.AUTHME_PERF_PASSWORD,
          otp: process.env.AUTHME_PERF_OTP ?? '',
          scope: process.env.AUTHME_PERF_SCOPE ?? 'openid offline_access',
          resource: process.env.AUTHME_PERF_RESOURCE,
        });
      } else {
        const response = await fetch(endpoint, { cache: 'no-store', signal: AbortSignal.timeout(10_000) });
        if (!response.ok) failures += 1;
        const discovery = await response.json();
        if (discovery.issuer !== new URL(`/realms/${encodeURIComponent(realm)}`, baseUrl).href.replace(/\/$/u, '')) failures += 1;
      }
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
  scenario, endpoint: scenario === 'discovery' ? endpoint.href : 'authorization-code + token + optional refresh', requests, concurrency, failures,
  throughputPerSecond: Number((requests / (elapsed / 1000)).toFixed(2)),
  latencyMs: { p50: Number(percentile(0.5).toFixed(2)), p95: Number(percentile(0.95).toFixed(2)), p99: Number(percentile(0.99).toFixed(2)) },
  target: { failures: 0, p95Ms: p95TargetMs },
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (failures || report.latencyMs.p95 > p95TargetMs) process.exitCode = 1;
