import assert from 'node:assert/strict';
import { test } from 'node:test';
import { monitorAvailability, probeRealmAvailability } from '../src/operations/availability-rehearsal.js';

test('realm availability probe validates readiness and exact protocol discovery', async () => {
  const fetch = async (url) => {
    const path = new URL(url).pathname;
    if (path === '/health/ready') return new Response(JSON.stringify({ status: 'ready' }), { status: 200 });
    return new Response(JSON.stringify({
      issuer: 'https://auth.example.test/realms/master',
      authorization_endpoint: 'https://auth.example.test/realms/master/protocol/openid-connect/auth',
      token_endpoint: 'https://auth.example.test/realms/master/protocol/openid-connect/token',
      jwks_uri: 'https://auth.example.test/realms/master/protocol/openid-connect/certs',
    }), { status: 200 });
  };
  assert.deepEqual(await probeRealmAvailability({ origin: 'https://auth.example.test', realm: 'master', fetch }), {
    ready: 'ready', issuer: 'https://auth.example.test/realms/master',
  });
  await assert.rejects(probeRealmAvailability({
    origin: 'https://auth.example.test', realm: 'master',
    fetch: async () => new Response(JSON.stringify({ status: 'ready' }), { status: 200 }),
  }), /discovery/iu);
  await assert.rejects(probeRealmAvailability({
    origin: 'https://auth.example.test', realm: 'master',
    fetch: async (url) => new Response(JSON.stringify(new URL(url).pathname === '/health/ready'
      ? { status: 'ready' }
      : {
          issuer: 'https://auth.example.test/realms/master',
          authorization_endpoint: 'https://attacker.example.test/authorize',
          token_endpoint: 'https://auth.example.test/realms/master/protocol/openid-connect/token',
          jwks_uri: 'https://auth.example.test/realms/master/protocol/openid-connect/certs',
        }), { status: 200 }),
  }), /discovery/iu);
});

test('availability monitor probes throughout an operation and reports transient failures', async () => {
  let probes = 0;
  const result = await monitorAvailability({
    intervalMs: 2,
    async probe() {
      probes += 1;
      if (probes === 2) throw new Error('transient readiness failure');
    },
    async operation() {
      while (probes < 4) await new Promise((resolve) => setTimeout(resolve, 2));
    },
  });
  assert.equal(result.operationError, undefined);
  assert(result.report.samples >= 3);
  assert.equal(result.report.failures, 1);
  assert.match(result.report.failureSamples[0].error, /readiness failure/iu);
});

test('availability monitor preserves rollout errors in its result', async () => {
  const expected = new Error('rollout failed');
  const result = await monitorAvailability({
    intervalMs: 1,
    async probe() {},
    async operation() { throw expected; },
  });
  assert.equal(result.operationError, expected);
  assert.equal(result.report.failures, 0);
  assert(result.report.samples >= 1);
});
