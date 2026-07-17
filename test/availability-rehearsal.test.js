import assert from 'node:assert/strict';
import { test } from 'node:test';
import { monitorAvailability } from '../src/operations/availability-rehearsal.js';

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
