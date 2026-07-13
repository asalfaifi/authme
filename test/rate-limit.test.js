import assert from 'node:assert/strict';
import test from 'node:test';
import { createRateLimits } from '../src/security/rate-limit.js';

test('a blocked IP cannot consume arbitrary account limiter buckets', async () => {
  const limits = createRateLimits(
    { redisUrl: undefined, passwordPepper: 'rate-limit-test-pepper-000000000000' },
    { warn() {} },
  );
  try {
    for (let index = 0; index < 20; index += 1) {
      await limits.consumeLogin('198.51.100.10', `account-${index}`);
    }
    for (let index = 0; index < 12; index += 1) {
      await assert.rejects(limits.consumeLogin('198.51.100.10', 'victim@example.test'));
    }
    await assert.doesNotReject(limits.consumeLogin('198.51.100.11', 'victim@example.test'));
  } finally {
    await limits.close();
  }
});
