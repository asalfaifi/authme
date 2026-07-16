import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import { test } from 'node:test';
import { createLogger } from '../src/logging.js';

test('HTTP redirect locations and nested action tokens are redacted from logs', async () => {
  let output = '';
  const destination = new Writable({
    write(chunk, _encoding, callback) { output += chunk.toString(); callback(); },
  });
  const logger = createLogger('info', destination);
  logger.info({
    res: { headers: { location: 'https://client.example/callback?code=secret-code&state=secret-state' } },
    response: { headers: { location: 'https://client.example/callback?response=secret-jarm' } },
    action: { token: 'secret-action-token' },
  }, 'redirect completed');
  await new Promise((resolve) => destination.end(resolve));
  assert.doesNotMatch(output, /secret-code|secret-state|secret-jarm|secret-action-token/u);
  assert.match(output, /\[Redacted\]/u);
});
