import assert from 'node:assert/strict';
import test from 'node:test';

import { loadAccountEmailSender } from '../src/account/email-delivery.js';

const base = {
  publicUrl: 'https://auth.example.test',
  realms: ['master'],
};

test('standalone account delivery loads a deployment module and validates both recovery methods', async () => {
  const specifier = new URL('../test-support/account-email.js', import.meta.url).href;
  const sender = await loadAccountEmailSender({ ...base, accountEmailModule: specifier });
  await sender.sendEmailVerification({});
  await sender.sendPasswordReset({});
  await assert.rejects(loadAccountEmailSender({ ...base, accountEmailModule: 'invalid' }, async () => ({
    default: { async sendPasswordReset() {} },
  })), /sendEmailVerification/iu);
});

test('standalone account delivery remains explicitly unavailable when no module is configured', async () => {
  assert.equal(await loadAccountEmailSender({ ...base, accountEmailModule: undefined }), undefined);
});
