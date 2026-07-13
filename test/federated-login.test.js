import assert from 'node:assert/strict';
import { test } from 'node:test';

import { resolveFederatedLogin } from '../src/authentication/federated-login.js';

const result = {
  protocol: 'oidc', providerId: 'workforce', issuer: 'https://idp.example.test',
  allowCreate: true,
  profile: { externalSubject: 'subject-1', username: 'alice', email: 'alice@example.test' },
};

test('validated federation results are resolved by immutable provider subject', async () => {
  let input;
  const resolution = await resolveFederatedLogin({
    realm: 'staff', result, repository: { async resolve(value) {
      input = value;
      return { status: 'created', user: { id: 'user-1', enabled: true } };
    } },
  });
  assert.equal(resolution.user.id, 'user-1');
  assert.deepEqual(input, {
    realm: 'staff', providerId: 'workforce', issuer: 'https://idp.example.test', externalSubject: 'subject-1',
    profile: result.profile, allowCreate: true,
  });
});

test('federated account creation is denied unless the provider explicitly opts in', async () => {
  let input;
  await assert.rejects(() => resolveFederatedLogin({
    realm: 'staff', result: { ...result, allowCreate: undefined }, repository: { async resolve(value) {
      input = value;
      return { status: 'not_found' };
    } },
  }), (error) => error.code === 'AUTHME_FEDERATED_ACCOUNT_REQUIRED');
  assert.equal(input.allowCreate, false);
});

test('federation collisions, disabled accounts, and disabled JIT fail closed', async () => {
  for (const [status, code] of [
    ['link_required', 'AUTHME_FEDERATED_LINK_REQUIRED'],
    ['not_found', 'AUTHME_FEDERATED_ACCOUNT_REQUIRED'],
    ['disabled', 'AUTHME_FEDERATED_LOGIN_DENIED'],
  ]) {
    await assert.rejects(
      () => resolveFederatedLogin({ realm: 'staff', result, repository: { resolve: async () => ({ status }) } }),
      (error) => error.code === code && error.status === 403,
    );
  }
});
