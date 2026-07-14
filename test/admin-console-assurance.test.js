import assert from 'node:assert/strict';
import test from 'node:test';

import { hasStrongAdminAuthentication } from '../src/routes/admin-console.js';
import { normalizeAdminPermissions } from '../src/security/admin-permissions.js';

test('administrator assurance requires a passkey or primary authentication plus a second factor', () => {
  assert.equal(hasStrongAdminAuthentication(['passkey']), true);
  assert.equal(hasStrongAdminAuthentication(['webauthn']), true);
  assert.equal(hasStrongAdminAuthentication(['pwd', 'otp']), true);
  assert.equal(hasStrongAdminAuthentication(['pwd', 'recovery']), true);
  assert.equal(hasStrongAdminAuthentication(['ldap', 'otp']), true);
  assert.equal(hasStrongAdminAuthentication(['federated', 'otp']), true);

  assert.equal(hasStrongAdminAuthentication(['federated']), false);
  assert.equal(hasStrongAdminAuthentication(['pwd']), false);
  assert.equal(hasStrongAdminAuthentication(['otp']), false);
  assert.equal(hasStrongAdminAuthentication(['mfa']), false);
  assert.equal(hasStrongAdminAuthentication([]), false);
  assert.equal(hasStrongAdminAuthentication(null), false);
});

test('administrator-account protection is an explicit grant permission', () => {
  assert.deepEqual(normalizeAdminPermissions(['administrators.manage']), ['administrators.manage']);
});
