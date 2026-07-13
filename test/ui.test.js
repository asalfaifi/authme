import test from 'node:test';
import assert from 'node:assert/strict';
import {
  renderConsent,
  renderDeviceConfirmation,
  renderDeviceInput,
  renderDeviceSuccess,
  renderLogin,
  renderLogoutConfirmation,
  renderLogoutSuccess,
} from '../src/ui/render.js';

test('authentication pages escape client-controlled display values', () => {
  const attack = '<img src=x onerror=alert(1)>';
  const pages = [
    renderLogin({ realm: 'master', uid: 'one', csrfToken: 'csrf', clientName: attack }),
    renderConsent({ realm: 'master', uid: 'two', csrfToken: 'csrf', clientName: attack, scopes: [attack] }),
    renderDeviceConfirmation({ realm: 'master', form: '<form id="op.deviceConfirmForm"></form>', clientName: attack, userCode: attack }),
    renderDeviceSuccess({ realm: 'master', clientName: attack }),
    renderLogoutConfirmation({ realm: 'master', form: '<form id="op.logoutForm"></form>', clientName: attack }),
    renderLogoutSuccess({ realm: 'master', clientName: attack }),
  ];
  for (const page of pages) {
    assert.doesNotMatch(page, /<img src=x/);
    assert.match(page, /&lt;img src=x/);
    assert.match(page, /\/assets\/authme\.css/);
    assert.match(page, /\/assets\/authme-passkeys\.css/);
  }
  const login = renderLogin({ realm: 'master', uid: 'login', csrfToken: 'csrf', clientName: 'Client' });
  assert.match(login, /data-passkey-options="\/realms\/master\/interaction\/login\/passkey\/options"/);
  assert.match(login, /data-passkey-verify="\/realms\/master\/interaction\/login\/passkey"/);
  assert.match(login, /src="\/assets\/authme-passkeys\.js"/);

  const federated = renderLogin({
    realm: 'master', uid: 'login', csrfToken: 'csrf', clientName: 'Client',
    federationProviders: [{
      extensionId: 'builtin.oidc-federation',
      providerId: 'workforce',
      displayName: '<Corporate SSO>',
      csrfToken: 'provider-bound-csrf',
    }],
  });
  assert.match(federated, /action="\/realms\/master\/interaction\/login\/federation\/builtin\.oidc-federation\/workforce"/);
  assert.match(federated, /value="provider-bound-csrf"/);
  assert.match(federated, /Continue with &lt;Corporate SSO&gt;/);
  assert.doesNotMatch(federated, /Continue with <Corporate SSO>/);
});

test('device input embeds only the provider-generated form slot', () => {
  const form = '<form id="op.deviceInputForm"><input name="user_code"></form>';
  const page = renderDeviceInput({ realm: 'master', form, error: 'Invalid <code>' });
  assert.match(page, /id="op\.deviceInputForm"/);
  assert.match(page, /form="op\.deviceInputForm"/);
  assert.match(page, /Invalid &lt;code&gt;/);
});
