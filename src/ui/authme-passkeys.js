function decodeBase64url(value) {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodeBase64url(value) {
  const bytes = new Uint8Array(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function assertionJSON(credential) {
  return {
    id: credential.id,
    rawId: encodeBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: encodeBase64url(credential.response.clientDataJSON),
      authenticatorData: encodeBase64url(credential.response.authenticatorData),
      signature: encodeBase64url(credential.response.signature),
      userHandle: credential.response.userHandle
        ? encodeBase64url(credential.response.userHandle)
        : undefined,
    },
  };
}

const button = document.querySelector('[data-passkey-options]');
const status = document.querySelector('[data-passkey-status]');
const loginForm = document.querySelector('[data-password-login]');

if (button && status && loginForm && window.PublicKeyCredential && navigator.credentials) {
  button.hidden = false;
  button.addEventListener('click', async () => {
    button.disabled = true;
    status.textContent = 'Waiting for your passkey…';
    try {
      const csrf = loginForm.elements.csrf.value;
      const response = await fetch(button.dataset.passkeyOptions, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
        body: new URLSearchParams({ csrf }),
      });
      if (!response.ok) throw new Error('Passkey options were unavailable');
      const ceremony = await response.json();
      const publicKey = ceremony.publicKey;
      publicKey.challenge = decodeBase64url(publicKey.challenge);
      if (publicKey.allowCredentials) {
        publicKey.allowCredentials = publicKey.allowCredentials.map((credential) => ({
          ...credential,
          id: decodeBase64url(credential.id),
        }));
      }
      const credential = await navigator.credentials.get({ publicKey });
      if (!credential) throw new Error('No passkey assertion was returned');

      const form = document.createElement('form');
      form.method = 'post';
      form.action = button.dataset.passkeyVerify;
      for (const [name, value] of Object.entries({
        csrf,
        challengeId: ceremony.challengeId,
        credential: JSON.stringify(assertionJSON(credential)),
      })) {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = name;
        input.value = value;
        form.append(input);
      }
      document.body.append(form);
      form.submit();
    } catch {
      status.textContent = 'Passkey sign-in was not completed. You can try again or use your password.';
      button.disabled = false;
    }
  });
}
