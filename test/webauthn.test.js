import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { test } from 'node:test';
import { isoCBOR } from '@simplewebauthn/server/helpers';

import { createWebAuthn } from '../src/security/webauthn.js';

const config = {
  publicUrl: 'https://login.example.test:8443',
  subjectSalt: 'webauthn-test-subject-salt-that-is-long-enough',
  webauthnChallengeTtl: 240,
};

const user = {
  id: 'b875a8bc-808d-4465-951b-1c68ccf58ae8',
  username: 'alice@example.test',
  name: 'Alice',
};

test('WebAuthn policy binds exact RP/origin, opaque realm user handles, discoverability, and user verification', async () => {
  const calls = [];
  const webauthn = createWebAuthn(config, {
    async generateRegistrationOptions(options) {
      calls.push(['registrationOptions', options]);
      return {
        challenge: 'registration-challenge-value-that-is-long-enough',
        rp: { id: options.rpID, name: options.rpName },
        user: {
          id: Buffer.from(options.userID).toString('base64url'),
          name: options.userName,
          displayName: options.userDisplayName,
        },
        pubKeyCredParams: [],
      };
    },
    async generateAuthenticationOptions(options) {
      calls.push(['authenticationOptions', options]);
      return { challenge: 'authentication-challenge-value-that-is-long-enough', rpId: options.rpID };
    },
  });

  const master = await webauthn.registrationOptions({
    realm: 'master',
    user,
    credentials: [{ id: 'existing-passkey', transports: ['internal'] }],
  });
  const staff = await webauthn.registrationOptions({ realm: 'staff', user, credentials: [] });
  const authentication = await webauthn.authenticationOptions();

  const masterCall = calls[0][1];
  assert.equal(webauthn.origin, 'https://login.example.test:8443');
  assert.equal(webauthn.rpID, 'login.example.test');
  assert.equal(masterCall.rpName, 'AuthMe (master)');
  assert.equal(masterCall.rpID, 'login.example.test');
  assert.equal(masterCall.attestationType, 'none');
  assert.deepEqual(masterCall.authenticatorSelection, { residentKey: 'required', userVerification: 'required' });
  assert.deepEqual(masterCall.excludeCredentials, [{ id: 'existing-passkey', transports: ['internal'] }]);
  assert.notEqual(master.user.id, staff.user.id);
  assert.doesNotMatch(Buffer.from(master.user.id, 'base64url').toString('utf8'), /alice/i);
  assert.equal(authentication.rpId, 'login.example.test');
  assert.equal(calls[2][1].userVerification, 'required');
  assert.equal(calls[2][1].allowCredentials, undefined);
});

test('WebAuthn verification passes exact ceremony context and maps maintained credential fields', async () => {
  const calls = [];
  const webauthn = createWebAuthn(config, {
    async verifyRegistrationResponse(options) {
      calls.push(['registration', options]);
      return {
        verified: true,
        registrationInfo: {
          credential: {
            id: 'credential-id',
            publicKey: Uint8Array.from([1, 2, 3]),
            counter: 7,
            transports: ['hybrid', 'internal'],
          },
          credentialDeviceType: 'multiDevice',
          credentialBackedUp: true,
          aaguid: '00000000-0000-0000-0000-000000000000',
        },
      };
    },
    async verifyAuthenticationResponse(options) {
      calls.push(['authentication', options]);
      return {
        verified: true,
        authenticationInfo: {
          newCounter: 8,
          credentialDeviceType: 'multiDevice',
          credentialBackedUp: true,
        },
      };
    },
  });
  const response = { id: 'credential-id' };
  const registered = await webauthn.verifyRegistration({ response, challenge: 'registration-challenge' });
  assert.deepEqual(registered, {
    id: 'credential-id',
    publicKey: Uint8Array.from([1, 2, 3]),
    counter: 7,
    transports: ['hybrid', 'internal'],
    deviceType: 'multiDevice',
    backedUp: true,
    aaguid: '00000000-0000-0000-0000-000000000000',
  });
  assert.equal(calls[0][1].expectedChallenge, 'registration-challenge');
  assert.equal(calls[0][1].expectedOrigin, config.publicUrl);
  assert.equal(calls[0][1].expectedRPID, 'login.example.test');
  assert.equal(calls[0][1].requireUserVerification, true);
  assert.equal(calls[0][1].requireUserPresence, true);

  const credential = { ...registered, userHandle: 'opaque-user-handle' };
  const authenticated = await webauthn.verifyAuthentication({
    response,
    challenge: 'authentication-challenge',
    credential,
  });
  assert.deepEqual(authenticated, { newCounter: 8, deviceType: 'multiDevice', backedUp: true });
  assert.equal(calls[1][1].expectedChallenge, 'authentication-challenge');
  assert.equal(calls[1][1].expectedOrigin, config.publicUrl);
  assert.equal(calls[1][1].expectedRPID, 'login.example.test');
  assert.equal(calls[1][1].requireUserVerification, true);
  assert.deepEqual(calls[1][1].credential.publicKey, Uint8Array.from([1, 2, 3]));
});

test('the real SimpleWebAuthn server integration generates ceremonies and rejects malformed responses', async () => {
  const webauthn = createWebAuthn(config);
  const registration = await webauthn.registrationOptions({ realm: 'master', user, credentials: [] });
  const authentication = await webauthn.authenticationOptions();

  assert.match(registration.challenge, /^[A-Za-z0-9_-]{32,}$/);
  assert.equal(registration.rp.id, 'login.example.test');
  assert.equal(registration.authenticatorSelection.residentKey, 'required');
  assert.equal(registration.authenticatorSelection.userVerification, 'required');
  assert.match(authentication.challenge, /^[A-Za-z0-9_-]{32,}$/);
  assert.equal(authentication.rpId, 'login.example.test');
  assert.equal(authentication.userVerification, 'required');
  await assert.rejects(
    webauthn.verifyRegistration({ response: { id: 'malformed' }, challenge: registration.challenge }),
  );
});

test('the real verifier accepts a P-256 passkey ceremony and rejects replay, origin, and RP-ID changes', async () => {
  const webauthn = createWebAuthn(config);
  const registrationOptions = await webauthn.registrationOptions({ realm: 'master', user, credentials: [] });
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const credentialId = randomBytes(32);
  const credentialIdLength = Buffer.alloc(2);
  credentialIdLength.writeUInt16BE(credentialId.length);
  const rpIdHash = createHash('sha256').update(webauthn.rpID).digest();
  const cosePublicKey = isoCBOR.encode(new Map([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, Buffer.from(jwk.x, 'base64url')],
    [-3, Buffer.from(jwk.y, 'base64url')],
  ]));
  const registrationAuthenticatorData = Buffer.concat([
    rpIdHash,
    Buffer.from([0x45]), // UP, UV, and attested credential data
    Buffer.alloc(4),
    Buffer.alloc(16),
    credentialIdLength,
    credentialId,
    Buffer.from(cosePublicKey),
  ]);
  const registrationClientData = Buffer.from(JSON.stringify({
    type: 'webauthn.create',
    challenge: registrationOptions.challenge,
    origin: webauthn.origin,
    crossOrigin: false,
  }));
  const attestationObject = isoCBOR.encode(new Map([
    ['fmt', 'none'],
    ['attStmt', new Map()],
    ['authData', registrationAuthenticatorData],
  ]));
  const registrationResponse = {
    id: credentialId.toString('base64url'),
    rawId: credentialId.toString('base64url'),
    type: 'public-key',
    authenticatorAttachment: 'platform',
    clientExtensionResults: {},
    response: {
      clientDataJSON: registrationClientData.toString('base64url'),
      attestationObject: Buffer.from(attestationObject).toString('base64url'),
      transports: ['internal'],
    },
  };
  const registered = await webauthn.verifyRegistration({
    response: registrationResponse,
    challenge: registrationOptions.challenge,
  });
  assert.equal(registered.id, registrationResponse.id);
  assert.equal(registered.counter, 0);
  assert.equal(registered.deviceType, 'singleDevice');

  const authenticationOptions = await webauthn.authenticationOptions();
  function authenticationResponse({ origin = webauthn.origin, rpHash = rpIdHash, counter = 1 } = {}) {
    const counterBytes = Buffer.alloc(4);
    counterBytes.writeUInt32BE(counter);
    const authenticatorData = Buffer.concat([rpHash, Buffer.from([0x05]), counterBytes]); // UP and UV
    const clientData = Buffer.from(JSON.stringify({
      type: 'webauthn.get',
      challenge: authenticationOptions.challenge,
      origin,
      crossOrigin: false,
    }));
    const signedData = Buffer.concat([
      authenticatorData,
      createHash('sha256').update(clientData).digest(),
    ]);
    return {
      id: registrationResponse.id,
      rawId: registrationResponse.rawId,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      clientExtensionResults: {},
      response: {
        clientDataJSON: clientData.toString('base64url'),
        authenticatorData: authenticatorData.toString('base64url'),
        signature: sign('sha256', signedData, privateKey).toString('base64url'),
        userHandle: registrationOptions.user.id,
      },
    };
  }

  const validAssertion = authenticationResponse();
  const authenticated = await webauthn.verifyAuthentication({
    response: validAssertion,
    challenge: authenticationOptions.challenge,
    credential: { ...registered, userHandle: registrationOptions.user.id },
  });
  assert.equal(authenticated.newCounter, 1);
  await assert.rejects(webauthn.verifyAuthentication({
    response: validAssertion,
    challenge: authenticationOptions.challenge,
    credential: { ...registered, counter: 1, userHandle: registrationOptions.user.id },
  }));
  await assert.rejects(webauthn.verifyAuthentication({
    response: authenticationResponse({ origin: 'https://attacker.example.test', counter: 2 }),
    challenge: authenticationOptions.challenge,
    credential: { ...registered, userHandle: registrationOptions.user.id },
  }));
  await assert.rejects(webauthn.verifyAuthentication({
    response: authenticationResponse({
      rpHash: createHash('sha256').update('other.example.test').digest(),
      counter: 2,
    }),
    challenge: authenticationOptions.challenge,
    credential: { ...registered, userHandle: registrationOptions.user.id },
  }));
});
