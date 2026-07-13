import { createHmac } from 'node:crypto';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';

function userHandle(secret, realm, userId) {
  return createHmac('sha256', secret)
    .update('authme-webauthn-user-handle\0')
    .update(realm)
    .update('\0')
    .update(userId)
    .digest();
}

/**
 * Realm-scoped WebAuthn policy. RP ID and origin are intentionally singular:
 * accepting sibling origins would broaden every credential's phishing surface.
 */
export function createWebAuthn(config, implementation = {}) {
  const api = {
    generateAuthenticationOptions,
    generateRegistrationOptions,
    verifyAuthenticationResponse,
    verifyRegistrationResponse,
    ...implementation,
  };
  const origin = new URL(config.publicUrl).origin;
  const rpID = new URL(config.publicUrl).hostname;
  const timeout = config.webauthnChallengeTtl * 1000;

  return Object.freeze({
    origin,
    rpID,

    async registrationOptions({ realm, user, credentials = [] }) {
      return api.generateRegistrationOptions({
        rpName: `AuthMe (${realm})`,
        rpID,
        userID: userHandle(config.subjectSalt, realm, user.id),
        userName: user.username,
        userDisplayName: user.name,
        timeout,
        attestationType: 'none',
        excludeCredentials: credentials.map((credential) => ({
          id: credential.id,
          transports: credential.transports,
        })),
        authenticatorSelection: {
          residentKey: 'required',
          userVerification: 'required',
        },
      });
    },

    async verifyRegistration({ response, challenge }) {
      const verification = await api.verifyRegistrationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserPresence: true,
        requireUserVerification: true,
      });
      if (!verification.verified || !verification.registrationInfo) return null;
      const {
        credential,
        credentialDeviceType,
        credentialBackedUp,
        aaguid,
      } = verification.registrationInfo;
      return {
        id: credential.id,
        publicKey: new Uint8Array(credential.publicKey),
        counter: credential.counter,
        transports: credential.transports ?? [],
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        aaguid,
      };
    },

    async authenticationOptions() {
      return api.generateAuthenticationOptions({
        rpID,
        timeout,
        userVerification: 'required',
      });
    },

    async verifyAuthentication({ response, challenge, credential }) {
      const verification = await api.verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: true,
        credential: {
          id: credential.id,
          publicKey: new Uint8Array(credential.publicKey),
          counter: credential.counter,
          transports: credential.transports,
        },
      });
      if (!verification.verified) return null;
      return {
        newCounter: verification.authenticationInfo.newCounter,
        deviceType: verification.authenticationInfo.credentialDeviceType,
        backedUp: verification.authenticationInfo.credentialBackedUp,
      };
    },
  });
}
