import assert from 'node:assert/strict';
import { createHash, randomUUID, webcrypto, X509Certificate } from 'node:crypto';
import { after, before, test } from 'node:test';
import {
  cryptoProvider,
  SubjectAlternativeNameExtension,
  X509CertificateGenerator,
} from '@peculiar/x509';
import { decodeJwt, SignJWT } from 'jose';
import request from 'supertest';

import { createAuthMeApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';

const base = 'http://127.0.0.1:34994';
const issuer = `${base}/realms/master`;
const tokenPath = '/realms/master/protocol/openid-connect/token';
const tokenEndpoint = `${issuer}/protocol/openid-connect/token`;
const introspectionPath = '/realms/master/protocol/openid-connect/token/introspect';
const resourceAudience = 'https://api.example.test/mtls';
const assertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const clientIds = {
  basic: 'mtls-existing-basic',
  none: 'mtls-existing-none',
  privateJwt: 'mtls-existing-private-jwt',
  secretJwt: 'mtls-existing-secret-jwt',
  selfSigned: 'mtls-self-signed-client',
  tls: 'mtls-pki-client',
};
const basicSecret = 'mtls-basic-client-secret-value-000000001';
const secretJwtSecret = 'mtls-secret-jwt-client-value-000000001';

let certificate;
let certificateHeader;
let certificateThumbprint;
let mismatchedCertificateHeader;
let privateJwtKey;
let runtime;

cryptoProvider.set(webcrypto);

async function generateCertificate(commonName) {
  const keys = await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const generated = await X509CertificateGenerator.createSelfSigned({
    name: `CN=${commonName}`,
    keys,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 86_400_000),
    extensions: [new SubjectAlternativeNameExtension([{ type: 'dns', value: commonName }])],
  });
  const pem = generated.toString('pem');
  const native = new X509Certificate(pem);
  const publicJwk = await webcrypto.subtle.exportKey('jwk', keys.publicKey);
  return { keys, native, pem, publicJwk };
}

function trustedPost(path, cert = certificateHeader) {
  const pending = request(runtime.app)
    .post(path)
    .set('host', new URL(base).host)
    .set('x-forwarded-for', '198.51.100.27')
    .set('x-ssl-client-verify', 'SUCCESS');
  if (cert !== null) pending.set('x-authme-client-cert', cert);
  return pending;
}

function assertionClaims(clientId) {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: clientId,
    sub: clientId,
    aud: tokenEndpoint,
    iat: now,
    exp: now + 120,
    jti: randomUUID(),
  };
}

before(async () => {
  const primary = await generateCertificate('mtls-client.example');
  const mismatch = await generateCertificate('other-client.example');
  certificate = primary.native;
  certificateHeader = encodeURIComponent(primary.pem);
  mismatchedCertificateHeader = encodeURIComponent(mismatch.pem);
  certificateThumbprint = createHash('sha256').update(certificate.raw).digest('base64url');
  privateJwtKey = primary.keys.privateKey;

  const selfSignedJwk = {
    ...primary.publicJwk,
    alg: 'ES256',
    kid: 'mtls-certificate',
    use: 'sig',
    x5c: [certificate.raw.toString('base64')],
  };
  const privateJwtJwk = {
    ...primary.publicJwk,
    alg: 'ES256',
    kid: 'private-jwt-key',
    use: 'sig',
  };

  runtime = await createAuthMeApp(loadConfig({
    AUTHME_DEV_MODE: 'true',
    AUTHME_PUBLIC_URL: base,
    AUTHME_PORT: '34994',
    AUTHME_LOG_LEVEL: 'silent',
    AUTHME_TRUST_PROXY: 'true',
    AUTHME_MTLS_CLIENT_CERT_HEADER: 'x-authme-client-cert',
    AUTHME_MTLS_TRUSTED_PROXY_CIDRS: '127.0.0.1/32,::1/128',
    AUTHME_RESOURCE_SERVERS_JSON: JSON.stringify({
      master: [{
        audience: resourceAudience,
        scopes: ['api.read'],
        authorized_client_ids: [clientIds.tls, clientIds.selfSigned],
      }],
    }),
    AUTHME_CLIENTS_JSON: JSON.stringify({
      master: [{
        client_id: clientIds.tls,
        token_endpoint_auth_method: 'tls_client_auth',
        tls_client_auth_san_dns: 'mtls-client.example',
        tls_client_certificate_bound_access_tokens: true,
        redirect_uris: [],
        response_types: [],
        grant_types: ['client_credentials'],
      }, {
        client_id: clientIds.selfSigned,
        token_endpoint_auth_method: 'self_signed_tls_client_auth',
        tls_client_certificate_bound_access_tokens: true,
        jwks: { keys: [selfSignedJwk] },
        redirect_uris: [],
        response_types: [],
        grant_types: ['client_credentials'],
      }, {
        client_id: clientIds.basic,
        client_secret: basicSecret,
        token_endpoint_auth_method: 'client_secret_basic',
        redirect_uris: [],
        response_types: [],
        grant_types: ['client_credentials'],
      }, {
        client_id: clientIds.secretJwt,
        client_secret: secretJwtSecret,
        token_endpoint_auth_method: 'client_secret_jwt',
        token_endpoint_auth_signing_alg: 'HS256',
        redirect_uris: [],
        response_types: [],
        grant_types: ['client_credentials'],
      }, {
        client_id: clientIds.privateJwt,
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'ES256',
        jwks: { keys: [privateJwtJwk] },
        redirect_uris: [],
        response_types: [],
        grant_types: ['client_credentials'],
      }, {
        client_id: clientIds.none,
        application_type: 'native',
        token_endpoint_auth_method: 'none',
        redirect_uris: ['http://127.0.0.1:49154/callback'],
        response_types: ['code'],
        grant_types: ['authorization_code'],
      }],
    }),
  }));
});

after(async () => {
  await runtime?.close();
});

test('PKI and self-signed mTLS clients receive certificate-bound access tokens', async () => {
  const discovery = await request(runtime.app)
    .get('/realms/master/.well-known/openid-configuration')
    .set('host', new URL(base).host)
    .expect(200);
  assert.equal(discovery.body.tls_client_certificate_bound_access_tokens, true);
  assert.deepEqual(discovery.body.token_endpoint_auth_methods_supported, [
    'client_secret_basic',
    'private_key_jwt',
    'client_secret_jwt',
    'none',
    'tls_client_auth',
    'self_signed_tls_client_auth',
  ]);

  for (const clientId of [clientIds.tls, clientIds.selfSigned]) {
    const token = await trustedPost(tokenPath)
      .type('form')
      .send({ client_id: clientId, grant_type: 'client_credentials' })
      .expect(200);
    assert.equal(typeof token.body.access_token, 'string');

    const introspection = await trustedPost(introspectionPath)
      .type('form')
      .send({ client_id: clientId, token: token.body.access_token })
      .expect(200);
    assert.equal(introspection.body.active, true);
    assert.deepEqual(introspection.body.cnf, { 'x5t#S256': certificateThumbprint });
  }

  const jwtToken = await trustedPost(tokenPath)
    .type('form')
    .send({
      client_id: clientIds.tls,
      grant_type: 'client_credentials',
      resource: resourceAudience,
      scope: 'api.read',
    })
    .expect(200);
  assert.deepEqual(decodeJwt(jwtToken.body.access_token).cnf, {
    'x5t#S256': certificateThumbprint,
  });
});

test('mTLS client authentication rejects missing and mismatched certificates', async () => {
  const missing = await trustedPost(tokenPath, null)
    .type('form')
    .send({ client_id: clientIds.tls, grant_type: 'client_credentials' })
    .expect(401);
  assert.equal(missing.body.error, 'invalid_client');

  const mismatch = await trustedPost(tokenPath, mismatchedCertificateHeader)
    .type('form')
    .send({ client_id: clientIds.tls, grant_type: 'client_credentials' })
    .expect(401);
  assert.equal(mismatch.body.error, 'invalid_client');

  const unverified = await request(runtime.app)
    .post(tokenPath)
    .set('host', new URL(base).host)
    .set('x-forwarded-for', '198.51.100.27')
    .set('x-authme-client-cert', certificateHeader)
    .set('x-ssl-client-verify', 'FAILED')
    .type('form')
    .send({ client_id: clientIds.tls, grant_type: 'client_credentials' })
    .expect(401);
  assert.equal(unverified.body.error, 'invalid_client');
});

test('a client certificate header on a direct request is ignored', async () => {
  const response = await request(runtime.app)
    .post(tokenPath)
    .set('host', new URL(base).host)
    .set('x-authme-client-cert', certificateHeader)
    .set('x-ssl-client-verify', 'SUCCESS')
    .type('form')
    .send({ client_id: clientIds.tls, grant_type: 'client_credentials' })
    .expect(401);
  assert.equal(response.body.error, 'invalid_client');
});

test('existing client authentication methods remain available', async () => {
  const basic = await request(runtime.app)
    .post(tokenPath)
    .set('host', new URL(base).host)
    .auth(clientIds.basic, basicSecret)
    .type('form')
    .send({ grant_type: 'client_credentials' })
    .expect(200);
  assert.equal(typeof basic.body.access_token, 'string');

  const secretAssertion = await new SignJWT(assertionClaims(clientIds.secretJwt))
    .setProtectedHeader({ alg: 'HS256' })
    .sign(Buffer.from(secretJwtSecret));
  await request(runtime.app)
    .post(tokenPath)
    .set('host', new URL(base).host)
    .type('form')
    .send({
      grant_type: 'client_credentials',
      client_assertion_type: assertionType,
      client_assertion: secretAssertion,
    })
    .expect(200);

  const privateAssertion = await new SignJWT(assertionClaims(clientIds.privateJwt))
    .setProtectedHeader({ alg: 'ES256', kid: 'private-jwt-key' })
    .sign(privateJwtKey);
  await request(runtime.app)
    .post(tokenPath)
    .set('host', new URL(base).host)
    .type('form')
    .send({
      grant_type: 'client_credentials',
      client_assertion_type: assertionType,
      client_assertion: privateAssertion,
    })
    .expect(200);

  const none = await request(runtime.app)
    .post(tokenPath)
    .set('host', new URL(base).host)
    .type('form')
    .send({
      grant_type: 'authorization_code',
      client_id: clientIds.none,
      code: 'not-a-real-authorization-code',
      redirect_uri: 'http://127.0.0.1:49154/callback',
      code_verifier: 'v'.repeat(43),
    })
    .expect(400);
  assert.equal(none.body.error, 'invalid_grant');
});
