import { randomBytes } from 'node:crypto';

import { loadConfig } from '../src/config.js';
import { hashPassword } from '../src/crypto/password.js';
import { createDataLayer } from '../src/db.js';
import { syncLdapProvider } from '../src/federation/ldap.js';
import { PostgresFederatedIdentityRepository } from '../src/repositories/federated-identity-repository.js';

function argumentsFor(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help') return { help: true };
    if (!['--realm', '--provider'].includes(argument) || !argv[index + 1] || argv[index + 1].startsWith('--')) {
      throw new Error('Usage: npm run ldap:sync -- --realm <realm> [--provider <provider-id>]');
    }
    const field = argument === '--realm' ? 'realm' : 'providerId';
    if (result[field]) throw new Error(`${argument} may be specified only once`);
    result[field] = argv[index + 1];
    index += 1;
  }
  if (!result.realm) throw new Error('--realm is required');
  return result;
}

function safeError(error) {
  const result = {};
  if (typeof error?.name === 'string' && error.name.length <= 100) result.name = error.name;
  if ((typeof error?.code === 'string' || typeof error?.code === 'number') && String(error.code).length <= 100) {
    result.code = error.code;
  }
  return result;
}

function logger(level) {
  return (fields, message) => {
    process.stderr.write(`${JSON.stringify({
      level,
      message,
      realm: fields.realm,
      providerId: fields.providerId,
      error: fields.error,
      reconciliation: fields.reconciliation,
    })}\n`);
  };
}

async function main() {
  const options = argumentsFor(process.argv.slice(2));
  if (options.help) {
    process.stdout.write('Usage: npm run ldap:sync -- --realm <realm> [--provider <provider-id>]\n');
    return;
  }
  const config = loadConfig();
  if (!config.databaseUrl) throw new Error('DATABASE_URL is required for LDAP synchronization');
  if (!config.realms.includes(options.realm)) throw new Error('Unknown LDAP sync realm');
  const providers = (config.ldapProvidersByRealm[options.realm] ?? [])
    .filter((provider) => provider.syncEnabled && (!options.providerId || provider.id === options.providerId));
  if (!providers.length) throw new Error('No matching sync-enabled LDAP provider');

  const data = await createDataLayer(config);
  try {
    const disabledPasswordHash = await hashPassword(
      randomBytes(32).toString('base64url'),
      config.passwordPepper,
    );
    const repository = new PostgresFederatedIdentityRepository(data.pool, { disabledPasswordHash });
    let failed = false;
    for (const provider of providers) {
      const result = await syncLdapProvider(provider, {
        realm: options.realm,
        repository,
      }, {
        logger: { warn: logger('warn'), error: logger('error') },
      });
      const { error, ...summary } = result;
      process.stdout.write(`${JSON.stringify(summary)}\n`);
      if (result.status !== 'success') failed = true;
    }
    if (failed) process.exitCode = 1;
  } finally {
    await data.close();
  }
}

try {
  await main();
} catch (error) {
  process.stderr.write(`${JSON.stringify({ status: 'failed', error: safeError(error) })}\n`);
  process.exitCode = 1;
}
