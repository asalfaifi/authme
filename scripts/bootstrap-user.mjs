import pg from 'pg';
import { loadConfig } from '../src/config.js';
import { hashPassword } from '../src/crypto/password.js';
import { PostgresIdentityStore, publicUser } from '../src/repositories/identity-store.js';

const config = loadConfig();
if (!config.databaseUrl) throw new Error('DATABASE_URL is required');
const realm = process.env.AUTHME_BOOTSTRAP_REALM ?? config.realms[0];
if (!config.realms.includes(realm)) throw new Error(`Unknown bootstrap realm: ${realm}`);
const username = process.env.AUTHME_BOOTSTRAP_USERNAME ?? 'admin';
const email = process.env.AUTHME_BOOTSTRAP_EMAIL ?? 'admin@example.com';
const password = process.env.AUTHME_BOOTSTRAP_PASSWORD;
if (!password || password.length < 12) throw new Error('AUTHME_BOOTSTRAP_PASSWORD must contain at least 12 characters');

const pool = new pg.Pool({ connectionString: config.databaseUrl, max: 1, application_name: 'authme-bootstrap' });
const store = new PostgresIdentityStore(pool);
try {
  await pool.query(
    'INSERT INTO realms (name, display_name) VALUES ($1,$2) ON CONFLICT (name) DO NOTHING',
    [realm, realm === 'master' ? 'Master' : realm],
  );
  if (await store.findUserByLogin(realm, username)) throw new Error(`User ${username} already exists in ${realm}`);
  const user = await store.createUser({
    realm,
    username,
    email,
    emailVerified: true,
    name: 'AuthMe Administrator',
    passwordHash: await hashPassword(password, config.passwordPepper),
    roles: ['admin'],
    groups: ['/administrators'],
  });
  await store.writeAudit({ realm, type: 'system.bootstrap_user.created', subjectId: user.id });
  console.log(JSON.stringify(publicUser(user), null, 2));
} finally {
  await store.close();
}
