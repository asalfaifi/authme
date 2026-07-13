import { randomBytes } from 'node:crypto';
import { link, mkdir, open, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { exportJWK, generateKeyPair } from 'jose';

const directory = process.env.AUTHME_JWKS_DIR ?? './.local/jwks';
const realms = (process.env.AUTHME_REALMS ?? 'master').split(',').map((value) => value.trim()).filter(Boolean);
await mkdir(directory, { recursive: true, mode: 0o700 });

for (const realm of realms) {
  if (!/^[a-z][a-z0-9-]{0,62}$/.test(realm)) throw new Error(`Invalid realm name: ${realm}`);
  const { privateKey } = await generateKeyPair('RS256', { modulusLength: 3072, extractable: true });
  const jwk = await exportJWK(privateKey);
  const destination = join(directory, `${realm}.json`);
  const temporary = `${destination}.${process.pid}.tmp`;
  const handle = await open(temporary, 'wx', 0o600);
  try {
    await handle.writeFile(`${JSON.stringify({ keys: [{ ...jwk, kid: randomBytes(16).toString('base64url'), use: 'sig', alg: 'RS256' }] }, null, 2)}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await link(temporary, destination);
    await unlink(temporary);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    if (error.code === 'EEXIST') throw new Error(`${destination} already exists; rotate keys deliberately instead of overwriting it`);
    throw error;
  }
  console.log(`generated ${destination}`);
}
