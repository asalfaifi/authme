import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const NODE_DIGEST = 'sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3';
const DOCKERFILE_FRONTEND_DIGEST = 'sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e';
const POSTGRES_DIGEST = 'sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193';
const REDIS_DIGEST = 'sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99';
const BUILDKIT_DIGEST = 'sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5';

test('runtime, package tooling, and tag workflow share pinned release inputs', async () => {
  const [nodeVersion, packageDocument, dockerfile, workflow] = await Promise.all([
    readFile('.nvmrc', 'utf8').then((value) => value.trim()),
    readFile('package.json', 'utf8').then(JSON.parse),
    readFile('Dockerfile', 'utf8'),
    readFile('.github/workflows/release.yml', 'utf8'),
  ]);
  assert.equal(nodeVersion, '22.23.1');
  assert.equal(packageDocument.packageManager, 'npm@10.9.8');

  assert.match(dockerfile, new RegExp(`^# syntax=docker/dockerfile:1\\.7@${DOCKERFILE_FRONTEND_DIGEST}$`, 'mu'));
  const nodeBase = `node:${nodeVersion}-bookworm-slim@${NODE_DIGEST}`;
  assert.equal([...dockerfile.matchAll(/^FROM ([^ ]+)/gmu)].map((match) => match[1]).filter((image) => image === nodeBase).length, 2);
  assert.match(workflow, /node-version-file: \.nvmrc/u);
  assert.match(workflow, new RegExp(`image: postgres:17-alpine@${POSTGRES_DIGEST}`));
  assert.match(workflow, new RegExp(`image: redis:7\\.4-alpine@${REDIS_DIGEST}`));
  assert.match(workflow, /docker\/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c/u);
  assert.match(workflow, /version: v0\.36\.0/u);
  assert.match(workflow, new RegExp(`driver-opts: image=moby/buildkit:v0\\.29\\.0@${BUILDKIT_DIGEST}`));
  assert.match(workflow, /SOURCE_DATE_EPOCH=\$source_date_epoch/u);
  assert.match(workflow, /docker buildx build --pull --no-cache --target runtime --platform linux\/amd64/u);
  assert.match(workflow, /rewrite-timestamp=true/u);
  assert.match(workflow, /test "\$primary_id" = "\$reproduction_id"/u);
  assert.match(workflow, /test "\$primary_layers" = "\$reproduction_layers"/u);
});
