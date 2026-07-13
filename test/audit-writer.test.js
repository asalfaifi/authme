import assert from 'node:assert/strict';
import test from 'node:test';

import {
  AUDIT_WRITE_RESULTS,
  BoundedAuditWriter,
  createAuditWriter,
} from '../src/observability/audit-writer.js';

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

function turn() {
  return new Promise((resolve) => setImmediate(resolve));
}

test('validates construction and sampling options', async () => {
  assert.throws(() => new BoundedAuditWriter(), /write must be a function/);
  assert.throws(() => new BoundedAuditWriter({ write() {}, maxQueue: -1 }), /maxQueue/);
  assert.throws(() => new BoundedAuditWriter({ write() {}, concurrency: 0 }), /concurrency/);
  assert.throws(() => new BoundedAuditWriter({ write() {}, maxSampleKeys: 0 }), /maxSampleKeys/);
  assert.throws(() => new BoundedAuditWriter({ write() {}, hooks: null }), /hooks/);

  const writer = createAuditWriter({ write() {} });
  assert.ok(writer instanceof BoundedAuditWriter);
  assert.throws(() => writer.enqueue({}, null), /options must be an object/);
  assert.throws(() => writer.enqueue({}, { sampleKey: 'failure' }), /provided together/);
  assert.throws(() => writer.enqueue({}, { sampleWindowMs: 10 }), /provided together/);
  assert.throws(
    () => writer.enqueue({}, { sampleKey: '', sampleWindowMs: 10 }),
    /sampleKey/,
  );
  assert.throws(
    () => writer.enqueue({}, { sampleKey: 'failure', sampleWindowMs: Infinity }),
    /sampleWindowMs/,
  );
  await writer.close();
});

test('bounds the queue, limits concurrency, and drops immediately when full', async () => {
  const gates = [];
  const started = [];
  const hookEvents = [];
  let active = 0;
  let peakActive = 0;

  const writer = new BoundedAuditWriter({
    maxQueue: 2,
    concurrency: 2,
    async write(event) {
      active += 1;
      peakActive = Math.max(peakActive, active);
      started.push(event.id);
      const gate = deferred();
      gates.push(gate);
      await gate.promise;
      active -= 1;
    },
    hooks: {
      accepted({ event }) { hookEvents.push(`accepted:${event.id}`); },
      dropped({ event, reason }) { hookEvents.push(`dropped:${event.id}:${reason}`); },
    },
  });

  assert.equal(writer.enqueue({ id: 1 }), AUDIT_WRITE_RESULTS.ACCEPTED);
  assert.equal(writer.enqueue({ id: 2 }), AUDIT_WRITE_RESULTS.ACCEPTED);
  assert.equal(writer.enqueue({ id: 3 }), AUDIT_WRITE_RESULTS.ACCEPTED);
  assert.equal(writer.enqueue({ id: 4 }), AUDIT_WRITE_RESULTS.ACCEPTED);
  assert.equal(writer.enqueue({ id: 5 }), AUDIT_WRITE_RESULTS.DROPPED);
  assert.deepEqual(writer.state, { accepting: true, active: 2, queued: 2, sampleKeys: 0 });

  await turn();
  assert.deepEqual(started, [1, 2]);
  assert.equal(peakActive, 2);

  gates[0].resolve();
  await turn();
  assert.deepEqual(started, [1, 2, 3]);
  assert.equal(peakActive, 2);

  gates[1].resolve();
  await turn();
  assert.deepEqual(started, [1, 2, 3, 4]);
  assert.equal(peakActive, 2);

  gates[2].resolve();
  gates[3].resolve();
  await writer.flush();

  assert.deepEqual(writer.counters, {
    accepted: 4,
    dropped: 1,
    sampled: 0,
    writeFailures: 0,
  });
  assert.deepEqual(hookEvents, [
    'accepted:1',
    'accepted:2',
    'accepted:3',
    'accepted:4',
    'dropped:5:queue_full',
  ]);
});

test('does not create delivery waiters for queued or dropped events', async () => {
  const gate = deferred();
  const writer = new BoundedAuditWriter({
    maxQueue: 1,
    concurrency: 1,
    write: () => gate.promise,
  });

  assert.equal(typeof writer.enqueue({ id: 'active' }), 'string');
  assert.equal(typeof writer.enqueue({ id: 'queued' }), 'string');
  for (let index = 0; index < 10_000; index += 1) {
    assert.equal(writer.enqueue({ id: index }), AUDIT_WRITE_RESULTS.DROPPED);
  }
  assert.equal(writer.state.queued, 1);
  assert.equal(writer.counters.dropped, 10_000);

  gate.resolve();
  await writer.close();
});

test('commits capacity and sampling state before invoking re-entrant hooks', async () => {
  const gate = deferred();
  const options = { sampleKey: 'invalid_client:reentrant', sampleWindowMs: 1_000 };
  let writer;
  let nestedResult;
  let active = 0;
  let peakActive = 0;

  writer = new BoundedAuditWriter({
    maxQueue: 1,
    concurrency: 1,
    async write() {
      active += 1;
      peakActive = Math.max(peakActive, active);
      await gate.promise;
      active -= 1;
    },
    hooks: {
      accepted({ event }) {
        if (event.id === 1) nestedResult = writer.enqueue({ id: 2 }, options);
      },
    },
  });

  assert.equal(writer.enqueue({ id: 1 }, options), AUDIT_WRITE_RESULTS.ACCEPTED);
  assert.equal(nestedResult, AUDIT_WRITE_RESULTS.SAMPLED);
  assert.deepEqual(writer.state, { accepting: true, active: 1, queued: 0, sampleKeys: 1 });
  await turn();
  assert.equal(peakActive, 1);

  gate.resolve();
  await writer.close();
  assert.equal(writer.counters.accepted, 1);
  assert.equal(writer.counters.sampled, 1);
});

test('samples repeated keys within caller-supplied windows and prunes expired keys', async () => {
  let now = 1_000;
  const written = [];
  const sampled = [];
  const writer = new BoundedAuditWriter({
    maxQueue: 10,
    concurrency: 1,
    now: () => now,
    write(event) { written.push(event.id); },
    hooks: {
      sampled(details) { sampled.push(details); },
    },
  });

  const options = { sampleKey: 'invalid_client:198.51.100.7', sampleWindowMs: 500 };
  assert.equal(writer.enqueue({ id: 1 }, options), AUDIT_WRITE_RESULTS.ACCEPTED);
  assert.equal(writer.enqueue({ id: 2 }, options), AUDIT_WRITE_RESULTS.SAMPLED);
  assert.equal(
    writer.enqueue({ id: 3 }, { sampleKey: 'invalid_client:203.0.113.9', sampleWindowMs: 500 }),
    AUDIT_WRITE_RESULTS.ACCEPTED,
  );

  now = 1_500;
  assert.equal(writer.enqueue({ id: 4 }, options), AUDIT_WRITE_RESULTS.ACCEPTED);
  await writer.flush();

  assert.deepEqual(written, [1, 3, 4]);
  assert.equal(sampled.length, 1);
  assert.equal(sampled[0].key, options.sampleKey);
  assert.deepEqual(writer.counters, {
    accepted: 3,
    dropped: 0,
    sampled: 1,
    writeFailures: 0,
  });
  assert.equal(writer.state.sampleKeys, 1);
});

test('caps sampling state and evicts the earliest-expiring key', async () => {
  let now = 0;
  const writer = new BoundedAuditWriter({
    maxQueue: 10,
    concurrency: 1,
    maxSampleKeys: 2,
    now: () => now,
    write() {},
  });

  writer.enqueue({ id: 'a' }, { sampleKey: 'a', sampleWindowMs: 100 });
  writer.enqueue({ id: 'b' }, { sampleKey: 'b', sampleWindowMs: 200 });
  writer.enqueue({ id: 'c' }, { sampleKey: 'c', sampleWindowMs: 300 });
  assert.equal(writer.state.sampleKeys, 2);

  // `a` was evicted to keep the map fixed-size, so it is accepted again.
  now = 1;
  assert.equal(
    writer.enqueue({ id: 'a-again' }, { sampleKey: 'a', sampleWindowMs: 100 }),
    AUDIT_WRITE_RESULTS.ACCEPTED,
  );
  assert.equal(writer.state.sampleKeys, 2);
  await writer.close();
});

test('contains write and hook failures while counting failed writes', async () => {
  const failures = [];
  const written = [];
  const writer = new BoundedAuditWriter({
    maxQueue: 5,
    concurrency: 2,
    async write(event) {
      written.push(event.id);
      if (event.fail === 'throw') throw new Error('destination unavailable');
      if (event.fail === 'reject') return Promise.reject(new Error('destination rejected'));
      return undefined;
    },
    hooks: {
      accepted() { throw new Error('broken accepted hook'); },
      dropped() { return Promise.reject(new Error('broken dropped hook')); },
      writeFailure({ event, error }) {
        failures.push([event.id, error.message]);
      },
    },
  });

  assert.equal(writer.enqueue({ id: 1, fail: 'throw' }), AUDIT_WRITE_RESULTS.ACCEPTED);
  assert.equal(writer.enqueue({ id: 2, fail: 'reject' }), AUDIT_WRITE_RESULTS.ACCEPTED);
  assert.equal(writer.enqueue({ id: 3 }), AUDIT_WRITE_RESULTS.ACCEPTED);
  await assert.doesNotReject(writer.flush());

  assert.deepEqual(written, [1, 2, 3]);
  assert.deepEqual(failures, [
    [1, 'destination unavailable'],
    [2, 'destination rejected'],
  ]);
  assert.equal(writer.counters.writeFailures, 2);
});

test('flush and close share drain promises, and close rejects new work', async () => {
  const first = deferred();
  const second = deferred();
  const started = [];
  const writer = new BoundedAuditWriter({
    maxQueue: 1,
    concurrency: 1,
    async write(event) {
      started.push(event.id);
      await (event.id === 1 ? first.promise : second.promise);
    },
  });

  writer.enqueue({ id: 1 });
  writer.enqueue({ id: 2 });
  const flushOne = writer.flush();
  const flushTwo = writer.flush();
  assert.strictEqual(flushOne, flushTwo);

  const closeOne = writer.close();
  const closeTwo = writer.close();
  assert.strictEqual(closeOne, closeTwo);
  assert.strictEqual(closeOne, flushOne);
  assert.equal(writer.state.accepting, false);
  assert.equal(writer.enqueue({ id: 3 }), AUDIT_WRITE_RESULTS.DROPPED);

  await turn();
  assert.deepEqual(started, [1]);
  first.resolve();
  await turn();
  assert.deepEqual(started, [1, 2]);
  second.resolve();
  await closeOne;

  assert.deepEqual(writer.state, { accepting: false, active: 0, queued: 0, sampleKeys: 0 });
  assert.deepEqual(writer.counters, {
    accepted: 2,
    dropped: 1,
    sampled: 0,
    writeFailures: 0,
  });
  await assert.doesNotReject(writer.flush());
});
