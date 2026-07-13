/**
 * Best-effort, bounded delivery for high-volume protocol audit events.
 *
 * Security-sensitive account and administration events that require durable,
 * synchronous recording must bypass this component and use the durable audit
 * store directly.
 */

const RESULTS = Object.freeze({
  ACCEPTED: 'accepted',
  DROPPED: 'dropped',
  SAMPLED: 'sampled',
});

const RESOLVED = Promise.resolve();
const MAX_SAMPLE_KEY_LENGTH = 512;

function requireInteger(name, value, minimum) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new TypeError(`${name} must be a safe integer greater than or equal to ${minimum}`);
  }
}

function invokeHook(hook, details) {
  if (typeof hook !== 'function') return;

  try {
    const result = hook(details);
    if (result && typeof result.then === 'function') {
      // Hooks are observational. Their failures must never affect audit delivery
      // or become unhandled promise rejections.
      void result.catch(() => {});
    }
  } catch {
    // A telemetry hook must not be able to break the writer.
  }
}

class FixedQueue {
  #items;
  #head = 0;
  #tail = 0;
  #length = 0;

  constructor(capacity) {
    this.capacity = capacity;
    this.#items = new Array(capacity);
  }

  get length() {
    return this.#length;
  }

  push(value) {
    if (this.#length === this.capacity) return false;

    this.#items[this.#tail] = value;
    this.#tail = (this.#tail + 1) % this.capacity;
    this.#length += 1;
    return true;
  }

  shift() {
    if (this.#length === 0) return undefined;

    const value = this.#items[this.#head];
    this.#items[this.#head] = undefined;
    this.#head = (this.#head + 1) % this.capacity;
    this.#length -= 1;
    return value;
  }
}

/**
 * A non-blocking, bounded asynchronous audit-event writer.
 *
 * `enqueue()` never returns a delivery promise and therefore cannot accumulate
 * one waiter per event. Use `flush()` only at explicit lifecycle boundaries.
 */
export class BoundedAuditWriter {
  #write;
  #queue;
  #concurrency;
  #active = 0;
  #accepting = true;
  #hooks;
  #counts = {
    accepted: 0,
    dropped: 0,
    sampled: 0,
    writeFailures: 0,
  };
  #samples = new Map();
  #maxSampleKeys;
  #now;
  #flushPromise = null;
  #resolveFlush = null;
  #closePromise = null;

  constructor({
    write,
    maxQueue = 1_024,
    concurrency = 4,
    maxSampleKeys = 4_096,
    hooks = {},
    now = Date.now,
  } = {}) {
    if (typeof write !== 'function') throw new TypeError('write must be a function');
    requireInteger('maxQueue', maxQueue, 0);
    requireInteger('concurrency', concurrency, 1);
    requireInteger('maxSampleKeys', maxSampleKeys, 1);
    if (hooks === null || typeof hooks !== 'object') throw new TypeError('hooks must be an object');
    if (typeof now !== 'function') throw new TypeError('now must be a function');

    this.#write = write;
    this.#queue = new FixedQueue(maxQueue);
    this.#concurrency = concurrency;
    this.#maxSampleKeys = maxSampleKeys;
    this.#hooks = hooks;
    this.#now = now;
  }

  get counters() {
    return Object.freeze({ ...this.#counts });
  }

  get state() {
    return Object.freeze({
      accepting: this.#accepting,
      active: this.#active,
      queued: this.#queue.length,
      sampleKeys: this.#samples.size,
    });
  }

  /**
   * Attempt to schedule an event without waiting.
   *
   * To sample repeated events, provide both a stable `sampleKey` and a positive
   * `sampleWindowMs`. The first event is accepted normally; repeats with the
   * same key inside that window return `sampled` and are not written.
   */
  enqueue(event, options = {}) {
    const sample = this.#validateSampleOptions(options);

    if (!this.#accepting) {
      this.#recordDropped(event, 'closed');
      return RESULTS.DROPPED;
    }

    let now;
    if (sample) {
      now = this.#readClock();
      this.#pruneSamples(now);
      const expiresAt = this.#samples.get(sample.key);
      if (expiresAt !== undefined && expiresAt > now) {
        this.#counts.sampled += 1;
        invokeHook(this.#hooks.sampled, {
          event,
          key: sample.key,
          windowMs: sample.windowMs,
          counters: this.counters,
        });
        return RESULTS.SAMPLED;
      }
    }

    const work = { event };
    let startImmediately = false;
    if (this.#active < this.#concurrency) {
      // Reserve the worker slot before invoking observational hooks. This keeps
      // the concurrency limit intact even if a hook re-enters enqueue().
      this.#active += 1;
      startImmediately = true;
    } else if (this.#queue.push(work)) {
      // The fixed queue owns this work item before any hook can re-enter.
    } else {
      this.#recordDropped(event, 'queue_full');
      return RESULTS.DROPPED;
    }

    if (sample) {
      const expiresAt = now + sample.windowMs;
      this.#rememberSample(sample.key, Number.isFinite(expiresAt) ? expiresAt : Number.MAX_VALUE);
    }
    this.#accept(work);
    if (startImmediately) this.#execute(work);
    return RESULTS.ACCEPTED;
  }

  /** Wait until every event accepted before the writer next becomes idle. */
  flush() {
    if (this.#active === 0 && this.#queue.length === 0) return RESOLVED;
    if (this.#flushPromise) return this.#flushPromise;

    this.#flushPromise = new Promise((resolve) => {
      this.#resolveFlush = resolve;
    });
    return this.#flushPromise;
  }

  /** Stop accepting events and drain all previously accepted work. */
  close() {
    if (this.#closePromise) return this.#closePromise;

    this.#accepting = false;
    this.#closePromise = this.flush();
    return this.#closePromise;
  }

  #validateSampleOptions(options) {
    if (options === null || typeof options !== 'object') {
      throw new TypeError('enqueue options must be an object');
    }

    const hasKey = options.sampleKey !== undefined && options.sampleKey !== null;
    const hasWindow = options.sampleWindowMs !== undefined && options.sampleWindowMs !== null;
    if (!hasKey && !hasWindow) return null;
    if (!hasKey || !hasWindow) {
      throw new TypeError('sampleKey and sampleWindowMs must be provided together');
    }
    if (
      typeof options.sampleKey !== 'string'
      || options.sampleKey.length === 0
      || options.sampleKey.length > MAX_SAMPLE_KEY_LENGTH
    ) {
      throw new TypeError(`sampleKey must be a non-empty string no longer than ${MAX_SAMPLE_KEY_LENGTH} characters`);
    }
    requireInteger('sampleWindowMs', options.sampleWindowMs, 1);

    return { key: options.sampleKey, windowMs: options.sampleWindowMs };
  }

  #readClock() {
    const value = this.#now();
    if (!Number.isFinite(value)) throw new TypeError('now must return a finite number');
    return value;
  }

  #pruneSamples(now) {
    for (const [key, expiresAt] of this.#samples) {
      if (expiresAt <= now) this.#samples.delete(key);
    }
  }

  #rememberSample(key, expiresAt) {
    if (!this.#samples.has(key) && this.#samples.size >= this.#maxSampleKeys) {
      let earliestKey;
      let earliestExpiry = Infinity;
      for (const [candidateKey, candidateExpiry] of this.#samples) {
        if (candidateExpiry < earliestExpiry) {
          earliestKey = candidateKey;
          earliestExpiry = candidateExpiry;
        }
      }
      this.#samples.delete(earliestKey);
    }
    this.#samples.set(key, expiresAt);
  }

  #accept({ event }) {
    this.#counts.accepted += 1;
    invokeHook(this.#hooks.accepted, { event, counters: this.counters });
  }

  #recordDropped(event, reason) {
    this.#counts.dropped += 1;
    invokeHook(this.#hooks.dropped, { event, reason, counters: this.counters });
  }

  #execute(work) {
    Promise.resolve()
      .then(() => this.#write(work.event))
      .catch((error) => {
        this.#counts.writeFailures += 1;
        invokeHook(this.#hooks.writeFailure, {
          event: work.event,
          error,
          counters: this.counters,
        });
      })
      .finally(() => {
        this.#active -= 1;
        this.#drain();
      });
  }

  #drain() {
    while (this.#active < this.#concurrency && this.#queue.length > 0) {
      this.#active += 1;
      this.#execute(this.#queue.shift());
    }

    if (this.#active !== 0 || this.#queue.length !== 0 || !this.#resolveFlush) return;

    const resolve = this.#resolveFlush;
    this.#resolveFlush = null;
    this.#flushPromise = null;
    resolve();
  }
}

export function createAuditWriter(options) {
  return new BoundedAuditWriter(options);
}

export const AUDIT_WRITE_RESULTS = RESULTS;
