#!/usr/bin/env node
import { runCommand } from '../src/operations/backup.js';
import { monitorAvailability, probeRealmAvailability } from '../src/operations/availability-rehearsal.js';

function option(name) { const index = process.argv.indexOf(name); return index === -1 ? undefined : process.argv[index + 1]; }
const baseUrl = option('--base-url');
if (!baseUrl) throw new Error('Usage: npm run ha:rehearse -- --base-url https://auth.example.com [--realm master --execute --namespace authme --deployment authme --probe-interval-ms 250]');
const origin = new URL(baseUrl).origin;
const realm = option('--realm') ?? 'master';
const probeIntervalMs = Number(option('--probe-interval-ms') ?? '250');
if (!Number.isSafeInteger(probeIntervalMs) || probeIntervalMs < 50 || probeIntervalMs > 10_000) throw new Error('--probe-interval-ms must be an integer between 50 and 10000');
const serviceProbe = () => probeRealmAvailability({ origin, realm });
const report = { startedAt: new Date().toISOString(), origin, realm, baseline: await serviceProbe() };
if (process.argv.includes('--execute')) {
  const namespace = option('--namespace');
  const deployment = option('--deployment') ?? 'authme';
  if (!namespace) throw new Error('--namespace is required with --execute');
  const context = option('--context');
  const prefix = context ? ['--context', context] : [];
  const monitored = await monitorAvailability({
    intervalMs: probeIntervalMs,
    probe: serviceProbe,
    async operation() {
      await runCommand('kubectl', [...prefix, '--namespace', namespace, 'rollout', 'restart', `deployment/${deployment}`]);
      await runCommand('kubectl', [...prefix, '--namespace', namespace, 'rollout', 'status', `deployment/${deployment}`, '--timeout=10m']);
    },
  });
  report.rollout = {
    namespace, deployment, completed: !monitored.operationError,
    ...(monitored.operationError ? { error: monitored.operationError.message } : {}),
  };
  report.availability = monitored.report;
  try {
    report.after = await serviceProbe();
  } catch (error) {
    report.after = { error: error.message };
    process.exitCode = 1;
  }
  if (monitored.operationError || monitored.report.failures) process.exitCode = 1;
} else {
  report.planOnly = true;
}
report.completedAt = new Date().toISOString();
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
