#!/usr/bin/env node

import { open, readFile, stat, unlink } from 'node:fs/promises';
import { basename, dirname, extname, join, resolve } from 'node:path';

import {
  formatCompatibilityReport,
  stableJsonStringify,
  transformKeycloakRealm,
} from '../src/migration/keycloak-import.js';

const maxExportBytes = 128 * 1024 * 1024;

function usage() {
  return `Usage: node scripts/kc-import.mjs <realm-export.json> [options]

Transforms one Keycloak realm export into an AuthMe import artifact and a
compatibility report. The command is a dry run unless --write is supplied.

Options:
  --public-url <origin>       AuthMe public origin used to construct the issuer
  --issuer <issuer>           Exact AuthMe issuer ending in /realms/{realm}
  --write                     Write three output files (exclusive; no overwrite)
  --config-out <file>         AuthMe import artifact path
  --report-out <file>         Structured JSON compatibility report path
  --human-report-out <file>   Human-readable compatibility report path
  --dry-run                   Explicitly retain dry-run behavior
  --help                      Show this help

In dry-run mode, stdout is a JSON object containing both config and report;
the human-readable report is written to stderr.
`;
}

function parseArguments(arguments_) {
  const options = { write: false };
  let input;
  const valueOptions = new Map([
    ['--public-url', 'publicUrl'],
    ['--issuer', 'issuer'],
    ['--config-out', 'configOut'],
    ['--out', 'configOut'],
    ['--report-out', 'reportOut'],
    ['--report', 'reportOut'],
    ['--human-report-out', 'humanReportOut'],
  ]);
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === '--help' || argument === '-h') return { help: true };
    if (argument === '--write') {
      options.write = true;
      continue;
    }
    if (argument === '--dry-run') {
      options.write = false;
      continue;
    }
    const option = valueOptions.get(argument);
    if (option) {
      const value = arguments_[index + 1];
      if (!value || value.startsWith('--')) throw new Error(`${argument} requires a value`);
      if (options[option] !== undefined) throw new Error(`${argument} was supplied more than once`);
      options[option] = value;
      index += 1;
      continue;
    }
    if (argument.startsWith('-')) throw new Error(`Unknown option: ${argument}`);
    if (input) throw new Error('Exactly one Keycloak realm export file is required');
    input = argument;
  }
  if (!input) throw new Error('A Keycloak realm export file is required');
  return { input, ...options };
}

function defaultOutputs(input) {
  const absolute = resolve(input);
  const extension = extname(absolute);
  const stem = basename(absolute, extension);
  const directory = dirname(absolute);
  return {
    configOut: join(directory, `${stem}.authme.json`),
    reportOut: join(directory, `${stem}.compatibility.json`),
    humanReportOut: join(directory, `${stem}.compatibility.txt`),
  };
}

async function readExport(path) {
  const metadata = await stat(path);
  if (!metadata.isFile()) throw new Error(`Keycloak export is not a regular file: ${path}`);
  if (metadata.size > maxExportBytes) throw new Error(`Keycloak export exceeds the ${maxExportBytes} byte safety limit`);
  const text = await readFile(path, 'utf8');
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`Keycloak export does not contain valid JSON: ${error.message}`, { cause: error });
  }
}

async function writeOutputs(outputs) {
  const opened = [];
  try {
    for (const [path, contents] of outputs) {
      const handle = await open(path, 'wx', 0o600);
      opened.push({ path, contents, handle });
    }
    for (const output of opened) {
      await output.handle.writeFile(output.contents, 'utf8');
      await output.handle.sync();
    }
  } catch (error) {
    await Promise.all(opened.map(({ handle }) => handle.close().catch(() => {})));
    await Promise.all(opened.map(({ path }) => unlink(path).catch(() => {})));
    throw error;
  }
  await Promise.all(opened.map(({ handle }) => handle.close()));
}

async function main() {
  const arguments_ = parseArguments(process.argv.slice(2));
  if (arguments_.help) {
    process.stdout.write(usage());
    return;
  }
  const input = resolve(arguments_.input);
  const source = await readExport(input);
  const result = transformKeycloakRealm(source, {
    ...(arguments_.publicUrl ? { publicUrl: arguments_.publicUrl } : {}),
    ...(arguments_.issuer ? { issuer: arguments_.issuer } : {}),
  });
  const humanReport = formatCompatibilityReport(result.report);
  if (!arguments_.write) {
    process.stdout.write(stableJsonStringify(result));
    process.stderr.write(humanReport);
    return;
  }

  const defaults = defaultOutputs(input);
  const outputs = {
    configOut: resolve(arguments_.configOut ?? defaults.configOut),
    reportOut: resolve(arguments_.reportOut ?? defaults.reportOut),
    humanReportOut: resolve(arguments_.humanReportOut ?? defaults.humanReportOut),
  };
  if (new Set(Object.values(outputs)).size !== 3 || Object.values(outputs).includes(input)) {
    throw new Error('Input, config, JSON report, and human report paths must all be distinct');
  }
  try {
    await writeOutputs([
      [outputs.configOut, stableJsonStringify(result.config)],
      [outputs.reportOut, stableJsonStringify(result.report)],
      [outputs.humanReportOut, humanReport],
    ]);
  } catch (error) {
    throw new Error(`Output files were not written: ${error.message}`, { cause: error });
  }
  process.stdout.write(`Wrote AuthMe config: ${outputs.configOut}\n`);
  process.stdout.write(`Wrote compatibility report JSON: ${outputs.reportOut}\n`);
  process.stdout.write(`Wrote compatibility report text: ${outputs.humanReportOut}\n`);
}

main().catch((error) => {
  process.stderr.write(`kc-import: ${error.message}\n`);
  process.exitCode = 1;
});
