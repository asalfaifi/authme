import { createServer } from 'node:http';
import { createAuthMeApp } from './app.js';
import { loadConfig } from './config.js';
import { createLogger } from './logging.js';

const config = loadConfig();
const logger = createLogger(config.logLevel);
const runtime = await createAuthMeApp(config, { logger });
const server = createServer(runtime.app);
let stopping = false;

server.requestTimeout = 30_000;
server.headersTimeout = 15_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 100;

async function shutdown(signal) {
  if (stopping) return;
  stopping = true;
  logger.info({ signal }, 'Shutting down AuthMe');
  const forced = setTimeout(() => {
    logger.error('Graceful shutdown timed out');
    process.exit(1);
  }, 15_000).unref();
  server.closeIdleConnections();
  await new Promise((resolve) => server.close(resolve));
  await runtime.close();
  clearTimeout(forced);
}

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => shutdown(signal).catch((error) => {
    logger.fatal({ error }, 'Shutdown failed');
    process.exitCode = 1;
  }));
}

process.on('uncaughtException', (error) => {
  logger.fatal({ error }, 'Uncaught exception');
  process.exit(1);
});
process.on('unhandledRejection', (error) => {
  logger.fatal({ error }, 'Unhandled rejection');
  process.exit(1);
});

server.listen(config.port, '0.0.0.0', () => {
  logger.info({ port: config.port, publicUrl: config.publicUrl, realms: config.realms }, 'AuthMe is ready');
});
