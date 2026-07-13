import client from 'prom-client';

export function createMetrics() {
  const registry = new client.Registry();
  client.collectDefaultMetrics({ register: registry, prefix: 'authme_' });

  const requests = new client.Counter({
    name: 'authme_http_requests_total',
    help: 'Completed HTTP requests.',
    labelNames: ['method', 'route_class', 'status_class'],
    registers: [registry],
  });
  const duration = new client.Histogram({
    name: 'authme_http_request_duration_seconds',
    help: 'HTTP request duration.',
    labelNames: ['method', 'route_class'],
    buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
    registers: [registry],
  });
  const protocolAudit = new client.Counter({
    name: 'authme_protocol_audit_events_total',
    help: 'Best-effort protocol audit events by queue outcome.',
    labelNames: ['outcome'],
    registers: [registry],
  });

  function routeClass(path) {
    if (path.startsWith('/realms/')) return 'oidc';
    if (path.startsWith('/admin/')) return 'admin';
    if (path.startsWith('/health/')) return 'health';
    if (path === '/metrics') return 'metrics';
    if (path.startsWith('/assets/')) return 'assets';
    return 'other';
  }

  return {
    middleware(req, res, next) {
      const started = process.hrtime.bigint();
      res.once('finish', () => {
        const labels = { method: req.method, route_class: routeClass(req.path) };
        requests.inc({ ...labels, status_class: `${Math.floor(res.statusCode / 100)}xx` });
        duration.observe(labels, Number(process.hrtime.bigint() - started) / 1e9);
      });
      next();
    },
    contentType: registry.contentType,
    recordProtocolAudit(outcome) {
      protocolAudit.inc({ outcome });
    },
    async render() {
      return registry.metrics();
    },
    clear() {
      registry.clear();
    },
  };
}
