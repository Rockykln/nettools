import type { ToolContext } from './tool';

export type EventKind = 'page' | 'query' | 'api' | 'rate_limited' | 'error';

export interface RequestEvent {
  kind: EventKind;
  /** Tool slug, or the route name for non-tool pages ("home", "legal", ...). */
  route: string;
  status: number;
  ms: number;
}

// Writes one data point per request to Analytics Engine and a structured log line for tool usage.
// User input and client IPs are deliberately not recorded (see the privacy section on /legal).
export function recordRequest(c: ToolContext, e: RequestEvent): void {
  const cf = c.req.cf as IncomingRequestCfProperties | undefined;
  const country = typeof cf?.country === 'string' ? cf.country : 'XX';
  const colo = typeof cf?.colo === 'string' ? cf.colo : 'unknown';
  try {
    // blob1 kind, blob2 route, blob3 country, blob4 colo; double1 ms, double2 status
    c.env.EVENTS?.writeDataPoint({
      blobs: [e.kind, e.route, country, colo],
      doubles: [e.ms, e.status],
      indexes: [e.route],
    });
  } catch {
    // Metrics must never break a request.
  }
  // Plain page views are already covered by invocation logs.
  if (e.kind !== 'page') console.log({ event: e.kind, route: e.route, status: e.status, ms: e.ms, colo, country });
}

export function logError(c: ToolContext, route: string, err: unknown): void {
  console.error({
    event: 'exception',
    route,
    path: c.url.pathname,
    message: err instanceof Error ? err.message : String(err),
    stack: err instanceof Error ? err.stack : undefined,
  });
}
