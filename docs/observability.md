# Observability

nettools uses three Cloudflare features and no client-side analytics. The metrics and structured logs written by
the code never contain client IP addresses or tool input, except the request path and error message when an
exception is logged. Cloudflare's invocation logs and traces do include the
request URL (and with it the input), the client IP, user agent and the `cf` request metadata, and are kept for up to
7 days (3 days on the Free plan); the privacy policy says so. From 1 December 2026 Cloudflare bills this under its
Observability pricing.

| What | Where to look | Configured in |
|---|---|---|
| Invocation logs, structured logs, exceptions | Dashboard → Workers → nettools → Logs | `observability` in `wrangler.jsonc` |
| Traces (20 % of requests, incl. outbound `fetch`) | Dashboard → Workers → nettools → Traces | `observability.traces` |
| Automatically detected error patterns | Dashboard → Workers → nettools → Observability | `observability.issue_detection` |
| Per-tool metrics | Analytics Engine SQL API (below) | `analytics_engine_datasets` |

All requests are logged (`head_sampling_rate: 1`) and query strings are not redacted (`redact_query_string: false`),
so the invocation log shows the full request URL.

Live logs while debugging: `npx wrangler tail`.

## Structured logs

Every tool execution (`query`), API call (`api`), rate-limited request (`rate_limited`) and error is logged as an
object, so its fields are indexed in Workers Logs:

```json
{ "event": "query", "route": "dns-lookup", "status": 200, "ms": 112, "colo": "FRA", "country": "DE" }
```

Uncaught exceptions are logged with `event: "exception"`, the route, the path, the error message and the stack
trace. Failures of the root server cron job are logged with `event: "exception"` and `job: "root-monitor"`.
Plain page views get no structured log line; the invocation log already covers them. Speed test transfers
(`/api/speed-test/...`) are neither logged individually nor counted as metrics; one test makes about 60 requests.

## Metrics (Analytics Engine)

Dataset `nettools_events`, one data point per request:

| Column | Content |
|---|---|
| `index1` | route (tool or landing page slug, `home`, `legal`, `ip`, `go`, `api-docs`, `badge`, `not_found`, `other`, `unknown`) |
| `blob1` | kind: `page`, `query`, `api`, `rate_limited`, `error` (any 5xx response) |
| `blob2` | route |
| `blob3` | country code |
| `blob4` | Cloudflare data center |
| `double1` | duration in ms (wall time, includes outbound lookups) |
| `double2` | HTTP status |

Query with an API token that has the *Account Analytics Read* permission:

```sh
curl "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/analytics_engine/sql" \
  -H "Authorization: Bearer $API_TOKEN" \
  --data "SELECT blob2 AS tool, blob1 AS kind, SUM(_sample_interval) AS requests
          FROM nettools_events
          WHERE timestamp > NOW() - INTERVAL '7' DAY
          GROUP BY tool, kind ORDER BY requests DESC"
```

More examples:

```sql
-- Average and slowest tool runs per day
SELECT blob2 AS tool, toStartOfDay(timestamp) AS day,
       SUM(_sample_interval * double1) / SUM(_sample_interval) AS avg_ms,
       max(double1) AS max_ms
FROM nettools_events
WHERE blob1 IN ('query', 'api')
GROUP BY tool, day ORDER BY day DESC, tool;

-- Error and rate-limit share per tool
SELECT blob2 AS tool,
       SUM(IF(blob1 = 'error', _sample_interval, 0)) AS errors,
       SUM(IF(blob1 = 'rate_limited', _sample_interval, 0)) AS limited,
       SUM(_sample_interval) AS total
FROM nettools_events
WHERE timestamp > NOW() - INTERVAL '1' DAY
GROUP BY tool;

-- Top countries
SELECT blob3 AS country, SUM(_sample_interval) AS requests
FROM nettools_events GROUP BY country ORDER BY requests DESC LIMIT 20;
```

Analytics Engine keeps data for three months. The free plan allows 100,000 data points per day.
