# Authz tracing

`authz_received` is emitted at WSGI application entry, before Flask dispatch.
`authz_completed` is emitted when the non-streaming auth response reaches
WSGI `start_response` (response ready), or when an uncaught application failure
escapes. These events do not measure TCP accept/worker queue time, header parsing,
network transit, socket flushing, or receipt by nginx. A worker killed in flight
may leave only a receipt. An absent event is not proof of a network problem:
queueing, logger level, lost logs, or delivery/retention failure can also explain it.

The forwarded `X-Pguru-Trace-ID` must be exactly 32 lowercase hexadecimal
characters. Otherwise a fresh local UUID hex value is used. `trace_source`
distinguishes `forwarded` from `generated`; a generated ID cannot correlate with
an upstream ID. Repeated valid IDs are possible: use timestamps and worker PID
as well. Trace IDs are JSON fields, never Prometheus or Loki stream labels.

Fields: `event`, `trace_id`, `trace_source`, integer `epoch_seconds`, constant
`route=/authz`, and `worker_pid`. Completion adds integer HTTP `status`, bounded
`outcome` (`allowed`, `denied`, `error`), and monotonic `elapsed_seconds`.
No response header or authorization decision changes. No raw access logs.

Existing auth result/error messages have been replaced. While executing /authz,
a filter on the root handlers sanitizes lower-level diagnostics before the Loki
queue: it retains severity/source and trace ID, replaces the message with a
constant, strips extras and exception/stack text, and sets `authz_diagnostic`.
This intentionally trades detailed exception messages for privacy; an internal
HMAC exception that is treated as denial still produces a correlated diagnostic.
Logs outside /authz are unchanged. Logging/metric emission failures must not
change the auth response. The existing byteforge-loki-logging asynchronous queue
is reused; it is not durable and does not guarantee delivery. Verify INFO trace
records reach Loki on each rollout and confirm retention with the Loki operator.

Example LogQL (query over an appropriate UTC incident time window):

```logql
{application="api-gatekeeper"} | json | trace_id="0123456789abcdef0123456789abcdef"
```

Do not add trace ID to stream labels. Verify a synthetic no-credential denial
with a known trace ID yields both events, identical IDs, and status 400 or 403.
Keep sensitive original URLs/headers out of test output and sample logs.

## Metrics changes

Counters and histograms are recorded once at the same response-ready boundary,
including early 400 responses and handled 500 responses. `result=error` and
`auth_errors_total{error_type="server_error"}` identify 5xx outcomes. Durations
use monotonic time; finite buckets extend through 2.5, 3, 5, 10 and 30 seconds.
Existing `route_pattern` labels remain matched configured route IDs (or the
constant `__unmatched__`), never the original URI. Method is from a fixed HTTP
method allowlist, with `__unknown__` for invalid/missing input.

Multiprocess collection already existed and is retained. Four-worker tests
verify summed counters/histograms and `livesum` gauges. Dead-worker cleanup
removes live gauge shards; cumulative counter/histogram shards intentionally
remain until the container startup cleanup resets the process-lifetime series.

Pool `idle` now means actual idle connections, rather than unused maximum
capacity. Snapshots of psycopg2 `_pool`/`_used` are taken under its `_lock`, since
there is no public statistics API. These are last-operation samples, not a queue
length or a continuously updated view during a blocked connection/pre-ping.
`max` remains configured capacity per live worker. Expect the idle series to
step down after this release; it is a semantic correction, not lost connections.
