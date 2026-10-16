# Operator operational telemetry

The operator exports bounded operational metrics, sampled control spans, and sanitized
error diagnostics through `kubescape/go-logger/otelsetup` v0.0.35. It answers:

- Are scan requests completing, failing, or taking longer? Which fixed class of work?
- Is the worker pool saturated, with callers waiting for workers?
- Is active work making no progress? Is admission evaluation dropping events?
- Is autoscaler reconciliation failing or slowing down?
- Are diagnostic records being suppressed during a failure storm?
- Is heap usage or goroutine count growing with pressure?

Read the shared [current implementation document](https://github.com/armosec/shared-designs-and-docs/blob/docs/otel-implementation-reality/projects/agent-telemetry-system/research/high-level-requirements.md#current-implementation-october-16-2026)
for system context. Its May proposal is historical. **5–15 KB/agent/hour is an
unvalidated planning target, not an enforced or measured operator budget.**

## Initialization and configuration

Discovery completes before the single shared provider initialization; the ordinary
logger is then constructed, followed by instruments and worker pools. Configuration
errors that prevent startup can still print local fatal logs before initialization.
Missing credentials and discovery/provider failures are nonfatal to operational
telemetry. Shutdown uses a fresh background context with a five-second deadline.
The old `logger.InitOtel` provider path is removed, avoiding duplicate exporters.

| Setting | Effective default / precedence |
|---|---|
| Discovery source | `API_URL` if present (including empty), otherwise `capabilities.json` → `configurations.server.discoveryUrl`; empty skips discovery. Existing backend v3 client URL/parser, `metrics` field, one attempt, 3-second deadline, 64 KiB response limit, no redirects. No new discovery protocol. |
| Endpoint | Base `OTEL_EXPORTER_OTLP_ENDPOINT=disable` (trimmed, case-insensitive) disables all operational signals and skips discovery, including per-signal/legacy settings. Any other present base value, including empty, skips discovery. Otherwise nonempty `OTEL_COLLECTOR_SVC` wins over discovery. Explicitly empty base prevents the shared legacy alias from re-enabling it. |
| Per-signal endpoints | `OTEL_EXPORTER_OTLP_{METRICS,TRACES,LOGS}_ENDPOINT` override base via shared setup; empty signal values fall back to base. Global `disable` wins. |
| Discovered normalization | Bare host defaults to `https://`; `http://`/`https://` preserved; `grpc://` → `http://`, `grpcs://` → `https://`, matching reference implementation. Explicit endpoints retain shared setup semantics (bare legacy host uses plaintext). |
| Identity | `service.name=operator`, `service.version=RELEASE`; cluster and namespace from existing operator config; node/pod from `NODE_NAME`/`POD_NAME` when supplied. Account is not a metric dimension. |
| Authentication | Existing `/etc/credentials` account/accessKey passed through `ProviderConfig`; shared setup injects `X-API-ACCOUNT`/`X-API-KEY` for every configured signal endpoint when accessKey is nonempty. Configure trusted endpoints only. Credentials are never in exported records. |
| Metric interval | `OTEL_METRIC_EXPORT_INTERVAL=300000` ms (5 minutes); timeout `OTEL_METRIC_EXPORT_TIMEOUT=3000` ms. Chosen for one operator per cluster and aggregate support/capacity signals; not copied from node agent. |
| Trace sampler | `OTEL_TRACES_SAMPLER=parentbased_traceidratio`, `OTEL_TRACES_SAMPLER_ARG=0.1`. Remote sampled parents remain sampled, but creation gates still apply. |
| Exported logs | Fixed error diagnostic `operator work failed` only, from operational instrumentation scope; export severity floor warn. Arbitrary legacy logs are denied independently of console verbosity. |
| Compression | `OTEL_EXPORTER_OTLP_COMPRESSION=gzip` (gRPC shared exporters). Standard per-signal settings override. |
| Rate limits | Error logs: 1 per fixed work kind per 60 seconds (6 keys, maximum 6/minute). Control spans: 1/minute globally across scheduling, remediation, autoscaler. Slow-work spans: separate 1/minute globally, only after ≥10 seconds. No per-workload keys. |
| Queues / retries | Trace queue 256 / batch 64; log queue 128 / batch 32; nonblocking SDK enqueue drops on overflow. `OTEL_BSP_*`/`OTEL_BLRP_*` export timeouts 3000 ms. `OTEL_EXPORTER_OTLP_TIMEOUT=3000` ms bounds exporter attempts including SDK retries; no application retry queue. Shared periodic metrics export is synchronous with a bounded timeout and cumulative aggregation. |
| Span data limits | Attribute count 16; event count 0. Operational scope uses only fixed names, kind and outcome. Legacy arbitrary span scopes are nonrecording. |

Standard environment defaults above are applied **only if unset**. Overrides can
increase volume and queue memory, reduce the interval, or lengthen retries; invalid
values follow the pinned SDK's fallback behavior. The fixed diagnostic/control/slow
rate gates and scope allowlists cannot be disabled through environment variables.
Per-signal `*_TIMEOUT` and `*_COMPRESSION` take precedence over the base settings.
Shared setup uses gRPC exporters; setting `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`
does not switch this implementation to HTTP. Exporter selection variables such as
`OTEL_SDK_DISABLED` are not the shared setup's disable mechanism; use base `disable`.

Operational telemetry never reads or writes `OTEL_EVENTS_EXPORTER_ENDPOINT`, which
belongs to the separate sandbox event stream. `components.otelCollector.enabled`
controls a different deployment feature and no longer gates operational exports.

## Inventory and cardinality

All instrument names start with `operator.`; metric dimensions contain no tenant,
workload, request, URL, Kubernetes kind/name, rule ID, or error string.

| Instrument | Dimensions / meaning |
|---|---|
| `work.completed` | `kind`, `outcome=success/error`; completed single scan/action dispatches, including itemized scope children |
| `work.duration` | Same; seconds, boundaries **.01, .1, 1, 10, 60, 300** |
| `work.active` | `kind`; currently executing single actions |
| `work.slow` | `kind`; all completions taking ≥10s, independent of span gate/sampling |
| `work.progress_age` | `kind`; seconds since a completion or start of a busy period while work is active; zero when idle |
| `worker_pool` | `state=running/waiting/capacity`; ants workers, callers blocked waiting for pool capacity, configured worker capacity |
| `runtime.heap`, `runtime.goroutines` | No dimensions; allocated Go heap bytes and goroutine count at collection; no additional runtime instrumentation/provider |
| `telemetry.suppressed` | `signal=logs`; safe error diagnostics dropped by the 60-second gate, not SDK transport loss |
| `admission.events` | `outcome=queued/dropped/self/unmatched_kind/empty/evaluated/error`; queue-full events counted independently of console warnings |
| `admission.duration` | `outcome=evaluated/error`; async evaluation seconds, boundaries **.001, .01, .1, 1, 10** |
| `admission.queue` | `state=queued/capacity`; evaluation queue pressure, registered while workers run |
| `autoscaler.cycles`, `autoscaler.duration` | `outcome=success/error`; reconciliation cycles and seconds, duration boundaries **.01, .1, 1, 10, 60, 300** |

Work kinds are exactly `image_scan`, `posture_scan`, `registry_scan`, `schedule`,
`remediation`, `other`. Unknown commands collapse to `other`. Outcomes are fixed
classifications. More workloads increase counts, not metric dimension combinations.
Distinct operator replicas and resource attributes still increase fleet series.
Histogram buckets add backend series; inventory all bucket/count/sum series when sizing.

Low-volume control spans (`operator.control`, `operator.autoscaler.reconcile`) retain
incoming W3C trace context and use a creation gate before sampling. High-volume scan
and admission flows do not create a span per event. `operator.work.slow` is created
retrospectively with the original start time at completion; it cannot contain child
spans from work already performed. Error status descriptions are fixed strings.
REST extracts W3C context without automatic HTTP spans/URL attributes. Scanner HTTP
requests inject W3C context (including retries) to Kubescape and Kubevuln. Asynchronous
admission work uses worker context and aggregate metrics; per-request context is not
retained in that existing queue.

Safe exported error logs carry only kind and outcome and inherit trace/span IDs from
the active context. Local console logs retain existing formatting/verbosity and may
contain more detail; they are excluded from operational log export. Do not forward
console logs through a separate collector expecting this application filter to apply.
The shared debug ring-buffer HTTP listener is deliberately disabled during shared
initialization, even if console `KS_LOGGER_LEVEL=debug`, because direct ring flush
would bypass the operational export filter. Safe records can still occupy the shared
7,500-record in-memory ring; there is no flush endpoint or flight-recorder guarantee.

## Deployment audit

No collector or deployment files were changed. Checked-in `configuration/capabilities.json`
has an illustrative `configurations.server.discoveryUrl=foo.com`, not a production
API endpoint; there is no credential sample in this repository. `build/Dockerfile`
sets `RELEASE` from image_version and packages only the binary. Local/container
execution needs mounted config and `/etc/credentials/{account,accessKey}` (or an
explicit endpoint for a collector that permits unauthenticated traffic).

Read-only Helm source audit at
[`1607513c0d00c0f0338692ba98b9958784a2cd36`](https://github.com/kubescape/helm-charts/tree/1607513c0d00c0f0338692ba98b9958784a2cd36/charts/kubescape-operator):

- `templates/operator/deployment.yaml` mounts cloud credentials at `/etc/credentials`,
  capabilities/config/clusterData files under `/etc/config`, supplies `NODE_NAME`,
  logger settings and arbitrary `operator.env`. It does not supply `POD_NAME` or
  `API_URL` by default.
- `templates/configs/cloud-secret.yaml` supplies account/accessKey from chart values,
  unless an existing cloud secret is selected. Blank defaults mean no authenticated
  telemetry until credentials are supplied.
- `templates/configs/components-configmap.yaml` copies `.Values.configurations`.
  Default `values.yaml` has no `configurations.server.discoveryUrl`. The unrelated
  top-level `server` does not reach this component's discovery field. Thus a default
  chart install does not automatically discover telemetry: supply `API_URL` using
  `operator.env`, set the existing nested discovery field, or provide an explicit
  base/per-signal endpoint. Offline installs with no API/endpoint remain off.

These are source checks, not rendered release manifests or a live deployment audit.
Follow-ups for chart owners: wire the intended backend API URL and pod identity and
verify the deployed cloud secret. Follow-ups for shared-library owners: expose
sampler/processor/exporter options and disable-ring options directly rather than
requiring environment defaults and provider policy wrappers; expose transport drop
counters. Collector owners must validate tenant/fleet quotas and pipeline protections
separately. None of those cross-repository changes is included here.

## Troubleshooting and verification

Examples (adapt metric names to the backend's OTLP-to-query translation):

- Compare `rate(operator.work.completed{outcome="error"}[15m])` with successful
  completions by kind, then examine `work.duration` percentiles.
- Rising `worker_pool{state="waiting"}` with running near capacity and growing heap
  suggests capacity pressure. Increasing `work.progress_age` with active work and no
  completed-count increase suggests stalled dispatch; it is a class-level progress
  signal, not a per-job deadline detector.
- `admission.events{outcome="dropped"}` increasing and queue at capacity means events
  were skipped; inspect evaluation duration and CPU availability before raising queue
  capacity. This queue is separate from the main ants pool.
- Failed autoscaler cycles mean desired DaemonSets may not be reconciled. Inspect a
  sampled reconciliation trace and existing local logs for detailed Kubernetes errors.
- A small number of generic error logs plus rising `telemetry.suppressed` means a
  repetitive failure storm; counters remain unsuppressed. Use trace IDs when present.
- No exports: verify opt-out/explicit-empty/base/per-signal precedence, nonempty API
  URL, discovery's `metrics` field, TLS scheme, trusted gRPC listener, credentials and
  network reachability. Startup warnings deliberately omit URLs and error payloads.

Run `go test -v ./telemetry` for offline discovery/precedence/cancellation tests and
local gRPC receiver fixtures. The normal fixture runs 60 operations; the burst fixture
runs 10,000 in one gate window, each mixing all six kinds and failures. Both initially
measured **8 emitted instruments, 30 OTLP data points, 1 span, 6 logs, 4,732 serialized
protobuf bytes** over a single final export with sampling forced to always-on. Completed-work counts equal operation counts. This fixture includes pool/runtime
metrics, not admission/autoscaler activity, slow work, or a representative live cluster.
Receiver-side gRPC stats also measured gzip request payloads: **1,987 bytes** normal
and **2,012 bytes** burst in one run; with gRPC message framing these were **2,002**
and **2,027 bytes**. Tests report uncompressed protobuf bytes by signal as well.
These values exclude HTTP/2/TLS framing, retries, periodic repeats, and collector-generated
data; they are not an hourly rate or complete network-byte accounting. Runtime values,
timestamps and trace IDs can change encoded sizes and compression ratios.

Additional tests exercise slow gates/progress age, bounded outcome classification,
admission drops, trace correlation, authentication injection, canceled discovery and
backend outage with bounded shutdown. Existing admission tests cover actual queue-full
and drain behavior. No tests contact production services. Full repository tests and
relevant race/vet/build checks are recorded in the PR.

Remaining limitations: sampling and fixed gates intentionally omit individual events;
work success means dispatch completion, not downstream scan completion; scoped-parent
list failures and existing silent skip paths are not individual work failures. Progress
age can miss a stuck member when peers in its kind continue completing. CPU and
end-to-end queue residence time are not measured. No application byte quota, live
fleet cardinality measurement, collector quota, or backend admission guarantee is
claimed. Batching, authentication, retention, and container memory limits are not ingest
quotas. During outages exports can be lost; core work does not wait for telemetry.
