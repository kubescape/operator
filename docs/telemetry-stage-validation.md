# Operator live stage validation — October 16, 2026

PR [#437](https://github.com/kubescape/operator/pull/437), implementation commit
`b55796edcbc1c9aa830d82554932218064563e14`, was temporarily deployed to the existing
operator in `armo-dev-stage`. Metrics, traces, and logs were verified in **SigNoz
running in that same cluster**, through the endpoint advertised by backend discovery.
The original Deployment specification was restored and its operator became ready.

This is a single-cluster measurement of real workload activity plus an explicitly
injected validation-failure burst. It is not a fleet-wide or hourly byte-budget audit.
**5–15 KB/agent/hour remains an unvalidated planning target, not a quota or live rate.**

## Environment and effective settings

| Setting | Verified value |
|---|---|
| Cluster / operator fleet | 25 mixed amd64/arm64 nodes; one operator replica |
| Original and restored image | `quay.io/kubescape/operator:v0.2.181` |
| Tested multi-architecture image digest | `sha256:c01ad301cd5e7ce1ec3d65eed624e2c129e90212af16fa3168a7c0b36d5fa376` |
| Tested service identity | `operator`, version `otel-measurement-b55796e` |
| Discovery source | Temporary `API_URL=https://api-dev.armosec.io`; existing backend v3 discovery client/parser |
| Advertised endpoint | `otel.dev-stage.armosec.io:443`, normalized to `https://otel.dev-stage.armosec.io:443` |
| Authentication | Existing mounted account/access-key credentials; no credential values extracted or logged |
| Metric interval | Default 300000 ms; live collection times confirm five-minute cadence |
| Trace sampler | Default parent-based 10% roots; test requests used a sampled incoming W3C parent to verify context, still subject to creation gates |
| Logs | Existing console configuration `zap`/`info`; separate fixed error-record export allowlist and per-kind 60-second gate |
| Compression / queues / retries | Unchanged application defaults documented in [telemetry configuration](telemetry.md); gzip behavior was measured separately by local receiver tests, not observed on the encrypted live connection |
| Collector | Existing two-replica `armo-signoz-otel-collector:v0.4.0`; authenticated OTLP, tenant stamping and span-metric generation; no collector changes |

Only the operator image, API_URL, and a measurement annotation were temporarily
changed, under explicit authorization. No chart source, shared library, discovery
contract, collector configuration, replica count, or resource limits were changed.

## Procedure and timing

1. Save the original Deployment and prepare a targeted restoration patch.
2. Build the PR code for both architectures and await the replacement operator's
   readiness. The test container started at **10:16:09 UTC** without restarts.
3. Query the cluster's SigNoz ClickHouse tables by service name/version for counts,
   series, dimension keys and timestamps. Check pod readiness and resource samples.
4. Send one initial validation probe, then 36 calibration requests between
   **10:18:43 and 10:20:04 UTC**, spread over approximately 80 seconds.
5. Observe normal cluster activity through two default metric export cycles.
6. At **10:26:32.938 UTC**, submit 1000 validation failures in a single 47014-byte
   HTTP request. The endpoint returned HTTP 200/`ok` at **10:26:33.465 UTC**:
   **0.526 seconds** to accept/dispatch the burst. Completion was verified separately
   from the next exported cumulative counter.
7. Observe the next metric collection, restore the Deployment, verify exact original
   spec equality and readiness, and check the test process's final exported collection.
   Restoration was verified at **10:32:22.814 UTC**.

All injected commands were `operatorAction` with empty arguments. They fail on missing
`action` before target resolution or resource mutation. They did not execute remediation
or deliberately trigger downstream scans. Actual cluster watchers continued dispatching
image/posture work independently. No outage or queue-overflow event was induced live;
those failure paths retain the targeted offline test evidence.

## Measured results

Cumulative values below are for the tested service version. Log/span totals were read
from ingested SigNoz records after each relevant collection.

| Observation | First collection | Normal checkpoint | After burst |
|---|---:|---:|---:|
| Metric timestamp, UTC | 10:21:09.477 | 10:26:09.478 | 10:31:09.478 |
| Successful image-scan dispatches | 1023 | 1080 | 1128 |
| Successful posture dispatches | 1 | 1 | 1 |
| Intentional validation failures completed | 37 | 37 | 1037 |
| Error logs suppressed | 34 | 34 | 1033 |
| Exported fixed-body error logs | 3 | 3 | 4 |
| Exported `operator.control` spans | 2 | 2 | 2 |
| Application stored series | 74 | 74 | 74 |
| Successful autoscaler cycles | 2 | 3 | 4 |
| Admission events queued / evaluated | 6 / 6 | 9 / 9 | 15 / 15 |

The burst added **1000 completed failures, one exported error log and 999 suppressed
logs**, with **no application series growth**. Normal image-scan dispatches also
continued: +57 in the normal five-minute interval and +48 in the interval containing
the burst. Dispatch completion does not establish downstream scan completion.

The live interval differences were **300.001 seconds** and **300.000 seconds**.
SigNoz received the test process's fourth collection at **10:31:55.496 UTC** during
restoration, providing evidence that shutdown performed a final metric flush.

### Cardinality and signal detail

- The application occupied **25 stored metric names / 74 series** before and after
  the burst. SigNoz expands histograms into bucket/count/sum/**min/max** metrics;
  these stored series are different from raw OTLP instrument/data-point counts.
- Collector-generated span metrics added **21 related series**:
  `signoz_calls_total` (1), `signoz_latency.bucket` (18), count (1), sum (1).
  The pre-restoration total was therefore **95 related stored series**.
- During restoration, admission outcome `empty` appeared for the first time, adding
  one bounded counter series. The final total was **75 application / 96 related
  series**. This was a new value from the fixed outcome enumeration, not a new
  workload/request dimension or growth caused by the 1000-request burst.
- Observed metric dimension keys were `kind`, `outcome`, `state`, `signal`, and the
  SDK/collector fields `le` and `__temporality__`. No workload/request identities,
  raw URLs or error strings appeared in application metric dimensions.
- All four exported error logs had the fixed body `operator work failed`, severity
  number 17 (error), and only `kind`/`outcome` diagnostic attributes. All carried trace
  context. Calibration control spans preserved the incoming W3C parent context.
- No per-image-scan spans appeared despite more than a thousand successful dispatches.
  The burst itself emitted no new control span because the global control gate was
  already occupied by autoscaler reconciliation. A sampled incoming parent did not
  bypass that gate. The burst log retained its incoming parent context even though
  there was no locally recorded child span; a trace ID does not guarantee a complete
  stored trace when gates or sampling omit spans.
- Readiness remained healthy and the test container had zero restarts. Point samples
  showed 2m CPU / 55 MiB memory before the burst and 2m / 51 MiB afterward. These are
  observations, not peak-load measurements or an A/B attribution of telemetry overhead.
  Main worker capacity was 3 and admission queue capacity was 1000; both queues were
  idle at metric collection times, which does not establish their instantaneous peak.

## Byte accounting and remaining limits

The live collector's `signozmeter` connector uses **metrics_flush_interval: 1h** and
hour buckets. No completed operator-specific byte-meter bucket was available during
this approximately 16-minute experiment. Live bytes by signal and an hourly operator
rate were therefore **not measured**. Compressed ClickHouse storage and unrelated
fleet traffic were not used as substitutes for ingest bytes. The local receiver's
measured protobuf/gzip/message sizes remain separate [synthetic evidence](telemetry.md).

This run verifies discovery routing, authenticated ingestion, identity, normal cadence,
bounded dimensions, real workload aggregation, burst suppression, trace correlation,
and a final shutdown metric collection. It does not establish a fleet quota, sustained
burst behavior across many clusters, representative hourly bytes, live outage recovery,
or a complete end-to-end trace through downstream scanners. Application/collector byte
limits and representative fleet measurements remain follow-ups.

For similar checks, query `signoz_metrics.time_series_v4` by the tested service version
for unique fingerprints, `samples_v4` for collection times and cumulative deltas, and
`signoz_traces.signoz_index_v3` / `signoz_logs.logs_v2` by service name/version for spans
and logs. Include collector-generated series whose service dimension is `operator`;
do not count only the `operator.*` names when sizing SigNoz. Keep queries time-bounded
and compare the same service version/resource population.

## Restoration evidence

The original Deployment's complete `spec` matched the saved pre-test spec after
restoration, including image, environment, mounts, settings and absence of the
measurement annotation. One original operator replica was ready. The local port-forward
and rollback watchdog were stopped, and temporary registry credential copies removed.
The test image tag is retained for reproducibility; it is not a released operator tag.
