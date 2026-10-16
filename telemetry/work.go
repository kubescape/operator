package telemetry

import (
	"context"
	"runtime"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/log/noop"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// Only enumerated classifications enter exported data, including span names.
func Kind(command string) string {
	switch command {
	case "scan", "scanContainerProfile":
		return "image_scan"
	case "kubescapeScan", "runKubescapeJob":
		return "posture_scan"
	case "scanRegistry", "scanRegistryV2":
		return "registry_scan"
	case "setKubescapeCronJob", "updateKubescapeCronJob", "deleteKubescapeCronJob", "setVulnScanCronJob", "updateVulnScanCronJob", "deleteVulnScanCronJob":
		return "schedule"
	case "operatorAction":
		return "remediation"
	default:
		return "other"
	}
}

type Recorder struct {
	completed metric.Int64Counter
	duration  metric.Float64Histogram
	active    metric.Int64UpDownCounter
	slow      metric.Int64Counter
	mu        sync.Mutex
	progress  map[string]progress
}
type progress struct {
	active int
	last   time.Time
}

func NewRecorder() *Recorder {
	m := otel.Meter(Scope)
	completed, _ := m.Int64Counter("operator.work.completed", metric.WithUnit("{operation}"))
	duration, _ := m.Float64Histogram("operator.work.duration", metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(.01, .1, 1, 10, 60, 300))
	active, _ := m.Int64UpDownCounter("operator.work.active", metric.WithUnit("{operation}"))
	slow, _ := m.Int64Counter("operator.work.slow", metric.WithUnit("{operation}"))
	r := &Recorder{completed: completed, duration: duration, active: active, slow: slow, progress: map[string]progress{}}
	age, _ := m.Float64ObservableGauge("operator.work.progress_age", metric.WithUnit("s"))
	_, _ = m.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		for kind, p := range r.progress {
			value := 0.0
			if p.active > 0 {
				value = time.Since(p.last).Seconds()
			}
			o.ObserveFloat64(age, value, metric.WithAttributes(attribute.String("kind", kind)))
		}
		return nil
	}, age)
	return r
}

// Begin counts every operation; high-volume work only creates a retrospectively
// timed slow-path span after 10s, globally gated to one per minute.
func (r *Recorder) Begin(ctx context.Context, command string) (context.Context, func(error)) {
	return r.beginAt(ctx, command, time.Now())
}
func (r *Recorder) beginAt(ctx context.Context, command string, start time.Time) (context.Context, func(error)) {
	kind := Kind(command)
	attrs := []attribute.KeyValue{attribute.String("kind", kind)}
	r.mu.Lock()
	p := r.progress[kind]
	if p.active == 0 {
		p.last = start
	}
	p.active++
	r.progress[kind] = p
	r.mu.Unlock()
	r.active.Add(ctx, 1, metric.WithAttributes(attrs...))
	var span trace.Span
	if (kind == "schedule" || kind == "remediation") && controlGate.allow("control", time.Now()) {
		ctx, span = otel.Tracer(Scope).Start(ctx, "operator.control", trace.WithAttributes(attrs...))
	}
	return ctx, func(err error) {
		r.mu.Lock()
		p := r.progress[kind]
		p.active--
		p.last = time.Now()
		r.progress[kind] = p
		r.mu.Unlock()
		elapsed := time.Since(start)
		outcome := "success"
		if err != nil {
			outcome = "error"
		}
		r.active.Add(ctx, -1, metric.WithAttributes(attrs...))
		dimensions := append(attrs, attribute.String("outcome", outcome))
		r.completed.Add(ctx, 1, metric.WithAttributes(dimensions...))
		r.duration.Record(ctx, elapsed.Seconds(), metric.WithAttributes(dimensions...))
		if elapsed >= 10*time.Second {
			r.slow.Add(ctx, 1, metric.WithAttributes(attrs...))
			if span == nil && slowGate.allow("slow", time.Now()) {
				ctx, span = otel.Tracer(Scope).Start(ctx, "operator.work.slow", trace.WithTimestamp(start), trace.WithAttributes(dimensions...))
			}
		}
		if span != nil {
			span.SetAttributes(attribute.String("outcome", outcome))
			if err != nil {
				span.SetStatus(codes.Error, "operation failed")
			}
			defer span.End()
		}
		if err != nil {
			record := otellog.Record{}
			record.SetTimestamp(time.Now())
			record.SetSeverity(otellog.SeverityError)
			record.SetBody(attribute.StringValue("operator work failed"))
			record.AddAttributes(attribute.String("kind", kind), attribute.String("outcome", outcome))
			global.GetLoggerProvider().Logger(Scope).Emit(ctx, record)
		}
	}
}

// fixedGate stores only bounded internal keys; one diagnostic per kind/minute.
type fixedGate struct {
	mu   sync.Mutex
	next map[string]time.Time
}

func (g *fixedGate) allow(key string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.Before(g.next[key]) {
		return false
	}
	if g.next == nil {
		g.next = map[string]time.Time{}
	}
	g.next[key] = now.Add(time.Minute)
	return true
}

var logGate, slowGate, controlGate fixedGate

// The export boundary denies legacy arbitrary log bodies/attributes, regardless
// of local logger verbosity. Only safe diagnostics from this package pass.
type safeLogs struct{ otellog.LoggerProvider }

func (p safeLogs) Logger(name string, opts ...otellog.LoggerOption) otellog.Logger {
	if name != Scope {
		return noop.NewLoggerProvider().Logger(name)
	}
	return filteredLog{Logger: p.LoggerProvider.Logger(name, opts...)}
}

type filteredLog struct{ otellog.Logger }

func (l filteredLog) Enabled(ctx context.Context, p otellog.EnabledParameters) bool {
	return p.Severity >= otellog.SeverityWarn && l.Logger.Enabled(ctx, p)
}
func (l filteredLog) Emit(ctx context.Context, r otellog.Record) {
	if r.Severity() < otellog.SeverityWarn || r.Body().AsString() != "operator work failed" {
		return
	}
	kind := "other"
	r.WalkAttributes(func(kv attribute.KeyValue) bool {
		if kv.Key == "kind" {
			kind = kv.Value.AsString()
		}
		return true
	})
	switch kind {
	case "image_scan", "posture_scan", "registry_scan", "schedule", "remediation":
	default:
		kind = "other"
	}
	if !logGate.allow(kind, time.Now()) {
		counter, _ := otel.Meter(Scope).Int64Counter("operator.telemetry.suppressed", metric.WithUnit("{record}"))
		counter.Add(ctx, 1, metric.WithAttributes(attribute.String("signal", "logs")))
		return
	}
	// Rebuild so caller-supplied attributes never escape the allowlist.
	clean := otellog.Record{}
	clean.SetTimestamp(r.Timestamp())
	clean.SetSeverity(otellog.SeverityError)
	clean.SetBody(attribute.StringValue("operator work failed"))
	clean.AddAttributes(attribute.String("kind", kind), attribute.String("outcome", "error"))
	l.Logger.Emit(ctx, clean)
}

// ObservePool reports pressure independently of workload identity. Registration
// is owned by the pool's lifetime and must be released on shutdown.
func ObservePool(running, waiting, capacity func() int) (metric.Registration, error) {
	m := otel.Meter(Scope)
	g, err := m.Int64ObservableGauge("operator.worker_pool", metric.WithUnit("{worker}"))
	if err != nil {
		return nil, err
	}
	heap, _ := m.Int64ObservableGauge("operator.runtime.heap", metric.WithUnit("By"))
	goroutines, _ := m.Int64ObservableGauge("operator.runtime.goroutines", metric.WithUnit("{goroutine}"))
	return m.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		o.ObserveInt64(heap, int64(stats.HeapAlloc))
		o.ObserveInt64(goroutines, int64(runtime.NumGoroutine()))
		for key, value := range map[string]int{"running": running(), "waiting": waiting(), "capacity": capacity()} {
			o.ObserveInt64(g, int64(value), metric.WithAttributes(attribute.String("state", key)))
		}
		return nil
	}, g, heap, goroutines)
}

// Admission records only fixed outcomes; it never exports objects or rule IDs.
func Admission(ctx context.Context, outcome string, elapsed time.Duration) {
	switch outcome {
	case "queued", "dropped", "self", "unmatched_kind", "empty", "evaluated", "error":
	default:
		outcome = "error"
	}
	m := otel.Meter(Scope)
	counter, _ := m.Int64Counter("operator.admission.events", metric.WithUnit("{event}"))
	counter.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
	if outcome == "evaluated" || outcome == "error" {
		hist, _ := m.Float64Histogram("operator.admission.duration", metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(.001, .01, .1, 1, 10))
		hist.Record(ctx, elapsed.Seconds(), metric.WithAttributes(attribute.String("outcome", outcome)))
	}
}
func ObserveAdmission(size, capacity func() int) (metric.Registration, error) {
	m := otel.Meter(Scope)
	g, err := m.Int64ObservableGauge("operator.admission.queue", metric.WithUnit("{event}"))
	if err != nil {
		return nil, err
	}
	return m.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		o.ObserveInt64(g, int64(size()), metric.WithAttributes(attribute.String("state", "queued")))
		o.ObserveInt64(g, int64(capacity()), metric.WithAttributes(attribute.String("state", "capacity")))
		return nil
	}, g)
}

// Reconcile instruments one autoscaler control cycle without node-group labels.
func Reconcile(ctx context.Context) (context.Context, func(error)) {
	start := time.Now()
	var span trace.Span
	if controlGate.allow("control", start) {
		ctx, span = otel.Tracer(Scope).Start(ctx, "operator.autoscaler.reconcile")
	}
	return ctx, func(err error) {
		outcome := "success"
		if err != nil {
			outcome = "error"
		}
		m := otel.Meter(Scope)
		counter, _ := m.Int64Counter("operator.autoscaler.cycles", metric.WithUnit("{cycle}"))
		counter.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
		hist, _ := m.Float64Histogram("operator.autoscaler.duration", metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(.01, .1, 1, 10, 60, 300))
		hist.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attribute.String("outcome", outcome)))
		if span != nil {
			span.SetAttributes(attribute.String("outcome", outcome))
			if err != nil {
				span.SetStatus(codes.Error, "operation failed")
			}
			span.End()
		}
	}
}
