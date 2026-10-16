package telemetry

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestSlowWorkAndProgress(t *testing.T) {
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	otel.SetMeterProvider(mp)
	defer func() { _ = mp.Shutdown(context.Background()); resetProviders() }()
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter), sdktrace.WithSampler(sdktrace.AlwaysSample()))
	otel.SetTracerProvider(tp)
	defer func() { _ = tp.Shutdown(context.Background()) }()
	slowGate = fixedGate{}
	r := NewRecorder()
	ctx, end := r.beginAt(context.Background(), "scan", time.Now().Add(-11*time.Second))
	var data metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &data); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name == "operator.work.progress_age" {
				g := m.Data.(metricdata.Gauge[float64])
				found = len(g.DataPoints) == 1 && g.DataPoints[0].Value >= 11
			}
		}
	}
	if !found {
		t.Fatal("active work age missing")
	}
	end(nil)
	_, end = r.beginAt(context.Background(), "scan", time.Now().Add(-12*time.Second))
	end(nil)
	spans := exporter.GetSpans()
	if len(spans) != 1 || spans[0].Name != "operator.work.slow" {
		t.Fatalf("slow gate spans: %v", spans)
	}
	if got := Kind("untrusted /secret?key=value"); got != "other" {
		t.Fatal(got)
	}
}
func TestFixedGate(t *testing.T) {
	var gate fixedGate
	now := time.Now()
	if !gate.allow("key", now) || gate.allow("key", now.Add(59*time.Second)) || !gate.allow("key", now.Add(time.Minute)) {
		t.Fatal("gate window")
	}
}
func TestAdmissionAndAutoscalerMetrics(t *testing.T) {
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	otel.SetMeterProvider(mp)
	defer func() { _ = mp.Shutdown(context.Background()); resetProviders() }()
	ctx := context.Background()
	Admission(ctx, "dropped", 0)
	Admission(ctx, "attacker controlled", time.Millisecond)
	_, end := Reconcile(ctx)
	end(nil)
	var data metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &data); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name == "operator.admission.events" {
				sum := m.Data.(metricdata.Sum[int64])
				for _, p := range sum.DataPoints {
					v, _ := p.Attributes.Value(attribute.Key("outcome"))
					if v.AsString() == "dropped" && p.Value == 1 {
						found = true
					}
					if v.AsString() != "dropped" && v.AsString() != "error" {
						t.Fatal("unbounded outcome")
					}
				}
			}
		}
	}
	if !found {
		t.Fatal("admission drop not counted")
	}
}
