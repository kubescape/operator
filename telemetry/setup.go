// Package telemetry owns the operator's operational telemetry policy.
package telemetry

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kubescape/backend/pkg/servicediscovery"
	v3 "github.com/kubescape/backend/pkg/servicediscovery/v3"
	"github.com/kubescape/go-logger/otelsetup"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/log/global"
	lognoop "go.opentelemetry.io/otel/log/noop"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

const Scope = "github.com/kubescape/operator/telemetry"
const endpointEnv = "OTEL_EXPORTER_OTLP_ENDPOINT"

// boundedDiscovery preserves the shared discovery URL and response protocol,
// replacing only its unbounded http.Get transport. No global HTTP state changes.
type boundedDiscovery struct {
	*v3.ServiceDiscoveryClientV3
	ctx context.Context
}

func (d boundedDiscovery) Get() (io.Reader, error) {
	req, err := http.NewRequestWithContext(d.ctx, http.MethodGet, d.GetServiceDiscoveryUrl(), nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 64*1024 {
		return nil, fmt.Errorf("discovery response too large")
	}
	return strings.NewReader(string(data)), nil
}
func discover(ctx context.Context, base string) (string, error) {
	c, err := v3.NewServiceDiscoveryClientV3(base)
	if err != nil {
		return "", err
	}
	s, err := servicediscovery.GetServices(boundedDiscovery{c, ctx})
	if err != nil {
		return "", err
	}
	return s.GetMetricsUrl(), nil
}
func normalize(endpoint string) string {
	if strings.HasPrefix(endpoint, "grpcs://") {
		return "https://" + strings.TrimPrefix(endpoint, "grpcs://")
	}
	if strings.HasPrefix(endpoint, "grpc://") {
		return "http://" + strings.TrimPrefix(endpoint, "grpc://")
	}
	if endpoint != "" && !strings.Contains(endpoint, "://") {
		return "https://" + endpoint
	}
	return endpoint
}

// ConfigureEndpoint returns false for explicit global opt-out. An explicitly
// empty base skips discovery but still allows per-signal overrides.
func ConfigureEndpoint(ctx context.Context, base string) (bool, error) {
	return configureEndpoint(ctx, base, discover)
}
func configureEndpoint(ctx context.Context, base string, get func(context.Context, string) (string, error)) (bool, error) {
	if value, ok := os.LookupEnv(endpointEnv); ok {
		if strings.EqualFold(strings.TrimSpace(value), "disable") {
			return false, nil
		}
		return true, nil
	}
	if legacy := os.Getenv("OTEL_COLLECTOR_SVC"); legacy != "" {
		return true, os.Setenv(endpointEnv, legacy)
	}
	if base == "" {
		return true, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	value, err := get(ctx, base)
	if err != nil {
		return true, err
	}
	if value != "" {
		err = os.Setenv(endpointEnv, normalize(value))
	}
	return true, err
}
func setDefault(key, value string) {
	if _, ok := os.LookupEnv(key); !ok {
		_ = os.Setenv(key, value)
	}
}

// Init uses exactly one shared provider set. Conservative defaults can be
// overridden via standard SDK environment variables (see docs/telemetry.md).
func Init(ctx context.Context, cfg otelsetup.ProviderConfig, enabled bool) (func(context.Context) error, error) {
	if !enabled {
		resetProviders()
		return func(context.Context) error { return nil }, nil
	}
	// Prevent the shared legacy alias from overriding an explicitly empty base.
	if value, ok := os.LookupEnv(endpointEnv); ok && value == "" {
		_ = os.Unsetenv("OTEL_COLLECTOR_SVC")
	}
	for key, value := range providerDefaults {
		setDefault(key, value)
	}
	// The shared debug ring flush bypasses the export gate. Disable its listener
	// while retaining the user's console log level.
	level, hadLevel := os.LookupEnv("KS_LOGGER_LEVEL")
	if level == "debug" {
		_ = os.Setenv("KS_LOGGER_LEVEL", "info")
	}
	shutdown, err := otelsetup.InitProviders(ctx, cfg)
	if hadLevel {
		_ = os.Setenv("KS_LOGGER_LEVEL", level)
	} else {
		_ = os.Unsetenv("KS_LOGGER_LEVEL")
	}
	if err != nil {
		resetProviders()
		return nil, err
	}
	// Legacy spans can contain workload data. Only the bounded operational scope
	// may export spans; existing call sites keep working with nonrecording spans.
	otel.SetTracerProvider(safeTraces{TracerProvider: otel.GetTracerProvider()})
	if os.Getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT") == "" && os.Getenv(endpointEnv) == "" {
		// Shared setup leaves the initial delegating provider untouched when
		// logs are unconfigured. Wrapping it would make it delegate to itself.
		global.SetLoggerProvider(lognoop.NewLoggerProvider())
	} else {
		global.SetLoggerProvider(safeLogs{LoggerProvider: global.GetLoggerProvider()})
	}
	return shutdown, nil
}

type safeTraces struct{ trace.TracerProvider }

func (p safeTraces) Tracer(name string, opts ...trace.TracerOption) trace.Tracer {
	if name != Scope {
		return noop.NewTracerProvider().Tracer(name)
	}
	return p.TracerProvider.Tracer(name, opts...)
}

func resetProviders() {
	otel.SetTracerProvider(noop.NewTracerProvider())
	otel.SetMeterProvider(metricnoop.NewMeterProvider())
	global.SetLoggerProvider(lognoop.NewLoggerProvider())
	otel.SetTextMapPropagator(propagation.TraceContext{})
}

// providerDefaults is immutable; explicit SDK environment values take precedence.
var providerDefaults = map[string]string{
	"OTEL_METRIC_EXPORT_INTERVAL": "300000", "OTEL_METRIC_EXPORT_TIMEOUT": "3000",
	"OTEL_TRACES_SAMPLER": "parentbased_traceidratio", "OTEL_TRACES_SAMPLER_ARG": "0.1",
	"OTEL_EXPORTER_OTLP_COMPRESSION": "gzip", "OTEL_EXPORTER_OTLP_TIMEOUT": "3000",
	"OTEL_BSP_MAX_QUEUE_SIZE": "256", "OTEL_BSP_MAX_EXPORT_BATCH_SIZE": "64", "OTEL_BSP_EXPORT_TIMEOUT": "3000",
	"OTEL_BLRP_MAX_QUEUE_SIZE": "128", "OTEL_BLRP_MAX_EXPORT_BATCH_SIZE": "32", "OTEL_BLRP_EXPORT_TIMEOUT": "3000",
	"OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT": "16", "OTEL_SPAN_EVENT_COUNT_LIMIT": "0",
}
