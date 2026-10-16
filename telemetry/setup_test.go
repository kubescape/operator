package telemetry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/go-logger/otelsetup"
)

func unset(t *testing.T, key string) { t.Helper(); t.Setenv(key, ""); _ = os.Unsetenv(key) }
func TestEndpointPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, value            string
		present, enabled, call bool
	}{
		{"unset", "", false, true, true}, {"empty", "", true, true, false}, {"explicit", "http://local:4317", true, true, false}, {"optout", " DiSaBlE ", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unset(t, endpointEnv)
			unset(t, "OTEL_COLLECTOR_SVC")
			t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://trace.example")
			t.Setenv("OTEL_EVENTS_EXPORTER_ENDPOINT", "events-unchanged")
			if tc.present {
				t.Setenv(endpointEnv, tc.value)
			}
			calls := 0
			enabled, err := configureEndpoint(context.Background(), "api.example", func(ctx context.Context, base string) (string, error) {
				calls++
				if _, ok := ctx.Deadline(); !ok {
					t.Error("missing deadline")
				}
				return "collector:443", nil
			})
			if err != nil || enabled != tc.enabled || (calls > 0) != tc.call {
				t.Fatalf("enabled=%v calls=%d err=%v", enabled, calls, err)
			}
			want := tc.value
			if tc.call {
				want = "https://collector:443"
			}
			if got := os.Getenv(endpointEnv); got != want {
				t.Fatalf("got %q want %q", got, want)
			}
			if os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != "https://trace.example" || os.Getenv("OTEL_EVENTS_EXPORTER_ENDPOINT") != "events-unchanged" {
				t.Fatal("signal/event override changed")
			}
		})
	}
}
func TestNormalization(t *testing.T) {
	for input, want := range map[string]string{"": "", "otel:443": "https://otel:443", "http://otel:4317": "http://otel:4317", "https://otel": "https://otel", "grpc://otel": "http://otel", "grpcs://otel": "https://otel"} {
		if got := normalize(input); got != want {
			t.Errorf("%q: %q != %q", input, got, want)
		}
	}
}
func TestDiscoveryFailureAndMissing(t *testing.T) {
	for _, err := range []error{nil, errors.New("unavailable")} {
		unset(t, endpointEnv)
		unset(t, "OTEL_COLLECTOR_SVC")
		enabled, got := configureEndpoint(context.Background(), "api", func(context.Context, string) (string, error) { return "", err })
		if !enabled || got != err {
			t.Fatalf("enabled=%v err=%v", enabled, got)
		}
		if _, ok := os.LookupEnv(endpointEnv); ok {
			t.Fatal("endpoint set on failed/empty discovery")
		}
	}
}
func TestDiscoveryProtocol(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		fail       bool
	}{
		{"success", `{"version":"v3","response":{"metrics":"otel:443"}}`, 200, false},
		{"missing", `{"version":"v3","response":{}}`, 200, false},
		{"status", "", 503, true}, {"malformed", "bad", 200, true}, {"oversized", strings.Repeat("x", 65537), 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v3/servicediscovery" {
					t.Error(r.URL.Path)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			value, err := discover(context.Background(), server.URL)
			if (err != nil) != tc.fail {
				t.Fatalf("%q %v", value, err)
			}
			if tc.name == "success" && value != "otel:443" {
				t.Fatal(value)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := discover(ctx, "http://127.0.0.1:1"); err == nil {
		t.Fatal("canceled discovery succeeded")
	}
}
func TestDisabledInitDoesNotContactEndpoints(t *testing.T) {
	preserveProviderEnv(t)
	t.Setenv(endpointEnv, "disable")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://127.0.0.1:1")
	start := time.Now()
	shutdown, err := Init(context.Background(), otelsetup.ProviderConfig{ServiceName: "operator"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("opt out blocked")
	}
}

func TestLegacyPrecedence(t *testing.T) {
	unset(t, endpointEnv)
	t.Setenv("OTEL_COLLECTOR_SVC", "collector:4317")
	called := false
	enabled, err := configureEndpoint(context.Background(), "api", func(context.Context, string) (string, error) { called = true; return "", nil })
	if err != nil || !enabled || called || os.Getenv(endpointEnv) != "collector:4317" {
		t.Fatal("legacy endpoint lost precedence")
	}
}

func TestDiscoveryRequestCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := discover(ctx, server.URL); err == nil {
		t.Fatal("request ignored cancellation")
	}
	if time.Since(start) > time.Second {
		t.Fatal("discovery exceeded caller deadline")
	}
}

// Register cleanup before Init supplies environment defaults, avoiding order-dependent tests.
func preserveProviderEnv(t *testing.T) {
	t.Helper()
	for key := range providerDefaults {
		value, present := os.LookupEnv(key)
		t.Setenv(key, value)
		if !present {
			_ = os.Unsetenv(key)
		}
	}
}
