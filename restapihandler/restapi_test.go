package restapihandler

import (
	"context"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	"github.com/panjf2000/ants/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestListenAddress(t *testing.T) {
	tests := []struct {
		name        string
		bindAddress string
		port        string
		want        string
	}{
		{name: "empty address binds every interface", bindAddress: "", port: "4002", want: ":4002"},
		{name: "loopback", bindAddress: "127.0.0.1", port: "4002", want: "127.0.0.1:4002"},
		{name: "ipv6 loopback is bracketed", bindAddress: "::1", port: "4002", want: "[::1]:4002"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, listenAddress(tt.bindAddress, tt.port))
		})
	}
}

func TestExtractContext(t *testing.T) {
	previous := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.TraceContext{})
	defer otel.SetTextMapPropagator(previous)
	request := httptest.NewRequest(http.MethodPost, "/v1/triggerAction", nil)
	request.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	called := false
	handler := extractContext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		sc := trace.SpanContextFromContext(r.Context())
		if !sc.IsRemote() || sc.TraceID().String() != "4bf92f3577b34da6a3ce929d0e0e4736" {
			t.Fatal("incoming trace context lost")
		}
	}))
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if !called {
		t.Fatal("handler not called")
	}
}

type telemetryConfig struct{ config.IConfig }

func (telemetryConfig) AccountID() string { return "test-account" }
func TestActionRequestPreservesAsyncTraceContext(t *testing.T) {
	previous := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.TraceContext{})
	defer otel.SetTextMapPropagator(previous)
	jobs := make(chan utils.Job, 1)
	pool, err := ants.NewPoolWithFunc(1, func(value interface{}) { jobs <- value.(utils.Job) })
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Release()
	handler := NewHTTPHandler(pool, telemetryConfig{})
	request := httptest.NewRequest(http.MethodPost, "/v1/triggerAction", strings.NewReader(`{"commands":[{"commandName":"kubescapeScan"}]}`))
	request.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	ctx, cancel := context.WithCancel(request.Context())
	request = request.WithContext(ctx)
	response := httptest.NewRecorder()
	extractContext(http.HandlerFunc(handler.ActionRequest)).ServeHTTP(response, request)
	cancel()
	if response.Code != http.StatusOK {
		t.Fatalf("%d: %s", response.Code, response.Body)
	}
	select {
	case job := <-jobs:
		sc := trace.SpanContextFromContext(job.Context())
		if sc.TraceID().String() != "4bf92f3577b34da6a3ce929d0e0e4736" || sc.SpanID().String() != "00f067aa0ba902b7" {
			t.Fatal("queued job lost trace context")
		}
		if job.Context().Err() != nil {
			t.Fatal("async work canceled with HTTP request")
		}
	case <-time.After(time.Second):
		t.Fatal("job not dispatched")
	}
}
