package telemetry

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/go-logger/otelsetup"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	logpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	metricpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
	"google.golang.org/protobuf/proto"
)

type captured struct {
	mu                         sync.Mutex
	metrics                    []*metricpb.ExportMetricsServiceRequest
	traces                     []*tracepb.ExportTraceServiceRequest
	logs                       []*logpb.ExportLogsServiceRequest
	authenticated              bool
	compressedBytes, grpcBytes int
}
type metricServer struct {
	metricpb.UnimplementedMetricsServiceServer
	c *captured
}

func (s metricServer) Export(ctx context.Context, r *metricpb.ExportMetricsServiceRequest) (*metricpb.ExportMetricsServiceResponse, error) {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	s.c.metrics = append(s.c.metrics, r)
	md, _ := metadata.FromIncomingContext(ctx)
	s.c.authenticated = len(md.Get("x-api-key")) == 1 && md.Get("x-api-key")[0] == "test-secret" && len(md.Get("x-api-account")) == 1 && md.Get("x-api-account")[0] == "test-account"
	return &metricpb.ExportMetricsServiceResponse{}, nil
}

type traceServer struct {
	tracepb.UnimplementedTraceServiceServer
	c *captured
}

func (s traceServer) Export(_ context.Context, r *tracepb.ExportTraceServiceRequest) (*tracepb.ExportTraceServiceResponse, error) {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	s.c.traces = append(s.c.traces, r)
	return &tracepb.ExportTraceServiceResponse{}, nil
}

type logServer struct {
	logpb.UnimplementedLogsServiceServer
	c *captured
}

func (s logServer) Export(_ context.Context, r *logpb.ExportLogsServiceRequest) (*logpb.ExportLogsServiceResponse, error) {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	s.c.logs = append(s.c.logs, r)
	return &logpb.ExportLogsServiceResponse{}, nil
}
func TestNormalAndBurstExports(t *testing.T) {
	for _, n := range []int{60, 10000} {
		t.Run(map[bool]string{true: "normal", false: "burst"}[n == 60], func(t *testing.T) {
			preserveProviderEnv(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			c := &captured{}
			server := grpc.NewServer(grpc.StatsHandler(payloadStats{c}))
			metricpb.RegisterMetricsServiceServer(server, metricServer{c: c})
			tracepb.RegisterTraceServiceServer(server, traceServer{c: c})
			logpb.RegisterLogsServiceServer(server, logServer{c: c})
			go func() { _ = server.Serve(listener) }()
			defer server.Stop()
			t.Setenv(endpointEnv, "http://"+listener.Addr().String())
			t.Setenv("OTEL_TRACES_SAMPLER", "always_on")
			t.Setenv("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip")
			t.Setenv("OTEL_METRIC_EXPORT_INTERVAL", "3600000")
			for _, signal := range []string{"TRACES", "LOGS", "METRICS"} {
				t.Setenv("OTEL_EXPORTER_OTLP_"+signal+"_ENDPOINT", "")
			}
			if n == 10000 {
				t.Setenv(endpointEnv, "http://127.0.0.1:1")
				for _, signal := range []string{"TRACES", "LOGS", "METRICS"} {
					t.Setenv("OTEL_EXPORTER_OTLP_"+signal+"_ENDPOINT", "http://"+listener.Addr().String())
				}
			}
			t.Setenv("KS_LOGGER_LEVEL", "debug")
			logGate = fixedGate{}
			controlGate = fixedGate{}
			slowGate = fixedGate{}
			shutdown, err := Init(context.Background(), otelsetup.ProviderConfig{ServiceName: "operator", ServiceVersion: "test", AccountID: "test-account", AccessKey: "test-secret"}, true)
			if err != nil {
				t.Fatal(err)
			}
			defer resetProviders()
			registration, err := ObservePool(func() int { return 1 }, func() int { return 0 }, func() int { return 4 })
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = registration.Unregister() }()
			recorder := NewRecorder()
			ctx := context.Background()
			commands := []string{"scan", "kubescapeScan", "scanRegistryV2", "setKubescapeCronJob", "operatorAction", "attacker-controlled-command"}
			for i := 0; i < n; i++ {
				_, end := recorder.Begin(ctx, commands[i%len(commands)])
				end(errors.New("sensitive payload must not export"))
			}
			// Legacy arbitrary logs and spans must not reach any exporter or ring buffer.
			r := otellog.Record{}
			r.SetSeverity(otellog.SeverityError)
			r.SetBody(attribute.StringValue("credential secret"))
			global.GetLoggerProvider().Logger("slog").Emit(ctx, r)
			_, span := otel.Tracer("").Start(ctx, "attacker span")
			span.End()
			if err := shutdown(ctx); err != nil {
				t.Fatal(err)
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			metrics, points, spans, logs, bytes := 0, 0, 0, 0, 0
			correlated := false
			metricBytes, traceBytes, logBytes := 0, 0, 0
			var operations int64
			for _, req := range c.metrics {
				metricBytes += proto.Size(req)
				bytes += proto.Size(req)
				for _, rm := range req.ResourceMetrics {
					for _, sm := range rm.ScopeMetrics {
						for _, m := range sm.Metrics {
							metrics++
							if sum := m.GetSum(); sum != nil {
								points += len(sum.DataPoints)
								if m.Name == "operator.work.completed" {
									for _, p := range sum.DataPoints {
										operations += p.GetAsInt()
									}
								}
							}
							if gauge := m.GetGauge(); gauge != nil {
								points += len(gauge.DataPoints)
							}
							if hist := m.GetHistogram(); hist != nil {
								points += len(hist.DataPoints)
								for _, p := range hist.DataPoints {
									if len(p.ExplicitBounds) != 6 {
										t.Error("wrong histogram boundaries")
									}
								}
							}
						}
					}
				}
			}
			for _, req := range c.traces {
				traceBytes += proto.Size(req)
				bytes += proto.Size(req)
				for _, rs := range req.ResourceSpans {
					for _, ss := range rs.ScopeSpans {
						spans += len(ss.Spans)
						for _, s := range ss.Spans {
							if s.Name != "operator.control" {
								t.Error("unexpected span", s.Name)
							}
						}
					}
				}
			}
			for _, req := range c.logs {
				logBytes += proto.Size(req)
				bytes += proto.Size(req)
				for _, rl := range req.ResourceLogs {
					for _, sl := range rl.ScopeLogs {
						logs += len(sl.LogRecords)
						for _, record := range sl.LogRecords {
							if len(record.TraceId) == 16 {
								correlated = true
							}
						}
						for _, r := range sl.LogRecords {
							if r.Body.GetStringValue() != "operator work failed" || len(r.Attributes) != 2 {
								t.Error("unsafe log")
							}
						}
					}
				}
			}
			if spans != 1 || logs != 6 || points != 30 || operations != int64(n) || !c.authenticated || !correlated {
				t.Fatalf("metrics=%d points=%d spans=%d logs=%d auth=%v", metrics, points, spans, logs, c.authenticated)
			}
			if c.compressedBytes <= 0 || c.compressedBytes >= bytes {
				t.Fatal("gzip request payload was not smaller than protobuf fixture")
			}
			t.Logf("metric_protobuf_bytes=%d trace_protobuf_bytes=%d log_protobuf_bytes=%d", metricBytes, traceBytes, logBytes)
			t.Logf("operations=%d metric_instruments=%d data_points=%d spans=%d logs=%d protobuf_bytes=%d gzip_payload_bytes=%d grpc_message_bytes=%d (one shutdown export; excludes HTTP2/TLS; not hourly traffic)", n, metrics, points, spans, logs, bytes, c.compressedBytes, c.grpcBytes)
		})
	}
}

func TestBackendOutageDoesNotBlockWork(t *testing.T) {
	preserveProviderEnv(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "http://" + listener.Addr().String()
	_ = listener.Close()
	t.Setenv(endpointEnv, endpoint)
	t.Setenv("OTEL_METRIC_EXPORT_INTERVAL", "3600000")
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "100")
	for _, signal := range []string{"TRACES", "LOGS", "METRICS"} {
		t.Setenv("OTEL_EXPORTER_OTLP_"+signal+"_ENDPOINT", "")
	}
	shutdown, err := Init(context.Background(), otelsetup.ProviderConfig{ServiceName: "operator"}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer resetProviders()
	r := NewRecorder()
	start := time.Now()
	for i := 0; i < 10000; i++ {
		_, end := r.Begin(context.Background(), "scan")
		end(errors.New("failure"))
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("core work blocked during outage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start = time.Now()
	_ = shutdown(ctx)
	if time.Since(start) > time.Second {
		t.Fatal("shutdown exceeded bound")
	}
}

// Receiver-side gRPC stats measure compressed request bytes plus message framing;
// unlike proto.Size, these values reflect gzip actually used by the exporters.
type payloadStats struct{ c *captured }

func (h payloadStats) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context { return ctx }
func (h payloadStats) HandleRPC(_ context.Context, s stats.RPCStats) {
	if p, ok := s.(*stats.InPayload); ok {
		h.c.mu.Lock()
		defer h.c.mu.Unlock()
		h.c.compressedBytes += p.CompressedLength
		h.c.grpcBytes += p.WireLength
	}
}
func (h payloadStats) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context { return ctx }
func (h payloadStats) HandleConn(context.Context, stats.ConnStats)                       {}
