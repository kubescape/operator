package restapihandler

import (
	"net"
	"net/http"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/docs"
	"github.com/panjf2000/ants/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

type HTTPHandler struct {
	pool   *ants.PoolWithFunc
	config config.IConfig
}

func NewHTTPHandler(pool *ants.PoolWithFunc, config config.IConfig) *HTTPHandler {
	return &HTTPHandler{
		pool:   pool,
		config: config,
	}
}

// listenAddress joins the configured bind address and port; an empty address binds every interface.
func listenAddress(bindAddress, port string) string {
	return net.JoinHostPort(bindAddress, port)
}

// newServer bounds what a client can hold: a trigger request is answered as soon as
// its commands are queued, so a request that takes longer than this to arrive or to
// be answered is a stalled client, and no trigger needs a larger header.
func newServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

// router builds the mux; a non-nil auth wraps only the trigger route, the OpenAPI UI stays open.
func (resthandler *HTTPHandler) router(auth func(http.Handler) http.Handler) http.Handler {
	rtr := http.NewServeMux()
	var trigger http.Handler = extractContext(http.HandlerFunc(resthandler.ActionRequest))
	if auth != nil {
		trigger = auth(trigger)
	}
	rtr.Handle("/v1/triggerAction", trigger)

	openAPIUIHandler := docs.NewOpenAPIUIHandler()
	rtr.Handle("GET "+docs.OpenAPIV2Prefix, extractContext(openAPIUIHandler))
	return rtr
}

// SetupHTTPListener set up listening http servers
func (resthandler *HTTPHandler) SetupHTTPListener(bindAddress, port string, auth func(http.Handler) http.Handler) error {
	server := newServer(listenAddress(bindAddress, port), resthandler.router(auth))

	logger.L().Info("Waiting for REST API to receive notifications, address: " + server.Addr)

	return server.ListenAndServe()
}

// Extract W3C context without generating a span for every HTTP request.
func extractContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
