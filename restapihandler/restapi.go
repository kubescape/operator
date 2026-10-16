package restapihandler

import (
	"crypto/tls"
	"net"
	"net/http"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/docs"
	"github.com/panjf2000/ants/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

type HTTPHandler struct {
	keyPair *tls.Certificate
	pool    *ants.PoolWithFunc
	config  config.IConfig
}

func NewHTTPHandler(pool *ants.PoolWithFunc, config config.IConfig) *HTTPHandler {
	return &HTTPHandler{
		keyPair: nil,
		pool:    pool,
		config:  config,
	}
}

// listenAddress joins the configured bind address and port; an empty address binds every interface.
func listenAddress(bindAddress, port string) string {
	return net.JoinHostPort(bindAddress, port)
}

// SetupHTTPListener set up listening http servers
func (resthandler *HTTPHandler) SetupHTTPListener(bindAddress, port string) error {
	err := resthandler.loadTLSKey()
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: listenAddress(bindAddress, port),
	}
	if resthandler.keyPair != nil {
		server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*resthandler.keyPair}}
	}
	rtr := http.NewServeMux()
	rtr.Handle("/v1/triggerAction", extractContext(http.HandlerFunc(resthandler.ActionRequest)))

	openAPIUIHandler := docs.NewOpenAPIUIHandler()
	rtr.Handle("GET "+docs.OpenAPIV2Prefix, extractContext(openAPIUIHandler))

	server.Handler = rtr

	logger.L().Info("Waiting for REST API to receive notifications, address: " + server.Addr)

	// listen
	if resthandler.keyPair != nil {
		return server.ListenAndServeTLS("", "")
	} else {
		return server.ListenAndServe()
	}
}

// Extract W3C context without generating a span for every HTTP request.
func extractContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
