package restapihandler

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/docs"
	"github.com/panjf2000/ants/v2"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
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

// SetupHTTPListener set up listening http servers
func (resthandler *HTTPHandler) SetupHTTPListener(port string) error {
	err := resthandler.loadTLSKey()
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: fmt.Sprintf(":%v", port),
	}
	if resthandler.keyPair != nil {
		server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*resthandler.keyPair}}
	}
	rtr := http.NewServeMux()
	rtr.Handle("/v1/triggerAction", otelhttp.NewHandler(http.HandlerFunc(resthandler.ActionRequest), "triggerAction"))

	openAPIUIHandler := docs.NewOpenAPIUIHandler()
	rtr.Handle("GET "+docs.OpenAPIV2Prefix, otelhttp.NewHandler(openAPIUIHandler, "openapi"))

	server.Handler = rtr

	logger.L().Info("Waiting for REST API to receive notifications, port: " + port)

	// listen
	if resthandler.keyPair != nil {
		return server.ListenAndServeTLS("", "")
	} else {
		return server.ListenAndServe()
	}
}
