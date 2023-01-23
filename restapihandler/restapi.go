package restapihandler

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/operator/docs"
	"github.com/kubescape/operator/utils"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gorilla/mux/otelmux"
)

type HTTPHandler struct {
	keyPair    *tls.Certificate
	sessionObj *chan utils.SessionObj
}

func NewHTTPHandler(sessionObj *chan utils.SessionObj) *HTTPHandler {
	return &HTTPHandler{
		keyPair:    nil,
		sessionObj: sessionObj,
	}
}

// SetupHTTPListener set up listening http servers
func (resthandler *HTTPHandler) SetupHTTPListener() error {
	err := resthandler.loadTLSKey()
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: fmt.Sprintf(":%v", utils.RestAPIPort),
	}
	if resthandler.keyPair != nil {
		server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*resthandler.keyPair}}
	}
	rtr := mux.NewRouter()
	rtr.Use(otelmux.Middleware("operator-http"))
	rtr.HandleFunc("/v1/triggerAction", resthandler.ActionRequest)

	openAPIUIHandler := docs.NewOpenAPIUIHandler()
	rtr.PathPrefix(docs.OpenAPIV2Prefix).Methods("GET").Handler(openAPIUIHandler)

	server.Handler = rtr

	logger.L().Info("Waiting for REST API to receive notifications, port: " + utils.RestAPIPort)

	// listen
	if resthandler.keyPair != nil {
		return server.ListenAndServeTLS("", "")
	} else {
		return server.ListenAndServe()
	}
}
