package restapihandler

import (
	"crypto/tls"
	"fmt"
	"k8s-ca-websocket/docs"
	"k8s-ca-websocket/utils"
	"net/http"

	"github.com/golang/glog"
	"github.com/gorilla/mux"
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
	rtr.HandleFunc("/v1/triggerAction", resthandler.ActionRequest)

	openAPIUIHandler := docs.NewOpenAPIUIHandler()
	rtr.PathPrefix(docs.OpenAPIV2Prefix).Methods("GET").Handler(openAPIUIHandler)

	server.Handler = rtr

	glog.Infof("Waiting for REST API to receive notifications, port: %s", utils.RestAPIPort)

	// listen
	if resthandler.keyPair != nil {
		return server.ListenAndServeTLS("", "")
	} else {
		return server.ListenAndServe()
	}
}
