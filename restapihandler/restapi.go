package restapihandler

import (
	"crypto/tls"
	"fmt"
	"k8s-ca-websocket/cautils"
	"net/http"

	"github.com/gorilla/mux"
)

type HTTPHandler struct {
	keyPair    *tls.Certificate
	sessionObj *chan cautils.SessionObj
}

func NewHTTPHandler(sessionObj *chan cautils.SessionObj) *HTTPHandler {
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
		Addr: fmt.Sprintf(":%v", cautils.RestAPIPort), // port
	}
	if resthandler.keyPair != nil {
		server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*resthandler.keyPair}}
	}
	rtr := mux.NewRouter()
	rtr.HandleFunc("/v1/safeMode", resthandler.SafeMode)
	server.Handler = rtr

	// listen
	if resthandler.keyPair != nil {
		return server.ListenAndServeTLS("", "")
	} else {
		return server.ListenAndServe()
	}
}
