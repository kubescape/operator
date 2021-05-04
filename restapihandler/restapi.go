package restapihandler

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"k8s-ca-websocket/cautils"
	"net/http"
	"net/url"

	"github.com/armosec/capacketsgo/apis"
	"github.com/armosec/capacketsgo/opapolicy"
	"github.com/golang/glog"
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
	rtr.HandleFunc("agent/InitFailure", resthandler.AgentRestAPIReport)
	server.Handler = rtr

	// listen
	if resthandler.keyPair != nil {
		return server.ListenAndServeTLS("", "")
	} else {
		return server.ListenAndServe()
	}
}
func (resthandler *HTTPHandler) AgentRestAPIReport(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			glog.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			bErr, _ := json.Marshal(err)
			w.Write(bErr)
		}
	}()
	defer r.Body.Close()
	var err error
	returnValue := []byte("ok")

	httpStatus := http.StatusOK
	readBuffer, _ := ioutil.ReadAll(r.Body)

	switch r.Method {
	case http.MethodPost:
		err = resthandler.handleDelete(r.URL.Query(), readBuffer)
	default:
		httpStatus = http.StatusMethodNotAllowed
		err = fmt.Errorf("Method %s no allowed", r.Method)
	}
	if err != nil {
		returnValue = []byte(err.Error())
		httpStatus = http.StatusBadRequest
	}

	w.WriteHeader(httpStatus)
	w.Write(returnValue)
}

func (resthandler *HTTPHandler) handleDelete(urlVals url.Values, readBuffer []byte) error {
	// customerGUID := urlVals.Get("customerGUID")
	wlid := urlVals.Get("wlid")
	if err := cautils.IsWlidValid(wlid); err != nil {
		err := fmt.Errorf("invalid: %s, wlid: %s", err.Error(), wlid)
		glog.Error(err)
		return err
	}
	command := cautils.Command{
		CommandName: apis.REMOVE, //
		Wlid:        wlid,
	}

	message := fmt.Sprintf("Detaching wlid '%s' since agent failed to load in container, agent log: %v", wlid, readBuffer)
	sessionObj := cautils.NewSessionObj(&command, message)
	*resthandler.sessionObj <- *sessionObj
	return nil
}

func convertRequest(bytesRequest []byte) (*opapolicy.PolicyNotification, error) {
	policyNotification := &opapolicy.PolicyNotification{}
	if err := json.Unmarshal(bytesRequest, policyNotification); err != nil {
		glog.Error(err)
		return nil, err
	}
	return policyNotification, nil

}
