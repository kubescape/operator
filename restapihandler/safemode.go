package restapihandler

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/golang/glog"
)

func (resthandler *HTTPHandler) SafeMode(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			glog.Errorf("recover in SafeMode: %v", err)
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
		err = resthandler.safeModePost(r.URL.Query(), readBuffer)
	default:
		httpStatus = http.StatusMethodNotAllowed
		err = fmt.Errorf("method '%s' not allowed", r.Method)
	}
	if err != nil {
		returnValue = []byte(err.Error())
		httpStatus = http.StatusBadRequest
	}

	w.WriteHeader(httpStatus)
	w.Write(returnValue)
}

func (resthandler *HTTPHandler) safeModePost(urlVals url.Values, readBuffer []byte) error {
	message := string(readBuffer)
	glog.Infof("REST-API SafeMode received: %s", message)

	// TODO
	// safeModeObj, _ := convertSafeModeRequest(readBuffer)
	// nh := notificationhandler.NewNotificationHandler(resthandler.sessionObj)
	// return nh.HandlerSafeModeNotification(safeModeObj)
	return nil
}
