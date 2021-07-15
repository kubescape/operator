package restapihandler

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/armosec/capacketsgo/apis"

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
		err = fmt.Errorf("Method '%s' not allowed", r.Method)
	}
	if err != nil {
		returnValue = []byte(err.Error())
		httpStatus = http.StatusBadRequest
	}

	w.WriteHeader(httpStatus)
	w.Write(returnValue)
}

func (resthandler *HTTPHandler) safeModePost(urlVals url.Values, readBuffer []byte) error {
	message := fmt.Sprintf("%s", readBuffer)
	glog.Infof("REST-API SafeMode received: %s", message)

	// TODO
	// safeModeObj, _ := convertSafeModeRequest(readBuffer)
	// nh := notificationhandler.NewNotificationHandler(resthandler.sessionObj)
	// return nh.HandlerSafeModeNotification(safeModeObj)
	return nil
}

func convertSafeModeRequest(bytesRequest []byte) (*apis.SafeMode, error) {
	safeMode := &apis.SafeMode{}
	if err := json.Unmarshal(bytesRequest, safeMode); err != nil {
		glog.Error(err)
		return nil, err
	}
	safeMode.InstanceID = safeMode.PodName
	if safeMode.Action == "" {
		safeMode.Action = "SafeMode notification"
	}
	return safeMode, nil

}
