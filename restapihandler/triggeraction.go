package restapihandler

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"k8s-ca-websocket/cautils"
	"net/http"

	"github.com/armosec/armoapi-go/apis"
	"github.com/golang/glog"
)

// HandlePostmanRequest Parse received commands and run the command
func (resthandler *HTTPHandler) HandleActionRequest(receivedCommands []byte) error {
	commands := apis.Commands{}
	if err := json.Unmarshal(receivedCommands, &commands); err != nil {
		glog.Error(err)
		return err
	}
	glog.Infof("restAPI receivedCommands: %s", receivedCommands)
	for _, c := range commands.Commands {
		sessionObj := cautils.NewSessionObj(&c, "Websocket", c.JobTracking.ParentID, c.JobTracking.JobID, c.JobTracking.LastActionNumber+1)

		if c.CommandName == "" {
			err := fmt.Errorf("command not found. id: %s", c.GetID())
			glog.Error(err)
			sessionObj.Reporter.SendError(err, true, true)
			continue
		}

		*resthandler.sessionObj <- *sessionObj
	}
	return nil
}

func (resthandler *HTTPHandler) ActionRequest(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			glog.Errorf("recover in ActionRequest: %v", err)
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
		err = resthandler.HandleActionRequest(readBuffer)
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
