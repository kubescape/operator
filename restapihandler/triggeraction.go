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

/*args may contain credentials*/
func displayReceivedCommand(receivedCommands []byte) {

	var err error
	var receivedCommandsWithNoArgs []byte
	commands := apis.Commands{}
	if err = json.Unmarshal(receivedCommands, &commands); err != nil {
		return
	}
	for i, _ := range commands.Commands {
		commands.Commands[i].Args = map[string]interface{}{}
	}

	if receivedCommandsWithNoArgs, err = json.Marshal(commands); err != nil {
		return
	}
	glog.Infof("restAPI receivedCommands: %s", receivedCommandsWithNoArgs)
}

// HandlePostmanRequest Parse received commands and run the command
func (resthandler *HTTPHandler) HandleActionRequest(receivedCommands []byte) error {
	commands := apis.Commands{}
	if err := json.Unmarshal(receivedCommands, &commands); err != nil {
		glog.Error(err)
		return err
	}

	displayReceivedCommand(receivedCommands)

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
	readBuffer, err := ioutil.ReadAll(r.Body)
	if err == nil {
		switch r.Method {
		case http.MethodPost:
			err = resthandler.HandleActionRequest(readBuffer)
		default:
			httpStatus = http.StatusMethodNotAllowed
			err = fmt.Errorf("method '%s' not allowed", r.Method)
		}
	}
	if err != nil {
		returnValue = []byte(err.Error())
		httpStatus = http.StatusInternalServerError
	}

	w.WriteHeader(httpStatus)
	w.Write(returnValue)
}
