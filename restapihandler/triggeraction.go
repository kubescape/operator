package restapihandler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/operator/utils"

	"github.com/armosec/armoapi-go/apis"
)

/*args may contain credentials*/
func displayReceivedCommand(receivedCommands []byte) {

	var err error
	var receivedCommandsWithNoArgs []byte
	commands := apis.Commands{}
	if err = json.Unmarshal(receivedCommands, &commands); err != nil {
		return
	}
	for i := range commands.Commands {
		commands.Commands[i].Args = map[string]interface{}{}
	}

	if receivedCommandsWithNoArgs, err = json.Marshal(commands); err != nil {
		return
	}
	logger.L().Info("restAPI receivedCommands: " + string(receivedCommandsWithNoArgs))
}

// HandleActionRequest Parse received commands and run the command
func (resthandler *HTTPHandler) HandleActionRequest(ctx context.Context, receivedCommands []byte) error {
	commands := apis.Commands{}
	if err := json.Unmarshal(receivedCommands, &commands); err != nil {
		logger.L().Ctx(ctx).Error(err.Error(), helpers.Error(err))
		return err
	}

	displayReceivedCommand(receivedCommands)

	for _, c := range commands.Commands {
		sessionObj := utils.NewSessionObj(ctx, &c, "Websocket", c.JobTracking.ParentID, c.JobTracking.JobID, c.JobTracking.LastActionNumber+1)
		if c.CommandName == "" {
			err := fmt.Errorf("command not found. id: %s", c.GetID())
			logger.L().Ctx(ctx).Error(err.Error(), helpers.Error(err))
			sessionObj.Reporter.SendError(err, true, true, sessionObj.ErrChan)
			continue
		}

		*resthandler.sessionObj <- *sessionObj
	}
	return nil
}

func (resthandler *HTTPHandler) ActionRequest(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			logger.L().Ctx(r.Context()).Error(fmt.Sprintf("recover in ActionRequest: %v", err))
			w.WriteHeader(http.StatusInternalServerError)
			bErr, _ := json.Marshal(err)
			w.Write(bErr)
		}
	}()
	defer r.Body.Close()
	var err error
	returnValue := []byte("ok")

	httpStatus := http.StatusOK
	readBuffer, err := io.ReadAll(r.Body)
	if err == nil {
		switch r.Method {
		case http.MethodPost:
			err = resthandler.HandleActionRequest(r.Context(), readBuffer)
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
