package restapihandler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/operator/utils"
)

// maxTriggerRequestBytes bounds a trigger request's body.
const maxTriggerRequestBytes = 1 << 20

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

	for i := range commands.Commands {
		c := commands.Commands[i]
		sessionObj := utils.NewSessionObj(ctx, resthandler.config, &c, c.JobTracking.ParentID, c.JobTracking.JobID)
		if c.CommandName == "" {
			err := fmt.Errorf("command not found. id: %s", c.GetID())
			logger.L().Ctx(ctx).Error(err.Error(), helpers.Error(err))
			sessionObj.SetOperatorCommandStatus(ctx, utils.WithError(err))
			continue
		}
		l := utils.Job{}
		l.SetContext(ctx)
		l.SetObj(*sessionObj)
		if err := resthandler.pool.Invoke(l); err != nil {
			logger.L().Ctx(ctx).Error("failed to invoke job", helpers.String("ID", c.GetID()), helpers.Error(err))
		}
	}
	return nil
}

func (resthandler *HTTPHandler) ActionRequest(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			bErr, _ := json.Marshal(err)
			w.Write(bErr)
			logger.L().Fatal("recover in ActionRequest", helpers.Interface("error", err))
		}
	}()

	defer r.Body.Close()
	var err error
	returnValue := []byte("ok")

	httpStatus := http.StatusOK
	// Bounded before it is read in full: the commands of a scheduled scan already fit
	// a ConfigMap, which Kubernetes caps at 1 MiB, and the listener answers anyone
	// who can reach it.
	readBuffer, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxTriggerRequestBytes))
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		w.Write([]byte(err.Error()))
		return
	}
	if err == nil {
		switch r.Method {
		case http.MethodPost:
			err = resthandler.HandleActionRequest(context.WithoutCancel(r.Context()), readBuffer)
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
