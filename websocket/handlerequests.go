package websocket

import (
	"encoding/json"
	"fmt"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/sign"

	"github.com/golang/glog"
)

var (
	// UPDATE workload
	UPDATE = "update"
	// REMOVE workload
	REMOVE = "remove"
	// SIGN image
	SIGN = "sign"

	CALabel = "cyberarmor"

	CAInject = "injectCyberArmor"
)

// HandlePostmanRequest Parse received commands and run the command
func (wsh *WebSocketHandler) HandlePostmanRequest(receivedCommands []byte) []error {
	commands := cautils.Commands{}
	errorList := []error{}

	if err := json.Unmarshal(receivedCommands, &commands); err != nil {
		glog.Error(err)
		return []error{err}
	}
	for _, c := range commands.Commands {
		if c.Wlid == "" || c.CommandName == "" {
			err := fmt.Errorf("command or wlid not found. wlid: %s, command: %s", c.Wlid, c.CommandName)
			glog.Error(err)
			return []error{err}
		}
		status := "SUCCESS"
		glog.Infof("Running %s command, wlid: %s", c.CommandName, c.Wlid)
		if err := wsh.runCommand(c); err != nil {
			glog.Errorf("%v", err)
			status = "FAIL"
			errorList = append(errorList, err)
		}
		glog.Infof("Done command %s, wlid: %s, status: %s", c.CommandName, c.Wlid, status)

	}
	return errorList
}
func (wsh *WebSocketHandler) runCommand(c cautils.Command) error {

	switch c.CommandName {
	case UPDATE:
		return updateWorkload(c.Wlid, UPDATE)
	case REMOVE:
		return updateWorkload(c.Wlid, REMOVE)
	case SIGN:
		return signWorkload(c.Wlid)
	default:
		glog.Errorf("Command %s not found", c.CommandName)
	}
	return nil
}

func signWorkload(wlid string) error {
	workload, err := getWorkload(wlid)
	if err != nil {
		return err
	}

	s := sign.NewSigner(wlid)
	if err := s.SignImage(workload); err != nil {
		return err
	}
	glog.Infof("Done signing, updating workload, wlid: %s", wlid)
	return updateWorkload(wlid, SIGN)
}
