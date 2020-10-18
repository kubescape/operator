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
	// INJECT namespace
	INJECT = "inject"
	// RESTART pod
	RESTART = "restart"

	CALabel = "cyberarmor"

	CAInjectOld = "injectCyberArmor"
	CAWlidOld   = "wlid"
	CAInject    = "cyberarmor.inject"

	//annotation related
	CAStatus   = "cyberarmor.status"
	CAAttached = "cyberarmor.attached"
	CASigned   = "cyberarmor.signed"
	CAWlid     = "cyberarmor.wlid"
	CAUpdate   = "cyberarmor.last-update"
)
var (
	controllerLable = "controller-uid"
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
		if c.CommandName == "" {
			err := fmt.Errorf("command not found. wlid: %s", c.Wlid)
			glog.Error(err)
			return []error{err}
		}
		if c.Wlid == "" {
			err := fmt.Errorf("wlid not found. command: %s", c.CommandName)
			glog.Error(err)
			return []error{err}
		}
		if err := cautils.IsWalidValid(c.Wlid); err != nil {
			err := fmt.Errorf("invalid: %s, wlid: %s", err.Error(), c.Wlid)
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
	case INJECT:
		return updateWorkload(c.Wlid, INJECT)
	default:
		glog.Errorf("Command %s not found", c.CommandName)
	}
	return nil
}

func signWorkload(wlid string) error {
	var err error
	workload, err := getWorkload(wlid)
	if err != nil {
		return err
	}

	s := sign.NewSigner(wlid)
	if cautils.CA_USE_DOCKER {
		err = s.SignImageDocker(workload)
	} else {
		err = s.SignImageOcimage(workload)
	}
	if err != nil {
		return err
	}

	glog.Infof("Done signing, updating workload, wlid: %s", wlid)
	// err = updateWorkload(wlid, SIGN)
	return err
}
