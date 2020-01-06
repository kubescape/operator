package websocket

import (
	"encoding/json"
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

	CALabel  = "cyberarmor"
	CAInject = "injectCyberArmor"
)

// HandlePostmanRequest Parse received commands and run the command
func (wsh *WebSocketHandler) HandlePostmanRequest(receivedCommands []byte) []error {
	// log.Printf("Recveived: %v", string(receivedCommands))
	commands := cautils.Commands{}
	errorList := []error{}

	if err := json.Unmarshal(receivedCommands, &commands); err != nil {
		glog.Error(err)
		glog.Infoln("Failed CyberArmor websocket")
		return []error{err}
	}
	for _, c := range commands.Commands {
		go func(c cautils.Command) {
			glog.Infof(" ================== Starting CyberArmor websocket, command: %s ================== ", c.CommandName)
			glog.Infof("Running %s command", c.CommandName)
			if err := wsh.runCommand(c); err != nil {
				glog.Errorf("%v", err)
				glog.Infof("----------------- Failed CyberArmor websocket, command: %s  -----------------", c.CommandName)
				errorList = append(errorList, err)
			}
			glog.Infof(" ================== Done CyberArmor websocket, command: %s ================== ", c.CommandName)
		}(c)
	}
	return errorList
}
func (wsh *WebSocketHandler) runCommand(c cautils.Command) error {
	glog.Infof("Wlid: %s", c.Wlid)

	workload, err := getWorkload(c.Wlid)
	if err != nil {
		return err
	}

	switch c.CommandName {
	case UPDATE:
		return updateWorkload(workload, c.Wlid)
	case REMOVE:
		return removeWorkload(workload, c.Wlid)
	case SIGN:
		return signWorkload(workload, c.Wlid)

	default:
		glog.Errorf("Command %s not found", c.CommandName)
	}
	return nil
}

func signWorkload(workload interface{}, wlid string) error {
	s := sign.NewSigner(wlid)

	if err := s.SignImage(workload); err != nil {
		return err
	}
	glog.Infof("Done signing, updating workload, wlid: %s", wlid)
	return updateWorkload(workload, wlid)
}
