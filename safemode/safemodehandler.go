package safemode

import (
	"fmt"
	"k8s-ca-websocket/cautils"

	reporterlib "github.com/armosec/capacketsgo/system-reports/datastructures"

	"github.com/armosec/capacketsgo/apis"
)

func (wsHandler *SafeModeHandler) HandlerSafeModeNotification(safeMode *apis.SafeMode) error {
	reporter := reporterlib.NewBaseReport(cautils.CA_CUSTOMER_GUID, safeMode.Reporter)
	reporter.SetTarget(safeMode.Wlid)
	reporter.SetActionName("Received safeMode notification")
	reporter.SetJobID(safeMode.JobID)
	switch safeMode.StatusCode {
	case 0:
		// ignore
	case 1, 2:
		reporter.SendError(fmt.Errorf(safeMode.Message), true, true)
	default:
		reporter.SendError(fmt.Errorf("Unknown exit code. Report: %s", safeMode.Message), true, true)
	}
	// command := apis.Command{
	// 	CommandName: apis.REMOVE, //
	// 	Wlid:        wlid,
	// }

	// message := fmt.Sprintf("Detaching wlid '%s' since agent failed to load in container, agent log: %v", wlid, readBuffer)
	// sessionObj := cautils.NewSessionObj(&command, message, "", 1)
	// *resthandler.sessionObj <- *sessionObj
	return nil
}
