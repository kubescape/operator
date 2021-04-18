package mainhandler

import (
	"encoding/json"
	"fmt"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/sign"

	"asterix.cyberarmor.io/cyberarmor/capacketsgo/apis"
	"asterix.cyberarmor.io/cyberarmor/capacketsgo/secrethandling"

	reporterlib "asterix.cyberarmor.io/cyberarmor/capacketsgo/system-reports/datastructures"

	"github.com/golang/glog"
)

var previousReports []string

// labels and annotations
const (
	CALabel = "cyberarmor"

	CAInjectOld = "injectCyberArmor"
	CAWlidOld   = "wlid"

	CAPrefix = "cyberarmor"
	CAInject = CAPrefix + ".inject"

	// annotation related
	CAStatus   = CAPrefix + ".status"
	CAAttached = CAPrefix + ".attached"
	CASigned   = CAPrefix + ".signed"
	CAWlid     = CAPrefix + ".wlid"
	CAUpdate   = CAPrefix + ".last-update"
	CAIgnoe    = CAPrefix + ".ignore"
	CAJobs     = CAPrefix + ".jobs"
)

type MainHandler struct {
	sessionObj *chan cautils.SessionObj
}

// CreateWebSocketHandler Create ws-handler obj
func NewMainHandler(sessionObj *chan cautils.SessionObj) *MainHandler {
	return &MainHandler{
		sessionObj: sessionObj,
	}
}

// HandlePostmanRequest Parse received commands and run the command
func (mainHandler *MainHandler) HandleRequest() []error {
	for {
		// recover
		defer func() {
			if err := recover(); err != nil {
				glog.Errorf("RECOVER in HandleRequest, reason: %v", err)
			}
		}()
		sessionObj := <-*mainHandler.sessionObj
		go func() {
			status := "SUCCESS"

			sessionObj.Reporter.SendAction(fmt.Sprintf("Processing request: '%s', ", sessionObj.Command.CommandName), true)
			err := mainHandler.runCommand(&sessionObj)
			if err != nil {
				sessionObj.Reporter.SendError(err, true, true)
				status = "FAIL"
			} else {
				sessionObj.Reporter.SendStatus(reporterlib.JobSuccess, true)
			}
			donePrint := fmt.Sprintf("Done command %s, wlid: %s, status: %s", sessionObj.Command.CommandName, sessionObj.Command.Wlid, status)
			if err != nil {
				donePrint += fmt.Sprintf(", reason: %s", err.Error())
			}
			glog.Infof(donePrint)
		}()
	}
}
func (mainHandler *MainHandler) runCommand(sessionObj *cautils.SessionObj) error {
	c := sessionObj.Command
	logCommandInfo := fmt.Sprintf("Running %s command", c.CommandName)
	if c.Wlid != "" {
		logCommandInfo += fmt.Sprintf(", wlid: %s", c.Wlid)
	}
	glog.Infof(logCommandInfo)
	switch c.CommandName {
	case apis.UPDATE:
		return updateWorkload(c.Wlid, apis.UPDATE, &c)
	case apis.RESTART:
		return updateWorkload(c.Wlid, apis.RESTART, &c)
	case apis.REMOVE:
		return detachWorkload(c.Wlid)
	case apis.SIGN:
		return signWorkload(c.Wlid)
	case apis.INJECT:
		return updateWorkload(c.Wlid, apis.INJECT, &c)
	case apis.ENCRYPT:
		sid, err := getSIDFromArgs(c.Args)
		if err != nil {
			return err
		}
		secretHandler := NewSecretHandler(sid)
		return secretHandler.encryptSecret()
	case apis.DECRYPT:
		sid, err := getSIDFromArgs(c.Args)
		if err != nil {
			err := fmt.Errorf("invalid secret-id: %s", err.Error())
			return err
		}
		secretHandler := NewSecretHandler(sid)
		return secretHandler.decryptSecret()
	case apis.SCAN:
		return scanWorkload(c.Wlid)
	default:
		glog.Errorf("Command %s not found", c.CommandName)
	}
	return nil
}

func detachWorkload(wlid string) error {
	// if cautils.GetKindFromWlid(wlid) != "Namespace" {
	// 	// add wlid to the ignore list
	// 	ns := cautils.GetNamespaceFromWlid(wlid)
	// 	namespaceWlid := cautils.GetWLID(cautils.GetClusterFromWlid(wlid), ns, "Namespace", ns)
	// 	if err := excludeWlid(namespaceWlid, wlid); err != nil { // add wlid to the namespace ignore list
	// 		return err
	// 	}
	// }
	return updateWorkload(wlid, apis.REMOVE, &cautils.Command{})
}

func attachWorkload(wlid string) error {
	// if cautils.GetKindFromWlid(wlid) != "Namespace" {
	// 	// remove wlid from the ignore list
	// 	ns := cautils.GetNamespaceFromWlid(wlid)
	// 	namespaceWlid := cautils.GetWLID(cautils.GetClusterFromWlid(wlid), ns, "Namespace", ns)
	// 	if err := includeWlid(namespaceWlid, wlid); err != nil { // add wlid to the namespace ignore list
	// 		return err
	// 	}
	// }
	return updateWorkload(wlid, apis.REMOVE, &cautils.Command{})
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
	return err
}

func getSIDFromArgs(args map[string]interface{}) (string, error) {
	sidInterface, ok := args["sid"]
	if !ok {
		return "", nil
	}
	sid, ok := sidInterface.(string)
	if !ok || sid == "" {
		return "", fmt.Errorf("sid found in args but empty")
	}
	if _, err := secrethandling.SplitSecretID(sid); err != nil {
		return "", err
	}
	return sid, nil
}

func getScanFromArgs(args map[string]interface{}) (*apis.WebsocketScanCommand, error) {
	scanInterface, ok := args["scan"]
	if !ok {
		return nil, nil
	}
	websocketScanCommand := &apis.WebsocketScanCommand{}
	scanBytes, err := json.Marshal(scanInterface)
	if err != nil {
		return nil, fmt.Errorf("cannot convert 'interface scan' to 'bytes array', reason: %s", err.Error())
	}
	if err = json.Unmarshal(scanBytes, websocketScanCommand); err != nil {
		return nil, fmt.Errorf("cannot convert 'bytes array scan' to 'WebsocketScanCommand', reason: %s", err.Error())
	}
	return websocketScanCommand, nil
}
