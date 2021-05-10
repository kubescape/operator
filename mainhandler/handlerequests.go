package mainhandler

import (
	"encoding/json"
	"fmt"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/sign"

	"github.com/armosec/capacketsgo/apis"
	pkgcautils "github.com/armosec/capacketsgo/cautils"
	"github.com/armosec/capacketsgo/secrethandling"

	"github.com/armosec/capacketsgo/k8sinterface"
	reporterlib "github.com/armosec/capacketsgo/system-reports/datastructures"

	icacli "github.com/armosec/capacketsgo/cacli"
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
	cacli      icacli.ICacli
	k8sAPI     *k8sinterface.KubernetesApi
}

type ActionHandler struct {
	cacli    icacli.ICacli
	k8sAPI   *k8sinterface.KubernetesApi
	reporter reporterlib.IReporter
	wlid     string
	sid      string
	command  cautils.Command
}

// CreateWebSocketHandler Create ws-handler obj
func NewMainHandler(sessionObj *chan cautils.SessionObj) *MainHandler {
	pkgcautils.InitNamespacesListToIgnore(cautils.CA_NAMESPACE)
	return &MainHandler{
		sessionObj: sessionObj,
		cacli:      icacli.NewCacli(cautils.CA_DASHBOARD_BACKEND, false),
		k8sAPI:     k8sinterface.NewKubernetesApi(),
	}
}

// CreateWebSocketHandler Create ws-handler obj
func NewActionHandler(cacliObj icacli.ICacli, k8sAPI *k8sinterface.KubernetesApi, sessionObj *cautils.SessionObj) *ActionHandler {
	pkgcautils.InitNamespacesListToIgnore(cautils.CA_NAMESPACE)
	return &ActionHandler{
		reporter: sessionObj.Reporter,
		command:  sessionObj.Command,
		cacli:    cacliObj,
		k8sAPI:   k8sAPI,
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
			actionHandler := NewActionHandler(mainHandler.cacli, mainHandler.k8sAPI, &sessionObj)
			sessionObj.Reporter.SendAction(fmt.Sprintf("%s", sessionObj.Command.CommandName), true)
			err := actionHandler.runCommand(&sessionObj)
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
func (actionHandler *ActionHandler) runCommand(sessionObj *cautils.SessionObj) error {
	c := sessionObj.Command
	if c.Wlid != "" {
		if pkgcautils.IfIgnoreNamespace(cautils.GetNamespaceFromWlid(c.Wlid)) {
			glog.Infof("Ignoring wlid: '%s'", c.Wlid)
			return nil
		}
		actionHandler.wlid = c.Wlid
	}
	logCommandInfo := fmt.Sprintf("Running %s command", c.CommandName)
	if c.Wlid != "" {
		logCommandInfo += fmt.Sprintf(", wlid: %s", c.Wlid)
	}
	glog.Infof(logCommandInfo)
	switch c.CommandName {
	case apis.UPDATE:
		glog.Infof("UPDATE")
		return actionHandler.update(apis.UPDATE)
	case apis.RESTART:
		return actionHandler.update(apis.UPDATE)
	case apis.REMOVE:
		return actionHandler.update(apis.REMOVE)
	case apis.INJECT:
		glog.Infof("INJECT")
		return actionHandler.update(apis.UPDATE)
	case apis.SIGN:
		return actionHandler.signWorkload()
	// case apis.INJECT:
	// 	return updateWorkload(c.Wlid, apis.INJECT, &c)
	case apis.ENCRYPT, apis.DECRYPT:
		return runSecretCommand(sessionObj)
	case apis.SCAN:
		return scanWorkload(c.Wlid)
	default:
		glog.Errorf("Command %s not found", c.CommandName)
	}
	return nil
}

func runSecretCommand(sessionObj *cautils.SessionObj) error {
	c := sessionObj.Command

	sid, err := getSIDFromArgs(c.Args)
	if err != nil {
		return err
	}
	if pkgcautils.IfIgnoreNamespace(secrethandling.GetSIDNamespace(sid)) {
		glog.Infof("Ignoring wlid: '%s'", c.Wlid)
		return nil
	}
	secretHandler := NewSecretHandler(sid)

	switch c.CommandName {
	case apis.ENCRYPT:
		err = secretHandler.encryptSecret()
	case apis.DECRYPT:
		err = secretHandler.decryptSecret()
	}
	return err
}

// func detachWorkload(wlid string) error {
// 	// if cautils.GetKindFromWlid(wlid) != "Namespace" {
// 	// 	// add wlid to the ignore list
// 	// 	ns := cautils.GetNamespaceFromWlid(wlid)
// 	// 	namespaceWlid := cautils.GetWLID(cautils.GetClusterFromWlid(wlid), ns, "Namespace", ns)
// 	// 	if err := excludeWlid(namespaceWlid, wlid); err != nil { // add wlid to the namespace ignore list
// 	// 		return err
// 	// 	}
// 	// }
// 	return updateWorkload(wlid, apis.REMOVE, &cautils.Command{})
// }

func (actionHandler *ActionHandler) signWorkload() error {
	var err error
	workload, err := actionHandler.k8sAPI.GetWorkloadByWlid(actionHandler.wlid)
	if err != nil {
		return err
	}

	s := sign.NewSigner(actionHandler.cacli, actionHandler.k8sAPI, actionHandler.reporter, actionHandler.wlid)
	if cautils.CA_USE_DOCKER {
		err = s.SignImageDocker(workload)
	} else {
		err = s.SignImageOcimage(workload)
	}
	if err != nil {
		return err
	}

	glog.Infof("Done signing, updating workload, wlid: %s", actionHandler.wlid)
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

func isForceDelete(args map[string]interface{}) bool {
	if args == nil || len(args) == 0 {
		return false
	}
	if v, ok := args["forceDelete"]; ok && v != nil {
		return v.(bool)
	}
	return false
}
