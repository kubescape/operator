package mainhandler

import (
	"context"
	"fmt"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/sign"

	"github.com/armosec/capacketsgo/apis"
	pkgcautils "github.com/armosec/capacketsgo/cautils"

	icacli "github.com/armosec/capacketsgo/cacli"
	"github.com/armosec/capacketsgo/k8sinterface"
	reporterlib "github.com/armosec/capacketsgo/system-reports/datastructures"
	"github.com/golang/glog"
	"golang.org/x/sync/semaphore"
)

var previousReports []string

type MainHandler struct {
	sessionObj      *chan cautils.SessionObj
	cacli           icacli.ICacli
	k8sAPI          *k8sinterface.KubernetesApi
	signerSemaphore *semaphore.Weighted
}

type ActionHandler struct {
	cacli           icacli.ICacli
	k8sAPI          *k8sinterface.KubernetesApi
	reporter        reporterlib.IReporter
	wlid            string
	sid             string
	command         apis.Command
	signerSemaphore *semaphore.Weighted
}

// CreateWebSocketHandler Create ws-handler obj
func NewMainHandler(sessionObj *chan cautils.SessionObj) *MainHandler {
	pkgcautils.InitNamespacesListToIgnore(cautils.CA_NAMESPACE)
	return &MainHandler{
		sessionObj:      sessionObj,
		cacli:           icacli.NewCacli(cautils.CA_DASHBOARD_BACKEND, false),
		k8sAPI:          k8sinterface.NewKubernetesApi(),
		signerSemaphore: semaphore.NewWeighted(cautils.SignerSemaphore),
	}
}

// CreateWebSocketHandler Create ws-handler obj
func NewActionHandler(cacliObj icacli.ICacli, k8sAPI *k8sinterface.KubernetesApi, signerSemaphore *semaphore.Weighted, sessionObj *cautils.SessionObj) *ActionHandler {
	pkgcautils.InitNamespacesListToIgnore(cautils.CA_NAMESPACE)
	return &ActionHandler{
		reporter:        sessionObj.Reporter,
		command:         sessionObj.Command,
		cacli:           cacliObj,
		k8sAPI:          k8sAPI,
		signerSemaphore: signerSemaphore,
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

		if ignoreNamespace(sessionObj.Command.CommandName, getCommandNamespace(&sessionObj.Command)) {
			glog.Infof("namespace '%s' out of scope. Ignoring wlid: %s, command: %s", getCommandNamespace(&sessionObj.Command), getCommandID(&sessionObj.Command), sessionObj.Command.CommandName)
			continue
		}

		if sessionObj.Command.WildWlid != "" {
			mainHandler.HandleScopedRequest(&sessionObj) // this might be a heavy action, do not send to a goroutine
		} else {
			go mainHandler.HandleSingleRequest(&sessionObj) // secrets - TODO - add 'sid' key
		}
	}
}

func (mainHandler *MainHandler) HandleSingleRequest(sessionObj *cautils.SessionObj) {
	status := "SUCCESS"
	actionHandler := NewActionHandler(mainHandler.cacli, mainHandler.k8sAPI, mainHandler.signerSemaphore, sessionObj)
	sessionObj.Reporter.SendAction(fmt.Sprintf("%s", sessionObj.Command.CommandName), true)
	err := actionHandler.runCommand(sessionObj)
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
}

func (actionHandler *ActionHandler) runCommand(sessionObj *cautils.SessionObj) error {
	c := sessionObj.Command
	if c.Wlid != "" {
		actionHandler.wlid = c.Wlid
	}
	logCommandInfo := fmt.Sprintf("Running %s command", c.CommandName)
	if c.Wlid != "" {
		logCommandInfo += fmt.Sprintf(", wlid: %s", c.Wlid)
	}
	glog.Infof(logCommandInfo)
	switch c.CommandName {
	case apis.UPDATE, apis.INJECT:
		return actionHandler.update()
	case apis.RESTART:
		return actionHandler.update()
	case apis.REMOVE:
		actionHandler.deleteConfigMaps()
		actionHandler.deleteWorkloadTemplate()
		return actionHandler.update()
	case apis.SIGN:
		actionHandler.signerSemaphore.Acquire(context.Background(), 1)
		defer actionHandler.signerSemaphore.Release(1)
		return actionHandler.signWorkload()
	case apis.ENCRYPT, apis.DECRYPT:
		return actionHandler.runSecretCommand(sessionObj)
	case apis.SCAN:
		return actionHandler.scanWorkload()
	default:
		glog.Errorf("Command %s not found", c.CommandName)
	}
	return nil
}

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

// HandleScopedRequest handle a request of a scope e.g. all workloads in a namespace
func (mainHandler *MainHandler) HandleScopedRequest(sessionObj *cautils.SessionObj) {
	namespace := cautils.GetNamespaceFromWildWlid(sessionObj.Command.WildWlid)
	labels := sessionObj.Command.GetLabels()

	info := fmt.Sprintf("wildWlid: '%s', namespace: '%s', labels: '%v'", sessionObj.Command.WildWlid, namespace, labels)
	glog.Infof(info)
	sessionObj.Reporter.SendAction(info, true)

	workloads, err := mainHandler.listWorkloads(namespace, "pods", labels)
	if err != nil {
		glog.Errorf(err.Error())
		sessionObj.Reporter.SendError(err, true, true)
	}
	if len(workloads) == 0 {
		err := fmt.Errorf("No workloads found. namespace: %s, labels: %v", namespace, labels)
		glog.Warningf(err.Error())
		sessionObj.Reporter.SendError(err, true, true)
		sessionObj.Reporter.SendStatus(reporterlib.JobFailed, true)
		return
	}
	wlids, errs := mainHandler.calculatePodsWlids(namespace, workloads)
	if len(errs) != 0 {
		for _, e := range errs {
			glog.Errorf(e.Error())
			sessionObj.Reporter.AddError(e.Error())
		}
		sessionObj.Reporter.Send()
	}
	if len(wlids) == 0 {
		err := fmt.Errorf("Failed to calculate workloadIDs. namespace: %s, labels: %v", namespace, labels)
		glog.Errorf(err.Error())
		sessionObj.Reporter.SendError(err, true, true)
		sessionObj.Reporter.SendStatus(reporterlib.JobFailed, true)
		return
	}
	sessionObj.Reporter.SendStatus(reporterlib.JobSuccess, true)

	glog.Infof("wlids found: '%v'", wlids)
	go func() { // send to goroutine so the channel will be released release the channel
		for i := range wlids {
			newSessionObj := cautils.NewSessionObj(sessionObj.Command.DeepCopy(), "Websocket", sessionObj.Reporter.GetJobID(), sessionObj.Reporter.GetActionIDN())
			newSessionObj.Command.Wlid = wlids[i]
			newSessionObj.Command.WildWlid = ""
			if err := cautils.IsWlidValid(newSessionObj.Command.Wlid); err != nil {
				err := fmt.Errorf("invalid: %s, wlid: %s", err.Error(), newSessionObj.Command.Wlid)
				glog.Error(err)
				sessionObj.Reporter.SendError(err, true, true)
				continue
			}
			glog.Infof("triggering wlid: '%s'", newSessionObj.Command.Wlid)
			sessionObj.Reporter.SendAction(fmt.Sprintf("triggering wlid: '%s'", newSessionObj.Command.Wlid), true)
			*mainHandler.sessionObj <- *newSessionObj
			sessionObj.Reporter.SendStatus(reporterlib.JobSuccess, true)
		}
	}()
}
