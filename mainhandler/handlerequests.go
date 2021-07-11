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

		// if scan disabled
		if cautils.ScanDisabled && sessionObj.Command.CommandName == apis.SCAN {
			err := fmt.Errorf("Scan is disabled in cluster")
			glog.Warningf("Scan is disabled in cluster")
			sessionObj.Reporter.SendError(err, true, true)
			continue
		}

		if sessionObj.Command.WildWlid != "" || sessionObj.Command.WildSid != "" {
			mainHandler.HandleScopedRequest(&sessionObj) // this might be a heavy action, do not send to a goroutine
			// } else if sessionObj.Command.Sid != "" {
			// 	go mainHandler.HandleSingleRequest(&sessionObj)
		} else {
			go mainHandler.HandleSingleRequest(&sessionObj)
		}
	}
}

func (mainHandler *MainHandler) HandleSingleRequest(sessionObj *cautils.SessionObj) {
	// FALLBACK
	sidFallback(sessionObj)

	if sessionObj.Command.GetID() == "" {
		glog.Errorf("Received empty id")
		return
	}

	status := "SUCCESS"
	actionHandler := NewActionHandler(mainHandler.cacli, mainHandler.k8sAPI, mainHandler.signerSemaphore, sessionObj)

	actionHandler.reporter.SendAction(fmt.Sprintf("%s", sessionObj.Command.CommandName), true)
	err := actionHandler.runCommand(sessionObj)
	if err != nil {
		actionHandler.reporter.SendError(err, true, true)
		status = "FAIL"
		// cautils.SendSafeModeReport(sessionObj, err.Error(), 1)
	} else {
		actionHandler.reporter.SendStatus(reporterlib.JobSuccess, true)
	}
	donePrint := fmt.Sprintf("Done command %s, wlid: %s, status: %s", sessionObj.Command.CommandName, sessionObj.Command.GetID(), status)
	if err != nil {
		donePrint += fmt.Sprintf(", reason: %s", err.Error())
	}
	glog.Infof(donePrint)
}

func (actionHandler *ActionHandler) runCommand(sessionObj *cautils.SessionObj) error {
	c := sessionObj.Command
	if pkgcautils.IsWlid(c.GetID()) {
		actionHandler.wlid = c.GetID()
	} else {
		actionHandler.sid = c.GetID()
	}

	logCommandInfo := fmt.Sprintf("Running %s command, id: '%s'", c.CommandName, c.GetID())

	glog.Infof(logCommandInfo)
	switch c.CommandName {
	case apis.UPDATE, apis.INJECT:
		return actionHandler.update(c.CommandName)
	case apis.RESTART:
		return actionHandler.update(c.CommandName)
	case apis.REMOVE:
		actionHandler.deleteConfigMaps()
		err := actionHandler.update(c.CommandName)
		go actionHandler.workloadCleanupDiscovery()
		return err
	case apis.UNREGISTERED:
		err := actionHandler.update(c.CommandName)
		go actionHandler.workloadCleanupAll()
		return err
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

	return actionHandler.update(apis.RESTART)
}

// HandleScopedRequest handle a request of a scope e.g. all workloads in a namespace
func (mainHandler *MainHandler) HandleScopedRequest(sessionObj *cautils.SessionObj) {
	if sessionObj.Command.GetID() == "" {
		glog.Errorf("Received empty id")
		return
	}

	namespace := pkgcautils.GetNamespaceFromWlid(sessionObj.Command.GetID())
	labels := sessionObj.Command.GetLabels()
	fields := sessionObj.Command.GetFieldSelector()
	resources := resourceList(sessionObj.Command.CommandName)

	info := fmt.Sprintf("%s: id: '%s', namespace: '%s', labels: '%v', fieldSelector: '%v'", sessionObj.Command.CommandName, sessionObj.Command.GetID(), namespace, labels, fields)
	glog.Infof(info)
	sessionObj.Reporter.SendAction(info, true)
	ids, errs := mainHandler.GetIDs(namespace, labels, fields, resources)
	for i := range errs {
		glog.Warningf(errs[i].Error())
		sessionObj.Reporter.SendError(errs[i], true, true)
	}

	sessionObj.Reporter.SendStatus(reporterlib.JobSuccess, true)

	glog.Infof("ids found: '%v'", ids)
	go func() { // send to goroutine so the channel will be released release the channel
		for i := range ids {
			newSessionObj := cautils.NewSessionObj(sessionObj.Command.DeepCopy(), "Websocket", sessionObj.Reporter.GetJobID(), "", 1)

			var err error
			if pkgcautils.IsWlid(ids[i]) {
				newSessionObj.Command.Wlid = ids[i]
				err = pkgcautils.IsWlidValid(newSessionObj.Command.Wlid)
			} else if pkgcautils.IsSid(ids[i]) {
				newSessionObj.Command.Sid = ids[i]
			} else {
				err = fmt.Errorf("Unknown id")
			}

			newSessionObj.Command.WildWlid = ""
			newSessionObj.Command.WildSid = ""

			if err != nil {
				err := fmt.Errorf("invalid: %s, id: '%s'", err.Error(), newSessionObj.Command.GetID())
				glog.Error(err)
				sessionObj.Reporter.SendError(err, true, true)
				continue
			}

			glog.Infof("triggering id: '%s'", newSessionObj.Command.GetID())
			sessionObj.Reporter.SendAction(fmt.Sprintf("triggering id: '%s'", newSessionObj.Command.GetID()), true)
			*mainHandler.sessionObj <- *newSessionObj
			sessionObj.Reporter.SendStatus(reporterlib.JobSuccess, true)
		}
	}()
}

func (mainHandler *MainHandler) GetIDs(namespace string, labels, fields map[string]string, resources []string) ([]string, []error) {
	ids := []string{}
	errs := []error{}
	for _, resource := range resources {
		workloads, err := mainHandler.listWorkloads(namespace, resource, labels, fields)
		if err != nil {
			errs = append(errs, err)
		}
		if len(workloads) == 0 {
			// err := fmt.Errorf("Resource: '%s', no workloads found. namespace: '%s', labels: '%v'", resource, namespace, labels)
			// errs = append(errs, err)
			continue
		}
		w, e := mainHandler.GetResourcesIDs(workloads)
		if len(errs) != 0 {
			errs = append(errs, e...)
		}
		if len(w) == 0 {
			err := fmt.Errorf("Resource: '%s', failed to calculate workloadIDs. namespace: '%s', labels: '%v'", resource, namespace, labels)
			errs = append(errs, err)
		}
		ids = append(ids, w...)
	}

	return ids, errs
}
