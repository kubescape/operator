package mainhandler

import (
	"context"
	"fmt"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/sign"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"

	"github.com/armosec/utils-k8s-go/armometadata"

	// pkgcautils "github.com/armosec/utils-k8s-go/wlid"
	cacli "github.com/armosec/cacli-wrapper-go/cacli"
	"github.com/armosec/k8s-interface/k8sinterface"
	pkgwlid "github.com/armosec/utils-k8s-go/wlid"

	reporterlib "github.com/armosec/logger-go/system-reports/datastructures"
	"github.com/golang/glog"
	"golang.org/x/sync/semaphore"
)

type MainHandler struct {
	sessionObj      *chan cautils.SessionObj
	cacli           cacli.ICacli
	k8sAPI          *k8sinterface.KubernetesApi
	signerSemaphore *semaphore.Weighted
}

type ActionHandler struct {
	cacli           cacli.ICacli
	k8sAPI          *k8sinterface.KubernetesApi
	reporter        reporterlib.IReporter
	wlid            string
	sid             string
	command         apis.Command
	signerSemaphore *semaphore.Weighted
}

// CreateWebSocketHandler Create ws-handler obj
func NewMainHandler(sessionObj *chan cautils.SessionObj, cacliRef cacli.ICacli) *MainHandler {
	armometadata.InitNamespacesListToIgnore(cautils.CA_NAMESPACE)
	return &MainHandler{
		sessionObj:      sessionObj,
		cacli:           cacliRef,
		k8sAPI:          k8sinterface.NewKubernetesApi(),
		signerSemaphore: semaphore.NewWeighted(cautils.SignerSemaphore),
	}
}

// CreateWebSocketHandler Create ws-handler obj
func NewActionHandler(cacliObj cacli.ICacli, k8sAPI *k8sinterface.KubernetesApi, signerSemaphore *semaphore.Weighted, sessionObj *cautils.SessionObj) *ActionHandler {
	armometadata.InitNamespacesListToIgnore(cautils.CA_NAMESPACE)
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
	// recover
	defer func() {
		if err := recover(); err != nil {
			glog.Errorf("RECOVER in HandleRequest, reason: %v", err)
		}
	}()
	for {
		sessionObj := <-*mainHandler.sessionObj

		if ignoreNamespace(sessionObj.Command.CommandName, getCommandNamespace(&sessionObj.Command)) {
			glog.Infof("namespace '%s' out of scope. Ignoring wlid: %s, command: %s", getCommandNamespace(&sessionObj.Command), getCommandID(&sessionObj.Command), sessionObj.Command.CommandName)
			continue
		}

		// if scan disabled
		if cautils.ScanDisabled && sessionObj.Command.CommandName == apis.SCAN {
			err := fmt.Errorf("scan is disabled in cluster")
			glog.Warningf(err.Error())
			sessionObj.Reporter.SetActionName(apis.SCAN)
			sessionObj.Reporter.SendError(err, true, true)
			continue
		}
		if sessionObj.Command.WildWlid != "" || sessionObj.Command.WildSid != "" || sessionObj.Command.Args["designators"] != nil {
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

	actionHandler.reporter.SendAction(sessionObj.Command.CommandName, true)
	err := actionHandler.runCommand(sessionObj)
	if err != nil {
		actionHandler.reporter.SendError(err, true, true)
		status = "FAIL"
		// cautils.SendSafeModeReport(sessionObj, err.Error(), 1)
	} else {
		actionHandler.reporter.SendStatus(jobStatus(sessionObj.Command.CommandName), true)
	}
	donePrint := fmt.Sprintf("Done command %s, wlid: %s, status: %s", sessionObj.Command.CommandName, sessionObj.Command.GetID(), status)
	if err != nil {
		donePrint += fmt.Sprintf(", reason: %s", err.Error())
	}
	glog.Infof(donePrint)
}

func (actionHandler *ActionHandler) runCommand(sessionObj *cautils.SessionObj) error {
	c := sessionObj.Command
	if pkgwlid.IsWlid(c.GetID()) {
		actionHandler.wlid = c.GetID()
	} else {
		actionHandler.sid = c.GetID()
	}

	logCommandInfo := fmt.Sprintf("Running %s command, id: '%s'", c.CommandName, c.GetID())

	glog.Infof(logCommandInfo)
	switch c.CommandName {
	case apis.UPDATE, apis.INJECT, apis.ATTACH:
		return actionHandler.update(c.CommandName)
	case apis.REMOVE, apis.DETACH:
		actionHandler.deleteConfigMaps(c)
		err := actionHandler.update(c.CommandName)
		go actionHandler.workloadCleanupDiscovery()
		return err
	case apis.RESTART, apis.INCOMPATIBLE, apis.IMAGE_UNREACHABLE, apis.REPLACE_HEADERS:
		return actionHandler.update(c.CommandName)
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

	namespaces := make([]string, 0, 1)
	namespaces = append(namespaces, pkgwlid.GetNamespaceFromWlid(sessionObj.Command.GetID()))
	labels := sessionObj.Command.GetLabels()
	fields := sessionObj.Command.GetFieldSelector()
	resources := resourceList(sessionObj.Command.CommandName)
	if len(sessionObj.Command.Designators) > 0 {
		namespaces = make([]string, 0, 3)
		for desiIdx := range sessionObj.Command.Designators {
			if ns, ok := sessionObj.Command.Designators[desiIdx].Attributes[armotypes.AttributeNamespace]; ok {
				namespaces = append(namespaces, ns)
			}
		}
	}

	info := fmt.Sprintf("%s: id: '%s', namespaces: '%v', labels: '%v', fieldSelector: '%v'", sessionObj.Command.CommandName, sessionObj.Command.GetID(), namespaces, labels, fields)
	glog.Infof(info)
	sessionObj.Reporter.SendAction(info, true)
	ids, errs := mainHandler.GetIDs(namespaces, labels, fields, resources)
	for i := range errs {
		glog.Warningf(errs[i].Error())
		sessionObj.Reporter.SendError(errs[i], true, true)
	}

	sessionObj.Reporter.SendStatus(reporterlib.JobSuccess, true)

	glog.Infof("ids found: '%v'", ids)
	go func() { // send to goroutine so the channel will be released release the channel
		for i := range ids {
			cmd := sessionObj.Command.DeepCopy()

			var err error
			if pkgwlid.IsWlid(ids[i]) {
				cmd.Wlid = ids[i]
				err = pkgwlid.IsWlidValid(cmd.Wlid)
			} else if pkgwlid.IsSid(ids[i]) {
				cmd.Sid = ids[i]
				// TODO - validate sid
			} else {
				err = fmt.Errorf("unknown id")
			}

			// clean all scope request parameters
			cmd.WildWlid = ""
			cmd.WildSid = ""
			cmd.Designators = make([]armotypes.PortalDesignator, 0)
			// send specific command to ourselve
			newSessionObj := cautils.NewSessionObj(cmd, "Websocket", sessionObj.Reporter.GetJobID(), "", 1)

			if err != nil {
				err := fmt.Errorf("invalid: %s, id: '%s'", err.Error(), newSessionObj.Command.GetID())
				glog.Error(err)
				sessionObj.Reporter.SendError(err, true, true)
				continue
			}

			glog.Infof("triggering id: '%s'", newSessionObj.Command.GetID())
			// sessionObj.Reporter.SendAction(fmt.Sprintf("triggering id: '%s'", newSessionObj.Command.GetID()), true)
			*mainHandler.sessionObj <- *newSessionObj
			// sessionObj.Reporter.SendStatus(reporterlib.JobSuccess, true)
		}
	}()
}

func (mainHandler *MainHandler) GetIDs(namespaces []string, labels, fields map[string]string, resources []string) ([]string, []error) {
	ids := []string{}
	errs := []error{}
	for _, resource := range resources {
		workloads, err := mainHandler.listWorkloads(namespaces, resource, labels, fields)
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
			err := fmt.Errorf("resource: '%s', failed to calculate workloadIDs. namespaces: '%v', labels: '%v'", resource, namespaces, labels)
			errs = append(errs, err)
		}
		ids = append(ids, w...)
	}

	return ids, errs
}

// HandlePostmanRequest Parse received commands and run the command
func (mainHandler *MainHandler) StartupTriggerActions(actions []apis.Command) {

	time.Sleep(2 * time.Second) // wait for master to start listenning to the channel

	for i := range actions {
		sessionObj := cautils.NewSessionObj(&actions[i], "Websocket", "", "", 1)
		*mainHandler.sessionObj <- *sessionObj
	}
}
