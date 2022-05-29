package mainhandler

import (
	"context"
	"fmt"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/sign"
	"regexp"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/utils-k8s-go/armometadata"
	uuid "github.com/google/uuid"

	// pkgcautils "github.com/armosec/utils-k8s-go/wlid"
	cacli "github.com/armosec/cacli-wrapper-go/cacli"
	"github.com/armosec/k8s-interface/k8sinterface"
	reporterlib "github.com/armosec/logger-go/system-reports/datastructures"
	pkgwlid "github.com/armosec/utils-k8s-go/wlid"
	"github.com/golang/glog"
	"golang.org/x/sync/semaphore"
)

/*
	this function need to return if it finish to handle the command response
	by true or false, and next time to rehandled
*/
type HandleCommandResponseCallBack func(payload interface{}) (bool, *time.Duration)

const (
	MAX_LIMITATION_INSERT_TO_COMMAND_RESPONSE_CHANNEL_GO_ROUTINE = 10
)

const (
	KubascapeResponse string = "KubascapeResponse"
)

type CommandResponseData struct {
	commandName                        string
	isCommandResponseNeedToBeRehandled bool
	nextHandledTime                    *time.Duration
	handleCallBack                     HandleCommandResponseCallBack
	payload                            interface{}
}

type timerData struct {
	timer   *time.Timer
	payload interface{}
}

type commandResponseChannelData struct {
	commandResponseChannel                  *chan *CommandResponseData
	limitedGoRoutinesCommandResponseChannel *chan *timerData
}

type MainHandler struct {
	sessionObj             *chan cautils.SessionObj // TODO: wrap chan with struct for mutex support
	cacli                  cacli.ICacli
	k8sAPI                 *k8sinterface.KubernetesApi
	signerSemaphore        *semaphore.Weighted
	commandResponseChannel *commandResponseChannelData
}

type ActionHandler struct {
	cacli                  cacli.ICacli
	k8sAPI                 *k8sinterface.KubernetesApi
	reporter               reporterlib.IReporter
	wlid                   string
	sid                    string
	command                apis.Command
	signerSemaphore        *semaphore.Weighted
	commandResponseChannel *commandResponseChannelData
}

type waitFunc func()

var k8sNamesRegex *regexp.Regexp
var actionNeedToBeWaitOnStartUp = map[apis.NotificationPolicyType]waitFunc{}

func init() {
	var err error
	k8sNamesRegex, err = regexp.Compile("[^A-Za-z0-9-]+")
	if err != nil {
		glog.Fatal(err)
	}

	actionNeedToBeWaitOnStartUp[apis.TypeScanImages] = waitForVulnScanReady
	actionNeedToBeWaitOnStartUp[apis.TypeRunKubescape] = waitForKubescapeReady
}

// CreateWebSocketHandler Create ws-handler obj
func NewMainHandler(sessionObj *chan cautils.SessionObj, cacliRef cacli.ICacli, k8sAPI *k8sinterface.KubernetesApi) *MainHandler {
	armometadata.InitNamespacesListToIgnore(cautils.CA_NAMESPACE)

	commandResponseChannel := make(chan *CommandResponseData, 100)
	limitedGoRoutinesCommandResponseChannel := make(chan *timerData, 10)
	return &MainHandler{
		sessionObj:             sessionObj,
		cacli:                  cacliRef,
		k8sAPI:                 k8sAPI,
		signerSemaphore:        semaphore.NewWeighted(cautils.SignerSemaphore),
		commandResponseChannel: &commandResponseChannelData{commandResponseChannel: &commandResponseChannel, limitedGoRoutinesCommandResponseChannel: &limitedGoRoutinesCommandResponseChannel},
	}
}

// CreateWebSocketHandler Create ws-handler obj
func NewActionHandler(cacliObj cacli.ICacli, k8sAPI *k8sinterface.KubernetesApi, signerSemaphore *semaphore.Weighted, sessionObj *cautils.SessionObj, commandResponseChannel *commandResponseChannelData) *ActionHandler {
	armometadata.InitNamespacesListToIgnore(cautils.CA_NAMESPACE)
	return &ActionHandler{
		reporter:               sessionObj.Reporter,
		command:                sessionObj.Command,
		cacli:                  cacliObj,
		k8sAPI:                 k8sAPI,
		signerSemaphore:        signerSemaphore,
		commandResponseChannel: commandResponseChannel,
	}
}

/*
	in this function we are waiting for command response to finish in order to get the result
*/
func waitBeforeInsertToCommandResponseChannel(channelData *commandResponseChannelData, data *CommandResponseData, estimateReadyTime time.Duration) {

}

func CreateNewCommandResponseData(commandName string, cb HandleCommandResponseCallBack, payload interface{}, nextHandledTime *time.Duration) *CommandResponseData {
	return &CommandResponseData{
		commandName:     commandName,
		handleCallBack:  cb,
		payload:         payload,
		nextHandledTime: nextHandledTime,
	}
}

func InsertNewCommandResponseData(commandResponseChannel *commandResponseChannelData, data *CommandResponseData) {
	glog.Infof("insert new data of %s to command response channel", data.commandName)
	timer := time.NewTimer(*data.nextHandledTime)
	*commandResponseChannel.limitedGoRoutinesCommandResponseChannel <- &timerData{
		timer:   timer,
		payload: data,
	}
}

func (mainHandler *MainHandler) waitTimerTofinishAndInsert(data *timerData) {
	<-data.timer.C
	*mainHandler.commandResponseChannel.commandResponseChannel <- data.payload.(*CommandResponseData)
}

func (mainHandler *MainHandler) handleLimitedGoroutineOfCommandsResponse() {
	for {
		tData := <-*mainHandler.commandResponseChannel.limitedGoRoutinesCommandResponseChannel
		mainHandler.waitTimerTofinishAndInsert(tData)
	}
}

func (mainHandler *MainHandler) createInsertCommandsResponseThreadPool() {
	for i := 0; i < MAX_LIMITATION_INSERT_TO_COMMAND_RESPONSE_CHANNEL_GO_ROUTINE; i++ {
		go mainHandler.handleLimitedGoroutineOfCommandsResponse()
	}
}

func (mainHandler *MainHandler) handleCommandResponse() {
	mainHandler.createInsertCommandsResponseThreadPool()
	for {
		data := <-*mainHandler.commandResponseChannel.commandResponseChannel
		glog.Infof("handle command response %s", data.commandName)
		data.isCommandResponseNeedToBeRehandled, data.nextHandledTime = data.handleCallBack(data.payload)
		glog.Infof("%s is need to be rehandled: %v", data.commandName, data.isCommandResponseNeedToBeRehandled)
		if data.isCommandResponseNeedToBeRehandled {
			InsertNewCommandResponseData(mainHandler.commandResponseChannel, data)
		}
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

	go mainHandler.handleCommandResponse()
	for {
		sessionObj := <-*mainHandler.sessionObj

		if ignoreNamespace(sessionObj.Command.CommandName, getCommandNamespace(&sessionObj.Command)) {
			glog.Infof("namespace '%s' out of scope. Ignoring wlid: %s, command: %s", getCommandNamespace(&sessionObj.Command), getCommandID(&sessionObj.Command), sessionObj.Command.CommandName)
			continue
		}

		// if scan disabled
		if cautils.ScanDisabled && sessionObj.Command.CommandName == apis.TypeScanImages {
			err := fmt.Errorf("scan is disabled in cluster")
			glog.Warningf(err.Error())
			sessionObj.Reporter.SetActionName(string(apis.TypeScanImages))
			sessionObj.Reporter.SendError(err, true, true)
			continue
		}
		isToItemizeScopeCommand := sessionObj.Command.WildWlid != "" || sessionObj.Command.WildSid != "" || len(sessionObj.Command.Designators) > 0
		switch sessionObj.Command.CommandName {
		case apis.TypeRunKubescape, apis.TypeRunKubescapeJob, apis.TypeSetKubescapeCronJob, apis.TypeDeleteKubescapeCronJob, apis.TypeUpdateKubescapeCronJob:
			isToItemizeScopeCommand = false

		case apis.TypeSetVulnScanCronJob, apis.TypeDeleteVulnScanCronJob, apis.TypeUpdateVulnScanCronJob:
			isToItemizeScopeCommand = false
		}

		if isToItemizeScopeCommand {
			mainHandler.HandleScopedRequest(&sessionObj) // this might be a heavy action, do not send to a goroutine
			// } else if sessionObj.Command.Sid != "" {
			// 	go mainHandler.HandleSingleRequest(&sessionObj)
		} else {
			// handle requests
			mainHandler.HandleSingleRequest(&sessionObj)
		}
	}
}

func (mainHandler *MainHandler) HandleSingleRequest(sessionObj *cautils.SessionObj) {
	// FALLBACK
	sidFallback(sessionObj)

	// if sessionObj.Command.CommandName != apis.SCAN_REGISTRY && sessionObj.Command.GetID() == "" {
	// 	glog.Errorf("Received empty id")
	// 	return
	// }

	status := "SUCCESS"

	actionHandler := NewActionHandler(mainHandler.cacli, mainHandler.k8sAPI, mainHandler.signerSemaphore, sessionObj, mainHandler.commandResponseChannel)
	glog.Infof("NewActionHandler: %v/%v", actionHandler.reporter.GetParentAction(), actionHandler.reporter.GetJobID())
	actionHandler.reporter.SendAction(string(sessionObj.Command.CommandName), true)
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
	case apis.TypeUpdateWorkload, apis.TypeInjectToWorkload, apis.TypeAttachWorkload:
		return actionHandler.update(c.CommandName)
	case apis.TypeRemoveWorkload, apis.TypeDetachWorkload:
		actionHandler.deleteConfigMaps(c)
		err := actionHandler.update(c.CommandName)
		go actionHandler.workloadCleanupDiscovery()
		return err
	case apis.TypeRestartWorkload, apis.TypeWorkloadIncompatible, apis.TypeImageUnreachableInWorkload, apis.TypeReplaceHeadersInWorkload:
		return actionHandler.update(c.CommandName)
	case apis.TypeClusterUnregistered:
		err := actionHandler.update(c.CommandName)
		go actionHandler.workloadCleanupAll()
		return err
	case apis.TypeSignWorkload:
		actionHandler.signerSemaphore.Acquire(context.Background(), 1)
		defer actionHandler.signerSemaphore.Release(1)
		return actionHandler.signWorkload()
	case apis.TypeEncryptSecret, apis.TypeDecryptSecret:
		return actionHandler.runSecretCommand(sessionObj)
	case apis.TypeScanImages:
		return actionHandler.scanWorkload(sessionObj)
	case apis.TypeScanRegistry:
		return actionHandler.scanRegistry(sessionObj)
	case apis.TypeRunKubescape, apis.TypeRunKubescapeJob:
		return actionHandler.kubescapeScan()
	case apis.TypeSetKubescapeCronJob:
		return actionHandler.setKubescapeCronJob()
	case apis.TypeUpdateKubescapeCronJob:
		return actionHandler.updateKubescapeCronJob()
	case apis.TypeDeleteKubescapeCronJob:
		return actionHandler.deleteKubescapeCronJob()
	case apis.TypeSetVulnScanCronJob:
		return actionHandler.setVulnScanCronJob()
	case apis.TypeUpdateVulnScanCronJob:
		return actionHandler.updateVulnScanCronJob()
	case apis.TypeDeleteVulnScanCronJob:
		return actionHandler.deleteVulnScanCronJob()
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

	return actionHandler.update(apis.TypeRestartWorkload)
}

// HandleScopedRequest handle a request of a scope e.g. all workloads in a namespace
func (mainHandler *MainHandler) HandleScopedRequest(sessionObj *cautils.SessionObj) {
	if sessionObj.Command.GetID() == "" {
		glog.Errorf("Received empty id")
		return
	}
	fmt.Printf("HandleScopedRequest: %v\n", sessionObj.Command.JobTracking)

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
	if len(namespaces) == 0 {
		namespaces = append(namespaces, "")
	}
	info := fmt.Sprintf("%s: id: '%s', namespaces: '%v', labels: '%v', fieldSelector: '%v'", sessionObj.Command.CommandName, sessionObj.Command.GetID(), namespaces, labels, fields)
	glog.Infof(info)
	sessionObj.Reporter.SendAction(info, true)
	ids, errs := mainHandler.getIDs(namespaces, labels, fields, resources)
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

func (mainHandler *MainHandler) getIDs(namespaces []string, labels, fields map[string]string, resources []string) ([]string, []error) {
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
		w, e := mainHandler.getResourcesIDs(workloads)
		if len(e) != 0 {
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

	for i := range actions {
		go func(index int) {
			waitFunc := isActionNeedToWait(actions[index])
			waitFunc()
			sessionObj := cautils.NewSessionObj(&actions[index], "Websocket", "", uuid.NewString(), 1)
			*mainHandler.sessionObj <- *sessionObj
		}(i)
	}
}
