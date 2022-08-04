package mainhandler

import (
	"fmt"
	"k8s-ca-websocket/utils"
	"regexp"

	apitypes "github.com/armosec/armoapi-go/armotypes"

	"github.com/armosec/armoapi-go/apis"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"

	utilsmetav1 "github.com/armosec/opa-utils/httpserver/meta/v1"
	uuid "github.com/google/uuid"

	"github.com/armosec/k8s-interface/k8sinterface"
	reporterlib "github.com/armosec/logger-go/system-reports/datastructures"
	pkgwlid "github.com/armosec/utils-k8s-go/wlid"
	"github.com/golang/glog"
)

type MainHandler struct {
	sessionObj             *chan utils.SessionObj // TODO: wrap chan with struct for mutex support
	k8sAPI                 *k8sinterface.KubernetesApi
	commandResponseChannel *commandResponseChannelData
}

type ActionHandler struct {
	k8sAPI                 *k8sinterface.KubernetesApi
	reporter               reporterlib.IReporter
	wlid                   string
	command                apis.Command
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
func NewMainHandler(sessionObj *chan utils.SessionObj, k8sAPI *k8sinterface.KubernetesApi) *MainHandler {
	utilsmetadata.InitNamespacesListToIgnore(utils.Namespace)

	commandResponseChannel := make(chan *CommandResponseData, 100)
	limitedGoRoutinesCommandResponseChannel := make(chan *timerData, 10)
	return &MainHandler{
		sessionObj:             sessionObj,
		k8sAPI:                 k8sAPI,
		commandResponseChannel: &commandResponseChannelData{commandResponseChannel: &commandResponseChannel, limitedGoRoutinesCommandResponseChannel: &limitedGoRoutinesCommandResponseChannel},
	}
}

// CreateWebSocketHandler Create ws-handler obj
func NewActionHandler(k8sAPI *k8sinterface.KubernetesApi, sessionObj *utils.SessionObj, commandResponseChannel *commandResponseChannelData) *ActionHandler {
	utilsmetadata.InitNamespacesListToIgnore(utils.Namespace)
	return &ActionHandler{
		reporter:               sessionObj.Reporter,
		command:                sessionObj.Command,
		k8sAPI:                 k8sAPI,
		commandResponseChannel: commandResponseChannel,
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

		// the all user experience depends on this line(the user/backend must get the action name in order to understand the job report)
		sessionObj.Reporter.SetActionName(string(sessionObj.Command.CommandName))

		isToItemizeScopeCommand := sessionObj.Command.WildWlid != "" || sessionObj.Command.WildSid != "" || len(sessionObj.Command.Designators) > 0
		switch sessionObj.Command.CommandName {
		case apis.TypeRunKubescape, apis.TypeRunKubescapeJob, apis.TypeSetKubescapeCronJob, apis.TypeDeleteKubescapeCronJob, apis.TypeUpdateKubescapeCronJob:
			isToItemizeScopeCommand = false

		case apis.TypeSetVulnScanCronJob, apis.TypeDeleteVulnScanCronJob, apis.TypeUpdateVulnScanCronJob:
			isToItemizeScopeCommand = false
		}

		if isToItemizeScopeCommand {
			mainHandler.HandleScopedRequest(&sessionObj) // this might be a heavy action, do not send to a goroutine
		} else {
			// handle requests
			mainHandler.HandleSingleRequest(&sessionObj)
		}
		close(sessionObj.ErrChan)
	}
}

func (mainHandler *MainHandler) HandleSingleRequest(sessionObj *utils.SessionObj) {

	status := "SUCCESS"

	actionHandler := NewActionHandler(mainHandler.k8sAPI, sessionObj, mainHandler.commandResponseChannel)
	glog.Infof("NewActionHandler: %v/%v", actionHandler.reporter.GetParentAction(), actionHandler.reporter.GetJobID())
	actionHandler.reporter.SetActionName(string(sessionObj.Command.CommandName))
	actionHandler.reporter.SendDetails("Handling single request", true, sessionObj.ErrChan)
	err := actionHandler.runCommand(sessionObj)
	if err != nil {
		actionHandler.reporter.SendError(err, true, true, sessionObj.ErrChan)
		status = "FAIL"
	} else {
		actionHandler.reporter.SendStatus(reporterlib.JobDone, true, sessionObj.ErrChan)
	}
	donePrint := fmt.Sprintf("Done command %s, wlid: %s, status: %s", sessionObj.Command.CommandName, sessionObj.Command.GetID(), status)
	if err != nil {
		donePrint += fmt.Sprintf(", reason: %s", err.Error())
	}
	glog.Infof(donePrint)
}

func (actionHandler *ActionHandler) runCommand(sessionObj *utils.SessionObj) error {
	c := sessionObj.Command
	if pkgwlid.IsWlid(c.GetID()) {
		actionHandler.wlid = c.GetID()
	}

	logCommandInfo := fmt.Sprintf("Running %s command, id: '%s'", c.CommandName, c.GetID())

	glog.Infof(logCommandInfo)
	switch c.CommandName {
	case apis.TypeScanImages:
		return actionHandler.scanWorkload(sessionObj)
	case apis.TypeScanRegistry:
		return actionHandler.scanRegistries(sessionObj)
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
	case apis.TypeSetRegistryScanCronJob:
		return actionHandler.setRegistryScanCronJob(sessionObj)
	case apis.TypeUpdateRegistryScanCronJob:
		return actionHandler.updateRegistryScanCronJob()
	case apis.TypeDeleteRegistryScanCronJob:
		return actionHandler.deleteRegistryScanCronJob()
	default:
		glog.Errorf("Command %s not found", c.CommandName)
	}
	return nil
}

// HandleScopedRequest handle a request of a scope e.g. all workloads in a namespace
func (mainHandler *MainHandler) HandleScopedRequest(sessionObj *utils.SessionObj) {
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
			if ns, ok := sessionObj.Command.Designators[desiIdx].Attributes[apitypes.AttributeNamespace]; ok {
				namespaces = append(namespaces, ns)
			}
		}
	}
	if len(namespaces) == 0 {
		namespaces = append(namespaces, "")
	}
	info := fmt.Sprintf("%s: id: '%s', namespaces: '%v', labels: '%v', fieldSelector: '%v'", sessionObj.Command.CommandName, sessionObj.Command.GetID(), namespaces, labels, fields)
	glog.Infof(info)
	sessionObj.Reporter.SendDetails(info, true, sessionObj.ErrChan)
	ids, errs := mainHandler.getIDs(namespaces, labels, fields, resources)
	for i := range errs {
		glog.Warningf(errs[i].Error())
		sessionObj.Reporter.SendError(errs[i], true, true, sessionObj.ErrChan)
	}

	sessionObj.Reporter.SendStatus(reporterlib.JobSuccess, true, sessionObj.ErrChan)

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
			cmd.Designators = make([]apitypes.PortalDesignator, 0)
			// send specific command to the channel
			newSessionObj := utils.NewSessionObj(cmd, "Websocket", sessionObj.Reporter.GetJobID(), "", 1)

			if err != nil {
				err := fmt.Errorf("invalid: %s, id: '%s'", err.Error(), newSessionObj.Command.GetID())
				glog.Error(err)
				sessionObj.Reporter.SendError(err, true, true, sessionObj.ErrChan)
				continue
			}

			glog.Infof("triggering id: '%s'", newSessionObj.Command.GetID())
			*mainHandler.sessionObj <- *newSessionObj
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
			sessionObj := utils.NewSessionObj(&actions[index], "Websocket", "", uuid.NewString(), 1)
			*mainHandler.sessionObj <- *sessionObj
		}(i)
	}
}

func GetStartupActions() []apis.Command {
	return []apis.Command{
		{
			CommandName: apis.TypeRunKubescape,
			WildWlid:    pkgwlid.GetK8sWLID(utils.ClusterConfig.ClusterName, "", "", ""),
			Args: map[string]interface{}{
				utils.KubescapeScanV1: utilsmetav1.PostScanRequest{},
			},
		},
		{
			CommandName: apis.TypeScanImages,
			WildWlid:    pkgwlid.GetK8sWLID(utils.ClusterConfig.ClusterName, "", "", ""),
		},
	}
}
