package mainhandler

import (
	"context"
	"fmt"
	"regexp"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/operator/utils"
	"github.com/kubescape/operator/watcher"
	"go.opentelemetry.io/otel"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/utils-go/httputils"

	"github.com/armosec/armoapi-go/apis"

	uuid "github.com/google/uuid"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"

	reporterlib "github.com/armosec/logger-go/system-reports/datastructures"
	pkgwlid "github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/k8s-interface/k8sinterface"
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
var KubescapeHttpClient httputils.IHttpClient
var VulnScanHttpClient httputils.IHttpClient

func init() {
	var err error
	k8sNamesRegex, err = regexp.Compile("[^A-Za-z0-9-]+")
	if err != nil {
		logger.L().Fatal(err.Error(), helpers.Error(err))
	}

	actionNeedToBeWaitOnStartUp[apis.TypeScanImages] = waitForVulnScanReady
	actionNeedToBeWaitOnStartUp[apis.TypeRunKubescape] = waitForKubescapeReady
}

// CreateWebSocketHandler Create ws-handler obj
func NewMainHandler(sessionObj *chan utils.SessionObj, k8sAPI *k8sinterface.KubernetesApi) *MainHandler {

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
	return &ActionHandler{
		reporter:               sessionObj.Reporter,
		command:                sessionObj.Command,
		k8sAPI:                 k8sAPI,
		commandResponseChannel: commandResponseChannel,
	}
}

func (mainHandler *MainHandler) HandleWatchers(ctx context.Context) {
	defer func() {
		if err := recover(); err != nil {
			logger.L().Ctx(ctx).Error(fmt.Sprintf("RECOVER in HandleWatchers, reason: %v", err))
		}
	}()

	watchHandler := watcher.NewWatchHandler()

	// build imageIDs and wlids maps
	err := watchHandler.Initialize(ctx)
	if err != nil {
		logger.L().Ctx(ctx).Error(err.Error(), helpers.Error(err))
		return
	}

	// scan all workloads in cluster
	mainHandler.triggerScanForWorkloads(ctx, watchHandler.GetWlidsMap())

	// start watching
	watchHandler.PodWatch(ctx)
}

func (mainHandler *MainHandler) triggerScanForWorkloads(ctx context.Context, wlidsToContainerToImageID map[string]map[string]string) {
	commandsList := mainHandler.buildScanCommandList(ctx, wlidsToContainerToImageID)
	go mainHandler.insertCommandsToChannel(ctx, commandsList)
}

func (mainHandler *MainHandler) insertCommandsToChannel(ctx context.Context, commandsList []*apis.Command) {
	for _, cmd := range commandsList {
		newSessionObj := utils.NewSessionObj(ctx, cmd, "Websocket", "", uuid.NewString(), 1)
		*mainHandler.sessionObj <- *newSessionObj
	}
}

func (mainHandler *MainHandler) buildScanCommandList(ctx context.Context, wlidsToContainerToImageID map[string]map[string]string) []*apis.Command {
	commandsList := make([]*apis.Command, 0)
	for wlid, containerToId := range wlidsToContainerToImageID {
		cmd := &apis.Command{}
		cmd.Wlid = wlid
		cmd.CommandName = apis.TypeScanImages
		cmd.Args = make(map[string]interface{})
		for container, imgID := range containerToId {
			cmd.Args[container] = imgID
			logger.L().Ctx(ctx).Info("Triggering scan for", helpers.String("wlid", wlid), helpers.String("args", fmt.Sprintf("%v", containerToId)))
			commandsList = append(commandsList, cmd)
		}
	}
	return commandsList
}

// HandlePostmanRequest Parse received commands and run the command
func (mainHandler *MainHandler) HandleRequest(ctx context.Context) []error {
	// recover
	defer func() {
		if err := recover(); err != nil {
			logger.L().Ctx(ctx).Error(fmt.Sprintf("RECOVER in HandleRequest, reason: %v", err))
		}
	}()

	go mainHandler.handleCommandResponse(ctx)
	for {
		sessionObj := <-*mainHandler.sessionObj
		ctx, span := otel.Tracer("").Start(ctx, string(sessionObj.Command.CommandName))

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
			mainHandler.HandleScopedRequest(ctx, &sessionObj) // this might be a heavy action, do not send to a goroutine
		} else {
			// handle requests
			mainHandler.HandleSingleRequest(ctx, &sessionObj)
		}
		span.End()
		close(sessionObj.ErrChan)
	}
}

func (mainHandler *MainHandler) HandleSingleRequest(ctx context.Context, sessionObj *utils.SessionObj) {
	ctx, span := otel.Tracer("").Start(ctx, "mainHandler.HandleSingleRequest")
	defer span.End()

	status := "SUCCESS"

	actionHandler := NewActionHandler(mainHandler.k8sAPI, sessionObj, mainHandler.commandResponseChannel)
	logger.L().Info(fmt.Sprintf("NewActionHandler: %v/%v", actionHandler.reporter.GetParentAction(), actionHandler.reporter.GetJobID()))
	actionHandler.reporter.SetActionName(string(sessionObj.Command.CommandName))
	actionHandler.reporter.SendDetails("Handling single request", true, sessionObj.ErrChan)
	err := actionHandler.runCommand(ctx, sessionObj)
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
	logger.L().Info(donePrint)
}

func (actionHandler *ActionHandler) runCommand(ctx context.Context, sessionObj *utils.SessionObj) error {
	c := sessionObj.Command
	if pkgwlid.IsWlid(c.GetID()) {
		actionHandler.wlid = c.GetID()
	}

	logCommandInfo := fmt.Sprintf("Running %s command, id: '%s'", c.CommandName, c.GetID())

	logger.L().Info(logCommandInfo)

	switch c.CommandName {
	case apis.TypeScanImages:
		return actionHandler.scanWorkload(ctx, sessionObj)
	case apis.TypeRunKubescape, apis.TypeRunKubescapeJob:
		return actionHandler.kubescapeScan(ctx)
	case apis.TypeSetKubescapeCronJob:
		return actionHandler.setKubescapeCronJob(ctx)
	case apis.TypeUpdateKubescapeCronJob:
		return actionHandler.updateKubescapeCronJob(ctx)
	case apis.TypeDeleteKubescapeCronJob:
		return actionHandler.deleteKubescapeCronJob(ctx)
	case apis.TypeSetVulnScanCronJob:
		return actionHandler.setVulnScanCronJob(ctx)
	case apis.TypeUpdateVulnScanCronJob:
		return actionHandler.updateVulnScanCronJob(ctx)
	case apis.TypeDeleteVulnScanCronJob:
		return actionHandler.deleteVulnScanCronJob(ctx)
	case apis.TypeSetRegistryScanCronJob:
		return actionHandler.setRegistryScanCronJob(ctx, sessionObj)
	case apis.TypeScanRegistry:
		return actionHandler.scanRegistries(ctx, sessionObj)
	case apis.TypeTestRegistryConnectivity:
		return actionHandler.testRegistryConnectivity(ctx, sessionObj)
	case apis.TypeUpdateRegistryScanCronJob:
		return actionHandler.updateRegistryScanCronJob(ctx, sessionObj)
	case apis.TypeDeleteRegistryScanCronJob:
		return actionHandler.deleteRegistryScanCronJob(ctx)
	default:
		logger.L().Ctx(ctx).Error(fmt.Sprintf("Command %s not found", c.CommandName))
	}
	return nil
}

// HandleScopedRequest handle a request of a scope e.g. all workloads in a namespace
func (mainHandler *MainHandler) HandleScopedRequest(ctx context.Context, sessionObj *utils.SessionObj) {
	ctx, span := otel.Tracer("").Start(ctx, "mainHandler.HandleScopedRequest")
	defer span.End()

	if sessionObj.Command.GetID() == "" {
		logger.L().Ctx(ctx).Error("Received empty id")
		return
	}

	namespaces := make([]string, 0, 1)
	namespaces = append(namespaces, pkgwlid.GetNamespaceFromWlid(sessionObj.Command.GetID()))
	labels := sessionObj.Command.GetLabels()
	fields := sessionObj.Command.GetFieldSelector()
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
	logger.L().Info(info)
	sessionObj.Reporter.SendDetails(info, true, sessionObj.ErrChan)
	ids, errs := mainHandler.getIDs(namespaces, labels, fields, []string{"pods"})
	for i := range errs {
		logger.L().Ctx(ctx).Warning(errs[i].Error())
		sessionObj.Reporter.SendError(errs[i], true, true, sessionObj.ErrChan)
	}

	sessionObj.Reporter.SendStatus(reporterlib.JobSuccess, true, sessionObj.ErrChan)

	logger.L().Info(fmt.Sprintf("ids found: '%v'", ids))
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
			newSessionObj := utils.NewSessionObj(ctx, cmd, "Websocket", sessionObj.Reporter.GetJobID(), "", 1)

			if err != nil {
				err := fmt.Errorf("invalid: %s, id: '%s'", err.Error(), newSessionObj.Command.GetID())
				logger.L().Ctx(ctx).Error(err.Error(), helpers.Error(err))
				sessionObj.Reporter.SendError(err, true, true, sessionObj.ErrChan)
				continue
			}

			logger.L().Info(fmt.Sprintf("triggering id: '%s'", newSessionObj.Command.GetID()))
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
func (mainHandler *MainHandler) StartupTriggerActions(ctx context.Context, actions []apis.Command) {

	for i := range actions {
		go func(index int) {
			waitFunc := isActionNeedToWait(actions[index])
			waitFunc()
			sessionObj := utils.NewSessionObj(ctx, &actions[index], "Websocket", "", uuid.NewString(), 1)
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
	}
}
