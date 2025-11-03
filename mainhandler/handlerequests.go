package mainhandler

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/armosec/utils-go/boolutils"
	"github.com/armosec/utils-go/httputils"
	pkgwlid "github.com/armosec/utils-k8s-go/wlid"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	instanceidhandlerv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/k8sinterface"
	v1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	exporters "github.com/kubescape/operator/admission/exporter"
	"github.com/kubescape/operator/config"
	cs "github.com/kubescape/operator/continuousscanning"
	"github.com/kubescape/operator/utils"
	"github.com/kubescape/operator/watcher"
	kssc "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	"github.com/panjf2000/ants/v2"
	"go.opentelemetry.io/otel"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/pager"
)

type MainHandler struct {
	eventWorkerPool        *ants.PoolWithFunc
	k8sAPI                 *k8sinterface.KubernetesApi
	ksStorageClient        kssc.Interface
	commandResponseChannel *commandResponseChannelData
	config                 config.IConfig
	exporter               exporters.Exporter
}

type ActionHandler struct {
	sessionObj             *utils.SessionObj
	config                 config.IConfig
	k8sAPI                 *k8sinterface.KubernetesApi
	commandResponseChannel *commandResponseChannelData
	wlid                   string
	exporter               exporters.Exporter
}

type waitFunc func(clusterConfig config.IConfig)

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
func NewMainHandler(config config.IConfig, k8sAPI *k8sinterface.KubernetesApi, exporter exporters.Exporter, ksStorageClient kssc.Interface) *MainHandler {

	commandResponseChannel := make(chan *CommandResponseData, 100)
	limitedGoRoutinesCommandResponseChannel := make(chan *timerData, 10)
	mainHandler := &MainHandler{
		k8sAPI:                 k8sAPI,
		ksStorageClient:        ksStorageClient,
		commandResponseChannel: &commandResponseChannelData{commandResponseChannel: &commandResponseChannel, limitedGoRoutinesCommandResponseChannel: &limitedGoRoutinesCommandResponseChannel},
		config:                 config,
		exporter:               exporter,
	}
	pool, _ := ants.NewPoolWithFunc(config.ConcurrencyWorkers(), func(i interface{}) {
		j, ok := i.(utils.Job)
		if !ok {
			logger.L().Error("failed to cast job", helpers.Interface("job", i))
			return
		}
		mainHandler.handleRequest(j)
	})
	mainHandler.eventWorkerPool = pool
	return mainHandler
}

// CreateWebSocketHandler Create ws-handler obj
func NewActionHandler(config config.IConfig, k8sAPI *k8sinterface.KubernetesApi, sessionObj *utils.SessionObj, commandResponseChannel *commandResponseChannelData, exporter exporters.Exporter) *ActionHandler {
	return &ActionHandler{
		sessionObj:             sessionObj,
		k8sAPI:                 k8sAPI,
		commandResponseChannel: commandResponseChannel,
		config:                 config,
		exporter:               exporter,
	}
}

// SetupContinuousScanning sets up the continuous cluster scanning function
func (mainHandler *MainHandler) SetupContinuousScanning(ctx context.Context) error {
	ksStorageClient, err := kssc.NewForConfig(k8sinterface.GetK8sConfig())
	if err != nil {
		logger.L().Ctx(ctx).Fatal("unable to initialize the storage client", helpers.Error(err))
	}

	triggeringHandler := cs.NewTriggeringHandler(mainHandler.eventWorkerPool, mainHandler.config)
	deletingHandler := cs.NewDeletedCleanerHandler(mainHandler.eventWorkerPool, mainHandler.config, ksStorageClient)

	rulesFilename := mainHandler.config.MatchingRulesFilename()
	rulesReader, err := os.Open(rulesFilename)
	if err != nil {
		return err
	}

	fetcher := cs.NewFileFetcher(rulesReader)
	loader := cs.NewTargetLoader(fetcher)

	dynClient := mainHandler.k8sAPI.DynamicClient
	svc := cs.NewContinuousScanningService(mainHandler.config, dynClient, loader, triggeringHandler, deletingHandler)
	svc.Launch(ctx)

	return nil
}

func (mainHandler *MainHandler) HandleWatchers(ctx context.Context) {
	defer func() {
		if err := recover(); err != nil {
			logger.L().Ctx(ctx).Fatal("recover in HandleWatchers", helpers.Interface("error", err))
		}
	}()

	commandWatchHandler := watcher.NewCommandWatchHandler(mainHandler.k8sAPI, mainHandler.config)
	operatorCommandsHandler := watcher.NewOperatorCommandsHandler(ctx, mainHandler.eventWorkerPool, mainHandler.k8sAPI, commandWatchHandler, mainHandler.config)

	if mainHandler.config.Components().Kubevuln.Enabled {
		eventQueue := watcher.NewCooldownQueue()
		watchHandler := watcher.NewWatchHandler(mainHandler.config, mainHandler.k8sAPI, mainHandler.ksStorageClient, eventQueue)

		registryCommandsHandler := watcher.NewRegistryCommandsHandler(ctx, mainHandler.k8sAPI, commandWatchHandler, mainHandler.config)
		go registryCommandsHandler.Start()

		// wait for the kubevuln component to be ready
		logger.L().Info("Waiting for vuln scan to be ready")
		waitFunc := isActionNeedToWait(apis.Command{CommandName: apis.TypeScanImages})
		waitFunc(mainHandler.config)

		// start watching
		if mainHandler.config.NodeSbomGenerationEnabled() {
			go watchHandler.SBOMWatch(ctx, mainHandler.eventWorkerPool)
		} else {
			go watchHandler.PodWatch(ctx, mainHandler.eventWorkerPool)
		}
		go watchHandler.ContainerProfileWatch(ctx, mainHandler.eventWorkerPool)
	}

	go operatorCommandsHandler.Start()
	go commandWatchHandler.CommandWatch(ctx)
}

func (h *MainHandler) StartContinuousScanning(_ context.Context) error {
	return nil
}

// HandlePostmanRequest Parse received commands and run the command
func (mainHandler *MainHandler) handleRequest(j utils.Job) {

	ctx := j.Context()
	sessionObj := j.Obj()

	ctx, span := otel.Tracer("").Start(ctx, string(sessionObj.Command.CommandName))

	isToItemizeScopeCommand := sessionObj.Command.WildWlid != "" || sessionObj.Command.WildSid != "" || len(sessionObj.Command.Designators) > 0
	switch sessionObj.Command.CommandName {
	case apis.TypeRunKubescape, apis.TypeRunKubescapeJob, apis.TypeSetKubescapeCronJob, apis.TypeDeleteKubescapeCronJob, apis.TypeUpdateKubescapeCronJob:
		isToItemizeScopeCommand = false

	case apis.TypeSetVulnScanCronJob, apis.TypeDeleteVulnScanCronJob, apis.TypeUpdateVulnScanCronJob:
		isToItemizeScopeCommand = false
	}

	if isToItemizeScopeCommand {
		if sessionObj.Command.CommandName == apis.TypeScanImages {
			mainHandler.HandleImageScanningScopedRequest(ctx, &sessionObj)
		} else {
			// TODO: handle scope request
			// I'm not sure when we will need this case
			mainHandler.HandleScopedRequest(ctx, &sessionObj) // this might be a heavy action, do not send to a goroutine
		}
	} else {
		// handle requests
		if err := mainHandler.HandleSingleRequest(ctx, &sessionObj); err != nil {
			logger.L().Ctx(ctx).Error("failed to complete action", helpers.String("command", string(sessionObj.Command.CommandName)), helpers.String("wlid", sessionObj.Command.GetID()), helpers.Error(err))
			sessionObj.SetOperatorCommandStatus(ctx, utils.WithError(err))
		} else {
			sessionObj.SetOperatorCommandStatus(ctx, utils.WithSuccess())
			logger.L().Info("action completed successfully", helpers.String("command", string(sessionObj.Command.CommandName)), helpers.String("wlid", sessionObj.Command.GetID()))
		}
	}
	span.End()
}

func (mainHandler *MainHandler) HandleSingleRequest(ctx context.Context, sessionObj *utils.SessionObj) error {
	ctx, span := otel.Tracer("").Start(ctx, "mainHandler.HandleSingleRequest")
	defer span.End()

	actionHandler := NewActionHandler(mainHandler.config, mainHandler.k8sAPI, sessionObj, mainHandler.commandResponseChannel, mainHandler.exporter)
	return actionHandler.runCommand(ctx)

}

func (actionHandler *ActionHandler) runCommand(ctx context.Context) error {
	sessionObj := actionHandler.sessionObj
	c := sessionObj.Command
	if pkgwlid.IsWlid(c.GetID()) {
		actionHandler.wlid = c.GetID()
	}

	switch c.CommandName {
	case apis.TypeScanImages:
		return actionHandler.scanImage(ctx)
	case utils.CommandScanContainerProfile:
		return actionHandler.scanContainerProfile(ctx)
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
	case apis.TypeScanRegistryV2:
		return actionHandler.scanRegistriesV2AndUpdateStatus(ctx)
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

	podLabels := sessionObj.Command.GetLabels()
	fieldSelector := sessionObj.Command.GetFieldSelector()
	namespaces, err := mainHandler.getNamespaces(ctx, sessionObj)
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to list namespaces", helpers.Error(err))
		sessionObj.SetOperatorCommandStatus(ctx, utils.WithError(err))
		return
	}

	info := fmt.Sprintf("%s: id: '%s', namespaces: '%v', labels: '%v', fieldSelector: '%v'", sessionObj.Command.CommandName, sessionObj.Command.GetID(), namespaces, podLabels, fieldSelector)
	logger.L().Info(info)

	listOptions := metav1.ListOptions{}
	if len(podLabels) > 0 {
		set := labels.Set(podLabels)
		listOptions.LabelSelector = k8sinterface.SelectorToString(set)
	}
	if len(fieldSelector) > 0 {
		set := labels.Set(fieldSelector)
		listOptions.FieldSelector = k8sinterface.SelectorToString(set)
	}

	errors := mapset.NewSet[error]()

	for _, ns := range namespaces {
		if mainHandler.config.SkipNamespace(ns) {
			continue
		}

		if err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			return mainHandler.k8sAPI.KubernetesClient.CoreV1().Pods(ns).List(ctx, opts)
		}).EachListItem(ctx, listOptions, func(obj runtime.Object) error {
			pod := obj.(*corev1.Pod)
			podId := pkgwlid.GetWLID(mainHandler.config.ClusterName(), pod.GetNamespace(), "pod", pod.GetName())
			cmd := sessionObj.Command.DeepCopy()

			var err error
			if pkgwlid.IsWlid(podId) {
				cmd.Wlid = podId
				err = pkgwlid.IsWlidValid(cmd.Wlid)
			} else {
				err = fmt.Errorf("unknown id")
			}

			// clean all scope request parameters
			cmd.WildWlid = ""
			cmd.Designators = make([]identifiers.PortalDesignator, 0)

			// send specific command to the channel
			newSessionObj := utils.NewSessionObj(ctx, mainHandler.config, cmd, sessionObj.JobID, "")

			if err != nil {
				err := fmt.Errorf("invalid: %s, id: '%s'", err.Error(), newSessionObj.Command.GetID())
				logger.L().Ctx(ctx).Error(err.Error())
				errors.Add(err)
				return nil
			}

			logger.L().Info("triggering", helpers.String("id", newSessionObj.Command.GetID()))
			if err := mainHandler.HandleSingleRequest(ctx, newSessionObj); err != nil {
				logger.L().Ctx(ctx).Error("failed to complete action", helpers.String("command", string(sessionObj.Command.CommandName)), helpers.String("wlid", sessionObj.Command.GetID()), helpers.Error(err))
				errors.Add(err)
				return nil
			}
			logger.L().Info("action completed successfully", helpers.String("command", string(sessionObj.Command.CommandName)), helpers.String("wlid", sessionObj.Command.GetID()))
			return nil
		}); err != nil {
			logger.L().Ctx(ctx).Warning(err.Error())
			errors.Add(err)
		}
	}

	if errors.Cardinality() > 0 {
		sessionObj.SetOperatorCommandStatus(ctx, utils.WithMultipleErrors(errors.ToSlice()))
	} else {
		sessionObj.SetOperatorCommandStatus(ctx, utils.WithSuccess())
	}
}

// HandleScopedRequest handle a request of a scope e.g. all workloads in a namespace
func (mainHandler *MainHandler) HandleImageScanningScopedRequest(ctx context.Context, sessionObj *utils.SessionObj) {
	ctx, span := otel.Tracer("").Start(ctx, "mainHandler.HandleImageScanningScopedRequest")
	defer span.End()

	if sessionObj.Command.GetID() == "" {
		logger.L().Ctx(ctx).Error("Received empty id")
		return
	}

	lbls := sessionObj.Command.GetLabels()
	fields := sessionObj.Command.GetFieldSelector()
	namespaces, err := mainHandler.getNamespaces(ctx, sessionObj)
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to list namespaces", helpers.Error(err))
		sessionObj.SetOperatorCommandStatus(ctx, utils.WithError(err))
		return
	}

	info := fmt.Sprintf("%s: id: '%s', namespaces: '%v', labels: '%v', fieldSelector: '%v'", sessionObj.Command.CommandName, sessionObj.Command.GetID(), namespaces, lbls, fields)
	logger.L().Info(info)

	listOptions := metav1.ListOptions{
		LabelSelector: k8sinterface.SelectorToString(lbls),
		FieldSelector: k8sinterface.SelectorToString(fields),
	}

	errors := mapset.NewSet[error]()
	slugs := map[string]bool{}

	for _, ns := range namespaces {
		if mainHandler.config.SkipNamespace(ns) {
			continue
		}
		if err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			return mainHandler.k8sAPI.KubernetesClient.CoreV1().Pods(ns).List(ctx, opts)
		}).EachListItem(ctx, listOptions, func(obj runtime.Object) error {
			pod := obj.(*corev1.Pod)
			if pod.Status.Phase != corev1.PodRunning {
				// skip non-running pods, for some reason the list includes non-running pods
				return nil
			}
			// need to set APIVersion and Kind before unstructured conversion, preparing for instanceID extraction
			pod.APIVersion = "v1"
			pod.Kind = "Pod"

			instanceIDs, err := instanceidhandlerv1.GenerateInstanceIDFromRuntimeObj(pod, mainHandler.config.ExcludeJsonPaths())
			if err != nil {
				logger.L().Ctx(ctx).Error("failed to generate instance ID for pod", helpers.String("pod", pod.GetName()), helpers.String("namespace", pod.GetNamespace()), helpers.Error(err))
				return nil
			}

			// for naked pods, only handle if pod is older than guard time
			if !utils.PodHasParent(pod) && time.Now().Before(pod.CreationTimestamp.Add(mainHandler.config.GuardTime())) {
				logger.L().Debug("naked pod younger than guard time detected, skipping scan", helpers.String("pod", pod.GetName()), helpers.String("namespace", pod.GetNamespace()), helpers.String("creationTimestamp", pod.CreationTimestamp.String()))
				return nil
			}
			for _, instanceID := range instanceIDs {
				s, _ := instanceID.GetSlug(false)
				if ok := slugs[s]; ok {
					// slug already scanned, there is no need to scan again in this request
					continue
				}

				// get container data
				containerData, err := utils.PodToContainerData(mainHandler.k8sAPI, pod, instanceID, mainHandler.config.ClusterName())
				if err != nil {
					// if pod is not running, we can't get the image id
					continue
				}

				noContainerSlug, _ := instanceID.GetSlug(true)
				if profile := utils.GetContainerProfileForRelevancyScan(ctx, mainHandler.ksStorageClient, noContainerSlug, ns); profile != nil {
					cmd := utils.GetContainerProfileScanCommand(profile, pod)

					// send specific command to the channel
					newSessionObj := utils.NewSessionObj(ctx, mainHandler.config, cmd, sessionObj.JobID, "")
					logger.L().Info("triggering container profile scan", helpers.String("wlid", cmd.Wlid), helpers.String("name", profile.Name), helpers.String("namespace", profile.Namespace))
					if err := mainHandler.HandleSingleRequest(ctx, newSessionObj); err != nil {
						logger.L().Error("failed to complete action", helpers.Error(err), helpers.String("id", newSessionObj.Command.GetID()), helpers.String("name", profile.Name), helpers.String("namespace", profile.Namespace))
						errors.Add(err)
						continue
					}
					logger.L().Info("action completed successfully", helpers.String("name", profile.Name), helpers.String("namespace", profile.Namespace))
					slugs[noContainerSlug] = true
				} else {
					// set scanning command
					cmd := &apis.Command{
						Wlid:        containerData.Wlid,
						CommandName: apis.TypeScanImages,
						Args: map[string]interface{}{
							utils.ArgsContainerData: containerData,
							utils.ArgsPod:           pod,
						},
					}
					// send specific command to the channel
					newSessionObj := utils.NewSessionObj(ctx, mainHandler.config, cmd, sessionObj.JobID, "")
					logger.L().Info("triggering scan image", helpers.String("id", newSessionObj.Command.GetID()), helpers.String("slug", s), helpers.String("containerName", containerData.ContainerName), helpers.String("imageTag", containerData.ImageTag), helpers.String("imageID", containerData.ImageID))

					if err := mainHandler.HandleSingleRequest(ctx, newSessionObj); err != nil {
						logger.L().Error("failed to complete action", helpers.Error(err), helpers.String("id", newSessionObj.Command.GetID()), helpers.String("slug", s), helpers.String("containerName", containerData.ContainerName), helpers.String("imageTag", containerData.ImageTag), helpers.String("imageID", containerData.ImageID))
						errors.Add(err)
						continue
					}
					logger.L().Info("action completed successfully", helpers.String("id", newSessionObj.Command.GetID()), helpers.String("slug", s), helpers.String("containerName", containerData.ContainerName), helpers.String("imageTag", containerData.ImageTag), helpers.String("imageID", containerData.ImageID))
					slugs[s] = true
				}
			}
			return nil
		}); err != nil {
			logger.L().Ctx(ctx).Error("failed to list pods", helpers.String("namespace", ns), helpers.Error(err))
			errors.Add(err)
			continue
		}
	}

	if errors.Cardinality() > 0 {
		sessionObj.SetOperatorCommandStatus(ctx, utils.WithMultipleErrors(errors.ToSlice()))
	} else {
		sessionObj.SetOperatorCommandStatus(ctx, utils.WithSuccess())
	}
}

func (mainHandler *MainHandler) getNamespaces(ctx context.Context, sessionObj *utils.SessionObj) ([]string, error) {
	namespaces := make([]string, 0, 1)
	namespaces = append(namespaces, pkgwlid.GetNamespaceFromWlid(sessionObj.Command.GetID()))
	if len(sessionObj.Command.Designators) > 0 {
		namespaces = make([]string, 0, 3)
		for desiIdx := range sessionObj.Command.Designators {
			if ns, ok := sessionObj.Command.Designators[desiIdx].Attributes[identifiers.AttributeNamespace]; ok {
				namespaces = append(namespaces, ns)
			}
		}
	}
	if len(namespaces) == 0 {
		namespacesList, err := mainHandler.k8sAPI.KubernetesClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, ns := range namespacesList.Items {
			namespaces = append(namespaces, ns.GetName())
		}
	}
	return namespaces, nil
}

// HandlePostmanRequest Parse received commands and run the command
func (mainHandler *MainHandler) StartupTriggerActions(ctx context.Context, actions []apis.Command) {

	for i := range actions {
		go func(index int) {
			waitFunc := isActionNeedToWait(actions[index])
			waitFunc(mainHandler.config)
			sessionObj := utils.NewSessionObj(ctx, mainHandler.config, &actions[index], "", "")
			l := utils.Job{}
			l.SetContext(ctx)
			l.SetObj(*sessionObj)
			if err := mainHandler.eventWorkerPool.Invoke(l); err != nil {
				logger.L().Ctx(ctx).Error("failed to invoke job", helpers.String("wlid", actions[index].GetID()), helpers.String("command", fmt.Sprintf("%v", actions[index].CommandName)), helpers.String("args", fmt.Sprintf("%v", actions[index].Args)), helpers.Error(err))
			}
		}(i)
	}
}

func (mainHandler *MainHandler) EventWorkerPool() *ants.PoolWithFunc {
	return mainHandler.eventWorkerPool
}

func (mainHandler *MainHandler) SendReports(ctx context.Context, period time.Duration) {
	for {
		v := versioncheck.NewVersionCheckHandler()
		versionCheckRequest := versioncheck.NewVersionCheckRequest(
			mainHandler.config.AccountID(), versioncheck.BuildNumber, "", "",
			"daily-report", mainHandler.k8sAPI.KubernetesClient)
		err := v.CheckLatestVersion(ctx, versionCheckRequest)
		if err != nil {
			logger.L().Ctx(ctx).Error("failed to send daily report", helpers.Error(err))
		}
		time.Sleep(period)
	}
}

func GetStartupActions(config config.IConfig) []apis.Command {
	return []apis.Command{
		{
			CommandName: apis.TypeRunKubescape,
			WildWlid:    pkgwlid.GetK8sWLID(config.ClusterName(), "", "", ""),
			Args: map[string]interface{}{
				utils.KubescapeScanV1: utilsmetav1.PostScanRequest{
					HostScanner: boolutils.BoolPointer(false),
					TargetType:  v1.KindFramework,
					TargetNames: []string{"allcontrols", "nsa", "mitre"},
				},
			},
		},
	}
}
