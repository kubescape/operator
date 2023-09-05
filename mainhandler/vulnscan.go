package mainhandler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/docker/docker/api/types"
	"github.com/kubescape/backend/pkg/server/v1/systemreports"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/operator/utils"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/strings/slices"

	uuid "github.com/google/uuid"

	"github.com/armosec/armoapi-go/apis"
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"

	"github.com/armosec/utils-go/httputils"
	"github.com/kubescape/k8s-interface/cloudsupport"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
)

const (
	cmDefaultMode cmMode = "default"
	cmLoadedMode  cmMode = "loaded"
)

type cmMode string

type testRegistryConnectivityStatus string

const (
	testRegistryInformationStatus    testRegistryConnectivityStatus = "registryInformation"
	testRegistryAuthenticationStatus testRegistryConnectivityStatus = "registryAuthentication"
	testRegistryRetrieveReposStatus  testRegistryConnectivityStatus = "retrieveRepositories"
	testRegistryRetrieveTagsStatus   testRegistryConnectivityStatus = "retrieveTags"
)

func getVulnScanURL(clusterConfig utilsmetadata.ClusterConfig) *url.URL {
	return &url.URL{
		Scheme: "http",
		Host:   clusterConfig.KubevulnURL,
		Path:   fmt.Sprintf("%s/%s", apis.VulnerabilityScanCommandVersion, apis.ContainerScanCommandPath),
	}
}

func getRegistryScanURL(clusterConfig utilsmetadata.ClusterConfig) *url.URL {
	return &url.URL{
		Scheme: "http",
		Host:   clusterConfig.KubevulnURL,
		Path:   fmt.Sprintf("%s/%s", apis.VulnerabilityScanCommandVersion, apis.RegistryScanCommandPath),
	}
}

func sendAllImagesToRegistryScan(ctx context.Context, clusterConfig utilsmetadata.ClusterConfig, registryScanCMDList []*apis.RegistryScanCommand) error {
	var err error
	errs := make([]error, 0)
	for _, registryScanCMD := range registryScanCMDList {
		err = sendWorkloadToRegistryScan(ctx, clusterConfig, registryScanCMD)
		if err != nil {
			logger.L().Ctx(ctx).Error("sendWorkloadToRegistryScan failed", helpers.Error(err))
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		err = fmt.Errorf("sendAllImagesToRegistryScan errors: ")
		for errIdx := range errs {
			err = fmt.Errorf("%s; %w", err, errs[errIdx])
		}
		return err
	}
	return nil
}

func convertImagesToRegistryScanCommand(cluster string, registry *registryScan, sessionObj *utils.SessionObj) []*apis.RegistryScanCommand {
	images := registry.mapImageToTags

	registryScanCMDList := make([]*apis.RegistryScanCommand, 0)
	for repository, tags := range images {
		// registry/project/repo --> repo
		repositoryName := strings.Replace(repository, registry.registry.hostname+"/", "", -1)
		if registry.registry.projectID != "" {
			repositoryName = strings.Replace(repositoryName, registry.registry.projectID+"/", "", -1)
		}
		for _, tag := range tags {
			registryScanCommand := &apis.ImageScanParams{
				ParentJobID: sessionObj.Reporter.GetJobID(),
				JobID:       uuid.NewString(),
				ImageTag:    repository + ":" + tag,
				Session:     apis.SessionChain{ActionTitle: "vulnerability-scan", JobIDs: make([]string, 0), Timestamp: sessionObj.Reporter.GetTimestamp()},
				Args: map[string]interface{}{
					identifiers.AttributeRegistryName:  registry.registry.hostname + "/" + registry.registry.projectID,
					identifiers.AttributeRepository:    repositoryName,
					identifiers.AttributeTag:           tag,
					identifiers.AttributeUseHTTP:       !*registry.registryInfo.IsHTTPS,
					identifiers.AttributeSkipTLSVerify: registry.registryInfo.SkipTLSVerify,
					identifiers.AttributeSensor:        cluster,
				},
			}
			// Check if auth is empty (used for public registries)
			authConfig := registry.authConfig()
			if authConfig != nil {
				registryScanCommand.Credentialslist = append(registryScanCommand.Credentialslist, *authConfig)
			}
			registryScanCMDList = append(registryScanCMDList, &apis.RegistryScanCommand{
				ImageScanParams: *registryScanCommand,
			})
		}
	}

	return registryScanCMDList

}

func (actionHandler *ActionHandler) scanRegistries(ctx context.Context, sessionObj *utils.SessionObj) error {
	ctx, span := otel.Tracer("").Start(ctx, "actionHandler.scanRegistries")
	defer span.End()

	if !actionHandler.components.Kubevuln.Enabled {
		return errors.New("Kubevuln is not enabled")
	}

	registryScan, err := actionHandler.loadRegistryScan(ctx, sessionObj)
	if err != nil {
		logger.L().Ctx(ctx).Error("in parseRegistryCommand", helpers.Error(err))
		sessionObj.Reporter.SetDetails("loadRegistryScan")
		return fmt.Errorf("scanRegistries failed with err %v", err)
	}

	err = registryScan.validateRegistryScanInformation()
	if err != nil {
		logger.L().Ctx(ctx).Error("in parseRegistryCommand", helpers.Error(err))
		sessionObj.Reporter.SetDetails("validateRegistryScanInformation")
		return fmt.Errorf("scanRegistries failed with err %v", err)
	}

	return actionHandler.scanRegistry(ctx, registryScan, sessionObj)
}

func (actionHandler *ActionHandler) loadRegistryScan(ctx context.Context, sessionObj *utils.SessionObj) (*registryScan, error) {
	registryScan := NewRegistryScan(actionHandler.clusterConfig, actionHandler.k8sAPI, actionHandler.eventReceiverRestURL)
	if regName := actionHandler.parseRegistryName(sessionObj); regName != "" {
		registryScan.setRegistryName(regName)
	}

	// for scan triggered by cronjob, we get the secret name
	if sessionObj.Command.CommandName == apis.TypeScanRegistry {
		secretName := actionHandler.parseSecretName(sessionObj)
		registryScan.setSecretName(secretName)
	}

	if err := registryScan.parseRegistry(ctx, sessionObj); err != nil {
		return nil, err
	}

	return &registryScan, nil
}

func (actionHandler *ActionHandler) testRegistryConnectivity(ctx context.Context, sessionObj *utils.SessionObj) error {
	ctx, span := otel.Tracer("").Start(ctx, "actionHandler.testRegistryConnectivity")
	defer span.End()

	if !actionHandler.components.Kubevuln.Enabled {
		return errors.New("Kubevuln is not enabled")
	}

	registryScan, err := actionHandler.loadRegistryScan(ctx, sessionObj)
	if err != nil {
		sessionObj.Reporter.SetDetails("loadRegistryScan")
		logger.L().Ctx(ctx).Error("in testRegistryConnectivity: loadRegistryScan failed", helpers.Error(err))
		return err
	}

	err = registryScan.validateRegistryScanInformation()
	if err != nil {
		sessionObj.Reporter.SetDetails(string(testRegistryInformationStatus))
		logger.L().Ctx(ctx).Error("in testRegistryConnectivity: validateRegistryScanInformation failed", helpers.Error(err))
		return err
	}

	err = actionHandler.testRegistryConnect(ctx, registryScan, sessionObj)
	if err != nil {
		logger.L().Ctx(ctx).Error("in testRegistryConnectivity: testRegistryConnect failed", helpers.Error(err))
		return err
	}

	return nil
}

func (actionHandler *ActionHandler) parseSecretName(sessionObj *utils.SessionObj) string {
	registryInfo, ok := sessionObj.Command.Args[apitypes.RegistryInfoArgKey].(map[string]interface{})
	if !ok {
		return ""
	}
	secretName, _ := registryInfo[secretNameField].(string)
	return secretName
}

func (actionHandler *ActionHandler) parseRegistryName(sessionObj *utils.SessionObj) string {
	registryInfo, ok := sessionObj.Command.Args[apitypes.RegistryInfoArgKey].(map[string]interface{})
	if !ok {
		return ""
	}
	registryName, ok := registryInfo[registryNameField].(string)
	if !ok {
		return ""
	}

	sessionObj.Reporter.SetTarget(fmt.Sprintf("%s: %s", identifiers.AttributeRegistryName,
		registryName))
	sessionObj.Reporter.SendDetails(fmt.Sprintf("registryInfo parsed: %v", registryInfo), actionHandler.sendReport, sessionObj.ErrChan)
	return registryName
}

func (actionHandler *ActionHandler) testRegistryConnect(ctx context.Context, registry *registryScan, sessionObj *utils.SessionObj) error {
	repos, err := registry.enumerateRepos(ctx)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unauthorized") || strings.Contains(strings.ToLower(err.Error()), "DENIED") || strings.Contains(strings.ToLower(err.Error()), "authentication") || strings.Contains(strings.ToLower(err.Error()), "empty token") {
			// registry info is good, but authentication failed
			sessionObj.Reporter.SetDetails(string(testRegistryInformationStatus))
			sessionObj.Reporter.SendStatus(systemreports.JobSuccess, actionHandler.sendReport, sessionObj.ErrChan)
			sessionObj.Reporter.SetDetails(string(testRegistryAuthenticationStatus))
			return fmt.Errorf("failed to retrieve repositories: authentication error: %v", err)
		} else {
			sessionObj.Reporter.SetDetails(string(testRegistryInformationStatus))
			return fmt.Errorf("testRegistryConnect failed with error:  %v", err)
		}
	}

	sessionObj.Reporter.SetDetails(string(testRegistryInformationStatus))
	sessionObj.Reporter.SendStatus(systemreports.JobSuccess, actionHandler.sendReport, sessionObj.ErrChan)
	sessionObj.Reporter.SetDetails(string(testRegistryAuthenticationStatus))
	sessionObj.Reporter.SendStatus(systemreports.JobSuccess, actionHandler.sendReport, sessionObj.ErrChan)

	if len(repos) == 0 {
		sessionObj.Reporter.SetDetails(fmt.Sprintf("%v failed with err %v", testRegistryRetrieveReposStatus, err))
		return fmt.Errorf("failed to retrieve repositories: got empty list of repositories")
	}

	sessionObj.Reporter.SetDetails(string(testRegistryRetrieveReposStatus))
	sessionObj.Reporter.SendStatus(systemreports.JobSuccess, actionHandler.sendReport, sessionObj.ErrChan)

	// check that we can pull tags. One is enough
	if len(repos) > 0 {
		reposToTags := make(chan map[string][]string, 1)
		if err := registry.setImageToTagsMap(ctx, repos[0], sessionObj.Reporter, reposToTags); err != nil {
			sessionObj.Reporter.SetDetails(string(testRegistryRetrieveTagsStatus))
			return fmt.Errorf("setImageToTagsMap failed with err %v", err)
		}
	}

	sessionObj.Reporter.SetDetails(string(testRegistryRetrieveTagsStatus))
	sessionObj.Reporter.SendStatus(systemreports.JobSuccess, actionHandler.sendReport, sessionObj.ErrChan)

	var repositories []apitypes.Repository
	for _, repo := range repos {
		repositories = append(repositories, apitypes.Repository{
			RepositoryName: repo,
		})
	}

	params := RepositoriesAndTagsParams{
		RegistryName: registry.registryInfo.RegistryName,
		CustomerGUID: sessionObj.Reporter.GetCustomerGUID(),
		JobID:        sessionObj.Reporter.GetJobID(),
		Repositories: repositories,
	}

	err = registry.SendRepositoriesAndTags(params)
	if err != nil {
		return err
	}
	return nil
}

func (actionHandler *ActionHandler) scanRegistry(ctx context.Context, registry *registryScan, sessionObj *utils.SessionObj) error {
	err := registry.getImagesForScanning(ctx, actionHandler.reporter)
	if err != nil {
		return fmt.Errorf("GetImagesForScanning failed with err %v", err)
	}
	registryScanCMDList := convertImagesToRegistryScanCommand(actionHandler.clusterConfig.ClusterName, registry, sessionObj)
	sessionObj.Reporter.SendDetails(fmt.Sprintf("sending %d images from registry %v to vuln scan", len(registryScanCMDList), registry.registry), actionHandler.sendReport, sessionObj.ErrChan)

	return sendAllImagesToRegistryScan(ctx, actionHandler.clusterConfig, registryScanCMDList)
}

func (actionHandler *ActionHandler) scanWorkload(ctx context.Context, sessionObj *utils.SessionObj) error {
	ctx, span := otel.Tracer("").Start(ctx, "actionHandler.scanWorkload")
	defer span.End()

	if !actionHandler.components.Kubevuln.Enabled {
		return errors.New("Kubevuln is not enabled")
	}

	span.AddEvent("scanning", trace.WithAttributes(attribute.String("wlid", actionHandler.wlid)))

	workload, err := actionHandler.k8sAPI.GetWorkloadByWlid(actionHandler.wlid)
	if err != nil {
		return fmt.Errorf("failed to get workload %s with err %v", actionHandler.wlid, err)
	}

	if workload.GetKind() == "CronJob" {
		logger.L().Ctx(ctx).Debug("workload is CronJob, skipping")
		return nil
	}

	pod, err := actionHandler.getPodByWLID(workload)
	if err != nil {
		err = fmt.Errorf("failed to get container to image ID map for workload %s with err %v", actionHandler.wlid, err)
		logger.L().Ctx(ctx).Error(err.Error())
		return err
	}

	// get container to imageID map
	var mapContainerToImageID map[string]string // map of container name to image ID. Container name is unique per pod

	// look for container to imageID map in the command args. If not found, look for it on Pod
	if val, ok := actionHandler.command.Args[utils.ContainerToImageIdsArg].(map[string]string); !ok {
		mapContainerToImageID = actionHandler.getContainerToImageIDsFromWorkload(pod)
	} else {
		// get from args
		mapContainerToImageID = val
	}

	if len(mapContainerToImageID) == 0 {
		logger.L().Debug(fmt.Sprintf("workload %s has no running containers, skipping", actionHandler.wlid))
		return nil
	}

	// get pod instanceID
	// logger.L().Debug(pod.GetOwnerReferences(), pod.Spec.Containers, , pod.GetNamespace(), pod.Kind, pod.GetName())
	instanceIDs, err := instanceidhandler.GenerateInstanceIDFromPod(pod)
	if err != nil {
		return fmt.Errorf("failed to get instanceID for pod '%s' of workload '%s' err '%v'", pod.GetName(), workload.GetID(), err)
	}

	// get all images of workload
	containers, err := listWorkloadImages(workload, instanceIDs)
	if err != nil {
		return fmt.Errorf("failed to get workloads from k8s, wlid: %s, reason: %s", actionHandler.wlid, err.Error())
	}

	return actionHandler.sendCommandForContainers(ctx, containers, mapContainerToImageID, pod, sessionObj, apis.TypeScanImages)
}

func prepareSessionChain(sessionObj *utils.SessionObj, websocketScanCommand *apis.WebsocketScanCommand, actionHandler *ActionHandler) {
	sessionParentJobId := sessionObj.Reporter.GetParentAction()
	if sessionParentJobId != "" {
		websocketScanCommand.Session.JobIDs = append(websocketScanCommand.Session.JobIDs, sessionParentJobId)
		websocketScanCommand.Session.RootJobID = sessionParentJobId
	}
	sessionJobID := sessionObj.Reporter.GetJobID()
	if websocketScanCommand.Session.RootJobID == "" {
		websocketScanCommand.Session.RootJobID = sessionJobID
	}
	websocketScanCommand.Session.JobIDs = append(websocketScanCommand.Session.JobIDs, sessionJobID)

	if actionHandler.reporter.GetParentAction() != "" && !slices.Contains(websocketScanCommand.Session.JobIDs, actionHandler.reporter.GetParentAction()) {
		websocketScanCommand.Session.JobIDs = append(websocketScanCommand.Session.JobIDs, actionHandler.reporter.GetParentAction())
	}

	if actionHandler.reporter.GetJobID() != "" && !slices.Contains(websocketScanCommand.Session.JobIDs, actionHandler.reporter.GetJobID()) {
		websocketScanCommand.Session.JobIDs = append(websocketScanCommand.Session.JobIDs, actionHandler.reporter.GetJobID())
	}

	websocketScanCommand.ParentJobID = actionHandler.reporter.GetJobID()
	websocketScanCommand.LastAction = actionHandler.reporter.GetActionIDN()
	websocketScanCommand.SetJobID(uuid.NewString())
	websocketScanCommand.Session.JobIDs = append(websocketScanCommand.Session.JobIDs, websocketScanCommand.GetJobID())
}

// send workload to the kubevuln with credentials
func sendWorkloadWithCredentials(ctx context.Context, scanUrl *url.URL, command apis.ImageScanCommand) error {
	jsonScannerC, err := json.Marshal(command)

	// TODO(dwertent,vladklokun): get instance ID in a more elegant way
	imageScanCommand, ok := command.(*apis.WebsocketScanCommand)
	instanceID := "NOT_A_WEBSOCKET_SCAN_COMMAND"
	if !ok {
		logger.L().Ctx(ctx).Debug("Not an image scan command")
	} else {
		instanceID = *imageScanCommand.InstanceID
	}

	if err != nil {
		return fmt.Errorf("failed to marshal websocketScanCommand with err %v", err)
	}
	if command.GetWlid() == "" {
		logger.L().Ctx(ctx).Debug(fmt.Sprintf("sending scan command to kubevuln: %s", string(jsonScannerC)))
	}

	creds := command.GetCreds()
	credsList := command.GetCredentialsList()
	hasCreds := creds != nil && len(creds.Username) > 0 && len(creds.Password) > 0 || len(credsList) > 0
	logger.L().Info("scan request", helpers.String("url", scanUrl.String()), helpers.String("wlid", command.GetWlid()), helpers.String("instanceID", instanceID), helpers.String("imageTag", command.GetImageTag()), helpers.String("imageHash", command.GetImageHash()), helpers.Interface("credentials", hasCreds))

	resp, err := httputils.HttpPost(VulnScanHttpClient, scanUrl.String(), map[string]string{"Content-Type": "application/json"}, jsonScannerC)
	refusedNum := 0
	for ; refusedNum < 5 && err != nil && strings.Contains(err.Error(), "connection refused"); resp, err = httputils.HttpPost(VulnScanHttpClient, scanUrl.String(), map[string]string{"Content-Type": "application/json"}, jsonScannerC) {
		logger.L().Ctx(ctx).Error("failed posting to vulnerability scanner", helpers.String("query", command.GetImageTag()), helpers.Error(err))
		time.Sleep(5 * time.Second)
		refusedNum++
	}
	if err != nil {
		return fmt.Errorf("failed posting to vulnerability scanner. query: '%s', reason: %s", command.GetImageTag(), err.Error())
	}
	if resp == nil {
		return fmt.Errorf("failed posting to vulnerability scanner. query: '%s', reason: 'empty response'", command.GetImageTag())
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	if resp.StatusCode < 200 || resp.StatusCode > 203 {
		return fmt.Errorf("failed posting to vulnerability scanner. query: '%s', reason: 'received bad status code: %d'", command.GetImageTag(), resp.StatusCode)
	}
	return nil

}

func sendWorkloadToRegistryScan(ctx context.Context, clusterConfig utilsmetadata.ClusterConfig, registryScanCommand *apis.RegistryScanCommand) error {
	return sendWorkloadWithCredentials(ctx, getRegistryScanURL(clusterConfig), registryScanCommand)
}

func sendWorkloadToCVEScan(ctx context.Context, clusterConfig utilsmetadata.ClusterConfig, websocketScanCommand *apis.WebsocketScanCommand) error {
	return sendWorkloadWithCredentials(ctx, getVulnScanURL(clusterConfig), websocketScanCommand)
}

func (actionHandler *ActionHandler) getPodByWLID(workload k8sinterface.IWorkload) (*corev1.Pod, error) {
	// if the workload is a pod, we can get the pod directly by parsing the workload
	if workload.GetKind() == "Pod" {
		pod := &corev1.Pod{}
		w, err := json.Marshal(workload.GetObject())
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(w, pod); err != nil {
			return nil, err
		}

		// set the api version and kind to be pod - this is needed for the the resourceID
		pod.APIVersion = "v1"
		pod.Kind = "Pod"

		return pod, nil
	}

	// we need to find the pod that is owned by the workload
	// we iterate over all the pods with the same labels as the workload until we find one pod that is owned by the workload
	labels := workload.GetPodLabels()
	pods, err := actionHandler.k8sAPI.ListPods(workload.GetNamespace(), labels)
	if err != nil {
		return nil, fmt.Errorf("failed listing pods for workload %s", workload.GetName())
	}

	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("no pods found for workload %s", workload.GetName())
	}

	for i := range pods.Items {

		// set the api version and kind to be pod - this is needed for the the resourceID
		// we need to do this because this is missing when listing pods
		pods.Items[i].APIVersion = "v1"
		pods.Items[i].Kind = "Pod"

		podMarshalled, err := json.Marshal(pods.Items[i])
		if err != nil {
			return nil, err
		}

		wl, err := workloadinterface.NewWorkload(podMarshalled)
		if err != nil {
			continue
		}

		kind, name, err := actionHandler.k8sAPI.CalculateWorkloadParentRecursive(wl)
		if err != nil {
			return nil, err
		}

		if kind == workload.GetKind() && name == workload.GetName() {
			return &pods.Items[i], nil
		}
	}

	return nil, fmt.Errorf("could not get Pod of workload: %s, kind: %s, namespace: %s", workload.GetName(), workload.GetKind(), workload.GetNamespace())
}

// get a workload, retrieves its pod and returns a map of container name to image id
func (actionHandler *ActionHandler) getContainerToImageIDsFromWorkload(pod *corev1.Pod) map[string]string {
	var mapContainerToImageID = make(map[string]string)

	for _, containerStatus := range pod.Status.ContainerStatuses {
		if containerStatus.State.Running != nil {
			imageID := containerStatus.ImageID
			mapContainerToImageID[containerStatus.Name] = utils.ExtractImageID(imageID)
		}
	}

	return mapContainerToImageID
}

func (actionHandler *ActionHandler) getCommand(container ContainerData, pod *corev1.Pod, imageID string, sessionObj *utils.SessionObj, command apis.NotificationPolicyType, containerRegistryAuths []registryAuth) (*apis.WebsocketScanCommand, error) {
	websocketScanCommand := &apis.WebsocketScanCommand{
		ImageScanParams: apis.ImageScanParams{
			Session:  apis.SessionChain{ActionTitle: string(command), JobIDs: make([]string, 0), Timestamp: sessionObj.Reporter.GetTimestamp()},
			ImageTag: container.image,
			JobID:    sessionObj.Reporter.GetJobID(),
		},
		Wlid:          actionHandler.wlid,
		ContainerName: container.container,
		ImageHash:     utils.ExtractImageID(imageID),
	}

	// Add instanceID only if container is not empty
	if container.id != "" {
		websocketScanCommand.InstanceID = &container.id
	}
	if actionHandler.reporter != nil {
		prepareSessionChain(sessionObj, websocketScanCommand, actionHandler)
	}

	if pod != nil {
		secrets, err := cloudsupport.GetImageRegistryCredentials(websocketScanCommand.ImageTag, pod)
		if err != nil {
			return nil, err
		} else if len(secrets) > 0 {
			for secretName := range secrets {
				websocketScanCommand.ImageScanParams.Credentialslist = append(websocketScanCommand.Credentialslist, secrets[secretName])
			}

			/*
				the websocketScanCommand.Credentials is deprecated, still use it for backward computability
			*/
			if len(websocketScanCommand.Credentialslist) != 0 {
				websocketScanCommand.Credentials = &websocketScanCommand.Credentialslist[0]
			}
		}
	}

	// add relevant credentials if exist in the registry scan secrets
	for _, creds := range containerRegistryAuths {
		if strings.Contains(websocketScanCommand.ImageTag, creds.Registry) && creds.Password != "" {
			logger.L().Debug(fmt.Sprintf("found registry scan secret for image: %s", websocketScanCommand.ImageTag), helpers.String("ImageTag", websocketScanCommand.ImageTag))
			websocketScanCommand.Credentialslist = append(websocketScanCommand.Credentialslist, types.AuthConfig{ServerAddress: creds.Registry, Username: creds.Username, Password: creds.Password})
		}
	}

	return websocketScanCommand, nil
}

func (actionHandler *ActionHandler) sendCommandForContainers(ctx context.Context, containers []ContainerData, mapContainerToImageID map[string]string, pod *corev1.Pod, sessionObj *utils.SessionObj, command apis.NotificationPolicyType) error {
	errs := ""

	// we build a list of all registry scan secrets
	containerRegistryAuths := []registryAuth{}
	if secrets, err := getRegistryScanSecrets(actionHandler.k8sAPI, ""); err == nil && len(secrets) > 0 {
		for i := range secrets {
			if auths, err := parseRegistryAuthSecret(secrets[i]); err == nil {
				containerRegistryAuths = append(containerRegistryAuths, auths...)
			}
		}
	}

	for i := range containers {
		imgID := ""
		if val, ok := mapContainerToImageID[containers[i].container]; !ok {
			logger.L().Ctx(ctx).Debug("container %s is not running, skipping", helpers.String("container", containers[i].container))
			continue
		} else {
			imgID = val
		}

		// some images don't have imageID prefix, we will add it for them
		imgID = getImageIDFromContainer(containers[i], imgID)
		websocketScanCommand, err := actionHandler.getCommand(containers[i], pod, imgID, sessionObj, command, containerRegistryAuths)
		if err != nil {
			errs += err.Error()
			logger.L().Error("failed to get command", helpers.String("image", containers[i].image), helpers.Error(err))
			continue
		}
		logger.L().Ctx(ctx).Debug("sending scan command", helpers.String("id", containers[i].id), helpers.String("image", containers[i].image), helpers.String("container", containers[i].container))

		if err := sendCommandToScanner(ctx, actionHandler.clusterConfig, websocketScanCommand, command); err != nil {
			errs += err.Error()
			logger.L().Error("scanning failed", helpers.String("image", websocketScanCommand.ImageTag), helpers.Error(err))
		}
	}

	if errs != "" {
		return fmt.Errorf(errs)
	}

	return nil
}

func sendCommandToScanner(ctx context.Context, clusterConfig utilsmetadata.ClusterConfig, webSocketScanCommand *apis.WebsocketScanCommand, command apis.NotificationPolicyType) error {
	var err error
	switch command {
	case apis.TypeScanImages:
		err = sendWorkloadToCVEScan(ctx, clusterConfig, webSocketScanCommand)
	default:
		err = fmt.Errorf("unknown command: %s", command)
	}
	return err
}

func getImageIDFromContainer(container ContainerData, imageID string) string {
	if strings.HasPrefix(imageID, "sha256") {
		imageID = container.image + "@" + imageID
	}
	return imageID
}
