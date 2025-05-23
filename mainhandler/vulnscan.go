package mainhandler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/armosec/registryx/common"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/armosec/armoapi-go/apis"
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/armosec/registryx/interfaces"
	"github.com/armosec/registryx/registryclients"
	"github.com/armosec/utils-go/httputils"
	"github.com/armosec/utils-k8s-go/armometadata"
	"github.com/distribution/reference"
	dockerregistry "github.com/docker/docker/api/types/registry"
	"github.com/google/uuid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/cloudsupport"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/strings/slices"
)

func getAPScanURL(config config.IConfig) *url.URL {
	return &url.URL{
		Scheme: "http",
		Host:   config.KubevulnURL(),
		Path:   fmt.Sprintf("%s/%s", apis.VulnerabilityScanCommandVersion, apis.ApplicationProfileScanCommandPath),
	}
}

const noImagesToScanError = "no images to scan"

func getVulnScanURL(config config.IConfig) *url.URL {
	return &url.URL{
		Scheme: "http",
		Host:   config.KubevulnURL(),
		Path:   fmt.Sprintf("%s/%s", apis.VulnerabilityScanCommandVersion, apis.ContainerScanCommandPath),
	}
}

func getRegistryScanURL(config config.IConfig) *url.URL {
	return &url.URL{
		Scheme: "http",
		Host:   config.KubevulnURL(),
		Path:   fmt.Sprintf("%s/%s", apis.VulnerabilityScanCommandVersion, apis.RegistryScanCommandPath),
	}
}

// ==========================================================================================================================
// ======================================== Registry scanning ===============================================================
// ==========================================================================================================================
func sendAllImagesToRegistryScan(ctx context.Context, config config.IConfig, registryScanCMDList []*apis.RegistryScanCommand) error {
	var err error
	errs := make([]error, 0)
	for _, registryScanCMD := range registryScanCMDList {
		err = sendWorkloadToRegistryScan(ctx, config, registryScanCMD)
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

func (actionHandler *ActionHandler) scanRegistriesV2AndUpdateStatus(ctx context.Context) error {
	ctx, span := otel.Tracer("").Start(ctx, "actionHandler.scanRegistriesV2")
	defer span.End()

	if !actionHandler.config.Components().Kubevuln.Enabled {
		return errors.New("kubevuln is not enabled")
	}

	scanTime := time.Now()
	imageRegistry, err := actionHandler.loadRegistryFromSessionObj()
	if err != nil {
		return fmt.Errorf("failed to load registry from sessionObj: %w", err)
	}

	err = actionHandler.scanRegistriesV2(ctx, imageRegistry)
	if err != nil {
		if err.Error() == noImagesToScanError { // nothing to scan
			actionHandler.exporter.SendRegistryStatus(imageRegistry.GetBase().GUID, apitypes.Completed, "", scanTime)
			return nil
		}
		actionHandler.exporter.SendRegistryStatus(imageRegistry.GetBase().GUID, apitypes.Failed, err.Error(), scanTime)
		return err
	}

	actionHandler.exporter.SendRegistryStatus(imageRegistry.GetBase().GUID, apitypes.InProgress, "", scanTime)
	return nil
}

func (actionHandler *ActionHandler) scanRegistriesV2(ctx context.Context, imageRegistry apitypes.ContainerImageRegistry) error {
	if err := actionHandler.loadRegistrySecret(ctx, imageRegistry); err != nil {
		return fmt.Errorf("failed to load secret: %w", err)
	}

	options := &common.RegistryOptions{}
	options = options.WithSkipTLSVerify(
		actionHandler.config.RegistryScanningSkipTlsVerify()).
		WithInsecure(actionHandler.config.RegistryScanningInsecure())
	client, err := registryclients.GetRegistryClient(imageRegistry, options)
	if err != nil {
		return fmt.Errorf("failed to get registry client: %w", err)
	}

	images, err := client.GetImagesToScan(ctx)
	if err != nil {
		return fmt.Errorf("failed to get registry images to scan: %w", err)
	} else if len(images) == 0 {
		return errors.New(noImagesToScanError)
	}

	registryScanCMDList, err := actionHandler.getRegistryImageScanCommands(client, imageRegistry, images)
	if err != nil {
		return fmt.Errorf("failed to get registry images scan commands: %w", err)
	}
	if err = sendAllImagesToRegistryScan(ctx, actionHandler.config, registryScanCMDList); err != nil {
		return fmt.Errorf("failed to send scan commands: %w", err)
	}

	return nil
}

func (actionHandler *ActionHandler) loadRegistrySecret(ctx context.Context, imageRegistry apitypes.ContainerImageRegistry) error {
	secretName := actionHandler.sessionObj.Command.Args[apitypes.RegistrySecretNameArgKey].(string)
	secret, err := actionHandler.k8sAPI.KubernetesClient.CoreV1().Secrets(actionHandler.config.Namespace()).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("loadRegistrySecret failed to get secret: %w", err)
	}

	var secretMap map[string]interface{}
	err = json.Unmarshal(secret.Data[apitypes.RegistryAuthFieldInSecret], &secretMap)
	if err != nil {
		return fmt.Errorf("loadRegistrySecret failed to unmarshal registry secret: %w", err)
	}
	err = imageRegistry.FillSecret(secretMap)
	if err != nil {
		return fmt.Errorf("loadRegistrySecret failed to fill registry secret: %w", err)
	}
	return nil
}

func (actionHandler *ActionHandler) loadRegistryFromSessionObj() (apitypes.ContainerImageRegistry, error) {
	regInfo := actionHandler.sessionObj.Command.Args[apitypes.RegistryInfoArgKey].(map[string]interface{})
	regInfoBytes, err := json.Marshal(regInfo)
	if err != nil {
		return nil, fmt.Errorf("scanRegistriesV2 failed to marshal command arg: %w", err)
	}
	imageRegistry, err := apitypes.UnmarshalRegistry(regInfoBytes)
	if err != nil {
		return nil, fmt.Errorf("scanRegistriesV2 failed to unmarshal command: %w", err)
	}
	return imageRegistry, nil
}

func (actionHandler *ActionHandler) getRegistryImageScanCommands(client interfaces.RegistryClient, imageRegistry apitypes.ContainerImageRegistry, images map[string]string) ([]*apis.RegistryScanCommand, error) {
	scanID := uuid.NewString()
	imagesCount := len(images)
	registryScanCMDList := make([]*apis.RegistryScanCommand, 0, imagesCount)
	for image, tag := range images {
		repository := image
		parts := strings.SplitN(image, "/", 2)
		if len(parts) > 1 {
			repository = parts[1]
		}
		registryScanCommand := &apis.ImageScanParams{
			ParentJobID: actionHandler.sessionObj.JobID,
			JobID:       uuid.NewString(),
			ImageTag:    image + ":" + tag,
			Session:     apis.SessionChain{ActionTitle: "vulnerability-scan", JobIDs: make([]string, 0), Timestamp: actionHandler.sessionObj.Timestamp},
			Args: map[string]interface{}{
				identifiers.AttributeRegistryName:            imageRegistry.GetDisplayName(),
				identifiers.AttributeRepository:              repository,
				identifiers.AttributeTag:                     tag,
				identifiers.AttributeUseHTTP:                 actionHandler.config.RegistryScanningInsecure(),
				identifiers.AttributeSkipTLSVerify:           actionHandler.config.RegistryScanningSkipTlsVerify(),
				identifiers.AttributeSensor:                  imageRegistry.GetBase().ClusterName,
				identifiers.AttributeRegistryID:              imageRegistry.GetBase().GUID,
				identifiers.AttributeRegistryScanID:          scanID,
				identifiers.AttributeRegistryScanImagesCount: strconv.Itoa(imagesCount),
			},
		}
		auth, err := client.GetDockerAuth()
		if err != nil {
			return nil, fmt.Errorf("failed to get docker auth: %w", err)
		}
		registryScanCommand.Credentialslist = append(registryScanCommand.Credentialslist, *auth)
		registryScanCMDList = append(registryScanCMDList, &apis.RegistryScanCommand{
			ImageScanParams: *registryScanCommand,
		})
	}
	return registryScanCMDList, nil
}

func (actionHandler *ActionHandler) scanImage(ctx context.Context) error {
	ctx, span := otel.Tracer("").Start(ctx, "actionHandler.scanImage")
	defer span.End()

	if !actionHandler.config.Components().Kubevuln.Enabled {
		return errors.New("kubevuln is not enabled")
	}

	pod, _ := actionHandler.sessionObj.Command.Args[utils.ArgsPod].(*corev1.Pod)

	containerData, ok := actionHandler.sessionObj.Command.Args[utils.ArgsContainerData].(*utils.ContainerData)
	if !ok {
		return fmt.Errorf("failed to get container for image %s", actionHandler.sessionObj.Command.Args[utils.ArgsContainerData])
	}

	imageScanConfig, err := getImageScanConfig(actionHandler.k8sAPI, actionHandler.config.Namespace(), pod, containerData.ImageTag)
	if err != nil {
		return fmt.Errorf("failed to get auth config for image %s", containerData.ImageTag)
	}

	span.AddEvent("scanning", trace.WithAttributes(attribute.String("wlid", actionHandler.wlid)))
	cmd := actionHandler.getImageScanCommand(containerData, imageScanConfig)

	if err := sendCommandToScanner(ctx, actionHandler.config, cmd, actionHandler.sessionObj.Command.CommandName); err != nil {
		return fmt.Errorf("failed to send command to scanner: %w", err)
	}
	return nil
}

func (actionHandler *ActionHandler) scanApplicationProfile(ctx context.Context) error {
	ctx, span := otel.Tracer("").Start(ctx, "actionHandler.scanApplicationProfile")
	defer span.End()

	if !actionHandler.config.Components().Kubevuln.Enabled {
		return errors.New("kubevuln is not enabled")
	}

	// get the pod from the session object
	pod, _ := actionHandler.sessionObj.Command.Args[utils.ArgsPod].(*corev1.Pod)

	var authConfigs []dockerregistry.AuthConfig
	if pod != nil {
		// build a list of secrets from the registry secrets
		secrets, err := cloudsupport.GetImageRegistryCredentials(actionHandler.k8sAPI, "", pod)
		if err != nil {
			return fmt.Errorf("failed to get registry credentials: %w", err)
		}
		for i := range secrets {
			authConfigs = append(authConfigs, secrets[i]...)
		}
	}

	span.AddEvent("scanning", trace.WithAttributes(attribute.String("wlid", actionHandler.wlid)))
	cmd := &apis.WebsocketScanCommand{
		Wlid: actionHandler.wlid,
		ImageScanParams: apis.ImageScanParams{
			Args: map[string]interface{}{
				"name":      actionHandler.sessionObj.Command.Args[utils.ArgsName],
				"namespace": actionHandler.sessionObj.Command.Args[utils.ArgsNamespace],
			},
			Credentialslist: authConfigs,
		},
	}

	prepareSessionChain(actionHandler.sessionObj, cmd, actionHandler)

	if err := sendCommandToScanner(ctx, actionHandler.config, cmd, apis.TypeScanApplicationProfile); err != nil {
		return fmt.Errorf("failed to send command to scanner: %w", err)
	}
	return nil
}

func (actionHandler *ActionHandler) getImageScanCommand(containerData *utils.ContainerData, imageScanConfig *ImageScanConfig) *apis.WebsocketScanCommand {
	cmd := &apis.WebsocketScanCommand{
		ImageScanParams: apis.ImageScanParams{
			Session: apis.SessionChain{
				ActionTitle: string(actionHandler.sessionObj.Command.CommandName),
				JobIDs:      make([]string, 0),
				Timestamp:   actionHandler.sessionObj.Timestamp,
			},
			Args:            map[string]interface{}{},
			ImageTag:        containerData.ImageTag,
			Credentialslist: imageScanConfig.authConfigs,
			JobID:           actionHandler.sessionObj.JobID,
		},
		Wlid:          containerData.Wlid,
		ContainerName: containerData.ContainerName,
		ImageHash:     containerData.ImageID,
	}

	if imageScanConfig.skipTLSVerify != nil && *imageScanConfig.skipTLSVerify {
		logger.L().Debug("setting skipTLSVerify (true) in image scan command", helpers.String("imageTag", containerData.ImageTag))
		cmd.Args[identifiers.AttributeSkipTLSVerify] = true
	}

	if imageScanConfig.insecure != nil && *imageScanConfig.insecure {
		logger.L().Debug("setting insecure (true) in image scan command", helpers.String("imageTag", containerData.ImageTag))
		cmd.Args[identifiers.AttributeUseHTTP] = true
	}

	// Add instanceID only if container is not empty
	if containerData.Slug != "" {
		cmd.InstanceID = &containerData.Slug
	}

	prepareSessionChain(actionHandler.sessionObj, cmd, actionHandler)

	return cmd
}

type ImageScanConfig struct {
	skipTLSVerify *bool
	insecure      *bool
	authConfigs   []dockerregistry.AuthConfig
}

func getImageScanConfig(k8sAPI *k8sinterface.KubernetesApi, namespace string, pod *corev1.Pod, imageTag string) (*ImageScanConfig, error) {
	imageScanConfig := ImageScanConfig{}
	registryName := getRegistryNameFromImageTag(imageTag)
	logger.L().Debug("parsed registry name from image tag", helpers.String("registryName", registryName), helpers.String("imageTag", imageTag))

	// build a list of secrets from the ImagePullSecrets
	if secrets, err := getRegistryScanSecrets(k8sAPI, namespace, ""); err == nil && len(secrets) > 0 {
		for i := range secrets {
			if auth, err := parseRegistryAuthSecret(secrets[i]); err == nil {
				for _, authConfig := range auth {
					// if we have a registry name and it matches the current registry, check if we need to skip TLS verification
					if registryName != "" && containsIgnoreCase(authConfig.Registry, registryName) {
						imageScanConfig.skipTLSVerify = authConfig.SkipTLSVerify
						imageScanConfig.insecure = authConfig.Insecure
					}

					imageScanConfig.authConfigs = append(imageScanConfig.authConfigs, dockerregistry.AuthConfig{
						Username:      authConfig.Username,
						Password:      authConfig.Password,
						ServerAddress: authConfig.Registry,
					})
				}
			}
		}
	}

	if pod != nil {
		// TODO: this should not happen every scan
		// build a list of secrets from the registry secrets
		secrets, err := cloudsupport.GetImageRegistryCredentials(k8sAPI, imageTag, pod)
		if err != nil {
			return nil, err
		}
		for i := range secrets {
			imageScanConfig.authConfigs = append(imageScanConfig.authConfigs, secrets[i]...)
		}
	}

	return &imageScanConfig, nil
}

func prepareSessionChain(sessionObj *utils.SessionObj, websocketScanCommand *apis.WebsocketScanCommand, actionHandler *ActionHandler) {
	sessionParentJobId := sessionObj.ParentJobID
	if sessionParentJobId != "" {
		websocketScanCommand.Session.JobIDs = append(websocketScanCommand.Session.JobIDs, sessionParentJobId)
		websocketScanCommand.Session.RootJobID = sessionParentJobId
	}
	sessionJobID := sessionObj.JobID
	if websocketScanCommand.Session.RootJobID == "" {
		websocketScanCommand.Session.RootJobID = sessionJobID
	}
	websocketScanCommand.Session.JobIDs = append(websocketScanCommand.Session.JobIDs, sessionJobID)

	if actionHandler.sessionObj.ParentJobID != "" && !slices.Contains(websocketScanCommand.Session.JobIDs, actionHandler.sessionObj.ParentJobID) {
		websocketScanCommand.Session.JobIDs = append(websocketScanCommand.Session.JobIDs, actionHandler.sessionObj.ParentJobID)
	}

	if actionHandler.sessionObj.JobID != "" && !slices.Contains(websocketScanCommand.Session.JobIDs, actionHandler.sessionObj.JobID) {
		websocketScanCommand.Session.JobIDs = append(websocketScanCommand.Session.JobIDs, actionHandler.sessionObj.JobID)
	}

	websocketScanCommand.ParentJobID = actionHandler.sessionObj.JobID
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
		logger.L().Debug("Not an image scan command")
	} else {
		if imageScanCommand.InstanceID != nil {
			instanceID = *imageScanCommand.InstanceID
		}
	}

	if err != nil {
		return fmt.Errorf("failed to marshal websocketScanCommand: %w", err)
	}
	if command.GetWlid() == "" {
		logger.L().Debug(fmt.Sprintf("sending scan command to kubevuln: %s", string(jsonScannerC)))
	}

	creds := command.GetCreds()
	credsList := command.GetCredentialsList()
	hasCreds := creds != nil && len(creds.Username) > 0 && len(creds.Password) > 0 || len(credsList) > 0
	logger.L().Debug("scan request", helpers.String("url", scanUrl.String()), helpers.String("wlid", command.GetWlid()), helpers.String("instanceID", instanceID), helpers.String("imageTag", command.GetImageTag()), helpers.String("imageHash", command.GetImageHash()), helpers.Interface("credentials", hasCreds))

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

func sendWorkloadToRegistryScan(ctx context.Context, config config.IConfig, registryScanCommand *apis.RegistryScanCommand) error {
	return sendWorkloadWithCredentials(ctx, getRegistryScanURL(config), registryScanCommand)
}

func sendWorkloadToAPScan(ctx context.Context, config config.IConfig, websocketScanCommand *apis.WebsocketScanCommand) error {
	return sendWorkloadWithCredentials(ctx, getAPScanURL(config), websocketScanCommand)
}

func sendWorkloadToCVEScan(ctx context.Context, config config.IConfig, websocketScanCommand *apis.WebsocketScanCommand) error {
	return sendWorkloadWithCredentials(ctx, getVulnScanURL(config), websocketScanCommand)
}

func sendCommandToScanner(ctx context.Context, config config.IConfig, webSocketScanCommand *apis.WebsocketScanCommand, command apis.NotificationPolicyType) error {
	var err error
	switch command {
	case apis.TypeScanApplicationProfile:
		err = sendWorkloadToAPScan(ctx, config, webSocketScanCommand)
	case apis.TypeScanImages:
		err = sendWorkloadToCVEScan(ctx, config, webSocketScanCommand)
	default:
		err = fmt.Errorf("unknown command: %s", command)
	}
	return err
}

func normalizeReference(ref string) string {
	n, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return ref
	}
	return n.String()
}

func getRegistryNameFromImageTag(imageTag string) string {
	imageTagNormalized := normalizeReference(imageTag)
	imageInfo, err := armometadata.ImageTagToImageInfo(imageTagNormalized)
	if err != nil {
		return ""
	}
	return imageInfo.Registry
}

// containsIgnoreCase reports whether substr is within s (ignoring case)
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
