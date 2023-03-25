package utils

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/utils-go/httputils"
	"github.com/google/uuid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	core1 "k8s.io/api/core/v1"
)

const KubescapeScanV1 = "scanV1"
const KubescapeRequestPathV1 = "v1/scan"
const KubescapeRequestStatusV1 = "v1/status"
const ContainerToImageIdsArg = "containerToImageIDs"
const dockerPullableURN = "docker-pullable://"

func MapToString(m map[string]interface{}) []string {
	s := []string{}
	for i := range m {
		s = append(s, i)
	}
	return s
}

type ClientMock struct {
}

func (c *ClientMock) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
		Body:       http.NoBody}, nil
}

func InitKubescapeHttpClient() httputils.IHttpClient {
	// If the KubescapeURL not configured, then the HttpClient defined as a mock
	if ClusterConfig.KubescapeURL == "" {
		return &ClientMock{}
	}
	return &http.Client{}
}
func InitVulnScanHttpClient() httputils.IHttpClient {
	// If the VulnScan URL not configured, then the HttpClient defined as a mock
	if ClusterConfig.KubevulnURL == "" {
		return &ClientMock{}
	}
	return &http.Client{}
}
func InitReporterHttpClient() httputils.IHttpClient {
	// If the EventReceiverREST not configured, then the HttpClient defined as a mock
	if ClusterConfig.EventReceiverRestURL == "" {
		return &ClientMock{}
	}
	return &http.Client{}
}

func ExtractImageID(imageID string) string {
	return strings.TrimPrefix(imageID, dockerPullableURN)
}

func GenerateInstanceID(parentApiVersion, namespace, kind, name, resourceVersion, containerName string) string {
	instanceID := fmt.Sprintf("apiVersion-%s/namespace-%s/kind-%s/name-%s/resourceVersion-%s/container-%s", parentApiVersion, namespace, kind, name, resourceVersion, containerName)
	return strings.ToLower(instanceID)
}
func AddCommandToChannel(ctx context.Context, cmd *apis.Command, channel *chan SessionObj) {
	logger.L().Ctx(ctx).Info("Triggering scan for", helpers.String("wlid", cmd.Wlid), helpers.String("command", fmt.Sprintf("%v", cmd.CommandName)), helpers.String("args", fmt.Sprintf("%v", cmd.Args)))
	newSessionObj := NewSessionObj(ctx, cmd, "Websocket", "", uuid.NewString(), 1)
	*channel <- *newSessionObj
}

func ExtractContainersToImageIDsFromPod(pod *core1.Pod) map[string]string {
	containersToImageIDs := make(map[string]string)
	for _, containerStatus := range pod.Status.ContainerStatuses {
		if containerStatus.State.Running != nil {
			imageID := ExtractImageID(containerStatus.ImageID)
			containersToImageIDs[containerStatus.Name] = imageID
		}
	}

	for _, containerStatus := range pod.Status.InitContainerStatuses {
		if containerStatus.State.Running != nil {
			imageID := ExtractImageID(containerStatus.ImageID)
			containersToImageIDs[containerStatus.Name] = imageID
		}
	}

	return containersToImageIDs
}
