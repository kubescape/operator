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
	"github.com/kubescape/operator/config"
	"github.com/panjf2000/ants/v2"
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

func InitHttpClient(url string) httputils.IHttpClient {
	// If the url is not configured, then the HttpClient defined as a mock
	if url == "" {
		return &ClientMock{}
	}
	return &http.Client{}
}

func ExtractImageID(imageID string) string {
	return strings.TrimPrefix(imageID, dockerPullableURN)
}

func AddCommandToChannel(ctx context.Context, config config.IConfig, cmd *apis.Command, workerPool *ants.PoolWithFunc) {
	logger.L().Ctx(ctx).Info(
		"issuing scan command",
		helpers.String("wlid", cmd.Wlid),
		helpers.String("command", string(cmd.CommandName)),
		helpers.Interface("args", cmd.Args),
	)
	newSessionObj := NewSessionObj(ctx, config, cmd, "Websocket", "", uuid.NewString(), 1)

	logger.L().Ctx(ctx).Debug("invoking worker pool job", helpers.Interface("session", newSessionObj))
	if err := workerPool.Invoke(Job{ctx: ctx, sessionObj: *newSessionObj}); err != nil {
		logger.L().Ctx(ctx).Error(
			"failed to invoke job",
			helpers.String("wlid", cmd.Wlid),
			helpers.String("command", string(cmd.CommandName)),
			helpers.Interface("args", cmd.Args),
			helpers.Error(err),
		)
	}

	logger.L().Ctx(ctx).Debug(
		"job invoked",
		helpers.String("wlid", cmd.Wlid),
		helpers.String("command", fmt.Sprintf("%v", cmd.CommandName)),
		helpers.String("args", fmt.Sprintf("%v", cmd.Args)),
	)
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
