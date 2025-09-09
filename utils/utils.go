package utils

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/utils-go/httputils"
	pkgwlid "github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/k8s-interface/instanceidhandler"
	instanceidhandlerv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/operator/config"
	"github.com/panjf2000/ants/v2"
	corev1 "k8s.io/api/core/v1"
)

const KubescapeScanV1 = "scanV1"
const KubescapeRequestPathV1 = "v1/scan"
const KubescapeRequestStatusV1 = "v1/status"
const ArgdContainerToImageIds = "containerToImageIDs"
const ArgsPod = "pod"
const ArgsContainerData = "containerData"
const ArgsName = "name"
const ArgsNamespace = "namespace"
const dockerPullableURN = "docker-pullable://"

const CommandScanApplicationProfile = "scanApplicationProfile"

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

func AddCommandToChannel(ctx context.Context, config config.IConfig, cmd *apis.Command, workerPool *ants.PoolWithFunc) error {
	newSessionObj := NewSessionObj(ctx, config, cmd, "", "")
	return workerPool.Invoke(Job{ctx: ctx, sessionObj: *newSessionObj})
}

func ExtractContainersToImageIDsFromPod(pod *corev1.Pod) map[string]string {
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

func PodToContainerData(k8sAPI *k8sinterface.KubernetesApi, pod *corev1.Pod, instanceID instanceidhandler.IInstanceID, clusterName string) (*ContainerData, error) {

	wlid, err := GetParentIDForPod(k8sAPI, pod, clusterName)
	if err != nil {
		return nil, err
	}
	slug, _ := instanceID.GetSlug(false)

	imageTag, imageID, ok := getImage(pod, instanceID)
	if !ok {
		// this should never happen
		return nil, errors.New("failed to get image ID")
	}

	return &ContainerData{
		ContainerName: instanceID.GetContainerName(),
		ImageID:       imageID,
		Slug:          slug,
		Wlid:          wlid,
		ContainerType: string(instanceID.GetInstanceType()),
		ImageTag:      imageTag,
		InstanceID:    instanceID.GetStringFormatted(),
	}, nil
}

func GetParentIDForPod(k8sAPI *k8sinterface.KubernetesApi, pod *corev1.Pod, clusterName string) (string, error) {
	pod.TypeMeta.Kind = "Pod"
	podMarshalled, err := json.Marshal(pod)
	if err != nil {
		return "", err
	}
	wl, err := workloadinterface.NewWorkload(podMarshalled)
	if err != nil {
		return "", err
	}
	kind, name, err := k8sAPI.CalculateWorkloadParentRecursive(wl)
	if kind == "Node" {
		return pkgwlid.GetWLID(clusterName, wl.GetNamespace(), wl.GetNamespace(), wl.GetName()), nil
	}
	if err != nil {
		return "", err
	}
	return pkgwlid.GetWLID(clusterName, wl.GetNamespace(), kind, name), nil
}

func getImage(pod *corev1.Pod, instanceID instanceidhandler.IInstanceID) (string, string, bool) {
	var imageTag, imageID string
	switch instanceID.GetInstanceType() {
	case instanceidhandlerv1.Container:
		imageTag = getImageFromSpec(instanceID, pod.Spec.Containers)
		// consider getting imageTag from status
		_, imageID = getImageFromStatus(instanceID, pod.Status.ContainerStatuses)
	case instanceidhandlerv1.InitContainer:
		imageTag = getImageFromSpec(instanceID, pod.Spec.InitContainers)
		// consider getting imageTag from status
		_, imageID = getImageFromStatus(instanceID, pod.Status.InitContainerStatuses)
		// FIXME add ephemeralContainer
	}

	if imageTag == "" || imageID == "" {
		return "", "", false
	}
	return imageTag, imageID, true
}

// returns the image and imageID of the container
func getImageFromStatus(instanceID instanceidhandler.IInstanceID, containerStatuses []corev1.ContainerStatus) (string, string) {
	for _, containerStatus := range containerStatuses {
		if instanceID.GetContainerName() == containerStatus.Name {
			return containerStatus.Image, ExtractImageID(containerStatus.ImageID)
		}
	}
	return "", ""
}

func getImageFromSpec(instanceID instanceidhandler.IInstanceID, containers []corev1.Container) string {
	for _, container := range containers {
		if instanceID.GetContainerName() == container.Name {
			return container.Image
		}
	}
	return ""
}

func PodHasParent(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	if len(pod.OwnerReferences) > 0 {
		return slices.Contains([]string{"apps/v1", "batch/v1", "batch/v1beta1"}, pod.OwnerReferences[0].APIVersion)
	}
	if podHash, ok := pod.Labels["pod-template-hash"]; ok && podHash != "" {
		return true
	}
	return false
}
