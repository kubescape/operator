package watcher

import (
	"strings"

	core1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const dockerPullableURN = "docker-pullable://"

func convertUnstructuredObjToCustom[T any](unstructuredObj map[string]interface{}) (T, error) {
	var convertedObj T

	err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj, &convertedObj)
	if err != nil {
		return convertedObj, err
	}
	return convertedObj, nil
}

func convertKindToDynamicKind(kind string) string {
	lowerCaseKind := strings.ToLower(kind)
	return lowerCaseKind + "s"
}

func extractImageIDsFromPod(pod *core1.Pod) []string {
	imageIDs := []string{}
	for containerStatus := range pod.Status.ContainerStatuses {
		imageID := pod.Status.ContainerStatuses[containerStatus].ImageID
		imageIDs = append(imageIDs, GetImageID(imageID))
	}
	return imageIDs
}

func GetImageID(imageID string) string {
	return strings.TrimPrefix(imageID, dockerPullableURN)
}
