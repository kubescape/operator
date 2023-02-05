package watcher

import (
	"strings"

	core1 "k8s.io/api/core/v1"
)

const dockerPullableURN = "docker-pullable://"

func extractImageIDsFromPod(pod *core1.Pod) []string {
	imageIDs := []string{}
	for containerStatus := range pod.Status.ContainerStatuses {
		imageID := pod.Status.ContainerStatuses[containerStatus].ImageID
		imageIDs = append(imageIDs, ExtractImageID(imageID))
	}
	return imageIDs
}

func ExtractImageID(imageID string) string {
	return strings.TrimPrefix(imageID, dockerPullableURN)
}