package watcher

import (
	"github.com/kubescape/operator/utils"
	corev1 "k8s.io/api/core/v1"
)

func extractImageIDsToContainersFromPod(pod *corev1.Pod) map[string][]string {
	imageIDsToContainers := make(map[string][]string)
	for _, containerStatus := range pod.Status.ContainerStatuses {
		imageID := utils.ExtractImageID(containerStatus.ImageID)
		if _, ok := imageIDsToContainers[imageID]; !ok {
			imageIDsToContainers[imageID] = []string{}
		}
		imageIDsToContainers[imageID] = append(imageIDsToContainers[imageID], containerStatus.Name)
	}

	for _, containerStatus := range pod.Status.InitContainerStatuses {
		imageID := utils.ExtractImageID(containerStatus.ImageID)
		if _, ok := imageIDsToContainers[imageID]; !ok {
			imageIDsToContainers[imageID] = []string{}
		}
		imageIDsToContainers[imageID] = append(imageIDsToContainers[imageID], containerStatus.Name)

	}

	return imageIDsToContainers
}

func extractImageIDsFromPod(pod *corev1.Pod) []string {
	imageIDs := []string{}
	for _, containerStatus := range pod.Status.ContainerStatuses {
		if containerStatus.State.Running != nil {
			imageID := containerStatus.ImageID
			imageIDs = append(imageIDs, utils.ExtractImageID(imageID))
		}
	}

	for _, containerStatus := range pod.Status.InitContainerStatuses {
		if containerStatus.State.Running != nil {
			imageID := containerStatus.ImageID
			imageIDs = append(imageIDs, utils.ExtractImageID(imageID))
		}
	}

	return imageIDs
}
func getWlidAndImageID(containerData *utils.ContainerData) string {
	return containerData.Wlid + containerData.ContainerName + containerData.ImageID
}
