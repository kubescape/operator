package watcher

import (
	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/operator/utils"
	core1 "k8s.io/api/core/v1"
)

func extractImageIDsToContainersFromPod(pod *core1.Pod) map[string][]string {
	imageIDsToContainers := make(map[string][]string)
	for containerStatus := range pod.Status.ContainerStatuses {
		imageID := utils.ExtractImageID(pod.Status.ContainerStatuses[containerStatus].ImageID)
		if _, ok := imageIDsToContainers[imageID]; !ok {
			imageIDsToContainers[imageID] = []string{}
		}
		imageIDsToContainers[imageID] = append(imageIDsToContainers[imageID], pod.Status.ContainerStatuses[containerStatus].Name)
	}

	for containerStatus := range pod.Status.InitContainerStatuses {
		imageID := utils.ExtractImageID(pod.Status.InitContainerStatuses[containerStatus].ImageID)
		if _, ok := imageIDsToContainers[imageID]; !ok {
			imageIDsToContainers[imageID] = []string{}
		}
		imageIDsToContainers[imageID] = append(imageIDsToContainers[imageID], pod.Status.InitContainerStatuses[containerStatus].Name)

	}

	return imageIDsToContainers
}

func extractImageIDsFromPod(pod *core1.Pod) []string {
	imageIDs := []string{}
	for containerStatus := range pod.Status.ContainerStatuses {
		imageID := pod.Status.ContainerStatuses[containerStatus].ImageID
		imageIDs = append(imageIDs, utils.ExtractImageID(imageID))
	}

	for containerStatus := range pod.Status.InitContainerStatuses {
		imageID := pod.Status.InitContainerStatuses[containerStatus].ImageID
		imageIDs = append(imageIDs, utils.ExtractImageID(imageID))
	}

	return imageIDs
}

func getImageScanCommand(wlid string, containerToimageID map[string]string) *apis.Command {
	return &apis.Command{
		Wlid:        wlid,
		CommandName: apis.TypeScanImages,
		Args:        map[string]interface{}{utils.ContainerToImageIdsArg: containerToimageID},
	}
}
