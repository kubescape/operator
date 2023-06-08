package watcher

import (
	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/operator/utils"
	core1 "k8s.io/api/core/v1"
	"regexp"
)

var (
	imageHashRegExp = regexp.MustCompile(`^[0-9a-f]+$`)
)

func extractImageIDsToContainersFromPod(pod *core1.Pod) map[string][]string {
	imageIDsToContainers := make(map[string][]string)
	for _, containerStatus := range pod.Status.ContainerStatuses {
		if containerStatus.State.Running != nil {
			imageID := containerStatus.ImageID
			if _, ok := imageIDsToContainers[imageID]; !ok {
				imageIDsToContainers[imageID] = []string{}
			}
			imageIDsToContainers[imageID] = append(imageIDsToContainers[imageID], containerStatus.Name)
		}
	}

	for _, containerStatus := range pod.Status.InitContainerStatuses {
		if containerStatus.State.Running != nil {
			imageID := containerStatus.ImageID
			if _, ok := imageIDsToContainers[imageID]; !ok {
				imageIDsToContainers[imageID] = []string{}
			}
			imageIDsToContainers[imageID] = append(imageIDsToContainers[imageID], containerStatus.Name)
		}

	}

	return imageIDsToContainers
}

func getImageScanCommand(wlid string, containerToimageID map[string]string) *apis.Command {
	return &apis.Command{
		Wlid:        wlid,
		CommandName: apis.TypeScanImages,
		Args:        map[string]interface{}{utils.ContainerToImageIdsArg: containerToimageID},
	}
}
