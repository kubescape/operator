package mainhandler

import (
	"github.com/armosec/k8s-interface/k8sinterface"
)

// ContainerData specific container data
type ContainerData struct {
	image     string
	container string
}

func getWorkloadcontainers(workload k8sinterface.IWorkload) ([]ContainerData, error) {
	containersData := []ContainerData{}

	// TODO get init containers
	containers, err := workload.GetContainers()
	if err != nil {
		return containersData, err
	}
	for i := range containers {
		containersData = append(containersData, ContainerData{image: containers[i].Image, container: containers[i].Name})
	}

	return containersData, nil

}

func getWorkloadImages(k8sAPI *k8sinterface.KubernetesApi, wlid string) ([]ContainerData, error) {

	containersData := []ContainerData{}

	workload, err := k8sAPI.GetWorkloadByWlid(wlid)
	if err != nil {
		return containersData, err
	}
	containers, err := workload.GetContainers()
	if err != nil {
		return containersData, err
	}
	for i := range containers {
		containersData = append(containersData, ContainerData{image: containers[i].Image, container: containers[i].Name})
	}

	return containersData, nil

}
