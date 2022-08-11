package mainhandler

import (
	"github.com/kubescape/k8s-interface/k8sinterface"
)

// ContainerData specific container data
type ContainerData struct {
	image     string
	container string
}

func listWorkloadImages(workload k8sinterface.IWorkload) ([]ContainerData, error) {

	containersData := []ContainerData{}

	containers, err := workload.GetContainers()
	if err != nil {
		return containersData, err
	}
	for i := range containers {
		containersData = append(containersData, ContainerData{image: containers[i].Image, container: containers[i].Name})
	}
	initContainers, err := workload.GetInitContainers()
	if err != nil {
		return containersData, err
	}
	for i := range initContainers {
		containersData = append(containersData, ContainerData{image: initContainers[i].Image, container: initContainers[i].Name})
	}

	return containersData, nil

}
