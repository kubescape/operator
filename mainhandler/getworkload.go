package mainhandler

import (
	"github.com/kubescape/k8s-interface/instanceidhandler"
	"github.com/kubescape/k8s-interface/k8sinterface"
)

// ContainerData specific container data
type ContainerData struct {
	image     string
	container string
	id        string
}

func listWorkloadImages(workload k8sinterface.IWorkload, instancesID []instanceidhandler.IInstanceID) ([]ContainerData, error) {

	containersData := []ContainerData{}

	containers, err := workload.GetContainers()
	if err != nil {
		return containersData, err
	}
	for i := range containers {
		containersData = append(containersData,
			ContainerData{
				image:     containers[i].Image,
				container: containers[i].Name,
				id:        getContainerID(instancesID, containers[i].Name),
			},
		)
	}
	initContainers, err := workload.GetInitContainers()
	if err != nil {
		return containersData, err
	}
	for i := range initContainers {
		containersData = append(containersData,
			ContainerData{
				image:     initContainers[i].Image,
				container: initContainers[i].Name,
				// id:        getContainer(instancesID, containers[i].Name), // TODO: Currently not supported in the k8s-interface
			},
		)
	}

	return containersData, nil

}

// getContainer returns the container ID
func getContainerID(instancesID []instanceidhandler.IInstanceID, container string) string {
	for i := range instancesID {
		if instancesID[i].GetContainerName() == container {
			return instancesID[i].GetHashed()
		}
	}
	return ""
}
