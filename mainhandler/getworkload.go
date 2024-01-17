package mainhandler

import (
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler"
	"github.com/kubescape/k8s-interface/k8sinterface"
)

// ContainerData specific container data
type ContainerData struct {
	image     string
	container string
	id        string
}

func listWorkloadImages(workload k8sinterface.IWorkload, instanceIDs []instanceidhandler.IInstanceID) ([]ContainerData, error) {

	containersData := []ContainerData{}

	containers, err := workload.GetContainers()
	if err != nil {
		return containersData, err
	}
	for i := range containers {
		c := ""
		id := getContainerID(instanceIDs, containers[i].Name)
		if id != nil {
			c, _ = id.GetSlug()
			containersData = append(containersData,
				ContainerData{
					image:     containers[i].Image,
					container: containers[i].Name,
					id:        c,
				},
			)
			logger.L().Debug("instanceID", helpers.String("str", id.GetStringFormatted()), helpers.String("id", id.GetHashed()), helpers.String("workloadID", workload.GetID()), helpers.String("container", containers[i].Name), helpers.String("image", containers[i].Image))
		} else {
			logger.L().Debug("instanceID is nil, skipping", helpers.String("workloadID", workload.GetID()), helpers.String("container", containers[i].Name), helpers.String("image", containers[i].Image))
		}
	}
	initContainers, err := workload.GetInitContainers()
	if err != nil {
		return containersData, err
	}
	for i := range initContainers {
		c := ""
		id := getContainerID(instanceIDs, initContainers[i].Name)
		if id != nil {
			c, _ = id.GetSlug()
			containersData = append(containersData,
				ContainerData{
					image:     initContainers[i].Image,
					container: initContainers[i].Name,
					id:        c,
				},
			)
			logger.L().Debug("instanceID", helpers.String("str", id.GetStringFormatted()), helpers.String("id", id.GetHashed()), helpers.String("workloadID", workload.GetID()), helpers.String("initContainer", containers[i].Name), helpers.String("image", containers[i].Image))
		} else {
			logger.L().Debug("instanceID is nil, skipping", helpers.String("workloadID", workload.GetID()), helpers.String("initContainer", containers[i].Name), helpers.String("image", containers[i].Image))
		}
	}

	return containersData, nil

}

// getContainer returns the container ID
func getContainerID(instanceIDs []instanceidhandler.IInstanceID, container string) instanceidhandler.IInstanceID {
	for i := range instanceIDs {
		if instanceIDs[i].GetContainerName() == container {
			return instanceIDs[i]
		}
	}
	return nil
}
