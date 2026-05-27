package watcher

import (
	"context"
	"slices"
	"strings"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/operator/utils"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/panjf2000/ants/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

// SBOMWatch uses the generic resource watcher for SBOMSyft resources
func (wh *WatchHandler) SBOMWatch(ctx context.Context, workerPool *ants.PoolWithFunc) {
	// SBOM watcher needs pods to build a map of <image ID> : set of <wlid>
	watchOpts := metav1.ListOptions{
		Watch:         true,
		FieldSelector: "status.phase=Running", // only when the pod is running
	}

	// we only need pods if we have a backend
	if wh.cfg.Components().ServiceDiscovery.Enabled {
		// list pods and add them to the queue, this is for the pods that were created before the watch started
		err := wh.listPods(ctx)
		if err != nil {
			logger.L().Error("failed to list existing pods", helpers.Error(err))
		}
		// start watching pods
		go wh.watchRetry(ctx, watchOpts)
	}

	GenericResourceWatch[*spdxv1beta1.SBOMSyft](ctx, wh.cfg, workerPool, func(ctx context.Context, opts metav1.ListOptions) ([]*spdxv1beta1.SBOMSyft, string, string, error) {
		list, err := wh.storageClient.SpdxV1beta1().SBOMSyfts("").List(ctx, opts)
		if err != nil {
			return nil, "", "", err
		}
		items := make([]*spdxv1beta1.SBOMSyft, len(list.Items))
		for i := range list.Items {
			items[i] = &list.Items[i]
		}
		return items, list.Continue, list.ResourceVersion, nil
	}, wh.HandleSBOMEvents)
}

func (wh *WatchHandler) HandleSBOMEvents(eventQueue *CooldownQueue, producedCommands chan<- *apis.Command, errorCh chan<- error) {
	defer close(errorCh)

	for e := range eventQueue.ResultChan {
		obj, ok := e.Object.(*spdxv1beta1.SBOMSyft)
		if !ok {
			errorCh <- ErrUnsupportedObject
			continue
		}

		switch e.Type {
		case watch.Added:
		//
		case watch.Modified:
		//
		case watch.Deleted:
			continue
		case watch.Bookmark:
			continue
		}

		if skipSBOM(obj.ObjectMeta.Annotations) {
			continue
		}

		imageID := obj.ObjectMeta.Annotations[helpersv1.ImageIDMetadataKey]
		imageContainerData := wh.ImageToContainerData.Get(hashFromImageID(imageID))
		containerData := &utils.ContainerData{
			ContainerName: imageContainerData.ContainerName,
			ImageID:       imageID,
			ImageTag:      obj.ObjectMeta.Annotations[helpersv1.ImageTagMetadataKey],
			Wlid:          imageContainerData.Wlid,
		}

		if err := validateContainerData(containerData); err != nil {
			logger.L().Error("failed to get container data from SBOM",
				helpers.String("name", obj.ObjectMeta.Name),
				helpers.String("namespace", obj.ObjectMeta.Namespace),
				helpers.Interface("annotations", obj.ObjectMeta.Annotations),
				helpers.Error(err))
			errorCh <- err
			continue
		}

		cmd := &apis.Command{
			Wlid:        containerData.Wlid,
			CommandName: apis.TypeScanImages,
			Args: map[string]interface{}{
				utils.ArgsContainerData: containerData,
			},
		}
		// send
		logger.L().Info("scanning SBOM", helpers.String("wlid", cmd.Wlid), helpers.String("slug", containerData.Slug), helpers.String("containerName", containerData.ContainerName), helpers.String("imageTag", containerData.ImageTag), helpers.String("imageID", containerData.ImageID))
		producedCommands <- cmd
	}
}

func hashFromImageID(imageID string) string {
	s := strings.Split(imageID, ":")
	return s[len(s)-1]
}

func skipSBOM(annotations map[string]string) bool {
	ann := []string{
		"", // empty string for backward compatibility
		helpersv1.Learning,
		helpersv1.Completed,
	}

	if len(annotations) == 0 {
		return true // skip
	}

	if status, ok := annotations[helpersv1.StatusMetadataKey]; ok {
		return !slices.Contains(ann, status)
	}
	return false // do not skip
}

func validateContainerData(containerData *utils.ContainerData) error {
	if containerData.ImageID == "" {
		return ErrMissingImageID
	}
	if containerData.ImageTag == "" {
		return ErrMissingImageTag
	}
	return nil
}
