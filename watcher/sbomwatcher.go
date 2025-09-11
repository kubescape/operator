package watcher

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/operator/utils"
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/panjf2000/ants/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/pager"
)

// SBOMWatch watches and processes changes on SBOMs
func (wh *WatchHandler) SBOMWatch(ctx context.Context, workerPool *ants.PoolWithFunc) {
	eventQueue := NewCooldownQueueWithParams(15*time.Second, 1*time.Second)
	cmdCh := make(chan *apis.Command)
	errorCh := make(chan error)
	sbomEvents := make(<-chan watch.Event)

	// The watcher is considered unavailable by default
	sbomWatcherUnavailable := make(chan struct{})
	go func() {
		sbomWatcherUnavailable <- struct{}{}
	}()

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

	// start watching SBOMs
	go wh.HandleSBOMEvents(eventQueue, cmdCh, errorCh)

	// notifyWatcherDown notifies the appropriate channel that the watcher
	// is down and backs off for the retry interval to not produce
	// unnecessary events
	notifyWatcherDown := func(watcherDownCh chan<- struct{}) {
		go func() { watcherDownCh <- struct{}{} }()
		time.Sleep(retryInterval)
	}

	// get the initial SBOMs
	if err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return wh.storageClient.SpdxV1beta1().SBOMSyfts("").List(ctx, opts)
	}).EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
		sbom := obj.(*spdxv1beta1.SBOMSyft)
		// simulate "add" event
		eventQueue.Enqueue(watch.Event{
			Type:   watch.Added,
			Object: sbom,
		})
		return nil
	}); err != nil {
		logger.L().Ctx(ctx).Error("failed to list existing SBOMs", helpers.Error(err))
	}

	var watcher watch.Interface
	for {
		select {
		// FIXME select processes the events randomly, so we might see the SBOM event before the pod event
		case event := <-wh.eventQueue.ResultChan: // this is the event queue for pods
			// skip non-pod objects
			pod, ok := event.Object.(*corev1.Pod)
			if !ok {
				continue
			}
			wlid, err := utils.GetParentIDForPod(wh.k8sAPI, pod, wh.cfg.ClusterName())
			if err != nil {
				logger.L().Ctx(ctx).Error("failed to get wlid for pod", helpers.Error(err), helpers.String("pod", pod.Name), helpers.String("namespace", pod.Namespace))
				continue
			}
			containerStatuses := slices.Concat(pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses, pod.Status.EphemeralContainerStatuses)
			for _, containerStatus := range containerStatuses {
				hash := hashFromImageID(containerStatus.ImageID)
				wh.ImageToContainerData.Set(hash, utils.ContainerData{
					ContainerName: containerStatus.Name,
					Wlid:          wlid,
				})
			}
		case sbomEvent, ok := <-sbomEvents:
			if ok {
				eventQueue.Enqueue(sbomEvent)
			} else {
				notifyWatcherDown(sbomWatcherUnavailable)
			}
		case cmd, ok := <-cmdCh:
			if ok {
				_ = utils.AddCommandToChannel(ctx, wh.cfg, cmd, workerPool)
			} else {
				notifyWatcherDown(sbomWatcherUnavailable)
			}
		case err, ok := <-errorCh:
			if ok {
				logger.L().Ctx(ctx).Error("error in SBOMWatch", helpers.Error(err))
			} else {
				notifyWatcherDown(sbomWatcherUnavailable)
			}
		case <-sbomWatcherUnavailable:
			if watcher != nil {
				watcher.Stop()
			}

			var err error
			watcher, err = wh.getSBOMWatcher()
			if err != nil {
				notifyWatcherDown(sbomWatcherUnavailable)
			} else {
				sbomEvents = watcher.ResultChan()
			}
		}
	}

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

func (wh *WatchHandler) getSBOMWatcher() (watch.Interface, error) {
	// no need to support ExcludeNamespaces and IncludeNamespaces since node-agent will respect them as well
	return wh.storageClient.SpdxV1beta1().SBOMSyfts("").Watch(context.Background(), metav1.ListOptions{})
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
