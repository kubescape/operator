package watcher

import (
	"context"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler"
	instanceidhandlerv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/operator/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/panjf2000/ants/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/pager"
)

func (wh *WatchHandler) PodWatch(ctx context.Context, workerPool *ants.PoolWithFunc) {
	watchOpts := metav1.ListOptions{
		Watch:         true,
		FieldSelector: "status.phase=Running", // only when the pod is running
	}

	// list pods and add them to the queue, this is for the pods that were created before the watch started
	err := wh.listPods(ctx)
	if err != nil {
		logger.L().Error("failed to list existing pods", helpers.Error(err))
	}

	// start watching
	go wh.watchRetry(ctx, watchOpts)

	// process events
	for event := range wh.eventQueue.ResultChan {
		// skip non-pod objects
		pod, ok := event.Object.(*corev1.Pod)
		if !ok {
			continue
		}
		// handle pod events
		switch event.Type {
		case watch.Modified, watch.Added:
			if !utils.PodHasParent(pod) && time.Now().Before(pod.CreationTimestamp.Add(wh.cfg.GuardTime())) {
				// for naked pods, only handle if pod still exists when older than guard time
				untilPodMature := time.Until(pod.CreationTimestamp.Add(wh.cfg.GuardTime()))
				logger.L().Debug("naked pod detected, delaying scan", helpers.String("pod", pod.GetName()), helpers.String("namespace", pod.GetNamespace()), helpers.String("time", untilPodMature.String()))
				time.AfterFunc(untilPodMature, func() {
					// use get to check if pod still exists
					_, err := wh.k8sAPI.KubernetesClient.CoreV1().Pods(pod.Namespace).Get(context.Background(), pod.Name, metav1.GetOptions{})
					if err == nil {
						logger.L().Debug("performing delayed scan for naked pod", helpers.String("pod", pod.GetName()), helpers.String("namespace", pod.GetNamespace()))
						wh.handlePodWatcher(ctx, pod, workerPool)
					}
				})
			} else {
				wh.handlePodWatcher(ctx, pod, workerPool)
			}
		default:
			continue
		}
	}
}

// handlePodWatcher handles the pod watch events
func (wh *WatchHandler) handlePodWatcher(ctx context.Context, pod *corev1.Pod, workerPool *ants.PoolWithFunc) {

	// get pod instanceIDs
	instanceIDs, err := instanceidhandlerv1.GenerateInstanceIDFromRuntimeObj(pod, wh.cfg.ExcludeJsonPaths())
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to generate instance ID for pod", helpers.String("pod", pod.GetName()), helpers.String("namespace", pod.GetNamespace()), helpers.Error(err))
		return
	}

	slugToInstanceID := mapSlugToInstanceID(instanceIDs)

	// map image hash from status
	slugsToImages := mapSlugsToImageIDs(pod, instanceIDs) // map of <slug> : []<image hash>
	if len(slugsToImages) == 0 {
		// no images to scan - this can happen when non of the  containers are running
		return
	}

	noContainerSlugs := map[string]bool{}

	// there are a few use-cases:
	// 1. new workload, new image - new wlid, new slug, new image // scan
	// 2. new workload, existing image - new wlid, new slug, existing image // scan
	// 3. existing workload, new image - existing wlid, new slug, new image // scan
	// 4. existing workload, existing image, new image hash - existing wlid, existing slug, new image. This can happen when restarting a workload that has same imageTag but the image hash changed // scan
	// 5. existing workload, existing image - existing wlid, new slug, existing image. This can happen when restarting a workload // ignore
	// 6. existing workload, existing image - existing wlid, existing slug, existing image. This is an ordinary watch event that nothing changed // ignore
	for slug := range slugsToImages {
		if imageID, ok := wh.SlugToImageID.Load(slug); ok {
			if imageID == slugsToImages[slug] {
				// slug and image are already cached, ignoring event
				// use-case 6
				continue
			} else {
				// new image
				// slug is cached, but image is new
				// use-case 4
				// get container data
				containerData, err := utils.PodToContainerData(wh.k8sAPI, pod, slugToInstanceID[slug], wh.cfg.ClusterName())
				if err != nil {
					logger.L().Ctx(ctx).Error("failed to get container data from pod", helpers.String("pod", pod.GetName()), helpers.String("namespace", pod.GetNamespace()), helpers.Error(err))
					continue
				}

				noContainerSlug, _ := slugToInstanceID[slug].GetSlug(true)
				if _, ok := noContainerSlugs[noContainerSlug]; ok {
					// already scanned the container profile
					wh.SlugToImageID.Set(containerData.Slug, containerData.ImageID)
					wh.WlidAndImageID.Add(getWlidAndImageID(containerData))
					continue
				}

				if profile := utils.GetContainerProfileForRelevancyScan(ctx, wh.storageClient, noContainerSlug, pod.GetNamespace()); profile != nil {
					wh.scanContainerProfile(ctx, profile, pod, workerPool)
					noContainerSlugs[noContainerSlug] = true
				} else {
					wh.scanImage(ctx, pod, containerData, workerPool)
				}

				wh.SlugToImageID.Set(containerData.Slug, containerData.ImageID)
				wh.WlidAndImageID.Add(getWlidAndImageID(containerData))
			}
		} else {
			// new workload
			// slug is not cached
			containerData, err := utils.PodToContainerData(wh.k8sAPI, pod, slugToInstanceID[slug], wh.cfg.ClusterName())
			if err != nil {
				logger.L().Ctx(ctx).Error("failed to get container data from pod", helpers.String("pod", pod.GetName()), helpers.String("namespace", pod.GetNamespace()), helpers.Error(err))
				continue
			}

			// cache the new slug
			wh.SlugToImageID.Set(containerData.Slug, containerData.ImageID)

			if wh.WlidAndImageID.Contains(getWlidAndImageID(containerData)) {
				// wlid+imageID already exists, ignoring event
				// this can happen when the workload restarted but the image was not changed
				// use-case 5
				continue
			}

			noContainerSlug, _ := slugToInstanceID[slug].GetSlug(true)
			if _, ok := noContainerSlugs[noContainerSlug]; ok {
				// already scanned the container profile
				wh.WlidAndImageID.Add(getWlidAndImageID(containerData))
				continue
			}

			// use-case 1, 2, 3
			if profile := utils.GetContainerProfileForRelevancyScan(ctx, wh.storageClient, noContainerSlug, pod.GetNamespace()); profile != nil {
				wh.scanContainerProfile(ctx, profile, pod, workerPool)
				noContainerSlugs[noContainerSlug] = true
			} else {
				wh.scanImage(ctx, pod, containerData, workerPool)
			}
			wh.WlidAndImageID.Add(getWlidAndImageID(containerData))

		}
	}

}

func (wh *WatchHandler) scanImage(ctx context.Context, pod *corev1.Pod, containerData *utils.ContainerData, workerPool *ants.PoolWithFunc) {
	// set scanning command
	cmd := &apis.Command{
		Wlid:        containerData.Wlid,
		CommandName: apis.TypeScanImages,
		Args: map[string]interface{}{
			utils.ArgsContainerData: containerData,
			utils.ArgsPod:           pod,
		},
	}

	// send
	logger.L().Info("scanning image", helpers.String("wlid", cmd.Wlid), helpers.String("slug", containerData.Slug), helpers.String("containerName", containerData.ContainerName), helpers.String("imageTag", containerData.ImageTag), helpers.String("imageID", containerData.ImageID))
	if err := utils.AddCommandToChannel(ctx, wh.cfg, cmd, workerPool); err != nil {
		logger.L().Ctx(ctx).Error("failed to add command to channel", helpers.Error(err), helpers.String("slug", containerData.Slug), helpers.String("imageID", containerData.ImageID))
	}
}

func (wh *WatchHandler) scanContainerProfile(ctx context.Context, profile *v1beta1.ContainerProfile, pod *corev1.Pod, workerPool *ants.PoolWithFunc) {
	// set scanning command
	cmd := utils.GetContainerProfileScanCommand(profile, pod)

	// send
	logger.L().Info("scanning container profile", helpers.String("wlid", cmd.Wlid), helpers.String("name", profile.Name), helpers.String("namespace", profile.Namespace))
	if err := utils.AddCommandToChannel(ctx, wh.cfg, cmd, workerPool); err != nil {
		logger.L().Ctx(ctx).Error("failed to add command to channel", helpers.Error(err), helpers.String("wlid", cmd.Wlid), helpers.String("name", profile.Name), helpers.String("namespace", profile.Namespace))
	}
}

func (wh *WatchHandler) listPods(ctx context.Context) error {
	if err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return wh.k8sAPI.KubernetesClient.CoreV1().Pods("").List(ctx, opts)
	}).EachListItem(ctx, metav1.ListOptions{
		FieldSelector: "status.phase=Running", // only running pods
	}, func(obj runtime.Object) error {
		pod := obj.(*corev1.Pod)
		if pod.Status.Phase != corev1.PodRunning {
			// skip non-running pods, for some reason the list includes non-running pods
			return nil
		}
		if wh.cfg.SkipNamespace(pod.Namespace) {
			return nil
		}
		pod.APIVersion = "v1"
		pod.Kind = "Pod"
		wh.eventQueue.Enqueue(watch.Event{
			Type:   watch.Added,
			Object: pod,
		})
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func mapSlugsToImageIDs(pod *corev1.Pod, instanceIDs []instanceidhandler.IInstanceID) map[string]string {
	l := map[string]string{}
	slugToImage(instanceIDs, l, pod.Status.ContainerStatuses)
	slugToImage(instanceIDs, l, pod.Status.InitContainerStatuses)
	slugToImage(instanceIDs, l, pod.Status.EphemeralContainerStatuses)
	return l
}
func slugToImage(instanceIDs []instanceidhandler.IInstanceID, l map[string]string, containerStatuses []corev1.ContainerStatus) {
	for _, containerStatus := range containerStatuses {
		imageID := utils.ExtractImageID(containerStatus.ImageID)
		if imageID == "" {
			continue
		}
		for _, instanceID := range instanceIDs {
			if instanceID.GetContainerName() == containerStatus.Name {
				s, _ := instanceID.GetSlug(false)
				l[s] = imageID
			}
		}
	}
}

func mapSlugToInstanceID(instanceIDs []instanceidhandler.IInstanceID) map[string]instanceidhandler.IInstanceID {
	l := map[string]instanceidhandler.IInstanceID{}
	for _, instanceID := range instanceIDs {
		s, _ := instanceID.GetSlug(false)
		l[s] = instanceID
	}
	return l
}
