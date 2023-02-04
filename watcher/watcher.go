package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	pkgwlid "github.com/armosec/utils-k8s-go/wlid"
	"github.com/golang/glog"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/operator/utils"
	core1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

type WatchHandler struct {
	k8sAPI                 *k8sinterface.KubernetesApi
	imagesIDsMap           map[string]bool
	wlidsMap               map[string]map[string]string // <wlid> : <containerName> : imageID
	imageIDsMapMutex       *sync.Mutex
	wlidsMapMutex          *sync.Mutex
	currentResourceVersion string // current PodList version, used by watcher (https://kubernetes.io/docs/reference/using-api/api-concepts/#efficient-detection-of-changes)
}

func NewWatchHandler() *WatchHandler {
	return &WatchHandler{
		k8sAPI:           k8sinterface.NewKubernetesApi(),
		imagesIDsMap:     make(map[string]bool),
		wlidsMap:         make(map[string]map[string]string),
		imageIDsMapMutex: &sync.Mutex{},
		wlidsMapMutex:    &sync.Mutex{},
	}
}

func (wh *WatchHandler) addToImageIDsMap(imageID string) {
	wh.imageIDsMapMutex.Lock()
	defer wh.imageIDsMapMutex.Unlock()
	if _, ok := wh.imagesIDsMap[imageID]; !ok {
		wh.imagesIDsMap[imageID] = true
	}
}

func (wh *WatchHandler) addTowlidsMap(wlid string, containerName string, imageID string) {
	wh.wlidsMapMutex.Lock()
	defer wh.wlidsMapMutex.Unlock()
	if _, ok := wh.wlidsMap[wlid]; !ok {
		wh.wlidsMap[wlid] = make(map[string]string)
		wh.wlidsMap[wlid][containerName] = imageID
	} else {
		wh.wlidsMap[wlid][containerName] = imageID
	}
}

func (wh *WatchHandler) GetWlidsMap() map[string]map[string]string {
	return wh.wlidsMap
}

func (wh *WatchHandler) GetImageIDsMap() map[string]bool {
	return wh.imagesIDsMap
}

func (wh *WatchHandler) buildImageIDsMap(pods core1.PodList) {
	for _, pod := range pods.Items {
		for _, imageID := range extractImageIDsFromPod(&pod) {
			if _, ok := wh.imagesIDsMap[imageID]; !ok {
				wh.addToImageIDsMap(imageID)
			}
		}
	}
}

func (wh *WatchHandler) buildwlidsMap(pods core1.PodList) {
	for _, pod := range pods.Items {
		parentWlid, err := wh.getParentIDForPod(&pod)
		if err != nil {
			glog.Warningf("failed to get parent for pod %s: %s", pod.Name, err.Error())
			continue
		}
		for _, containerStatus := range pod.Status.ContainerStatuses {
			wh.addTowlidsMap(parentWlid, containerStatus.Name, GetImageID(containerStatus.ImageID))
		}
	}
}

func (wh *WatchHandler) getParentIDForPod(pod *core1.Pod) (string, error) {
	pod.TypeMeta.Kind = "Pod"
	podMarshalled, err := json.Marshal(pod)
	if err != nil {
		return "", err
	}
	wl, err := workloadinterface.NewWorkload(podMarshalled)
	if err != nil {
		return "", err
	}
	kind, name, err := wh.k8sAPI.CalculateWorkloadParentRecursive(wl)
	if err != nil {
		return "", err
	}
	return pkgwlid.GetWLID(utils.ClusterConfig.ClusterName, wl.GetNamespace(), kind, name), nil

}

// list all pods, build imageIDsMap and wlidsMap
// set current resource version for pod watcher
func (wh *WatchHandler) Initialize(scanNewWorkloads bool) error {
	// list all Pods and their image IDs
	podsList, err := wh.k8sAPI.ListPods("", map[string]string{})
	if err != nil {
		return err
	}

	wh.buildImageIDsMap(*podsList)

	if scanNewWorkloads {
		wh.buildwlidsMap(*podsList)
	}

	wh.currentResourceVersion = podsList.GetResourceVersion()

	return nil
}

func (wh *WatchHandler) updateResourceVersion() error {
	podsList, err := wh.k8sAPI.ListPods("", map[string]string{})
	if err != nil {
		return err
	}
	wh.currentResourceVersion = podsList.GetResourceVersion()
	return nil
}

func (wh *WatchHandler) triggerSBOMCalculation(wlid string, imageIDs []string) error {
	// TODO: send command to calculate SBOM
	return nil
}

func (wh *WatchHandler) triggerWorkloadScan() error {
	// TODO: send command to calculate SBOM
	return nil
}

func (wh *WatchHandler) PodWatch(ctx context.Context, scanNewWorkloads bool) {
	if !scanNewWorkloads {
		wh.watchPodsNoScanOnNewWorkloads(ctx)
	} else {
		wh.watchPodsTriggerScanOnNewWorkloads(ctx)
	}
}

func (wh *WatchHandler) getPodWatcher() (watch.Interface, error) {
	podsWatch, err := wh.k8sAPI.KubernetesClient.CoreV1().Pods("").Watch(context.TODO(), v1.ListOptions{
		ResourceVersion: wh.currentResourceVersion,
	})
	if err != nil {
		return nil, err
	}

	return podsWatch, nil
}

func (wh *WatchHandler) restartResourceVersion(podWatch watch.Interface) error {
	podWatch.Stop()
	return wh.updateResourceVersion()
}

func (wh *WatchHandler) getNewImages(pod *core1.Pod) []string {
	newImgs := make([]string, 0)
	for _, imageID := range extractImageIDsFromPod(pod) {
		if _, ok := wh.imagesIDsMap[imageID]; !ok {
			wh.imagesIDsMap[imageID] = true
			newImgs = append(newImgs, imageID)
		}
	}
	return newImgs
}

func (wh *WatchHandler) getPodFromEventIfRunning(event watch.Event) (*core1.Pod, bool) {
	if event.Type != watch.Modified {
		return nil, false
	}
	var pod *core1.Pod
	if val, ok := event.Object.(*core1.Pod); ok {
		pod = val
		if pod.Status.Phase != core1.PodRunning {
			return nil, false
		}
	}

	// check that Pod exists
	// when deleting a Pod we get MODIFIED events with Running status
	_, err := wh.k8sAPI.GetWorkload(pod.GetNamespace(), "pod", pod.GetName())
	if err != nil {
		return nil, false
	}

	return pod, true
}

// pod watcher that does not  trigger scan on new workloads
func (wh *WatchHandler) watchPodsNoScanOnNewWorkloads(ctx context.Context) {
	logger.L().Ctx(ctx).Debug("starting pod watch")
	for {
		podsWatch, err := wh.getPodWatcher()
		if err != nil {
			logger.L().Ctx(ctx).Error(fmt.Sprintf("error to getPodWatcher, err :%s", err.Error()), helpers.Error(err))
			time.Sleep(3 * time.Second)
			continue
		}

		for {
			event, ok := <-podsWatch.ResultChan()
			if !ok {
				// channel closed, restart watch
				err = wh.restartResourceVersion(podsWatch)
				if err != nil {
					logger.L().Ctx(ctx).Error(fmt.Sprintf("error to restartResourceVersion, err :%s", err.Error()), helpers.Error(err))
				}
				break

			}

			if pod, ok := wh.getPodFromEventIfRunning(event); ok {
				newImgs := wh.getNewImages(pod)

				if len(newImgs) > 0 {
					parentWlid, err := wh.getParentIDForPod(pod)
					if err != nil {
						logger.L().Ctx(ctx).Error(fmt.Sprintf("error to getParentIDForPod, err :%s", err.Error()), helpers.Error(err))
						continue
					}
					wh.triggerSBOMCalculation(parentWlid, newImgs)
				}
			}
		}
	}
}

// pod watcher that triggers scan on new workloads
func (wh *WatchHandler) watchPodsTriggerScanOnNewWorkloads(ctx context.Context) {
	for {
		podsWatch, err := wh.getPodWatcher()
		if err != nil {
			logger.L().Ctx(ctx).Error(fmt.Sprintf("error to getPodWatcher, err :%s", err.Error()), helpers.Error(err))
			time.Sleep(3 * time.Second)
			continue
		}

		for {
			event, ok := <-podsWatch.ResultChan()
			if !ok {
				err = wh.restartResourceVersion(podsWatch)
				if err != nil {
					logger.L().Ctx(ctx).Error(fmt.Sprintf("error to restartResourceVersion, err :%s", err.Error()), helpers.Error(err))
				}
				break
			}

			if pod, ok := wh.getPodFromEventIfRunning(event); ok {
				parentWlid, err := wh.getParentIDForPod(pod)
				if err != nil {
					logger.L().Ctx(ctx).Error(fmt.Sprintf("error to getParentIDForPod, err :%s", err.Error()), helpers.Error(err))
					continue
				}

				newImgs := wh.getNewImages(pod)

				if _, ok := wh.wlidsMap[parentWlid]; !ok {
					// new WLID
					containerNameToImageID := make(map[string]string)
					// add <container> : <imageID> to map
					for _, containerStatus := range pod.Status.ContainerStatuses {
						containerNameToImageID[containerStatus.Name] = GetImageID(containerStatus.ImageID)
					}
					for container, img := range containerNameToImageID {
						wh.addTowlidsMap(parentWlid, container, img)
					}

					wh.triggerWorkloadScan()
				} else {
					if len(newImgs) > 0 {
						// old WLID, new image
						wh.triggerSBOMCalculation(parentWlid, newImgs)
					}
				}
			}
		}
	}
}
