package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	pkgwlid "github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/operator/utils"
	core1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

var ScanOnNewImage = false

const retryInterval = 3 * time.Second

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

func (wh *WatchHandler) addToWlidsMap(wlid string, containerName string, imageID string) {
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

func (wh *WatchHandler) buildImageIDsMap(pods *core1.PodList) {
	for _, pod := range pods.Items {
		for _, imageID := range extractImageIDsFromPod(&pod) {
			if _, ok := wh.imagesIDsMap[imageID]; !ok {
				wh.addToImageIDsMap(imageID)
			}
		}
	}
}

func (wh *WatchHandler) buildwlidsMap(ctx context.Context, pods *core1.PodList) {
	for _, pod := range pods.Items {
		parentWlid, err := wh.getParentIDForPod(&pod)
		if err != nil {
			logger.L().Ctx(ctx).Error("Failed to get parent ID for pod", helpers.String("pod", pod.Name), helpers.String("namespace", pod.Namespace), helpers.Error(err))
			continue
		}
		for _, containerStatus := range pod.Status.ContainerStatuses {
			wh.addToWlidsMap(parentWlid, containerStatus.Name, ExtractImageID(containerStatus.ImageID))
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
func (wh *WatchHandler) Initialize(ctx context.Context) error {
	// list all Pods and their image IDs
	podsList, err := wh.k8sAPI.ListPods("", map[string]string{})
	if err != nil {
		return err
	}

	wh.buildImageIDsMap(podsList)

	if ScanOnNewImage {
		wh.buildwlidsMap(ctx, podsList)
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

func (wh *WatchHandler) PodWatch(ctx context.Context) {
	logger.L().Ctx(ctx).Debug("starting pod watch")
	for {
		podsWatch, err := wh.getPodWatcher()
		if err != nil {
			logger.L().Ctx(ctx).Error(fmt.Sprintf("error to getPodWatcher, err :%s", err.Error()), helpers.Error(err))
			time.Sleep(retryInterval)
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

			if pod, ok := wh.getPodFromEventIfRunning(ctx, event); ok {
				if !ScanOnNewImage {
					wh.handleEventsNoScanOnNewWorkloads(ctx, pod)
				} else {
					wh.handleEventsTriggerScanOnNewWorkloads(ctx, pod)
				}
			}
		}
	}
}

// returns a watcher watching from current resource version
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
			wh.addToImageIDsMap(imageID)
			newImgs = append(newImgs, imageID)
		}
	}
	return newImgs
}

// returns pod and true if event status is modified, pod is exists and is running
func (wh *WatchHandler) getPodFromEventIfRunning(ctx context.Context, event watch.Event) (*core1.Pod, bool) {
	if event.Type != watch.Modified {
		return nil, false
	}
	var pod *core1.Pod
	if val, ok := event.Object.(*core1.Pod); ok {
		pod = val
		if pod.Status.Phase != core1.PodRunning {
			return nil, false
		}
	} else {
		logger.L().Ctx(ctx).Error("Failed to cast event object to pod", helpers.Error(fmt.Errorf("failed to cast event object to pod")))
		return nil, false
	}

	// check that Pod exists (when deleting a Pod we get MODIFIED events with Running status)
	_, err := wh.k8sAPI.GetWorkload(pod.GetNamespace(), "pod", pod.GetName())
	if err != nil {
		return nil, false
	}

	return pod, true
}

// pod watcher that does not  trigger scan on new workloads
func (wh *WatchHandler) handleEventsNoScanOnNewWorkloads(ctx context.Context, pod *core1.Pod) {
	newImgs := wh.getNewImages(pod)
	if len(newImgs) == 0 {
		return
	}

	parentWlid, err := wh.getParentIDForPod(pod)
	if err != nil {
		logger.L().Ctx(ctx).Error(fmt.Sprintf("error to getParentIDForPod, err :%s", err.Error()), helpers.Error(err))
		return
	}
	wh.triggerSBOMCalculation(parentWlid, newImgs)
}

// pod watcher that triggers scan on new workloads
func (wh *WatchHandler) handleEventsTriggerScanOnNewWorkloads(ctx context.Context, pod *core1.Pod) {
	parentWlid, err := wh.getParentIDForPod(pod)
	if err != nil {
		logger.L().Ctx(ctx).Error(fmt.Sprintf("error to getParentIDForPod, err :%s", err.Error()), helpers.Error(err))
		return
	}

	newImgs := wh.getNewImages(pod)

	_, ok := wh.wlidsMap[parentWlid]
	if ok {
		if len(newImgs) > 0 {
			// old WLID, new image
			wh.triggerSBOMCalculation(parentWlid, newImgs)
		}
	} else {
		// new WLID

		// add <container> : <imageID> to wlids map
		for _, containerStatus := range pod.Status.ContainerStatuses {
			wh.addToWlidsMap(parentWlid, containerStatus.Name, ExtractImageID(containerStatus.ImageID))
		}
		wh.triggerWorkloadScan()
	}
}
