package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/armosec/armoapi-go/apis"
	pkgwlid "github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/operator/utils"
	"golang.org/x/exp/slices"
	core1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

const retryInterval = 3 * time.Second

type WatchHandler struct {
	k8sAPI                            *k8sinterface.KubernetesApi
	imagesIDToWlidsMap                map[string][]string
	wlidsToContainerToImageIDMap      map[string]map[string]string // <wlid> : <containerName> : imageID
	imageIDsMapMutex                  *sync.Mutex
	wlidsToContainerToImageIDMapMutex *sync.Mutex
	currentPodListResourceVersion     string // current PodList version, used by watcher (https://kubernetes.io/docs/reference/using-api/api-concepts/#efficient-detection-of-changes)
}

// NewWatchHandler creates a new WatchHandler, initializes the maps and returns it
func NewWatchHandler(ctx context.Context) (*WatchHandler, error) {

	wh := &WatchHandler{
		k8sAPI:                            k8sinterface.NewKubernetesApi(),
		imagesIDToWlidsMap:                make(map[string][]string),
		wlidsToContainerToImageIDMap:      make(map[string]map[string]string),
		imageIDsMapMutex:                  &sync.Mutex{},
		wlidsToContainerToImageIDMapMutex: &sync.Mutex{},
	}

	// list all Pods and extract their image IDs
	podsList, err := wh.k8sAPI.ListPods("", map[string]string{})
	if err != nil {
		return nil, err
	}

	wh.buildMaps(ctx, podsList)

	wh.currentPodListResourceVersion = podsList.GetResourceVersion()
	return wh, nil
}

// returns wlids map
func (wh *WatchHandler) GetWlidsToContainerToImageIDMap() map[string]map[string]string {
	return wh.wlidsToContainerToImageIDMap
}

// returns imageIDs map
func (wh *WatchHandler) GetImagesIDsToWlidMap() map[string][]string {
	return wh.imagesIDToWlidsMap
}

// watch for sbom changes, and trigger scans accordingly
func (wh *WatchHandler) SBOMWatch(ctx context.Context, sessionObjChan *chan utils.SessionObj) {
	// TODO: implement
}

// watch for pods changes, and trigger scans accordingly
func (wh *WatchHandler) PodWatch(ctx context.Context, sessionObjChan *chan utils.SessionObj) {
	logger.L().Ctx(ctx).Debug("starting pod watch")
	for {
		podsWatch, err := wh.getPodWatcher()
		if err != nil {
			logger.L().Ctx(ctx).Error(fmt.Sprintf("error to getPodWatcher, err :%s", err.Error()), helpers.Error(err))
			time.Sleep(retryInterval)
			continue
		}
		wh.handlePodWatcher(ctx, podsWatch, sessionObjChan)
	}
}

func (wh *WatchHandler) ListImageIDsFromStorage() ([]string, error) {
	// TODO: Implement
	return []string{}, nil
}

// returns a list of imageIDs that are not in storage
func (wh *WatchHandler) ListImageIDsNotInStorage() ([]string, error) {
	newImageIDs := []string{}
	imageIDsFromStorage, err := wh.ListImageIDsFromStorage()
	if err != nil {
		return newImageIDs, err
	}

	for imageID := range wh.GetImagesIDsToWlidMap() {
		if !slices.Contains(imageIDsFromStorage, imageID) {
			newImageIDs = append(newImageIDs, imageID)
		}
	}
	return newImageIDs, nil
}

func (wh *WatchHandler) GetWlidsForImageID(imageID string) []string {
	return wh.imagesIDToWlidsMap[imageID]
}

func (wh *WatchHandler) GetContainerToImageIDForWlid(wlid string) map[string]string {
	return wh.wlidsToContainerToImageIDMap[wlid]
}

func (wh *WatchHandler) addToImageIDToWlidsMap(imageID string, wlids ...string) {
	if len(wlids) == 0 {
		return
	}
	imageID = utils.ExtractImageID(imageID)

	wh.imageIDsMapMutex.Lock()
	defer wh.imageIDsMapMutex.Unlock()

	if _, ok := wh.imagesIDToWlidsMap[imageID]; !ok {
		wh.imagesIDToWlidsMap[imageID] = wlids
	} else {
		// imageID exists, add wlid if not exists
		for _, w := range wlids {
			if !slices.Contains(wh.imagesIDToWlidsMap[imageID], w) {
				wh.imagesIDToWlidsMap[imageID] = append(wh.imagesIDToWlidsMap[imageID], w)
			}
		}
	}
}

func (wh *WatchHandler) addToWlidsToContainerToImageIDMap(wlid string, containerName string, imageID string) {
	wh.wlidsToContainerToImageIDMapMutex.Lock()
	defer wh.wlidsToContainerToImageIDMapMutex.Unlock()

	if _, ok := wh.wlidsToContainerToImageIDMap[wlid]; !ok {
		wh.wlidsToContainerToImageIDMap[wlid] = make(map[string]string)
	}

	wh.wlidsToContainerToImageIDMap[wlid][containerName] = imageID
}

func (wh *WatchHandler) buildMaps(ctx context.Context, podList *core1.PodList) {
	for i := range podList.Items {
		parentWlid, err := wh.getParentIDForPod(&podList.Items[i])
		if err != nil {
			logger.L().Ctx(ctx).Error("Failed to get parent ID for pod", helpers.String("pod", podList.Items[i].Name), helpers.String("namespace", podList.Items[i].Namespace), helpers.Error(err))
			continue
		}
		for _, imgID := range extractImageIDsFromPod(&podList.Items[i]) {
			wh.addToImageIDToWlidsMap(imgID, parentWlid)
		}
		for _, containerStatus := range podList.Items[i].Status.ContainerStatuses {
			wh.addToWlidsToContainerToImageIDMap(parentWlid, containerStatus.Name, utils.ExtractImageID(containerStatus.ImageID))
		}
	}
}

func (wh *WatchHandler) getSBOMWatcher() {
	// TODO: implement
}

// returns a watcher watching from current resource version
func (wh *WatchHandler) getPodWatcher() (watch.Interface, error) {
	podsWatch, err := wh.k8sAPI.KubernetesClient.CoreV1().Pods("").Watch(context.TODO(), v1.ListOptions{
		ResourceVersion: wh.currentPodListResourceVersion,
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

func (wh *WatchHandler) updateResourceVersion() error {
	podsList, err := wh.k8sAPI.ListPods("", map[string]string{})
	if err != nil {
		return err
	}
	wh.currentPodListResourceVersion = podsList.GetResourceVersion()
	return nil
}

// returns a map of <imageID> : <containerName> for imageIDs in pod that are not in the map
func (wh *WatchHandler) getNewContainerToImageIDsFromPod(pod *core1.Pod) map[string]string {
	newContainerToImageIDs := make(map[string]string)
	imageIDsToContainers := extractImageIDsToContainersFromPod(pod)

	for imageID, container := range imageIDsToContainers {
		if _, ok := wh.imagesIDToWlidsMap[imageID]; !ok {
			newContainerToImageIDs[container] = imageID
		}
	}

	return newContainerToImageIDs
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

func (wh *WatchHandler) handlePodWatcher(ctx context.Context, podsWatch watch.Interface, sessionObjChan *chan utils.SessionObj) {
	var err error
	for {
		event, ok := <-podsWatch.ResultChan()
		if !ok {
			err = wh.restartResourceVersion(podsWatch)
			if err != nil {
				logger.L().Ctx(ctx).Error(fmt.Sprintf("error to restartResourceVersion, err :%s", err.Error()), helpers.Error(err))
			}
			return
		}

		pod, ok := wh.getPodFromEventIfRunning(ctx, event)
		if !ok {
			continue
		}

		parentWlid, err := wh.getParentIDForPod(pod)
		if err != nil {
			logger.L().Ctx(ctx).Error(fmt.Sprintf("error to getParentIDForPod, err :%s", err.Error()), helpers.Error(err))
			continue
		}

		newContainersToImageIDs := wh.getNewContainerToImageIDsFromPod(pod)

		var cmd *apis.Command
		if len(newContainersToImageIDs) > 0 {
			// new image, add to respective maps
			for container, imgID := range newContainersToImageIDs {
				wh.addToImageIDToWlidsMap(imgID, parentWlid)
				wh.addToWlidsToContainerToImageIDMap(parentWlid, container, imgID)
			}
			// new image, trigger SBOM
			cmd = getSBOMCalculationCommand(parentWlid, newContainersToImageIDs)
		} else {
			// old image
			if _, ok := wh.wlidsToContainerToImageIDMap[parentWlid]; ok {
				// old workload, no need to trigger CVE
				continue
			}
			// new workload, trigger CVE
			containersToImageIds := extractContainersToImageIDsFromPod(pod)
			for container, imgID := range containersToImageIds {
				wh.addToWlidsToContainerToImageIDMap(parentWlid, container, imgID)
			}
			cmd = getCVEScanCommand(parentWlid, containersToImageIds)
		}

		utils.AddCommandToChannel(ctx, cmd, sessionObjChan)
	}
}
