package watcher

import (
	"context"
	"encoding/json"
	"errors"
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
	spdxv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	kssc "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	"golang.org/x/exp/slices"
	core1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

var (
	ErrUnsupportedObject = errors.New("Unsupported object type")
	ErrUnknownImageID    = errors.New("Unknown image ID")
)

type WlidsToContainerToImageIDMap map[string]map[string]string

const retryInterval = 3 * time.Second

type WatchHandler struct {
	k8sAPI                            *k8sinterface.KubernetesApi
	storageClient                     kssc.Interface
	imagesIDToWlidsMap                map[string][]string
	instanceIDs                       []string
	wlidsToContainerToImageIDMap      WlidsToContainerToImageIDMap // <wlid> : <containerName> : imageID
	imageIDsMapMutex                  *sync.RWMutex
	instanceIDsMutex                  *sync.RWMutex
	wlidsToContainerToImageIDMapMutex *sync.RWMutex
	currentPodListResourceVersion     string // current PodList version, used by watcher (https://kubernetes.io/docs/reference/using-api/api-concepts/#efficient-detection-of-changes)
}

// remove unused imageIDs and instanceIDs from storage. Update internal maps
func (wh *WatchHandler) cleanUp(ctx context.Context) {
	storageImageIDs, err := wh.ListImageIDsFromStorage()
	if err != nil {
		// we should continue in order to clean up instanceIDs

		// logger.L().Ctx(ctx).Error("error to ListImageIDsFromStorage", helpers.Error(err))
	}

	storageInstanceIDs, err := wh.ListInstanceIDsFromStorage()
	if err != nil {
		// we should continue in order to clean up the internal maps

		// logger.L().Ctx(ctx).Error("error to ListInstanceIDsFromStorage", helpers.Error(err))
	}

	// list Pods, extract their imageIDs and instanceIDs
	podsList, err := wh.k8sAPI.ListPods("", map[string]string{})
	if err != nil {
		logger.L().Ctx(ctx).Error("could not complete cleanUp routine: error to ListPods", helpers.Error(err))
		return
	}

	// reset maps - clean them and build them again
	wh.cleanUpIDs()
	wh.buildIDs(ctx, podsList)

	// get current instance IDs
	currentInstanceIDs := wh.listInstanceIDs()

	// image IDs in storage that are not in current map should be deleted
	imageIDsForDeletion := make([]string, 0)
	for _, imageID := range storageImageIDs {
		if !wh.isImageIDInMap(imageID) {
			imageIDsForDeletion = append(imageIDsForDeletion, imageID)
		}
	}

	if err = wh.deleteImageIDsFromStorage(imageIDsForDeletion); err != nil {
		//  logger.L().Ctx(ctx).Error("error to deleteImageIDsFromStorage", helpers.Error(err))
		return
	}

	// instance IDs in storage that are not in current list should be deleted
	instanceIDsForDeletion := make([]string, 0)
	for _, instanceID := range storageInstanceIDs {
		if !slices.Contains(currentInstanceIDs, instanceID) {
			instanceIDsForDeletion = append(instanceIDsForDeletion, instanceID)
		}
	}

	if err = wh.deleteInstanceIDsFromStorage(instanceIDsForDeletion); err != nil {
		//  logger.L().Ctx(ctx).Error("error to deleteInstanceIDsFromStorage", helpers.Error(err))
	}
}

// NewWatchHandler creates a new WatchHandler, initializes the maps and returns it
func NewWatchHandler(ctx context.Context, k8sAPI *k8sinterface.KubernetesApi, storageClient kssc.Interface) (*WatchHandler, error) {

	wh := &WatchHandler{
		storageClient:                     storageClient,
		k8sAPI:                            k8sAPI,
		imagesIDToWlidsMap:                make(map[string][]string),
		wlidsToContainerToImageIDMap:      make(WlidsToContainerToImageIDMap),
		imageIDsMapMutex:                  &sync.RWMutex{},
		wlidsToContainerToImageIDMapMutex: &sync.RWMutex{},
		instanceIDsMutex:                  &sync.RWMutex{},
		instanceIDs:                       make([]string, 0),
	}

	// list all Pods and extract their image IDs
	podsList, err := wh.k8sAPI.ListPods("", map[string]string{})
	if err != nil {
		return nil, err
	}

	wh.buildIDs(ctx, podsList)

	wh.currentPodListResourceVersion = podsList.GetResourceVersion()

	wh.startCleanUpAndTriggerScanRoutine(ctx)

	return wh, nil
}

// start routine which cleans up unused imageIDs and instanceIDs from storage, and  triggers relevancy scan
func (wh *WatchHandler) startCleanUpAndTriggerScanRoutine(ctx context.Context) {
	go func() {
		for {
			time.Sleep(utils.CleanUpRoutineInterval)
			wh.cleanUp(ctx)
			// must be called after cleanUp, since we can have two instanceIDs with same wlid
			// wh.triggerRelevancyScan(ctx)
		}
	}()
}

func (wh *WatchHandler) triggerRelevancyScan(ctx context.Context) {
	// TODO: implement
	// list new SBOM's from storage
	// for each, trigger scan
}

func (wh *WatchHandler) deleteImageIDsFromStorage(imageIDs []string) error {
	// TODO: Implement
	return fmt.Errorf("not implemented")
}

func (wh *WatchHandler) deleteInstanceIDsFromStorage(imageIDs []string) error {
	// TODO: Implement
	return fmt.Errorf("not implemented")
}

func (wh *WatchHandler) listInstanceIDs() []string {
	wh.instanceIDsMutex.RLock()
	defer wh.instanceIDsMutex.RUnlock()

	return wh.instanceIDs
}

// returns true if imageID is in map
func (wh *WatchHandler) isImageIDInMap(imageID string) bool {
	wh.imageIDsMapMutex.RLock()
	defer wh.imageIDsMapMutex.RUnlock()

	_, ok := wh.imagesIDToWlidsMap[imageID]
	return ok
}

// returns wlids map
func (wh *WatchHandler) getWlidsToContainerToImageIDMap() WlidsToContainerToImageIDMap {
	wh.wlidsToContainerToImageIDMapMutex.RLock()
	defer wh.wlidsToContainerToImageIDMapMutex.RUnlock()

	return wh.wlidsToContainerToImageIDMap
}

// returns imageIDs map
func (wh *WatchHandler) getImagesIDsToWlidMap() map[string][]string {
	wh.imageIDsMapMutex.RLock()
	defer wh.imageIDsMapMutex.RUnlock()

	return wh.imagesIDToWlidsMap
}

// HandleSBOMEvents handles SBOM-related events
//
// Handling events is defined as dispatching scan commands that match a given
// SBOM to the main command channel
func (wh *WatchHandler) HandleSBOMEvents(sbomEvents <-chan watch.Event, commands chan<- *apis.Command, errorCh chan<- error) {
	defer close(commands)
	defer close(errorCh)

	for event := range sbomEvents {
		obj, ok := event.Object.(*spdxv1beta1.SBOMSPDXv2p3)
		if !ok {
			errorCh <- ErrUnsupportedObject
			continue
		}

		// We need to schedule scans only for new SBOMs, not changes to
		// existing ones or other operations
		if event.Type != watch.Added {
			continue
		}

		imageID := obj.ObjectMeta.Name

		wh.imageIDsMapMutex.RLock()
		wlids, ok := wh.imagesIDToWlidsMap[imageID]
		wh.imageIDsMapMutex.RUnlock()
		if !ok {
			errorCh <- ErrUnknownImageID
			continue
		}

		wlid := wlids[0]

		commands <- getCVEScanCommand(wlid, map[string]string{})
	}
}

// watch for sbom changes, and trigger scans accordingly
func (wh *WatchHandler) SBOMWatch(ctx context.Context, sessionObjChan *chan utils.SessionObj) {
	commands := make(chan *apis.Command)
	errorCh := make(chan error)

	watcher, err := wh.storageClient.SpdxV1beta1().SBOMSPDXv2p3s("").Watch(context.TODO(), v1.ListOptions{})
	if err != nil {
		panic(err)
	}

	go wh.HandleSBOMEvents(watcher.ResultChan(), commands, errorCh)

	for {
		select {
		case cmd, ok := <-commands:
			if !ok {
				logger.L().Ctx(ctx).Warning("commands: channel closed")
			} else {
				utils.AddCommandToChannel(ctx, cmd, sessionObjChan)
			}
		case err, ok := <-errorCh:
			if !ok {
				logger.L().Ctx(ctx).Warning("errors: channel closed")
			} else {
				logger.L().Ctx(ctx).Error(fmt.Sprintf("error in SBOMWatch: %v", err.Error()))
			}
		}
	}
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
	return []string{}, fmt.Errorf("not implemented")
}

func (wh *WatchHandler) cleanUpIDs() {
	wh.cleanUpImagesIDToWlidsMap()
	wh.cleanUpWlidsToContainerToImageIDMap()
}

func (wh *WatchHandler) cleanUpImagesIDToWlidsMap() {
	wh.imageIDsMapMutex.Lock()
	defer wh.imageIDsMapMutex.Unlock()

	wh.imagesIDToWlidsMap = make(map[string][]string)
}

func (wh *WatchHandler) cleanUpWlidsToContainerToImageIDMap() {
	wh.wlidsToContainerToImageIDMapMutex.Lock()
	defer wh.wlidsToContainerToImageIDMapMutex.Unlock()

	wh.wlidsToContainerToImageIDMap = make(WlidsToContainerToImageIDMap)
}

func (wh *WatchHandler) ListInstanceIDsFromStorage() ([]string, error) {
	// TODO: Implement
	return []string{}, fmt.Errorf("not implemented")
}

// returns a list of imageIDs that are not in storage
func (wh *WatchHandler) ListImageIDsNotInStorage(ctx context.Context) ([]string, error) {
	newImageIDs := []string{}
	imageIDsFromStorage, err := wh.ListImageIDsFromStorage()
	if err != nil {
		// logger.L().Ctx(ctx).Error(fmt.Sprintf("error to ListImageIDsFromStorage, err :%s", err.Error()), helpers.Error(err))
	}

	for imageID := range wh.getImagesIDsToWlidMap() {
		if !slices.Contains(imageIDsFromStorage, imageID) {
			newImageIDs = append(newImageIDs, imageID)
		}
	}
	return newImageIDs, nil
}

func (wh *WatchHandler) GetWlidsForImageID(imageID string) []string {
	wh.imageIDsMapMutex.RLock()
	defer wh.imageIDsMapMutex.RUnlock()

	wlids, ok := wh.imagesIDToWlidsMap[imageID]
	if !ok {
		return []string{}
	}
	return wlids
}

func (wh *WatchHandler) GetContainerToImageIDForWlid(wlid string) map[string]string {
	wh.wlidsToContainerToImageIDMapMutex.RLock()
	defer wh.wlidsToContainerToImageIDMapMutex.RUnlock()

	containerToImageIds, ok := wh.wlidsToContainerToImageIDMap[wlid]
	if !ok {
		return map[string]string{}
	}
	return containerToImageIds
}

func (wh *WatchHandler) addToInstanceIDsList(instanceID string) {
	wh.instanceIDsMutex.Lock()
	defer wh.instanceIDsMutex.Unlock()

	if !slices.Contains(wh.instanceIDs, instanceID) {
		wh.instanceIDs = append(wh.instanceIDs, instanceID)
	}
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

func (wh *WatchHandler) buildIDs(ctx context.Context, podList *core1.PodList) {
	for i := range podList.Items {

		if podList.Items[i].Status.Phase != core1.PodRunning {
			continue
		}

		wl, err := wh.getParentWorkloadForPod(&podList.Items[i])
		if err != nil {
			logger.L().Ctx(ctx).Error("Failed to get parent ID for pod", helpers.String("pod", podList.Items[i].Name), helpers.String("namespace", podList.Items[i].Namespace), helpers.Error(err))
			continue
		}

		parentWlid := pkgwlid.GetWLID(utils.ClusterConfig.ClusterName, wl.GetNamespace(), wl.GetKind(), wl.GetName())

		imgIDsToContainers := extractImageIDsToContainersFromPod(&podList.Items[i])

		for imgID, containerName := range imgIDsToContainers {
			wh.addToImageIDToWlidsMap(imgID, parentWlid)
			wh.addToWlidsToContainerToImageIDMap(parentWlid, containerName, imgID)
			instanceID := utils.GenerateInstanceID(wl.GetApiVersion(), wl.GetNamespace(), wl.GetKind(), wl.GetName(), wl.GetResourceVersion(), containerName)
			wh.addToInstanceIDsList(instanceID)
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
		if !wh.isImageIDInMap(imageID) {
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

func (wh *WatchHandler) getParentWorkloadForPod(pod *core1.Pod) (workloadinterface.IWorkload, error) {
	pod.TypeMeta.Kind = "Pod"
	podMarshalled, err := json.Marshal(pod)
	if err != nil {
		return nil, err
	}
	wl, err := workloadinterface.NewWorkload(podMarshalled)
	if err != nil {
		return nil, err
	}
	kind, name, err := wh.k8sAPI.CalculateWorkloadParentRecursive(wl)
	if err != nil {
		return nil, err
	}
	parentWorkload, err := wh.k8sAPI.GetWorkload(wl.GetNamespace(), kind, name)
	if err != nil {
		return nil, err
	}
	return parentWorkload, nil
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
			if wh.isWlidInMap(parentWlid) {
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

func (wh *WatchHandler) isWlidInMap(wlid string) bool {
	wh.wlidsToContainerToImageIDMapMutex.RLock()
	defer wh.wlidsToContainerToImageIDMapMutex.RUnlock()

	_, ok := wh.wlidsToContainerToImageIDMap[wlid]
	return ok
}
