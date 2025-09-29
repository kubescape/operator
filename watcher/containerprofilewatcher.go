package watcher

import (
	"context"
	"fmt"
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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/pager"
)

// ContainerProfileWatch watches and processes changes on ContainerProfile resources
func (wh *WatchHandler) ContainerProfileWatch(ctx context.Context, workerPool *ants.PoolWithFunc) {
	eventQueue := NewCooldownQueueWithParams(15*time.Second, 1*time.Second)
	cmdCh := make(chan *apis.Command)
	errorCh := make(chan error)
	apEvents := make(<-chan watch.Event)

	// The watcher is considered unavailable by default
	apWatcherUnavailable := make(chan struct{})
	go func() {
		apWatcherUnavailable <- struct{}{}
	}()

	go wh.HandleContainerProfileEvents(eventQueue, cmdCh, errorCh)

	// notifyWatcherDown notifies the appropriate channel that the watcher
	// is down and backs off for the retry interval to not produce
	// unnecessary events
	notifyWatcherDown := func(watcherDownCh chan<- struct{}) {
		go func() { watcherDownCh <- struct{}{} }()
		time.Sleep(retryInterval)
	}

	// get the initial profiles
	if err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return wh.storageClient.SpdxV1beta1().ContainerProfiles("").List(ctx, opts)
	}).EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
		ap := obj.(*spdxv1beta1.ContainerProfile)
		// simulate "add" event
		eventQueue.Enqueue(watch.Event{
			Type:   watch.Added,
			Object: ap,
		})
		return nil
	}); err != nil {
		logger.L().Ctx(ctx).Error("failed to list existing container profiles", helpers.Error(err))
	}

	var watcher watch.Interface
	var err error
	for {
		select {
		case apEvent, ok := <-apEvents:
			if ok {
				eventQueue.Enqueue(apEvent)
			} else {
				notifyWatcherDown(apWatcherUnavailable)
			}
		case cmd, ok := <-cmdCh:
			if ok {
				_ = utils.AddCommandToChannel(ctx, wh.cfg, cmd, workerPool)
			} else {
				notifyWatcherDown(apWatcherUnavailable)
			}
		case err, ok := <-errorCh:
			if ok {
				logger.L().Ctx(ctx).Error("error in ContainerProfileWatch", helpers.Error(err))
			} else {
				notifyWatcherDown(apWatcherUnavailable)
			}
		case <-apWatcherUnavailable:
			if watcher != nil {
				watcher.Stop()
			}

			watcher, err = wh.getContainerProfileWatcher()
			if err != nil {
				notifyWatcherDown(apWatcherUnavailable)
			} else {
				apEvents = watcher.ResultChan()
			}
		}
	}

}

func (wh *WatchHandler) HandleContainerProfileEvents(eventQueue *CooldownQueue, producedCommands chan<- *apis.Command, errorCh chan<- error) {
	defer close(errorCh)

	for e := range eventQueue.ResultChan {
		obj, ok := e.Object.(*spdxv1beta1.ContainerProfile)
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

		if skip, _ := utils.SkipContainerProfile(obj.ObjectMeta.Annotations); skip {
			continue
		}

		// eventually skip processing if there is no matching pod
		if wh.cfg.SkipProfilesWithoutInstances() && !wh.hasMatchingPod(obj.Labels) {
			continue
		}

		// assemble command arguments
		args := map[string]interface{}{
			utils.ArgsName:      obj.Name,
			utils.ArgsNamespace: obj.Namespace,
		}

		// load pod spec
		pod, err := getPod(wh.k8sAPI.KubernetesClient, obj)
		if err != nil {
			logger.L().Error("failed loading pod spec", helpers.String("wlid", obj.Annotations[helpersv1.WlidMetadataKey]), helpers.String("name", obj.Name), helpers.String("namespace", obj.Namespace), helpers.Error(err))
		} else if pod != nil {
			args[utils.ArgsPod] = pod
		}

		// create command
		cmd := &apis.Command{
			Wlid:        obj.Annotations[helpersv1.WlidMetadataKey],
			CommandName: utils.CommandScanContainerProfile,
			Args:        args,
		}
		// send command
		logger.L().Info("scanning container profile", helpers.String("wlid", cmd.Wlid), helpers.String("name", obj.Name), helpers.String("namespace", obj.Namespace))
		producedCommands <- cmd
	}
}

func (wh *WatchHandler) getContainerProfileWatcher() (watch.Interface, error) {
	// no need to support ExcludeNamespaces and IncludeNamespaces since node-agent will respect them as well
	return wh.storageClient.SpdxV1beta1().ContainerProfiles("").Watch(context.Background(), metav1.ListOptions{})
}

func getPod(client kubernetes.Interface, obj *spdxv1beta1.ContainerProfile) (*corev1.Pod, error) {
	if kind, ok := obj.Labels[helpersv1.KindMetadataKey]; !ok || kind != "Pod" {
		return nil, nil
	}

	podName, ok := obj.Labels[helpersv1.NameMetadataKey]
	if !ok || podName == "" {
		return nil, fmt.Errorf("label %s is missing", helpersv1.NameMetadataKey)
	}

	pod, err := client.CoreV1().Pods(obj.Namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	return pod, err
}

func (wh *WatchHandler) hasMatchingPod(labels map[string]string) bool {
	// construct the GroupVersionResource for the workload
	gvr := schema.GroupVersionResource{
		Group:    labels[helpersv1.ApiGroupMetadataKey],
		Version:  labels[helpersv1.ApiVersionMetadataKey],
		Resource: strings.ToLower(labels[helpersv1.KindMetadataKey]) + "s",
	}
	name := labels[helpersv1.NameMetadataKey]
	namespace := labels[helpersv1.NamespaceMetadataKey]
	// get the unstructured workload object
	workloadObj, err := wh.k8sAPI.DynamicClient.Resource(gvr).Namespace(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		logger.L().Debug("hasMatchingPod - failed to get workload matching labels", helpers.String("gvr", gvr.String()), helpers.String("namespace", namespace), helpers.String("name", name), helpers.Error(err))
		return false
	}
	// extract the pod selector labels
	selector, found, err := unstructured.NestedMap(workloadObj.Object, "spec", "selector", "matchLabels")
	if err != nil || !found {
		logger.L().Debug("hasMatchingPod - failed to get pod selector from workload", helpers.String("gvr", gvr.String()), helpers.String("namespace", namespace), helpers.String("name", name), helpers.Error(err))
		return false
	}
	// convert the map of labels to a label selector string
	labelsStr := strings.Builder{}
	for key, val := range selector {
		if labelsStr.Len() > 0 {
			labelsStr.WriteString(",")
		}
		labelsStr.WriteString(fmt.Sprintf("%s=%s", key, val))
	}
	if labelsStr.Len() == 0 {
		logger.L().Debug("hasMatchingPod - empty pod selector from workload", helpers.String("gvr", gvr.String()), helpers.String("namespace", namespace), helpers.String("name", name))
		return false
	}
	// list pods matching the selector
	podList, err := wh.k8sAPI.KubernetesClient.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: labelsStr.String(),
	})
	if err != nil {
		logger.L().Debug("hasMatchingPod - failed to list pods matching selector", helpers.String("selector", labelsStr.String()), helpers.String("namespace", namespace), helpers.Error(err))
		return false
	}
	if len(podList.Items) > 0 {
		return true
	}
	// no matching pods found
	return false
}
