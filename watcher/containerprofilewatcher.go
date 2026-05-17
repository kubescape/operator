package watcher

import (
	"context"
	"fmt"
	"strings"

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
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

// ContainerProfileWatch uses the generic resource watcher for ContainerProfiles
func (wh *WatchHandler) ContainerProfileWatch(ctx context.Context, workerPool *ants.PoolWithFunc) {
	GenericResourceWatch[*spdxv1beta1.ContainerProfile](ctx, wh.cfg, workerPool, func(ctx context.Context, opts metav1.ListOptions) ([]*spdxv1beta1.ContainerProfile, string, string, error) {
		list, err := wh.storageClient.SpdxV1beta1().ContainerProfiles("").List(ctx, opts)
		if err != nil {
			return nil, "", "", err
		}
		items := make([]*spdxv1beta1.ContainerProfile, len(list.Items))
		for i := range list.Items {
			items[i] = &list.Items[i]
		}
		return items, list.Continue, list.ResourceVersion, nil
	}, wh.HandleContainerProfileEvents)
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
