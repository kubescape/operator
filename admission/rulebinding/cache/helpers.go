package cache

import (
	typesv1 "node-agent/pkg/rulebindingmanager/types/v1"
	"node-agent/pkg/utils"
	"node-agent/pkg/watcher"

	k8sruntime "k8s.io/apimachinery/pkg/runtime"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func uniqueName(obj metav1.Object) string {
	return utils.CreateK8sPodID(obj.GetNamespace(), obj.GetName())
}

func unstructuredToPod(obj *unstructured.Unstructured) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	if err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, pod); err != nil {
		return nil, err
	}
	return pod, nil

}

func unstructuredToRuleBinding(obj *unstructured.Unstructured) (*typesv1.RuntimeAlertRuleBinding, error) {
	rb := &typesv1.RuntimeAlertRuleBinding{}
	if err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, rb); err != nil {
		return nil, err
	}
	return rb, nil
}

func resourcesToWatch() []watcher.WatchResource {
	var w []watcher.WatchResource

	// add rule binding
	rb := watcher.NewWatchResource(typesv1.RuleBindingAlertGvr, metav1.ListOptions{})
	w = append(w, rb)

	return w
}
