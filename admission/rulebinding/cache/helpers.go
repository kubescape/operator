package cache

import (
	typesv1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/pkg/watcher"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
)

func uniqueName(obj metav1.Object) string {
	return utils.CreateK8sPodID(obj.GetNamespace(), obj.GetName())
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
