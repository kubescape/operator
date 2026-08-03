package cache

import (
	typesv1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/pkg/watcher"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
)

// namespaceListHasName reports whether name is an exact member of list.Items.
// Do not use strings.Contains(list.String(), name): NamespaceList.String() is a
// debug dump, so substrings (e.g. "dev" in "devel") falsely match.
func namespaceListHasName(list *corev1.NamespaceList, name string) bool {
	if list == nil {
		return false
	}
	for i := range list.Items {
		if list.Items[i].Name == name {
			return true
		}
	}
	return false
}

// ruleBindingKind is the Kind value the CRD reports for RuntimeAlertRuleBinding
// objects. The dynamic watcher dispatches events from all watched GVRs to every
// adaptor, so handlers in this package use this constant to drop events for
// other CRDs (notably Rules) before attempting type conversion.
const ruleBindingKind = "RuntimeRuleAlertBinding"

func uniqueName(obj metav1.Object) string {
	return utils.CreateK8sPodID(obj.GetNamespace(), obj.GetName())
}

// isRuleBinding reports whether the given unstructured object is a
// RuntimeAlertRuleBinding. Returns false for nil or other Kinds.
func isRuleBinding(obj *unstructured.Unstructured) bool {
	if obj == nil {
		return false
	}
	return obj.GetKind() == ruleBindingKind
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
