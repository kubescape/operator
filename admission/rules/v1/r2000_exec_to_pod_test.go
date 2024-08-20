package rules

import (
	"testing"

	"github.com/kubescape/operator/objectcache"
	"github.com/zeebo/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
)

func TestR2000(t *testing.T) {
	event := admission.NewAttributesRecord(
		&unstructured.Unstructured{
			Object: map[string]interface{}{
				"kind": "PodExecOptions",
			},
		},
		nil,
		schema.GroupVersionKind{
			Kind: "PodExecOptions",
		},
		"test-namespace",
		"test-pod",
		schema.GroupVersionResource{
			Resource: "pods",
		},
		"",
		admission.Create,
		nil,
		false,
		&user.DefaultInfo{
			Name:   "test-user",
			Groups: []string{"test-group"},
		},
	)

	rule := CreateRuleR2000ExecToPod()
	result := rule.ProcessEvent(event, objectcache.KubernetesCacheMockImpl{})

	assert.NotNil(t, result)
	assert.Equal(t, "test-workload", result.GetRuntimeAlertK8sDetails().WorkloadName)
	assert.Equal(t, "test-namespace", result.GetRuntimeAlertK8sDetails().WorkloadNamespace)
	assert.Equal(t, "ReplicaSet", result.GetRuntimeAlertK8sDetails().WorkloadKind)
	assert.Equal(t, "test-node", result.GetRuntimeAlertK8sDetails().NodeName)
	assert.Equal(t, "Exec to pod detected on pod test-pod", result.GetRuleAlert().RuleDescription)
	assert.Equal(t, "test-pod", result.GetRuntimeAlertK8sDetails().PodName)
	assert.Equal(t, "test-namespace", result.GetRuntimeAlertK8sDetails().Namespace)
}
