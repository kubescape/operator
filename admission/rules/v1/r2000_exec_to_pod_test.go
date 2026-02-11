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
				"kind":       "PodExecOptions",
				"apiVersion": "v1",
				"command":    []interface{}{"bash"},
				"container":  "test-container",
				"stdin":      true,
				"stdout":     true,
				"stderr":     true,
				"tty":        true,
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
		"exec",
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
	assert.Equal(t, "test-container", result.GetRuntimeAlertK8sDetails().ContainerName)
	assert.Equal(t, "test-workload", result.GetRuntimeAlertK8sDetails().WorkloadName)
	assert.Equal(t, "test-namespace", result.GetRuntimeAlertK8sDetails().WorkloadNamespace)
	assert.Equal(t, "ReplicaSet", result.GetRuntimeAlertK8sDetails().WorkloadKind)
	assert.Equal(t, "test-replicaset-uid-12345", result.GetRuntimeAlertK8sDetails().WorkloadUID)
	assert.Equal(t, "test-node", result.GetRuntimeAlertK8sDetails().NodeName)
	assert.Equal(t, "Exec to pod detected on pod test-pod", result.GetRuleAlert().RuleDescription)
	assert.Equal(t, "test-pod", result.GetRuntimeAlertK8sDetails().PodName)
	assert.Equal(t, "test-namespace", result.GetRuntimeAlertK8sDetails().Namespace)
	assert.Equal(t, "containerd://abcdef1234567890", result.GetRuntimeAlertK8sDetails().ContainerID)
}

func TestR2000_EmptyContainerName(t *testing.T) {
	// Test that empty container name defaults to first container (Kubernetes behavior)
	event := admission.NewAttributesRecord(
		&unstructured.Unstructured{
			Object: map[string]interface{}{
				"kind":       "PodExecOptions",
				"apiVersion": "v1",
				"command":    []interface{}{"sh"},
				// No "container" field - should default to first container
				"stdin":  true,
				"stdout": true,
				"stderr": true,
				"tty":    true,
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
		"exec",
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
	// Container name should be empty (not specified)
	assert.Equal(t, "", result.GetRuntimeAlertK8sDetails().ContainerName)
	// But ContainerID should be resolved to first container
	assert.Equal(t, "containerd://abcdef1234567890", result.GetRuntimeAlertK8sDetails().ContainerID)
	// WorkloadUID should be populated even though container name was empty
	assert.Equal(t, "test-replicaset-uid-12345", result.GetRuntimeAlertK8sDetails().WorkloadUID)
	assert.Equal(t, "test-workload", result.GetRuntimeAlertK8sDetails().WorkloadName)
	assert.Equal(t, "ReplicaSet", result.GetRuntimeAlertK8sDetails().WorkloadKind)
}
