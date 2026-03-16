package rules

import (
	"testing"

	"github.com/kubescape/operator/objectcache"
	"github.com/zeebo/assert"
	corev1 "k8s.io/api/core/v1"
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
	assert.Equal(t, "nginx:1.14.2", result.GetRuntimeAlertK8sDetails().Image)
	assert.Equal(t, "nginx@sha256:abc123def456", result.GetRuntimeAlertK8sDetails().ImageDigest)
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
	// Image fields should fall back to first container when container name is empty
	assert.Equal(t, "nginx:1.14.2", result.GetRuntimeAlertK8sDetails().Image)
	assert.Equal(t, "nginx@sha256:abc123def456", result.GetRuntimeAlertK8sDetails().ImageDigest)
}

func TestGetContainerImage(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "web", Image: "nginx:1.14.2"},
				{Name: "sidecar", Image: "envoy:1.0"},
			},
			InitContainers: []corev1.Container{
				{Name: "init", Image: "busybox:latest"},
			},
		},
	}

	assert.Equal(t, "nginx:1.14.2", GetContainerImage(pod, "web"))
	assert.Equal(t, "envoy:1.0", GetContainerImage(pod, "sidecar"))
	assert.Equal(t, "busybox:latest", GetContainerImage(pod, "init"))
	// Empty name falls back to first container
	assert.Equal(t, "nginx:1.14.2", GetContainerImage(pod, ""))
	// Unknown container returns empty
	assert.Equal(t, "", GetContainerImage(pod, "unknown"))
	// Nil pod returns empty
	assert.Equal(t, "", GetContainerImage(nil, "web"))
}

func TestGetContainerImageDigest(t *testing.T) {
	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "web", ImageID: "docker-pullable://nginx@sha256:abc123"},
				{Name: "sidecar", ImageID: "envoy@sha256:def456"},
			},
			InitContainerStatuses: []corev1.ContainerStatus{
				{Name: "init", ImageID: "docker-pullable://busybox@sha256:789"},
			},
		},
	}

	assert.Equal(t, "nginx@sha256:abc123", GetContainerImageDigest(pod, "web"))
	assert.Equal(t, "envoy@sha256:def456", GetContainerImageDigest(pod, "sidecar"))
	assert.Equal(t, "busybox@sha256:789", GetContainerImageDigest(pod, "init"))
	// Empty name falls back to first container
	assert.Equal(t, "nginx@sha256:abc123", GetContainerImageDigest(pod, ""))
	// Unknown container returns empty
	assert.Equal(t, "", GetContainerImageDigest(pod, "unknown"))
	// Nil pod returns empty
	assert.Equal(t, "", GetContainerImageDigest(nil, "web"))
}
