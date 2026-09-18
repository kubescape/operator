package utils

import (
	"reflect"
	"testing"

	instanceidhandlerv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestExtractContainersToImageIDsFromPod(t *testing.T) {
	tests := []struct {
		pod      *corev1.Pod
		expected map[string]string
		name     string
	}{
		{
			name: "one container",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod1",
					Namespace: "namespace1",
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{
							State: corev1.ContainerState{
								Running: &corev1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:1",
							Name:    "container1",
						},
					},
				},
			},
			expected: map[string]string{
				"container1": "alpine@sha256:1",
			},
		},
		{
			name: "two containers",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod2",
					Namespace: "namespace2",
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{
							State: corev1.ContainerState{
								Running: &corev1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:1",
							Name:    "container1",
						},
						{
							State: corev1.ContainerState{
								Running: &corev1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:2",
							Name:    "container2",
						},
					},
				},
			},
			expected: map[string]string{
				"container1": "alpine@sha256:1",
				"container2": "alpine@sha256:2",
			},
		},
		{
			name: "init container",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod2",
					Namespace: "namespace2",
				},
				Status: corev1.PodStatus{
					InitContainerStatuses: []corev1.ContainerStatus{
						{
							State: corev1.ContainerState{
								Running: &corev1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:1",
							Name:    "container1",
						},
						{
							State: corev1.ContainerState{
								Running: &corev1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:2",
							Name:    "container2",
						},
					},
				},
			},
			expected: map[string]string{
				"container1": "alpine@sha256:1",
				"container2": "alpine@sha256:2",
			},
		},
		{
			name: "ephemeral container running",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod3",
					Namespace: "namespace3",
				},
				Status: corev1.PodStatus{
					EphemeralContainerStatuses: []corev1.ContainerStatus{
						{
							State: corev1.ContainerState{
								Running: &corev1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://busybox@sha256:3",
							Name:    "debugger",
						},
					},
				},
			},
			expected: map[string]string{
				"debugger": "busybox@sha256:3",
			},
		},
		{
			name: "ephemeral container terminated (should be ignored)",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-terminated-debug",
					Namespace: "namespace3",
				},
				Status: corev1.PodStatus{
					EphemeralContainerStatuses: []corev1.ContainerStatus{
						{
							State: corev1.ContainerState{
								Terminated: &corev1.ContainerStateTerminated{
									ExitCode: 0,
									Reason:   "Completed",
								},
							},
							ImageID: "docker-pullable://busybox@sha256:3",
							Name:    "debugger",
						},
					},
				},
			},
			expected: map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, reflect.DeepEqual(ExtractContainersToImageIDsFromPod(tt.pod), tt.expected))
		})
	}
}

func TestPodToContainerData_EphemeralContainer(t *testing.T) {
	pod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			EphemeralContainers: []corev1.EphemeralContainer{
				{
					EphemeralContainerCommon: corev1.EphemeralContainerCommon{
						Name:  "debugger",
						Image: "busybox:latest",
					},
				},
			},
		},
		Status: corev1.PodStatus{
			EphemeralContainerStatuses: []corev1.ContainerStatus{
				{
					Name:    "debugger",
					Image:   "busybox:latest",
					ImageID: "docker-pullable://busybox@sha256:33333",
				},
			},
		},
	}

	k8sClient := k8sfake.NewClientset(pod)
	k8sAPI := NewK8sInterfaceFake(k8sClient)

	instanceIDs, err := instanceidhandlerv1.GenerateInstanceIDFromRuntimeObj(pod, nil)
	require.NoError(t, err)
	require.Len(t, instanceIDs, 1)

	debugData, err := PodToContainerData(k8sAPI, pod, instanceIDs[0], "test-cluster")
	require.NoError(t, err)
	assert.Equal(t, "debugger", debugData.ContainerName)
	assert.Equal(t, "busybox:latest", debugData.ImageTag)
	assert.Equal(t, "busybox@sha256:33333", debugData.ImageID)
	assert.Equal(t, "ephemeralContainer", debugData.ContainerType)
}
