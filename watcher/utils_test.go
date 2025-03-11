package watcher

import (
	"reflect"
	"testing"

	"github.com/kubescape/operator/utils"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test_extractImageIDsFromPod(t *testing.T) {
	tests := []struct {
		name     string
		pod      *corev1.Pod
		expected []string
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
			expected: []string{"alpine@sha256:1"},
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
			expected: []string{"alpine@sha256:1", "alpine@sha256:2"},
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
			expected: []string{"alpine@sha256:1", "alpine@sha256:2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, reflect.DeepEqual(extractImageIDsFromPod(tt.pod), tt.expected))
		})
	}
}
func Test_extractImageIDsToContainersFromPod(t *testing.T) {
	tests := []struct {
		pod      *corev1.Pod
		expected map[string][]string
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
			expected: map[string][]string{"alpine@sha256:1": {"container1"}},
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
			expected: map[string][]string{
				"alpine@sha256:1": {"container1"},
				"alpine@sha256:2": {"container2"},
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
			expected: map[string][]string{
				"alpine@sha256:1": {"container1"},
				"alpine@sha256:2": {"container2"},
			},
		},
		{
			name: "two containers with same image",
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
							ImageID: "docker-pullable://alpine@sha256:1",
							Name:    "container2",
						},
					},
				},
			},
			expected: map[string][]string{
				"alpine@sha256:1": {"container1", "container2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, reflect.DeepEqual(extractImageIDsToContainersFromPod(tt.pod), tt.expected))
		})
	}
}

func TestGetWlidAndImageID(t *testing.T) {
	containerData := &utils.ContainerData{
		Wlid:          "wlid1",
		ContainerName: "container1",
		ImageID:       "imageID1",
	}

	expected := "wlid1container1imageID1"
	result := getWlidAndImageID(containerData)

	assert.Equal(t, expected, result)
}
