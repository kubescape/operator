package watcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
	core1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test_extractImageIDsToContainersFromPod(t *testing.T) {
	tests := []struct {
		name     string
		pod      *core1.Pod
		expected map[string][]string
	}{
		{
			name: "one container",
			pod: &core1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name:      "pod1",
					Namespace: "namespace1",
				},
				Status: core1.PodStatus{
					ContainerStatuses: []core1.ContainerStatus{
						{
							State: core1.ContainerState{
								Running: &core1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:1",
							Name:    "container1",
						},
					},
				},
			},
			expected: map[string][]string{"docker-pullable://alpine@sha256:1": {"container1"}},
		},
		{
			name: "two containers",
			pod: &core1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name:      "pod2",
					Namespace: "namespace2",
				},
				Status: core1.PodStatus{
					ContainerStatuses: []core1.ContainerStatus{
						{
							State: core1.ContainerState{
								Running: &core1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:1",
							Name:    "container1",
						},
						{
							State: core1.ContainerState{
								Running: &core1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:2",
							Name:    "container2",
						},
					},
				},
			},
			expected: map[string][]string{
				"docker-pullable://alpine@sha256:1": {"container1"},
				"docker-pullable://alpine@sha256:2": {"container2"},
			},
		},
		{
			name: "init container",
			pod: &core1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name:      "pod2",
					Namespace: "namespace2",
				},
				Status: core1.PodStatus{
					InitContainerStatuses: []core1.ContainerStatus{
						{
							State: core1.ContainerState{
								Running: &core1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:1",
							Name:    "container1",
						},
						{
							State: core1.ContainerState{
								Running: &core1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:2",
							Name:    "container2",
						},
					},
				},
			},
			expected: map[string][]string{
				"docker-pullable://alpine@sha256:1": {"container1"},
				"docker-pullable://alpine@sha256:2": {"container2"},
			},
		},
		{
			name: "two containers with same image",
			pod: &core1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name:      "pod2",
					Namespace: "namespace2",
				},
				Status: core1.PodStatus{
					ContainerStatuses: []core1.ContainerStatus{
						{
							State: core1.ContainerState{
								Running: &core1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:1",
							Name:    "container1",
						},
						{
							State: core1.ContainerState{
								Running: &core1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:1",
							Name:    "container2",
						},
					},
				},
			},
			expected: map[string][]string{
				"docker-pullable://alpine@sha256:1": {"container1", "container2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractImageIDsToContainersFromPod(tt.pod)
			assert.Equal(t, tt.expected, got)
		})
	}
}
