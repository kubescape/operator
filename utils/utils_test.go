package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	core1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestExtractContainersToImageIDsFromPod(t *testing.T) {
	tests := []struct {
		name     string
		pod      *core1.Pod
		expected map[string]string
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
							ImageID: "docker-pullable://alpine@sha256:13e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
							Name:    "container1",
						},
					},
				},
			},
			expected: map[string]string{
				"container1": "docker.io/library/alpine@sha256:13e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
			},
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
							ImageID: "docker-pullable://alpine@sha256:13e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
							Name:    "container1",
						},
						{
							State: core1.ContainerState{
								Running: &core1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:23e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
							Name:    "container2",
						},
					},
				},
			},
			expected: map[string]string{
				"container1": "docker.io/library/alpine@sha256:13e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
				"container2": "docker.io/library/alpine@sha256:23e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
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
							ImageID: "docker-pullable://alpine@sha256:13e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
							Name:    "container1",
						},
						{
							State: core1.ContainerState{
								Running: &core1.ContainerStateRunning{},
							},
							ImageID: "docker-pullable://alpine@sha256:23e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
							Name:    "container2",
						},
					},
				},
			},
			expected: map[string]string{
				"container1": "docker.io/library/alpine@sha256:13e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
				"container2": "docker.io/library/alpine@sha256:23e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ExtractContainersToImageIDsFromPod(tt.pod))
		})
	}
}
