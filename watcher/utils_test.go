package watcher

import (
	"reflect"
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
			expected: map[string][]string{"alpine@sha256:1": {"container1"}},
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
				"alpine@sha256:1": {"container1"},
				"alpine@sha256:2": {"container2"},
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
				"alpine@sha256:1": {"container1"},
				"alpine@sha256:2": {"container2"},
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

func Test_extractImageIDsFromPod(t *testing.T) {
	tests := []struct {
		name     string
		pod      *core1.Pod
		expected []string
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
			expected: []string{"alpine@sha256:1"},
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
			expected: []string{"alpine@sha256:1", "alpine@sha256:2"},
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
			expected: []string{"alpine@sha256:1", "alpine@sha256:2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, reflect.DeepEqual(extractImageIDsFromPod(tt.pod), tt.expected))
		})
	}
}

func Test_extractImageHash(t *testing.T) {
	tt := []struct {
		name              string
		inputImageID      string
		expectedImageHash string
		expectedError     error
	}{
		{
			name:              "Extracting from imageHash should return the same hash",
			inputImageID:      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
			expectedImageHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		{
			name:              "Extracting from hashType:imageHash should return the expected hash",
			inputImageID:      "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
			expectedImageHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		{
			name:              "Extracting from imageTag@hashType:imageHash should return the expected hash",
			inputImageID:      "alpine@sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
			expectedImageHash: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		{
			name:              "Extracting from repoName/imageTag@hashType:imageHash should return the expected hash",
			inputImageID:      "registry.k8s.io/kube-apiserver:v1.25.4@sha256:00631e54acba3a4d507a9f7b7095a81151b8a8f909f93e50f64269ea39daf2cf",
			expectedImageHash: "00631e54acba3a4d507a9f7b7095a81151b8a8f909f93e50f64269ea39daf2cf",
		},
		{
			name:              "Extracting from invalid value less than 64 chars should return an error",
			inputImageID:      "this is definitely not a valid imageID",
			expectedImageHash: "",
			expectedError:     errInvalidImageID,
		},
		{
			name:              "Extracting from invalid value over 63 chars should return an error",
			inputImageID:      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890!@#$%^&*()",
			expectedImageHash: "",
			expectedError:     errInvalidImageID,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			actualImageHash, err := extractImageHash(tc.inputImageID)

			assert.Equal(t, tc.expectedImageHash, actualImageHash)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}
