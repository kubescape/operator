package mainhandler

import (
	"context"
	_ "embed"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
)

//go:embed testdata/vulnscan/pod.json
var podJson []byte

//go:embed testdata/vulnscan/deployment.json
var deploymentJson []byte

func TestGetPodByWLID(t *testing.T) {
	tests := []struct {
		name              string
		workloadObj       []byte
		expectedPhase     v1.PodPhase
		expectedNamespace string
	}{
		{
			name:              "pod with status",
			workloadObj:       podJson,
			expectedPhase:     v1.PodPhase("Running"),
			expectedNamespace: "default",
		},
		{
			name:              "workload no status",
			workloadObj:       deploymentJson,
			expectedPhase:     v1.PodPhase(""),
			expectedNamespace: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workload, err := workloadinterface.NewWorkload(tt.workloadObj)
			assert.NoError(t, err)
			got := getPodByWLID(context.TODO(), workload)
			assert.Equal(t, tt.expectedPhase, got.Status.Phase)
			assert.Equal(t, tt.expectedNamespace, got.Namespace)
		})
	}
}

func TestGetContainerToImageIDsFromPod(t *testing.T) {
	tests := []struct {
		name                        string
		pod                         *v1.Pod
		expectedContainerToImageIDs map[string]string
	}{
		{
			name: "docker-pullable prefix",
			pod: &v1.Pod{
				Status: v1.PodStatus{
					ContainerStatuses: []v1.ContainerStatus{
						{
							Name:    "test",
							ImageID: "docker-pullable://test",
						},
					},
				},
			},
			expectedContainerToImageIDs: map[string]string{
				"test": "test",
			},
		},
		{
			name: "no docker-pullable prefix",
			pod: &v1.Pod{
				Status: v1.PodStatus{
					ContainerStatuses: []v1.ContainerStatus{
						{
							Name:    "test",
							ImageID: "test",
						},
					},
				},
			},
			expectedContainerToImageIDs: map[string]string{
				"test": "test",
			},
		},
		{
			name: "two containers",
			pod: &v1.Pod{
				Status: v1.PodStatus{
					ContainerStatuses: []v1.ContainerStatus{
						{
							Name:    "test",
							ImageID: "docker-pullable://test",
						},
						{
							Name:    "test2",
							ImageID: "docker-pullable://test2",
						},
					},
				},
			},
			expectedContainerToImageIDs: map[string]string{
				"test":  "test",
				"test2": "test2",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedContainerToImageIDs, getContainerToImageIDsFromPod(tt.pod))
		})
	}
}

func TestGetImageIDFromContainer(t *testing.T) {
	tests := []struct {
		name      string
		container ContainerData
		imageID   string
		expected  string
	}{
		{
			name: "sha prefix",
			container: ContainerData{
				image: "docker.io/kindest/kindnetd:v20220726-ed811e41",
			},
			imageID:  "sha256:d921cee8494827575ce8b9cc6cf7dae988b6378ce3f62217bf430467916529b9",
			expected: "docker.io/kindest/kindnetd:v20220726-ed811e41@sha256:d921cee8494827575ce8b9cc6cf7dae988b6378ce3f62217bf430467916529b9",
		},
		{
			name: "no sha prefix",
			container: ContainerData{
				image: "nginx:latest",
			},
			imageID:  "nginx@sha256:d921cee8494827575ce8b9cc6cf7dae988b6378ce3f62217bf430467916529b9",
			expected: "nginx@sha256:d921cee8494827575ce8b9cc6cf7dae988b6378ce3f62217bf430467916529b9",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, getImageIDFromContainer(tt.container, tt.imageID))
		})
	}
}
