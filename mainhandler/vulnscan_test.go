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
			name:              "TestGetPodByWLID",
			workloadObj:       podJson,
			expectedPhase:     v1.PodPhase("Running"),
			expectedNamespace: "default",
		},
		{
			name:              "TestGetPodByWLID",
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
