package utils

import (
	"fmt"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/stretchr/testify/assert"
)

func TestSkipContainerProfile(t *testing.T) {
	tests := []struct {
		annotations map[string]string
		name        string
		wantSkip    bool
		expectedErr error
	}{
		{
			name: "status is empty",
			annotations: map[string]string{
				helpersv1.CompletionMetadataKey: "complete",
				helpersv1.StatusMetadataKey:     "",
				helpersv1.WlidMetadataKey:       "wlid",
				helpersv1.InstanceIDMetadataKey: "instanceID",
			},
			wantSkip: false,
		},
		{
			name: "status is Ready",
			annotations: map[string]string{
				helpersv1.CompletionMetadataKey: "complete",
				helpersv1.StatusMetadataKey:     helpersv1.Learning,
				helpersv1.WlidMetadataKey:       "wlid",
				helpersv1.InstanceIDMetadataKey: "instanceID",
			},
			wantSkip: false,
		},
		{
			name: "partial AP",
			annotations: map[string]string{
				helpersv1.CompletionMetadataKey: "partial",
				helpersv1.StatusMetadataKey:     helpersv1.Learning,
				helpersv1.WlidMetadataKey:       "wlid",
				helpersv1.InstanceIDMetadataKey: "instanceID",
			},
			wantSkip: false,
		},
		{
			name: "invalid completion status",
			annotations: map[string]string{
				helpersv1.CompletionMetadataKey: "invalid",
				helpersv1.StatusMetadataKey:     helpersv1.Learning,
				helpersv1.WlidMetadataKey:       "wlid",
				helpersv1.InstanceIDMetadataKey: "instanceID",
			},
			wantSkip: false,
		},
		{
			name: "missing completion status",
			annotations: map[string]string{
				helpersv1.StatusMetadataKey:     helpersv1.Learning,
				helpersv1.WlidMetadataKey:       "wlid",
				helpersv1.InstanceIDMetadataKey: "instanceID",
			},
			wantSkip: false,
		},
		{
			name: "status is Completed",
			annotations: map[string]string{
				helpersv1.CompletionMetadataKey: "complete",
				helpersv1.StatusMetadataKey:     helpersv1.Completed,
				helpersv1.WlidMetadataKey:       "wlid",
				helpersv1.InstanceIDMetadataKey: "instanceID",
			},
			wantSkip: false,
		},
		{
			name: "status is not recognized",
			annotations: map[string]string{
				helpersv1.CompletionMetadataKey: "complete",
				helpersv1.StatusMetadataKey:     "NotRecognized",
			},
			wantSkip:    true,
			expectedErr: fmt.Errorf("invalid status"),
		},
		{
			name:        "no annotations",
			annotations: map[string]string{},
			wantSkip:    true,
			expectedErr: fmt.Errorf("no annotations"),
		},
		{
			name: "missing instance WLID annotation",
			annotations: map[string]string{
				helpersv1.CompletionMetadataKey: "complete",
				helpersv1.StatusMetadataKey:     helpersv1.Learning,
				helpersv1.InstanceIDMetadataKey: "instanceID",
			},
			wantSkip:    true,
			expectedErr: fmt.Errorf("missing WLID annotation"),
		},
		{
			name: "missing instance ID annotation",
			annotations: map[string]string{
				helpersv1.CompletionMetadataKey: "complete",
				helpersv1.StatusMetadataKey:     helpersv1.Learning,
				helpersv1.WlidMetadataKey:       "wlid",
			},
			wantSkip:    true,
			expectedErr: fmt.Errorf("missing InstanceID annotation"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSkip, err := SkipContainerProfile(tt.annotations)
			assert.Equal(t, tt.wantSkip, gotSkip)
			assert.Equal(t, tt.expectedErr, err)
		})
	}
}

func TestHostNodeFromWlid(t *testing.T) {
	tests := []struct {
		name     string
		wlid     string
		wantNode string
		wantOK   bool
	}{
		{name: "host", wlid: "wlid://cluster-unknown/namespace-host/host-worker-1", wantNode: "worker-1", wantOK: true},
		{name: "deployment in a namespace called host", wlid: "wlid://cluster-c/namespace-host/deployment-nginx"},
		{name: "host kind outside the host namespace", wlid: "wlid://cluster-c/namespace-default/host-worker-1"},
		{name: "no node name", wlid: "wlid://cluster-c/namespace-host/host-"},
		{name: "deployment", wlid: "wlid://cluster-c/namespace-default/deployment-nginx"},
		{name: "empty", wlid: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, ok := HostNodeFromWlid(tt.wlid)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantNode, node)
		})
	}
}

func TestContainerProfileFilterNamespace(t *testing.T) {
	// node-agent stores the host profile in its own namespace; the host is filtered as "host".
	assert.Equal(t, HostNamespace, ContainerProfileFilterNamespace("wlid://cluster-unknown/namespace-host/host-worker-1", "kubescape"))
	assert.Equal(t, "payments", ContainerProfileFilterNamespace("wlid://cluster-c/namespace-payments/deployment-api", "payments"))
	assert.Equal(t, "", ContainerProfileFilterNamespace("wlid://cluster-c/namespace-payments/deployment-api", ""))
}
