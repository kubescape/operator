package utils

import (
	"fmt"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/stretchr/testify/assert"
)

func TestSkipApplicationProfile(t *testing.T) {
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
				helpersv1.StatusMetadataKey:     helpersv1.Ready,
				helpersv1.WlidMetadataKey:       "wlid",
				helpersv1.InstanceIDMetadataKey: "instanceID",
			},
			wantSkip: false,
		},
		{
			name: "partial AP",
			annotations: map[string]string{
				helpersv1.CompletionMetadataKey: "partial",
				helpersv1.StatusMetadataKey:     helpersv1.Ready,
				helpersv1.WlidMetadataKey:       "wlid",
				helpersv1.InstanceIDMetadataKey: "instanceID",
			},
			wantSkip:    true,
			expectedErr: fmt.Errorf("partial - workload restart required"),
		},
		{
			name: "invalid completion status",
			annotations: map[string]string{
				helpersv1.CompletionMetadataKey: "invalid",
				helpersv1.StatusMetadataKey:     helpersv1.Ready,
				helpersv1.WlidMetadataKey:       "wlid",
				helpersv1.InstanceIDMetadataKey: "instanceID",
			},
			wantSkip:    true,
			expectedErr: fmt.Errorf("partial - workload restart required"),
		},
		{
			name: "missing completion status",
			annotations: map[string]string{
				helpersv1.StatusMetadataKey:     helpersv1.Ready,
				helpersv1.WlidMetadataKey:       "wlid",
				helpersv1.InstanceIDMetadataKey: "instanceID",
			},
			wantSkip:    true,
			expectedErr: fmt.Errorf("partial - workload restart required"),
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
				helpersv1.StatusMetadataKey:     helpersv1.Ready,
				helpersv1.InstanceIDMetadataKey: "instanceID",
			},
			wantSkip:    true,
			expectedErr: fmt.Errorf("missing WLID annotation"),
		},
		{
			name: "missing instance ID annotation",
			annotations: map[string]string{
				helpersv1.CompletionMetadataKey: "complete",
				helpersv1.StatusMetadataKey:     helpersv1.Ready,
				helpersv1.WlidMetadataKey:       "wlid",
			},
			wantSkip:    true,
			expectedErr: fmt.Errorf("missing InstanceID annotation"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSkip, err := SkipApplicationProfile(tt.annotations)
			assert.Equal(t, tt.wantSkip, gotSkip)
			assert.Equal(t, tt.expectedErr, err)
		})
	}
}
