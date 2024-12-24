package utils

import (
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/stretchr/testify/assert"
)

func TestSkipApplicationProfile(t *testing.T) {
	tests := []struct {
		annotations map[string]string
		name        string
		wantSkip    bool
	}{
		{
			name: "status is empty",
			annotations: map[string]string{
				helpersv1.StatusMetadataKey: "",
			},
			wantSkip: false,
		},
		{
			name: "status is Ready",
			annotations: map[string]string{
				helpersv1.StatusMetadataKey: helpersv1.Ready,
			},
			wantSkip: false,
		},
		{
			name: "status is Completed",
			annotations: map[string]string{
				helpersv1.StatusMetadataKey: helpersv1.Completed,
			},
			wantSkip: false,
		},
		{
			name: "status is not recognized",
			annotations: map[string]string{
				helpersv1.StatusMetadataKey: "NotRecognized",
			},
			wantSkip: true,
		},
		{
			name:        "no status annotation",
			annotations: map[string]string{},
			wantSkip:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSkip, _ := SkipApplicationProfile(tt.annotations)
			assert.Equal(t, tt.wantSkip, gotSkip)
		})
	}
}
