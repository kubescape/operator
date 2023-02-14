package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateInstanceID(t *testing.T) {
	tests := []struct {
		testName         string
		parentApiVersion string
		namespace        string
		kind             string
		name             string
		resourceVersion  string
		containerName    string
		want             string
	}{
		{
			testName:         "test upper case",
			parentApiVersion: "v1",
			namespace:        "Default",
			kind:             "Pod",
			name:             "Test",
			resourceVersion:  "1",
			containerName:    "container",
			want:             "apiversion-v1/namespace-default/kind-pod/name-test/resourceversion-1/container-container",
		},
		{
			testName:         "test lower case",
			parentApiVersion: "v1",
			namespace:        "default",
			kind:             "pod",
			name:             "test",
			resourceVersion:  "1",
			containerName:    "container",
			want:             "apiversion-v1/namespace-default/kind-pod/name-test/resourceversion-1/container-container",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateInstanceID(tt.parentApiVersion, tt.namespace, tt.kind, tt.name, tt.resourceVersion, tt.containerName)
			assert.Equal(t, tt.want, got)
		})
	}
}
