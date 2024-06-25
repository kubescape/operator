package servicehandler

import (
	"testing"
)

var TestAuthentications = ServiceAuthentication{
	kind:       "ServiceScanResult",
	apiVersion: "servicesscanresults",
	metadata: struct {
		name      string
		namespace string
	}{
		name:      "test",
		namespace: "test",
	},
	spec: struct {
		clusterIP string
		ports     []Port
	}{
		clusterIP: "127.0.0.1",
		ports: []Port{
			{
				port:              80,
				protocol:          "TCP",
				sessionLayer:      "test",
				presentationLayer: "test",
				applicationLayer:  "test",
				authenticated:     true,
			},
			{
				port:              443,
				protocol:          "TCP",
				sessionLayer:      "test",
				presentationLayer: "test",
				applicationLayer:  "test",
				authenticated:     true,
			},
		},
	},
}

func TestUnstructured(t *testing.T) {
	obj, err := TestAuthentications.Unstructured()
	if err == nil {
		t.Errorf("Unstructured() got an error: %v", err)
	}
	if obj == nil {
		t.Errorf("Unstructured() returned nil")
	}
}
