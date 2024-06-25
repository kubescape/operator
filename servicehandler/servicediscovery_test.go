package servicehandler

import (
	"fmt"
	"testing"
)

var TestAuthentications = ServicreAuthenticaion{
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
	obj := TestAuthentications.Unstructured()
	fmt.Print(obj)
	if obj == nil {
		t.Errorf("Unstructured() returned nil")
	}

}
