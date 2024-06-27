package servicehandler

import (
	"testing"

	v1 "k8s.io/api/core/v1"
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

func TestContains(t *testing.T) {
	services := currentServiceList{
		{"test", "test"},
	}
	if !services.contains("test", "test") {
		t.Errorf("contains() returned false")
	}
}

func TestInitialPorts(t *testing.T) {
	ports := []v1.ServicePort{
		{
			Port:     80,
			Protocol: "TCP",
		},
		{
			Port:     443,
			Protocol: "TCP",
		},
	}
	TestAuthentications.initialPorts(ports)
	if len(TestAuthentications.spec.ports) != 2 {
		t.Errorf("initialPorts() did not add all ports")
	}
}

//TODO: Add more tests

//TODO use fake client

//TODO add tests to strict functionallity

//TODO use kwok for perfomnace by using scale
