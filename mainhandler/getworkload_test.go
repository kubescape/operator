package mainhandler

import (
	"testing"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
)

func Test_getContainer(t *testing.T) {
	type instanceIDstruct struct {
		apiVersion    string
		namespace     string
		kind          string
		name          string
		containerName string
	}
	tests := []struct {
		instanceID    instanceIDstruct
		testName      string
		wantContainer string
		found         bool
	}{
		{
			testName:      "test found",
			instanceID:    instanceIDstruct{apiVersion: "v1", namespace: "default", kind: "Pod", name: "Test", containerName: "container"},
			wantContainer: "container",
			found:         true,
		},
		{
			testName:      "test not found",
			instanceID:    instanceIDstruct{apiVersion: "v1", namespace: "default", kind: "Pod", name: "Test", containerName: "container"},
			wantContainer: "container-0",
			found:         false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			ins := &instanceidhandler.InstanceID{}
			ins.SetAPIVersion(tt.instanceID.apiVersion)
			ins.SetNamespace(tt.instanceID.namespace)
			ins.SetKind(tt.instanceID.kind)
			ins.SetName(tt.instanceID.name)
			ins.SetContainerName(tt.instanceID.containerName)

			got := getContainerID([]*instanceidhandler.InstanceID{ins}, tt.wantContainer)
			if tt.found && got == "" {
				t.Errorf("getContainer() = %v, want %v", got, tt.wantContainer)
			}
			if !tt.found && got != "" {
				t.Errorf("getContainer() = %v, want %v", got, tt.wantContainer)
			}
		})
	}
}
