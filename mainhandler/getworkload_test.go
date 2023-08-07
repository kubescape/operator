package mainhandler

import (
	"testing"

	"github.com/kubescape/k8s-interface/instanceidhandler"
	instanceidhandlerv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
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
		want          string
		found         bool
	}{
		{
			testName:      "test found",
			instanceID:    instanceIDstruct{apiVersion: "v1", namespace: "default", kind: "Pod", name: "Test", containerName: "container"},
			wantContainer: "container",
			found:         true,
			want:          "928a269dc4f125d58cae6db0dd0fecac2f7d5b91fc44cf206796df2a05cc1d37",
		},
		{
			testName:      "test not found",
			instanceID:    instanceIDstruct{apiVersion: "v1", namespace: "default", kind: "Pod", name: "Test", containerName: "container"},
			wantContainer: "container-0",
			found:         false,
			want:          "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			ins := &instanceidhandlerv1.InstanceID{}
			ins.SetAPIVersion(tt.instanceID.apiVersion)
			ins.SetNamespace(tt.instanceID.namespace)
			ins.SetKind(tt.instanceID.kind)
			ins.SetName(tt.instanceID.name)
			ins.SetContainerName(tt.instanceID.containerName)

			got := getContainerID([]instanceidhandler.IInstanceID{ins}, tt.wantContainer)
			if tt.found && got == nil {
				t.Errorf("getContainer() = %v, want %v", got, tt.wantContainer)
			}
			if !tt.found && got != nil {
				t.Errorf("getContainer() = %v, want %v", got, tt.wantContainer)
			}
			if got != nil && got.GetHashed() != tt.want {
				t.Errorf("getContainer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_listWorkloadImages(t *testing.T) {
	instanceID := instanceidhandlerv1.InstanceID{}
	instanceID.SetContainerName("cont")
	type args struct {
		workload    k8sinterface.IWorkload
		instanceIDs []instanceidhandler.IInstanceID
	}
	tests := []struct {
		name string
		args args
		want []ContainerData
	}{
		{
			name: "test found",
			args: args{
				workload: workloadinterface.NewWorkloadObj(map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Pod",
					"spec": map[string]interface{}{
						"initContainers": []interface{}{
							map[string]interface{}{
								"name":  "init",
								"image": "alpine",
							},
						},
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "cont",
								"image": "nginx",
							},
						},
					},
				}),
				instanceIDs: []instanceidhandler.IInstanceID{&instanceID},
			},
			want: []ContainerData{
				{
					container: "cont",
					image:     "docker.io/library/nginx",
				},
				{
					container: "init",
					image:     "docker.io/library/alpine",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := listWorkloadImages(tt.args.workload, tt.args.instanceIDs)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
