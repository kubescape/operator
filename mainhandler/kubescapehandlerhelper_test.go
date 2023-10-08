package mainhandler

import (
	"fmt"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/utils-go/boolutils"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/kubescape/operator/utils"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/batch/v1"
)

func TestGetKubescapeV1ScanRequest(t *testing.T) {
	{
		actionHandler := ActionHandler{
			command: apis.Command{
				Args: map[string]interface{}{
					utils.KubescapeScanV1: nil,
				},
			},
		}
		req, err := getKubescapeV1ScanRequest(actionHandler.command.Args)
		assert.NoError(t, err)
		assert.NotNil(t, 0, req)
	}
	{
		actionHandler := ActionHandler{
			command: apis.Command{Args: map[string]interface{}{utils.KubescapeScanV1: map[string]interface{}{"format": "json"}}},
		}
		req, err := getKubescapeV1ScanRequest(actionHandler.command.Args)
		assert.NoError(t, err)
		assert.Equal(t, "json", req.Format)
	}
	{
		actionHandler := ActionHandler{
			command: apis.Command{Args: map[string]interface{}{utils.KubescapeScanV1: map[string]interface{}{}}},
		}
		req, err := getKubescapeV1ScanRequest(actionHandler.command.Args)
		assert.NoError(t, err)
		assert.Equal(t, "all", req.TargetNames[0])
		assert.Equal(t, utilsapisv1.KindFramework, req.TargetType)
	}
	{
		actionHandler := ActionHandler{
			command: apis.Command{Args: map[string]interface{}{utils.KubescapeScanV1: map[string]interface{}{"targetType": utilsapisv1.KindFramework, "targetNames": []string{""}}}},
		}
		req, err := getKubescapeV1ScanRequest(actionHandler.command.Args)
		assert.NoError(t, err)
		assert.Equal(t, "all", req.TargetNames[0])
		assert.Equal(t, utilsapisv1.KindFramework, req.TargetType)
	}
}

func TestUpdateCronJobTemplate(t *testing.T) {
	{
		jobTemplateObj := &v1.CronJob{}
		name := "1234"
		schedule := "* * * * *"
		jobID := "5678"
		setCronJobTemplate(jobTemplateObj, name, schedule, jobID, "nsa", utilsapisv1.KindFramework, boolutils.BoolPointer(true))
		assert.Equal(t, name, jobTemplateObj.ObjectMeta.Name)
		assert.Equal(t, schedule, jobTemplateObj.Spec.Schedule)
		assert.Equal(t, jobID, jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations["armo.jobid"])
		assert.Equal(t, "nsa", jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations["armo.framework"])
		assert.Equal(t, "true", jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations["armo.host-scanner"])
	}
}

func TestFixK8sNameLimit(t *testing.T) {
	if res := fixK8sNameLimit("AA-bb-", 63); res != "aa-bb" {
		t.Errorf("invalid k8s:%s", res)
	}
	if res := fixK8sNameLimit("aa-bb-fddddddddddddDDDDDdfdsfsdfdsfdsere122347985-046mntwensd8yf98", 63); res != "aa-bb-fddddddddddddddddddfdsfsdfdsfdsere122347985-046mntwensd8y" {
		t.Errorf("invalid k8s:%s", res)
	}
	if res := fixK8sNameLimit("aa-bb-fddddddddddddDDDDDdfdsfsdfdsfdsere122347985_046mntwensd--f98", 63); res != "aa-bb-fddddddddddddddddddfdsfsdfdsfdsere122347985-046mntwensd" {
		t.Errorf("invalid k8s:%s", res)
	}

}

func TestGetKubescapeV1ScanURL(t *testing.T) {
	clusterConfig := utilsmetadata.ClusterConfig{
		KubescapeURL: "kubescape",
	}
	u := getKubescapeV1ScanURL(clusterConfig)
	assert.Equal(t, "http://kubescape/v1/scan?keep=false", u.String())
}

func TestGetKubescapeV1ScanStatusURL(t *testing.T) {
	clusterConfig := utilsmetadata.ClusterConfig{
		KubescapeURL: "armo-kubescape:8080",
	}
	url := getKubescapeV1ScanStatusURL(clusterConfig, "123").String()
	assert.Equal(t, url, "http://armo-kubescape:8080/v1/status?ID=123", "getKubescapeV1ScanStatusURL failed")
}

func TestAppendSecurityFramework(t *testing.T) {
	tests := []struct {
		name            string
		postScanRequest *utilsmetav1.PostScanRequest
		expected        *utilsmetav1.PostScanRequest
	}{
		{
			name:            "framework scan with one framework ",
			postScanRequest: &utilsmetav1.PostScanRequest{TargetType: utilsapisv1.KindFramework, TargetNames: []string{"nsa"}},
			expected:        &utilsmetav1.PostScanRequest{TargetType: utilsapisv1.KindFramework, TargetNames: []string{"nsa", "security"}},
		},
		{
			name:            "framework scan with all",
			postScanRequest: &utilsmetav1.PostScanRequest{TargetType: utilsapisv1.KindFramework, TargetNames: []string{"all"}},
			expected:        &utilsmetav1.PostScanRequest{TargetType: utilsapisv1.KindFramework, TargetNames: []string{"all"}},
		},
		{
			name:            "framework scan with security",
			postScanRequest: &utilsmetav1.PostScanRequest{TargetType: utilsapisv1.KindFramework, TargetNames: []string{"security"}},
			expected:        &utilsmetav1.PostScanRequest{TargetType: utilsapisv1.KindFramework, TargetNames: []string{"security"}},
		},
		{
			name:            "not framework scan",
			postScanRequest: &utilsmetav1.PostScanRequest{TargetType: utilsapisv1.KindControl, TargetNames: []string{"c-0001"}},
			expected:        &utilsmetav1.PostScanRequest{TargetType: utilsapisv1.KindControl, TargetNames: []string{"c-0001"}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			appendSecurityFramework(test.postScanRequest)
			assert.Equal(t, test.expected, test.postScanRequest)
		})
	}

}

func Test_appendSecurityFramework(t *testing.T) {
	type args struct {
		postScanRequest *utilsmetav1.PostScanRequest
	}
	tests := []struct {
		args     args
		name     string
		expected []string
	}{
		{
			name: "framework scan with one framework ",
			args: args{
				postScanRequest: &utilsmetav1.PostScanRequest{TargetType: utilsapisv1.KindFramework, TargetNames: []string{"nsa"}},
			},
			expected: []string{"nsa", "security"},
		},
		{
			name: "framework scan with all",
			args: args{
				postScanRequest: &utilsmetav1.PostScanRequest{TargetType: utilsapisv1.KindFramework, TargetNames: []string{"all"}},
			},
			expected: []string{"all", "security"},
		},
		{
			name: "framework scan with security",
			args: args{
				postScanRequest: &utilsmetav1.PostScanRequest{TargetType: utilsapisv1.KindFramework, TargetNames: []string{"security"}},
			},
			expected: []string{"security"},
		},
		{
			name: "not framework scan",
			args: args{
				postScanRequest: &utilsmetav1.PostScanRequest{TargetType: utilsapisv1.KindControl, TargetNames: []string{"c-0001"}},
			},
			expected: []string{"c-0001"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appendSecurityFramework(tt.args.postScanRequest)
			assert.Equal(t, fmt.Sprint(tt.args.postScanRequest.TargetNames), fmt.Sprint(tt.expected))
		})
	}
}
