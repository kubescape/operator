package mainhandler

import (
	"testing"

	"github.com/kubescape/operator/utils"

	"github.com/armosec/utils-go/boolutils"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/batch/v1"

	"github.com/armosec/armoapi-go/apis"
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
	utils.ClusterConfig.KubescapeURL = "kubescape"
	u := getKubescapeV1ScanURL()
	assert.Equal(t, "http://kubescape/v1/scan?keep=false", u.String())
}

func TestGetKubescapeV1ScanStatusURL(t *testing.T) {
	utils.ClusterConfig.KubescapeURL = "armo-kubescape:8080"
	url := getKubescapeV1ScanStatusURL("123").String()
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
