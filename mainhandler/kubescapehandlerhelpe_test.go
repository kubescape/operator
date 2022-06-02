package mainhandler

import (
	"k8s-ca-websocket/cautils"
	"testing"

	utilsapisv1 "github.com/armosec/opa-utils/httpserver/apis/v1"
	"github.com/armosec/utils-go/boolutils"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/batch/v1"

	"github.com/armosec/armoapi-go/apis"
)

func TestGetKubescapeV1ScanRequest(t *testing.T) {
	{
		actionHandler := ActionHandler{
			command: apis.Command{
				Args: map[string]interface{}{
					cautils.KubescapeScanV1: nil,
				},
			},
		}
		req, err := getKubescapeV1ScanRequest(actionHandler.command.Args)
		assert.NoError(t, err)
		assert.NotNil(t, 0, req)
	}
	{
		actionHandler := ActionHandler{
			command: apis.Command{Args: map[string]interface{}{cautils.KubescapeScanV1: map[string]interface{}{"format": "json"}}},
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
	cautils.ClusterConfig.KubescapeURL = "kubescape"
	u := getKubescapeV1ScanURL()
	assert.Equal(t, "http://kubescape/v1/scan?keep=true", u.String())
}

func TestGetKubescapeV1ScanStatusURL(t *testing.T) {
	cautils.ClusterConfig.KubescapeURL = "armo-kubescape:8080"
	url := getKubescapeV1ScanStatusURL("123").String()
	assert.Equal(t, url, "http://armo-kubescape:8080/v1/status?ID=123", "getKubescapeV1ScanStatusURL failed unitest")
}
