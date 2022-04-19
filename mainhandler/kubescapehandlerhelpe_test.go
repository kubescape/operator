package mainhandler

import (
	"k8s-ca-websocket/cautils"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/batch/v1"

	"github.com/armosec/armoapi-go/apis"
)

func TestGetKubescapeV1ScanRequest(t *testing.T) {
	{
		actionHandler := ActionHandler{
			command: apis.Command{
				Args: map[string]interface{}{
					cautils.KubescapeRequestPathV1: nil,
				},
			},
		}
		req, err := getKubescapeV1ScanRequest(actionHandler.command.Args)
		assert.NoError(t, err)
		assert.NotEqual(t, 0, len(req))
	}
	{
		actionHandler := ActionHandler{
			command: apis.Command{Args: map[string]interface{}{cautils.KubescapeRequestPathV1: map[string]interface{}{"format": "json"}}},
		}
		req, err := getKubescapeV1ScanRequest(actionHandler.command.Args)
		assert.NoError(t, err)
		assert.NotEqual(t, 0, len(req))
	}
}

func TestUpdateCronJobTemplate(t *testing.T) {
	{
		jobTemplateObj := &v1.CronJob{}
		name := "1234"
		jobID := "5678"
		updateCronJobTemplate(jobTemplateObj, name, jobID, "")
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
