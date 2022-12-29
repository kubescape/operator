package mainhandler

import (
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/stretchr/testify/assert"
)

func getCommandForConfigMap(jobName, cronTabSchedule string) *apis.Command {
	jobParams := apis.CronJobParams{
		JobName:         jobName,
		CronTabSchedule: cronTabSchedule,
	}
	return &apis.Command{
		CommandName: apis.TypeSetVulnScanCronJob,
		WildWlid:    "wlid://cluster-minikube",
		Args: map[string]interface{}{
			"jobParams": jobParams,
		},
	}
}
func TestGetJobParams(t *testing.T) {
	jobName := "aaaa"
	cronTabSchedule := "bbbb"
	command := getCommandForConfigMap(jobName, cronTabSchedule)
	jobParams := getJobParams(command)

	assert.Equal(t, jobParams.JobName, jobName)
	assert.Equal(t, jobParams.CronTabSchedule, cronTabSchedule)

}
