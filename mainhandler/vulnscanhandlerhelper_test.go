package mainhandler

import (
	"k8s-ca-websocket/cautils"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/stretchr/testify/assert"
)

func getSetCronjobCommand() *apis.Command {
	jobParams := apis.CronJobParams{
		JobName:         "",
		CronTabSchedule: "",
	}
	return &apis.Command{
		CommandName: apis.TypeSetVulnScanCronJob,
		WildWlid:    "wlid://cluster-minikube-moshe",
		Args: map[string]interface{}{
			"jobParams": jobParams,
		},
	}
}

// Extract vuln-scan command from create cronjob command
func TestGetVulnScanRequest(t *testing.T) {
	commandSet := getSetCronjobCommand()
	commandScan := getVulnScanRequest(commandSet)
	assert.NotEqual(t, commandScan.CommandName, commandSet.CommandName)
	assert.Equal(t, commandScan.CommandName, (apis.NotificationPolicyType)(cautils.VulnScan))
	assert.Equal(t, commandScan.Args, map[string]interface{}(nil))

}
