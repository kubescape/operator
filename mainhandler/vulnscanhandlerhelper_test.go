package mainhandler

import (
	"k8s-ca-websocket/cautils"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
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
	commandsScan := getVulnScanRequest(commandSet)
	assert.NotEqual(t, commandsScan.Commands[0].CommandName, commandSet.CommandName)
	assert.Equal(t, commandsScan.Commands[0].CommandName, (apis.NotificationPolicyType)(cautils.VulnScan))
	assert.Equal(t, commandsScan.Commands[0].Args, map[string]interface{}(nil))

}

func TestGetNamespaceFromVulnScanCommand(t *testing.T) {
	tests := []struct {
		name              string
		command           *apis.Command
		expectedNamespace string
	}{
		{
			name: "no namespace in WildWlid - empty string",
			command: &apis.Command{
				CommandName: apis.TypeSetVulnScanCronJob,
				WildWlid:    "wlid://cluster-minikube-moshe",
				Args: map[string]interface{}{
					"jobParams": apis.CronJobParams{
						JobName:         "",
						CronTabSchedule: "",
					},
				},
			},
			expectedNamespace: "",
		},
		{
			name: "invalid command - empty string",
			command: &apis.Command{
				CommandName: apis.TypeSetVulnScanCronJob,
				Args: map[string]interface{}{
					"jobParams": apis.CronJobParams{
						JobName:         "",
						CronTabSchedule: "",
					},
				},
			},
			expectedNamespace: "",
		},
		{
			name: "namespace from designators",
			command: &apis.Command{
				CommandName: apis.TypeSetVulnScanCronJob,
				Designators: []armotypes.PortalDesignator{
					{
						DesignatorType: armotypes.DesignatorAttributes,
						Attributes: map[string]string{
							armotypes.AttributeCluster:   "minikube",
							armotypes.AttributeNamespace: "test-333",
						},
					},
				},
				Args: map[string]interface{}{
					"jobParams": apis.CronJobParams{
						JobName:         "",
						CronTabSchedule: "",
					},
				},
			},
			expectedNamespace: "test-333",
		},
		{
			name: "namespace from WildWlid",
			command: &apis.Command{
				CommandName: apis.TypeSetVulnScanCronJob,
				WildWlid:    "wlid://cluster-minikube-moshe/namespace-test-123",
				Args: map[string]interface{}{
					"jobParams": apis.CronJobParams{
						JobName:         "",
						CronTabSchedule: "",
					},
				},
			},
			expectedNamespace: "test-123",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ns := getNamespaceFromVulnScanCommand(tc.command)
			assert.Equal(t, tc.expectedNamespace, ns)
		})
	}
}
