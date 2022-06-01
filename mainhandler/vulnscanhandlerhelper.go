package mainhandler

import (
	"k8s-ca-websocket/cautils"

	"github.com/armosec/armoapi-go/apis"
)

// Extract vuln-scan command from create cronjob command
func getVulnScanRequest(command *apis.Command) *apis.Command {
	c := *command
	c.CommandName = cautils.VulnScan
	c.Args = nil

	return &c
}
