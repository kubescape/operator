package mainhandler

import (
	"k8s-ca-websocket/cautils"

	"github.com/armosec/armoapi-go/apis"
)

// Extract vuln-scan command from create cronjob command,
// And warp it with commands so the websocket can parse the request
func getVulnScanRequest(command *apis.Command) *apis.Commands {

	c := *command
	c.CommandName = cautils.VulnScan
	c.Args = nil
	commands := apis.Commands{
		Commands: []apis.Command{c},
	}
	return &commands
}
