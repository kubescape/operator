package mainhandler

import (
	"k8s-ca-websocket/cautils"

	"github.com/armosec/armoapi-go/apis"
	pkgwlid "github.com/armosec/utils-k8s-go/wlid"
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

func getNamespaceFromVulnScanCommand(command *apis.Command) string {
	if command.WildWlid != "" {
		return pkgwlid.GetNamespaceFromWlid(command.WildWlid)
	}

	if len(command.Designators) > 0 {
		return command.Designators[0].GetNamespace()
	}

	return ""
}
