package websocket

import (
	"fmt"
	"k8s-ca-websocket/cautils"
	"net/http"
	"strconv"

	"asterix.cyberarmor.io/cyberarmor/capacketsgo/apis"
)

func sendWorkloadToVulnerabilityScanner(websocketScanCommand *apis.WebsocketScanCommand) error {
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/%s/%s", cautils.CA_VULNSCAN, apis.WebsocketScanCommandVersion, apis.WebsocketScanCommandPath), nil)
	req.Header.Set("Content-Type", "application/json")
	q := req.URL.Query()
	// q.Add("customerGUID", cautils.CA_CUSTOMER_GUID)
	q.Add("imageTag", websocketScanCommand.ImageTag)
	q.Add("isScanned", strconv.FormatBool(websocketScanCommand.IsScanned))
	req.URL.RawQuery = q.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed posting to vulnerability scanner. query: '%s', reason: %s", req.URL.RawQuery, err.Error())
	}
	defer resp.Body.Close()
	return nil
}
