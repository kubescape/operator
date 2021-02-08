package websocket

import (
	"bytes"
	"encoding/json"
	"fmt"
	"k8s-ca-websocket/cautils"
	"net/http"

	"asterix.cyberarmor.io/cyberarmor/capacketsgo/apis"
	"github.com/golang/glog"
)

func scanWorkload(wlid string) error {
	// get all images of workload
	errs := ""
	containers, err := getWorkloadImages(wlid, apis.SCAN)
	if err != nil {
		return fmt.Errorf("cant get workloads from k8s, wlid: %s, reason: %s", wlid, err.Error())
	}
	websocketScanCommand := &apis.WebsocketScanCommand{
		Wlid: wlid,
	}
	for i := range containers {
		websocketScanCommand.ImageTag = containers[i].image
		websocketScanCommand.ContainerName = containers[i].container
		if err := sendWorkloadToVulnerabilityScanner(websocketScanCommand); err != nil {
			errs += fmt.Sprintf("failed scanning, wlid: '%s', image: '%s', container: %s, reason: %s", wlid, containers[i].image, containers[i].container, err.Error())
		}
	}
	if errs != "" {
		return fmt.Errorf(errs)
	}
	return nil
}

func sendWorkloadToVulnerabilityScanner(websocketScanCommand *apis.WebsocketScanCommand) error {

	jsonScannerC, err := json.Marshal(websocketScanCommand)
	if err != nil {
		return err
	}
	pathScan := fmt.Sprintf("%s/%s/%s", cautils.CA_VULNSCAN, apis.WebsocketScanCommandVersion, apis.WebsocketScanCommandPath)
	glog.Infof("requesting scan. url: %s, data: %s", pathScan, string(jsonScannerC))

	req, err := http.NewRequest("POST", pathScan, bytes.NewBuffer(jsonScannerC))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	// q := req.URL.Query()
	// q.Add("imageTag", websocketScanCommand.ImageTag)
	// q.Add("isScanned", strconv.FormatBool(websocketScanCommand.IsScanned))
	// req.URL.RawQuery = q.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed posting to vulnerability scanner. query: '%s', reason: %s", string(jsonScannerC), err.Error())
	}
	defer resp.Body.Close()
	if resp == nil {
		return fmt.Errorf("failed posting to vulnerability scanner. query: '%s', reason: 'empty response'", string(jsonScannerC))
	}

	if resp.StatusCode > 200 || resp.StatusCode > 203 {
		return fmt.Errorf("failed posting to vulnerability scanner. query: '%s', reason: 'received bad status code: %d'", string(jsonScannerC), resp.StatusCode)
	}
	return nil
}
