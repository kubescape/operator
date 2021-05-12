package mainhandler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"k8s-ca-websocket/cautils"
	"net/http"

	"github.com/armosec/capacketsgo/apis"
	"github.com/armosec/capacketsgo/k8sinterface"
	reporterlib "github.com/armosec/capacketsgo/system-reports/datastructures"
	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
)

func scanWorkload(wlid string, pod *corev1.Pod, reporter reporterlib.IReporter) error {
	// get all images of workload
	errs := ""
	glog.Infof("in scanWorkload")
	containers, err := getWorkloadImages(wlid, apis.SCAN)
	if err != nil {
		return fmt.Errorf("cant get workloads from k8s, wlid: %s, reason: %s", wlid, err.Error())
	}
	websocketScanCommand := &apis.WebsocketScanCommand{
		Wlid: wlid,
	}
	if reporter != nil {
		websocketScanCommand.JobID = reporter.GetJobID()
		websocketScanCommand.LastAction = reporter.GetActionIDN()
	}

	glog.Infof("iterating over containers")

	for i := range containers {
		websocketScanCommand.ImageTag = containers[i].image
		websocketScanCommand.ContainerName = containers[i].container
		if pod != nil {
			secrets, err := k8sinterface.GetImageRegistryCredentials(websocketScanCommand.ImageTag, pod)
			if err != nil {
				glog.Error(err)
			} else if len(secrets) > 0 {
				if secret, isOk := secrets[websocketScanCommand.ImageTag]; isOk {
					glog.Infof("found relevant secret for: %v", websocketScanCommand.ImageTag)
					websocketScanCommand.Credentials = &secret
				} else {
					glog.Errorf("couldn't find image: %v secret", websocketScanCommand.ImageTag)
				}

			}
		}
		if err := sendWorkloadToVulnerabilityScanner(websocketScanCommand); err != nil {
			glog.Errorf("scanning %v failed due to: %v", websocketScanCommand.ImageTag, err.Error())
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
	hasCreds := websocketScanCommand.Credentials != nil && len(websocketScanCommand.Credentials.Username) > 0 && len(websocketScanCommand.Credentials.Password) > 0
	glog.Infof("requesting scan. url: %s wlid: %s image: %s with credentials: %v", pathScan, websocketScanCommand.Wlid, websocketScanCommand.ImageTag, hasCreds)

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
		return fmt.Errorf("failed posting to vulnerability scanner. query: '%s', reason: %s", websocketScanCommand.ImageTag, err.Error())
	}
	defer resp.Body.Close()
	if resp == nil {
		return fmt.Errorf("failed posting to vulnerability scanner. query: '%s', reason: 'empty response'", websocketScanCommand.ImageTag)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 203 {
		return fmt.Errorf("failed posting to vulnerability scanner. query: '%s', reason: 'received bad status code: %d'", websocketScanCommand.ImageTag, resp.StatusCode)
	}
	return nil
}
