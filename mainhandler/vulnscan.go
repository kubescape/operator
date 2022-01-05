package mainhandler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"k8s-ca-websocket/cautils"
	"net/http"
	"strings"

	corev1 "k8s.io/api/core/v1"

	pkgwlid "github.com/armosec/utils-k8s-go/wlid"
	uuid "github.com/satori/go.uuid"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/k8s-interface/cloudsupport"
	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/golang/glog"
)

func (actionHandler *ActionHandler) scanWorkload() error {
	pod, err := actionHandler.getPodByWLID(actionHandler.wlid)
	if err != nil {
		glog.Errorf("scanning might fail if some images require credentials")
	}
	// get all images of workload
	errs := ""
	glog.Infof("in scanWorkload")
	containers, err := getWorkloadImages(actionHandler.k8sAPI, actionHandler.wlid)
	if err != nil {
		return fmt.Errorf("cant get workloads from k8s, wlid: %s, reason: %s", actionHandler.wlid, err.Error())
	}
	// we want running pod in order to have the image hash
	actionHandler.getRunningPodDescription(pod)

	glog.Infof("iterating over containers")

	for i := range containers {

		websocketScanCommand := &apis.WebsocketScanCommand{
			Wlid:          actionHandler.wlid,
			ImageTag:      containers[i].image,
			ContainerName: containers[i].container,
		}
		if actionHandler.reporter != nil {
			websocketScanCommand.ParentJobID = actionHandler.reporter.GetJobID()
			websocketScanCommand.LastAction = actionHandler.reporter.GetActionIDN()
			websocketScanCommand.JobID = uuid.NewV4().String()
		}
		for contIdx := range pod.Status.ContainerStatuses {
			if pod.Status.ContainerStatuses[contIdx].Name == containers[i].container {
				const dockerPullableURN string = "docker-pullable://"
				imageNameWithHash := pod.Status.ContainerStatuses[contIdx].ImageID
				if strings.HasPrefix(imageNameWithHash, dockerPullableURN) {
					imageNameWithHash = imageNameWithHash[len(dockerPullableURN):]
				}
				websocketScanCommand.ImageHash = imageNameWithHash
			}
		}
		if pod != nil {
			secrets, err := cloudsupport.GetImageRegistryCredentials(websocketScanCommand.ImageTag, pod)
			if err != nil {
				glog.Error(err)
			} else if len(secrets) > 0 {
				for secretName := range secrets {
					websocketScanCommand.Credentialslist = append(websocketScanCommand.Credentialslist, secrets[secretName])
				}

				/*
					the websocketScanCommand.Credentials is depracated, still use it for backward compstability
				*/
				if len(websocketScanCommand.Credentialslist) != 0 {
					websocketScanCommand.Credentials = &websocketScanCommand.Credentialslist[0]
				}
			}
		}
		if err := sendWorkloadToVulnerabilityScanner(websocketScanCommand); err != nil {
			glog.Errorf("scanning %v failed due to: %v", websocketScanCommand.ImageTag, err.Error())
			errs += fmt.Sprintf("failed scanning, wlid: '%s', image: '%s', container: %s, reason: %s", actionHandler.wlid, containers[i].image, containers[i].container, err.Error())

		}

	}
	if errs != "" {
		return fmt.Errorf(errs)
	}
	return nil
}

// func (actionHandler *ActionHandler) scanWorkload() error {
// 	workload, err := actionHandler.k8sAPI.GetWorkloadByWlid(actionHandler.wlid)
// 	if err != nil {
// 		glog.Errorf("scanning might fail if some images require credentials")
// 	}
// 	// get all images of workload
// 	errs := ""
// 	glog.Infof("in scanWorkload")
// 	containers, err := getWorkloadcontainers(workload)
// 	if err != nil {
// 		return fmt.Errorf("cant get workloads from k8s, wlid: %s, reason: %s", actionHandler.wlid, err.Error())
// 	}
// 	websocketScanCommand := &apis.WebsocketScanCommand{
// 		Wlid: actionHandler.wlid,
// 	}
// 	if actionHandler.reporter != nil {
// 		websocketScanCommand.JobID = actionHandler.reporter.GetJobID()
// 		websocketScanCommand.LastAction = actionHandler.reporter.GetActionIDN()
// 	}

// 	for i := range containers {
// 		websocketScanCommand.ImageTag = containers[i].image
// 		websocketScanCommand.ContainerName = containers[i].container
// 		secrets, err := cloudsupport.GetWorkloadImageRegistryCredentials(websocketScanCommand.ImageTag, workload)
// 		if err != nil {
// 			glog.Error(err)
// 		} else if len(secrets) > 0 {
// 			if secret, isOk := secrets[websocketScanCommand.ImageTag]; isOk {
// 				glog.Infof("found relevant secret for: %v", websocketScanCommand.ImageTag)
// 				websocketScanCommand.Credentials = &secret
// 			} else {
// 				glog.Errorf("could not find image: %s secret", websocketScanCommand.ImageTag)
// 			}

// 		}
// 		if err := sendWorkloadToVulnerabilityScanner(websocketScanCommand); err != nil {
// 			glog.Errorf("scanning %v failed due to: %v", websocketScanCommand.ImageTag, err.Error())
// 			errs += fmt.Sprintf("failed scanning, wlid: '%s', image: '%s', container: %s, reason: %s", actionHandler.wlid, containers[i].image, containers[i].container, err.Error())

// 		}

// 	}
// 	if errs != "" {
// 		return fmt.Errorf(errs)
// 	}
// 	return nil
// }
func (actionHandler *ActionHandler) getRunningPodDescription(pod *corev1.Pod) {
	if workloadObj, err := actionHandler.k8sAPI.GetWorkloadByWlid(actionHandler.wlid); err == nil {
		if selectors, err := workloadObj.GetSelector(); err == nil {
			gvr, _ := k8sinterface.GetGroupVersionResource("Pod")
			podList, err := actionHandler.k8sAPI.ListWorkloads(&gvr, workloadObj.GetNamespace(), selectors.MatchLabels, map[string]string{"status.phase": "Running"})
			if err == nil {
				if len(podList) > 0 {
					wlidKind := pkgwlid.GetKindFromWlid(actionHandler.wlid)
					wlidName := pkgwlid.GetNameFromWlid(actionHandler.wlid)
					for podIdx := range podList {
						parentKind, parentName, err := actionHandler.k8sAPI.CalculateWorkloadParentRecursive(podList[podIdx])
						if err == nil && parentKind == wlidKind && wlidName == parentName {
							podBts, err := json.Marshal(podList[podIdx].GetObject())
							if err != nil {
								continue
							}
							err = json.Unmarshal(podBts, pod)
							if err != nil {
								continue
							}
							break
						}
					}
				}
			}
		}
	}
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
	if resp == nil {
		return fmt.Errorf("failed posting to vulnerability scanner. query: '%s', reason: 'empty response'", websocketScanCommand.ImageTag)
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	if resp.StatusCode < 200 || resp.StatusCode > 203 {
		return fmt.Errorf("failed posting to vulnerability scanner. query: '%s', reason: 'received bad status code: %d'", websocketScanCommand.ImageTag, resp.StatusCode)
	}
	return nil
}

func (actionHandler *ActionHandler) getPodByWLID(wlid string) (*corev1.Pod, error) {
	var err error
	workload, err := actionHandler.k8sAPI.GetWorkloadByWlid(actionHandler.wlid)
	if err != nil {
		return nil, err
	}
	podspec, err := workload.GetPodSpec()
	if err != nil {
		return nil, err
	}
	podObj := &corev1.Pod{Spec: *podspec}
	podObj.ObjectMeta.Namespace = pkgwlid.GetNamespaceFromWlid(wlid)
	return podObj, nil
}

// func (actionHandler *ActionHandler) getPodByWLID(wlid string) (*corev1.Pod, error) {
// 	var err error
// 	workload, err := actionHandler.k8sAPI.GetWorkloadByWlid(actionHandler.wlid)
// 	if err != nil {
// 		return nil, err
// 	}
// 	podspec, err := workload.GetPodSpec()
// 	if err != nil {
// 		return nil, err
// 	}
// 	podObj := &corev1.Pod{Spec: *podspec}
// 	podObj.ObjectMeta.Namespace = pkgwlid.GetNamespaceFromWlid(wlid)
// 	return podObj, nil
// }
func getScanFromArgs(args map[string]interface{}) (*apis.WebsocketScanCommand, error) {
	scanInterface, ok := args["scan"]
	if !ok {
		return nil, nil
	}
	websocketScanCommand := &apis.WebsocketScanCommand{}
	scanBytes, err := json.Marshal(scanInterface)
	if err != nil {
		return nil, fmt.Errorf("cannot convert 'interface scan' to 'bytes array', reason: %s", err.Error())
	}
	if err = json.Unmarshal(scanBytes, websocketScanCommand); err != nil {
		return nil, fmt.Errorf("cannot convert 'bytes array scan' to 'WebsocketScanCommand', reason: %s", err.Error())
	}
	return websocketScanCommand, nil
}
