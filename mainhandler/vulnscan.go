package mainhandler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"k8s-ca-websocket/cautils"
	"net/http"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/strings/slices"

	pkgwlid "github.com/armosec/utils-k8s-go/wlid"
	"github.com/docker/docker/api/types"
	uuid "github.com/google/uuid"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/k8s-interface/cloudsupport"
	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/golang/glog"
)

const dockerPullableURN = "docker-pullable://"

func getVulnScanURL() *url.URL {
	vulnURL := url.URL{}
	vulnURL.Scheme = "http"
	vulnURL.Host = cautils.ClusterConfig.VulnScanURL
	vulnURL.Path = fmt.Sprintf("%s/%s", apis.WebsocketScanCommandVersion, apis.WebsocketScanCommandPath)
	return &vulnURL
}
func sendAllImagesToVulnScan(webSocketScanCMDList []*apis.WebsocketScanCommand) error {
	var err error
	errs := make([]error, 0)
	for _, webSocketScanCMD := range webSocketScanCMDList {
		err = sendWorkloadToVulnerabilityScanner(webSocketScanCMD)
		if err != nil {
			glog.Errorf("sendWorkloadToVulnerabilityScanner failed with err %v", err)
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return err
	}
	return nil
}

func convertImagesToWebsocketScanCommand(images map[string][]string, sessionObj *cautils.SessionObj, registry *registryScan) ([]*apis.WebsocketScanCommand, error) {

	webSocketScanCMDList := make([]*apis.WebsocketScanCommand, 0)
	for repository, tags := range images {
		// registry/project/repo --> repo
		repositoryName := strings.Replace(repository, registry.registry.hostname+"/"+registry.registry.projectID+"/", "", -1)
		for _, tag := range tags {
			glog.Info("image ", repository+":"+tag)
			websocketScanCommand := &apis.WebsocketScanCommand{
				ImageTag: repository + ":" + tag,
				Session:  apis.SessionChain{ActionTitle: "vulnerability-scan", JobIDs: make([]string, 0), Timestamp: sessionObj.Reporter.GetTimestamp()},
				Args: map[string]interface{}{
					armotypes.AttributeRegistryName: registry.registry.hostname + "/" + registry.registry.projectID,
					armotypes.AttributeRepository:   repositoryName,
					armotypes.AttributeTag:          tag,
				},
			}
			// Check if auth is empty (used for public registries)
			if registry.registryAuth != (types.AuthConfig{}) {
				websocketScanCommand.Credentialslist = append(websocketScanCommand.Credentialslist, registry.registryAuth)
			}
			webSocketScanCMDList = append(webSocketScanCMDList, websocketScanCommand)
		}
	}

	return webSocketScanCMDList, nil
}

func decryptAuth(auth types.AuthConfig) types.AuthConfig {
	return auth
}

func decryptSecretsData(Args map[string]interface{}) (types.AuthConfig, error) {

	username := ""
	password := ""
	innerAuth := ""
	identityToken := ""
	registryToken := ""

	if _, ok := Args["username"]; ok {
		username = Args["username"].(string)
	}
	if _, ok := Args["password"]; ok {
		password = Args["password"].(string)
	}
	if _, ok := Args["auth"]; ok {
		innerAuth = Args["auth"].(string)
	}
	if _, ok := Args["identityToken"]; ok {
		identityToken = Args["identityToken"].(string)
	}
	if _, ok := Args["registryToken"]; ok {
		registryToken = Args["registryToken"].(string)
	}

	auth := types.AuthConfig{
		Username:      username,
		Password:      password,
		Auth:          innerAuth,
		IdentityToken: identityToken,
		RegistryToken: registryToken,
	}

	decrypt_auth := decryptAuth(auth)
	return decrypt_auth, nil
}

func (actionHandler *ActionHandler) loadSecretRegistryScanHandler(registryScanHandler *registryScanHandler, registryName string) error {
	secret, err := actionHandler.getRegistryScanSecret()
	if err != nil {
		return err
	}
	secretData := secret.GetData()
	err = registryScanHandler.ParseSecretsData(secretData, registryName)

	return err
}

func (actionHandler *ActionHandler) loadConfigMapRegistryScanHandler(registryScanHandler *registryScanHandler) error {
	configMap, err := actionHandler.k8sAPI.GetWorkload(armoNamespace, "ConfigMap", registryScanConfigmap)
	if err != nil {
		return err
	}
	configData := configMap.GetData()
	err = registryScanHandler.ParseConfigMapData(configData)
	return err

}

func (actionHandler *ActionHandler) getRegistryScanSecret() (k8sinterface.IWorkload, error) {
	secret, err := actionHandler.k8sAPI.GetWorkload(armoNamespace, "Secret", registryScanSecret)
	return secret, err

}

func (actionHandler *ActionHandler) scanRegistries(sessionObj *cautils.SessionObj) error {

	/*
		Auth data must be stored in kubescape-registry-scan secret
		Config data must be stored in "kubescape-registry-scan" config map
	*/

	registryScanHandler := NewRegistryScanHandler()

	registryName, err := actionHandler.parseRegistryNameArg(sessionObj)
	if err != nil {
		glog.Infof("parseRegistryNameArg failed with err %v", err)
		return err
	}
	err = actionHandler.loadSecretRegistryScanHandler(registryScanHandler, registryName)
	if err != nil {
		glog.Infof("loadSecretRegistryScanHandler failed with err %v", err)
		return err
	}
	err = actionHandler.loadConfigMapRegistryScanHandler(registryScanHandler)
	if err != nil {
		glog.Infof("loadConfigMapRegistryScanHandler failed with err %v", err)
		return err
	}
	glog.Infof("scanRegistries: %s secret and %s configmap parsing successful", registryScanSecret, registryScanConfigmap)

	for _, reg := range registryScanHandler.registryScan {
		err = actionHandler.scanRegistry(&reg, sessionObj, registryScanHandler)
	}

	return err
}

func (actionHandler *ActionHandler) parseRegistryNameArg(sessionObj *cautils.SessionObj) (string, error) {
	registryInfo, ok := sessionObj.Command.Args[registryInfoV1].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("could not parse registry info")
	}
	registryName, ok := registryInfo[registryNameField].(string)
	if !ok {
		return "", fmt.Errorf("could not parse registry name")
	}
	return registryName, nil
}

func (actionHandler *ActionHandler) scanRegistry(registry *registryScan, sessionObj *cautils.SessionObj, registryScanHandler *registryScanHandler) error {
	err := registryScanHandler.GetImagesForScanning(*registry)
	if err != nil {
		glog.Infof("GetImagesForScanning failed with err %v", err)
		return err
	}
	webSocketScanCMDList, err := convertImagesToWebsocketScanCommand(registry.mapImageToTags, sessionObj, registry)
	if err != nil {
		glog.Infof("convertImagesToWebsocketScanCommand failed with err %v", err)
		return err
	}
	err = sendAllImagesToVulnScan(webSocketScanCMDList)
	if err != nil {
		glog.Infof("sendAllImagesToVulnScanByMemLimit failed with err %v", err)
	}
	return err
}

func (actionHandler *ActionHandler) scanWorkload(sessionObj *cautils.SessionObj) error {

	pod, err := actionHandler.getPodByWLID(actionHandler.wlid)
	if err != nil {
		glog.Errorf("scanning might fail if some images require credentials")
	}
	// get all images of workload
	errs := ""
	containers, err := getWorkloadImages(actionHandler.k8sAPI, actionHandler.wlid)
	if err != nil {
		return fmt.Errorf("failed to get workloads from k8s, wlid: %s, reason: %s", actionHandler.wlid, err.Error())
	}

	// we want running pod in order to have the image hash
	actionHandler.getRunningPodDescription(pod)

	for i := range containers {

		websocketScanCommand := &apis.WebsocketScanCommand{
			Wlid:          actionHandler.wlid,
			ImageTag:      containers[i].image,
			ContainerName: containers[i].container,
			Session:       apis.SessionChain{ActionTitle: "vulnerability-scan", JobIDs: make([]string, 0), Timestamp: sessionObj.Reporter.GetTimestamp()},
		}
		if actionHandler.reporter != nil {

			prepareSessionChain(sessionObj, websocketScanCommand, actionHandler)

			glog.Infof("wlid: %s, container: %s, image: %s, jobIDs: %s/%s/%s", websocketScanCommand.Wlid, websocketScanCommand.ContainerName, websocketScanCommand.ImageTag, actionHandler.reporter.GetParentAction(), websocketScanCommand.ParentJobID, websocketScanCommand.JobID)

			// if websocketScanCommand.ParentJobID != actionHandler.command.JobTracking.ParentID {
			// 	glog.Errorf("websocket command parent: %v, child: %v, VS actionhandler.command parent: %v child %v", websocketScanCommand.ParentJobID, websocketScanCommand.JobID, actionHandler.command.JobTracking.ParentID, actionHandler.command.JobTracking.JobID)
			// }
		}
		for contIdx := range pod.Status.ContainerStatuses {
			if pod.Status.ContainerStatuses[contIdx].Name == containers[i].container {
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

func prepareSessionChain(sessionObj *cautils.SessionObj, websocketScanCommand *apis.WebsocketScanCommand, actionHandler *ActionHandler) {
	sessParentJobId := sessionObj.Reporter.GetParentAction()
	if sessParentJobId != "" {
		websocketScanCommand.Session.JobIDs = append(websocketScanCommand.Session.JobIDs, sessParentJobId)
		websocketScanCommand.Session.RootJobID = sessParentJobId
	}
	sessJobID := sessionObj.Reporter.GetJobID()
	if websocketScanCommand.Session.RootJobID == "" {
		websocketScanCommand.Session.RootJobID = sessJobID
	}
	websocketScanCommand.Session.JobIDs = append(websocketScanCommand.Session.JobIDs, sessJobID)

	if actionHandler.reporter.GetParentAction() != "" && !slices.Contains(websocketScanCommand.Session.JobIDs, actionHandler.reporter.GetParentAction()) {
		websocketScanCommand.Session.JobIDs = append(websocketScanCommand.Session.JobIDs, actionHandler.reporter.GetParentAction())
	}

	if actionHandler.reporter.GetJobID() != "" && !slices.Contains(websocketScanCommand.Session.JobIDs, actionHandler.reporter.GetJobID()) {
		websocketScanCommand.Session.JobIDs = append(websocketScanCommand.Session.JobIDs, actionHandler.reporter.GetJobID())
	}

	websocketScanCommand.ParentJobID = actionHandler.reporter.GetJobID()
	websocketScanCommand.LastAction = actionHandler.reporter.GetActionIDN()
	websocketScanCommand.JobID = uuid.NewString()
	websocketScanCommand.Session.JobIDs = append(websocketScanCommand.Session.JobIDs, websocketScanCommand.JobID)
}

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
	vulnURL := getVulnScanURL()

	creds := websocketScanCommand.Credentials
	credsList := websocketScanCommand.Credentialslist
	hasCreds := creds != nil && len(creds.Username) > 0 && len(creds.Password) > 0 || len(credsList) > 0
	glog.Infof("requesting scan. url: %s wlid: %s image: %s with credentials: %v", vulnURL.String(), websocketScanCommand.Wlid, websocketScanCommand.ImageTag, hasCreds)

	req, err := http.NewRequest("POST", vulnURL.String(), bytes.NewBuffer(jsonScannerC))
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
	refusedNum := 0
	for ; refusedNum < 5 && err != nil && strings.Contains(err.Error(), "connection refused"); resp, err = client.Do(req) {
		glog.Errorf("failed posting to vulnerability scanner. query: '%s', reason: %s", websocketScanCommand.ImageTag, err.Error())
		time.Sleep(5 * time.Second)
		refusedNum++
	}
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
