package mainhandler

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/kubescape/operator/utils"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/strings/slices"

	uuid "github.com/google/uuid"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	apitypes "github.com/armosec/armoapi-go/armotypes"
	reporterlib "github.com/armosec/logger-go/system-reports/datastructures"
	"github.com/armosec/utils-go/httputils"
	"github.com/golang/glog"
	"github.com/kubescape/k8s-interface/cloudsupport"
	"github.com/kubescape/k8s-interface/k8sinterface"
)

const (
	dockerPullableURN        = "docker-pullable://"
	cmDefaultMode     cmMode = "default"
	cmLoadedMode      cmMode = "loaded"
)

type cmMode string

func getVulnScanURL() *url.URL {
	vulnURL := url.URL{}
	vulnURL.Scheme = "http"
	vulnURL.Host = utils.ClusterConfig.KubevulnURL
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
		err = fmt.Errorf("sendAllImagesToVulnScan errors: ")
		for errIdx := range errs {
			err = fmt.Errorf("%s; %w", err, errs[errIdx])
		}
		return err
	}
	return nil
}

func convertImagesToWebsocketScanCommand(registry *registryScan, sessionObj *utils.SessionObj) []*apis.WebsocketScanCommand {
	images := registry.mapImageToTags

	webSocketScanCMDList := make([]*apis.WebsocketScanCommand, 0)
	for repository, tags := range images {
		// registry/project/repo --> repo
		repositoryName := strings.Replace(repository, registry.registry.hostname+"/"+registry.registry.projectID+"/", "", -1)
		for _, tag := range tags {
			websocketScanCommand := &apis.WebsocketScanCommand{
				ParentJobID: sessionObj.Reporter.GetJobID(),
				JobID:       uuid.NewString(),
				ImageTag:    repository + ":" + tag,
				Session:     apis.SessionChain{ActionTitle: "vulnerability-scan", JobIDs: make([]string, 0), Timestamp: sessionObj.Reporter.GetTimestamp()},
				Args: map[string]interface{}{
					apitypes.AttributeRegistryName:  registry.registry.hostname + "/" + registry.registry.projectID,
					apitypes.AttributeRepository:    repositoryName,
					apitypes.AttributeTag:           tag,
					apitypes.AttributeUseHTTP:       !registry.registryInfo.IsHTTPs,
					apitypes.AttributeSkipTLSVerify: registry.registryInfo.SkipTLSVerify,
					apitypes.AttributeSensor:        utils.ClusterConfig.ClusterName,
				},
			}
			// Check if auth is empty (used for public registries)
			authConfig := registry.authConfig()
			if authConfig != nil {
				websocketScanCommand.Credentialslist = append(websocketScanCommand.Credentialslist, *authConfig)
			}
			webSocketScanCMDList = append(webSocketScanCMDList, websocketScanCommand)
		}
	}

	return webSocketScanCMDList
}

func (actionHandler *ActionHandler) scanRegistries(sessionObj *utils.SessionObj) error {

	registryScan, err := actionHandler.loadRegistryScan(sessionObj)
	if err != nil {
		glog.Errorf("in parseRegistryCommand: error: ", err.Error())
		return fmt.Errorf("scanRegistries failed with err %v", err)
	}

	return actionHandler.scanRegistry(registryScan, sessionObj)
}

func (actionHandler *ActionHandler) loadRegistryScan(sessionObj *utils.SessionObj) (*registryScan, error) {
	registryScan := NewRegistryScan(actionHandler.k8sAPI)
	var err error
	if registryScan.isParseRegistryFromCommand(sessionObj.Command) {
		err = registryScan.parseRegistryFromCommand(sessionObj)
	} else {
		err = registryScan.parseRegistryFromCluster(sessionObj)
	}
	if err != nil {
		return nil, err
	}
	return &registryScan, nil
}

func (actionHandler *ActionHandler) testRegistryConnectivity(sessionObj *utils.SessionObj) error {
	registryScan, err := actionHandler.loadRegistryScan(sessionObj)
	if err != nil {
		glog.Errorf("in testRegistryConnectivity: loadRegistryScan failed with error: %v", err.Error())
		return err
	}
	err = actionHandler.testRegistryConnect(registryScan, sessionObj)
	if err != nil {
		glog.Errorf("in testRegistryConnectivity: testRegistryConnect failed with error: %v", err.Error())
		return err
	}
	return nil
}

func (actionHandler *ActionHandler) parseRegistryNameArg(sessionObj *utils.SessionObj) (string, error) {
	registryInfo, ok := sessionObj.Command.Args[armotypes.RegistryInfoArgKey].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("could not parse registry info")
	}
	registryName, ok := registryInfo[registryNameField].(string)
	if !ok {
		return "", fmt.Errorf("could not parse registry name")
	}

	sessionObj.Reporter.SetTarget(fmt.Sprintf("%s: %s", apitypes.AttributeRegistryName,
		registryName))
	sessionObj.Reporter.SendDetails(fmt.Sprintf("registryInfo parsed: %v", registryInfo), true, sessionObj.ErrChan)
	return registryName, nil
}

func (actionHandler *ActionHandler) testRegistryConnect(registry *registryScan, sessionObj *utils.SessionObj) error {
	repos, err := registry.enumerateRepoes()
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unauthorized") || strings.Contains(strings.ToLower(err.Error()), "DENIED") || strings.Contains(strings.ToLower(err.Error()), "authentication") {
			// registry info is good, but authentication failed
			sessionObj.Reporter.SetDetails(string(testRegistryInformationStatus))
			sessionObj.Reporter.SendStatus(reporterlib.JobSuccess, true, sessionObj.ErrChan)
			sessionObj.Reporter.SetDetails(fmt.Sprintf("%v failed with err %v", testRegistryAuthenticationStatus, err))
			return fmt.Errorf("failed to retrieve repositories: authentication error: %v", err)
		} else {
			sessionObj.Reporter.SetDetails(fmt.Sprintf("%v failed with err %v", testRegistryInformationStatus, err))
			return fmt.Errorf("testRegistryConnect failed with error:  %v", err)
		}
	}

	sessionObj.Reporter.SetDetails(string(testRegistryInformationStatus))
	sessionObj.Reporter.SendStatus(reporterlib.JobSuccess, true, sessionObj.ErrChan)
	sessionObj.Reporter.SetDetails(string(testRegistryAuthenticationStatus))
	sessionObj.Reporter.SendStatus(reporterlib.JobSuccess, true, sessionObj.ErrChan)

	if len(repos) == 0 {
		sessionObj.Reporter.SetDetails(fmt.Sprintf("%v failed with err %v", testRegistryRetrieveReposStatus, err))
		return fmt.Errorf("failed to retrieve repositories: got empty list of repositories")
	}

	sessionObj.Reporter.SetDetails(string(testRegistryRetrieveReposStatus))
	sessionObj.Reporter.SendStatus(reporterlib.JobSuccess, true, sessionObj.ErrChan)

	for _, repo := range repos {
		if err := registry.setImageToTagsMap(repo, sessionObj.Reporter); err != nil {
			sessionObj.Reporter.SetDetails(fmt.Sprintf("%v failed with err %v", testRegistryRetrieveTagsStatus, err))
			return fmt.Errorf("setImageToTagsMap failed with err %v", err)
		}
	}

	sessionObj.Reporter.SetDetails(string(testRegistryRetrieveTagsStatus))
	sessionObj.Reporter.SendStatus(reporterlib.JobSuccess, true, sessionObj.ErrChan)

	params := RepositoriesAndTagsParams{
		RegistryName:        registry.registryInfo.RegistryName,
		CustomerGUID:        sessionObj.Reporter.GetCustomerGUID(),
		JobID:               sessionObj.Reporter.GetJobID(),
		RepositoriesAndTags: registry.mapImageToTags,
	}
	err = registry.SendRepositoriesAndTags(params)
	if err != nil {
		return err
	}
	return nil
}

func (actionHandler *ActionHandler) scanRegistry(registry *registryScan, sessionObj *utils.SessionObj) error {
	err := registry.getImagesForScanning(actionHandler.reporter)
	if err != nil {
		return fmt.Errorf("GetImagesForScanning failed with err %v", err)
	}
	webSocketScanCMDList := convertImagesToWebsocketScanCommand(registry, sessionObj)
	sessionObj.Reporter.SendDetails(fmt.Sprintf("sending %d images from registry %v to vuln scan", len(webSocketScanCMDList), registry.registry), true, sessionObj.ErrChan)

	return sendAllImagesToVulnScan(webSocketScanCMDList)
}

func (actionHandler *ActionHandler) scanWorkload(sessionObj *utils.SessionObj) error {

	workload, err := actionHandler.k8sAPI.GetWorkloadByWlid(actionHandler.wlid)
	if err != nil {
		return fmt.Errorf("failed to get workload %s with err %v", actionHandler.wlid, err)
	}
	pod := actionHandler.getPodByWLID(workload)
	if pod == nil {
		glog.Infof("workload %s has no podSpec, skipping", actionHandler.wlid)
		return nil
	}
	// get all images of workload
	errs := ""
	containers, err := listWorkloadImages(workload)
	if err != nil {
		return fmt.Errorf("failed to get workloads from k8s, wlid: %s, reason: %s", actionHandler.wlid, err.Error())
	}

	// we want running pod in order to have the image hash
	// actionHandler.getRunningPodDescription(pod)

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
		}
		for contIdx := range pod.Status.ContainerStatuses {
			if pod.Status.ContainerStatuses[contIdx].Name == containers[i].container {
				imageNameWithHash := pod.Status.ContainerStatuses[contIdx].ImageID
				imageNameWithHash = strings.TrimPrefix(imageNameWithHash, dockerPullableURN)
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
					the websocketScanCommand.Credentials is deprecated, still use it for backward computability
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

func prepareSessionChain(sessionObj *utils.SessionObj, websocketScanCommand *apis.WebsocketScanCommand, actionHandler *ActionHandler) {
	sessionParentJobId := sessionObj.Reporter.GetParentAction()
	if sessionParentJobId != "" {
		websocketScanCommand.Session.JobIDs = append(websocketScanCommand.Session.JobIDs, sessionParentJobId)
		websocketScanCommand.Session.RootJobID = sessionParentJobId
	}
	sessionJobID := sessionObj.Reporter.GetJobID()
	if websocketScanCommand.Session.RootJobID == "" {
		websocketScanCommand.Session.RootJobID = sessionJobID
	}
	websocketScanCommand.Session.JobIDs = append(websocketScanCommand.Session.JobIDs, sessionJobID)

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

	resp, err := httputils.HttpPost(VulnScanHttpClient, vulnURL.String(), map[string]string{"Content-Type": "application/json"}, jsonScannerC)
	refusedNum := 0
	for ; refusedNum < 5 && err != nil && strings.Contains(err.Error(), "connection refused"); resp, err = httputils.HttpPost(VulnScanHttpClient, vulnURL.String(), map[string]string{"Content-Type": "application/json"}, jsonScannerC) {
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

func (actionHandler *ActionHandler) getPodByWLID(workload k8sinterface.IWorkload) *corev1.Pod {
	var err error

	podspec, err := workload.GetPodSpec()
	if err != nil {
		return nil
	}
	podObj := &corev1.Pod{Spec: *podspec}
	podObj.ObjectMeta.Namespace = workload.GetNamespace()
	return podObj
}
