package mainhandler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kubescape/operator/utils"
	"github.com/mitchellh/mapstructure"

	regCommon "github.com/armosec/registryx/common"
	regInterfaces "github.com/armosec/registryx/interfaces"
	regFactory "github.com/armosec/registryx/registries"
	"github.com/kubescape/k8s-interface/cloudsupport"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/logger-go/system-reports/datastructures"
	reporterlib "github.com/armosec/logger-go/system-reports/datastructures"
	"github.com/docker/docker/api/types"
	"github.com/golang/glog"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kubescape/k8s-interface/k8sinterface"
	v1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/strings/slices"
)

type AuthMethods string

const (
	registryScanConfigmap                                                     = "kubescape-registry-scan"
	registryNameField                                                         = "registryName"
	imagesToScanLimit                                                         = 500
	registriesAuthFieldInSecret                                               = "registriesAuth"
	accessTokenAuth                            AuthMethods                    = "accesstoken"
	registryCronjobTemplate                                                   = "registry-scan-cronjob-template"
	tagsPageSize                                                              = 1000
	registryScanDocumentation                                                 = "https://hub.armosec.io/docs/registry-vulnerability-scan"
	testRegistryConnectivityStatusInfo         testRegistryConnectivityStatus = "registryInformation"
	testRegistryConnectivityStatusAuth         testRegistryConnectivityStatus = "registryAuthentication"
	testRegistryConnectivityStatusRetrieveRepo testRegistryConnectivityStatus = "retrieveRepositories"
	testRegistryConnectivityStatusRetrieveTag  testRegistryConnectivityStatus = "retrieveTags"
)

type testRegistryConnectivityStatus string

type registryScanConfig struct {
	Registry string   `json:"registry"`
	Depth    int      `json:"depth"`
	Include  []string `json:"include,omitempty"`
	Exclude  []string `json:"exclude,omitempty"`
}
type registryAuth struct {
	Registry      string `json:"registry"`
	AuthMethod    string `json:"auth_method,omitempty"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	RegistryToken string `json:"registryToken,omitempty"`

	Kind          regCommon.RegistryKind `json:"kind,omitempty"`
	SkipTLSVerify *bool                  `json:"skipTLSVerify,omitempty"`
	Insecure      *bool                  `json:"http,omitempty"`
}

type registry struct {
	hostname  string
	projectID string
}

type registryScan struct {
	k8sAPI         *k8sinterface.KubernetesApi
	registry       registry
	registryInfo   armotypes.RegistryInfo
	mapImageToTags map[string][]string
}

type registryCreds struct {
	registryName string
	auth         *types.AuthConfig
}

func NewRegistryScanConfig(registryName string) *registryScanConfig {
	return &registryScanConfig{
		Registry: registryName,
		Depth:    1,
		Include:  make([]string, 0),
		Exclude:  make([]string, 0),
	}
}

func errorWithDocumentationRef(errorMessage string) error {
	return fmt.Errorf("%s. Please refer to the documentation %s", errorMessage, registryScanDocumentation)
}

func NewRegistryScan(k8sAPI *k8sinterface.KubernetesApi) registryScan {
	return registryScan{
		registry:       registry{},
		mapImageToTags: make(map[string][]string),
		registryInfo:   armotypes.RegistryInfo{},
		k8sAPI:         k8sAPI,
	}
}

func (rs *registryScan) makeRegistryInterface() (regInterfaces.IRegistry, error) {
	return regFactory.Factory(&authn.AuthConfig{Username: rs.registryInfo.AuthMethod.Username, Password: rs.registryInfo.AuthMethod.Password, RegistryToken: rs.registryInfo.RegistryToken}, rs.registry.hostname,
		regCommon.MakeRegistryOptions(false, !*&rs.registryInfo.IsHTTPs, *&rs.registryInfo.SkipTLS, "", "", rs.registry.projectID, regCommon.RegistryKind(rs.registryInfo.Kind)))
}

func makeRegistryAuth(registryName string) registryAuth {
	kind, _ := regCommon.GetRegistryKind(strings.Split(registryName, "/")[0])
	falseInsecure := false
	falseSkipTLS := false
	return registryAuth{SkipTLSVerify: &falseSkipTLS, Insecure: &falseInsecure, Kind: kind}
}

func (rs *registryScan) hasAuth() bool {
	//TODO: support registry token
	return rs.registryInfo.AuthMethod.Type != "public"
}

func (rs *registryScan) registryCredentials() *registryCreds {
	var regCreds *registryCreds
	if rs.hasAuth() {
		regCreds = &registryCreds{
			auth:         rs.authConfig(),
			registryName: rs.registry.hostname,
		}
	}
	return regCreds
}

func (rs *registryScan) authConfig() *types.AuthConfig {
	var authConfig *types.AuthConfig
	if rs.hasAuth() {
		authConfig = &types.AuthConfig{
			Username: rs.registryInfo.AuthMethod.Username,
			Password: rs.registryInfo.AuthMethod.Password,
			Auth:     rs.registryInfo.AuthMethod.Type,
			//TODO: add tokens support
		}
	}
	return authConfig
}

func (reg *registryAuth) initDefaultValues() error {
	switch reg.AuthMethod {
	case string(accessTokenAuth), "", "credentials":
		if reg.Password == "" || reg.Username == "" {
			return errorWithDocumentationRef("auth_method accesstoken requirers username and password")
		}
	case "public":
		//do nothing
		break
	case "ips":
		// retrieve token and consider it as regular accesstoken auth
		authConfig, err := cloudsupport.GetCloudVendorRegistryCredentials(reg.Registry)
		if err != nil {
			return fmt.Errorf("error getting credentials: %v", err)
		}

		if authConfigReg, ok := authConfig[reg.Registry]; ok {
			reg.Username = authConfigReg.Username
			reg.Password = authConfigReg.Password
			reg.AuthMethod = string(accessTokenAuth)
		} else {
			return fmt.Errorf("error getting credentials for: %v", reg.Registry)
		}
	case "identity_token", "registry_token":
		fallthrough
	default:
		return errorWithDocumentationRef(fmt.Sprintf("auth_method (%s) not supported", reg.AuthMethod))
	}
	if reg.Insecure == nil {
		falseBool := false
		reg.Insecure = &falseBool
	}
	if reg.SkipTLSVerify == nil {
		falseBool := false
		reg.SkipTLSVerify = &falseBool
	}
	var err error
	if reg.Kind != "" {
		if reg.Kind, err = regCommon.GetRegistryKind(string(reg.Kind)); err != nil {
			//user defined unknown kind
			glog.Error("cannot validate registry kind", err)
			return err
		}
	} else {
		//try to get the kind from the reg name - if not found it will fallback to default kind
		reg.Kind, _ = regCommon.GetRegistryKind(strings.Split(reg.Registry, "/")[0])
	}
	return err
}

func (rs *registryScan) filterRepositories(repos []string) []string {
	if len(rs.registryInfo.Include) == 0 && len(rs.registryInfo.Include) == 0 {
		return repos
	}
	filteredRepos := []string{}
	for _, repo := range repos {
		if rs.registry.projectID != "" {
			if !strings.Contains(repo, rs.registry.projectID+"/") {
				continue
			}
		}
		if len(rs.registryInfo.Include) != 0 && slices.Contains(rs.registryInfo.Include, strings.Replace(repo, rs.registry.projectID+"/", "", -1)) {
			filteredRepos = append(filteredRepos, repo)
		}
		if len(rs.registryInfo.Exclude) != 0 {
			if !slices.Contains(rs.registryInfo.Exclude, strings.Replace(repo, rs.registry.projectID+"/", "", -1)) {
				filteredRepos = append(filteredRepos, repo)
			} else {
				repomsg := rs.registry.hostname + "/"
				if rs.registry.projectID != "" {
					repomsg += rs.registry.projectID + "/"
				}
				repomsg += repo
				glog.Warningf("image registry scan::%s was excluded", repomsg) // systest dependent
			}

		}
	}
	return filteredRepos
}

func (registryScan *registryScan) createTriggerRequestConfigMap(k8sAPI *k8sinterface.KubernetesApi, name, registryName string, webSocketScanCMD apis.Command) error {
	configMap := corev1.ConfigMap{}
	configMap.Name = name
	if configMap.Labels == nil {
		configMap.Labels = make(map[string]string)
	}
	configMap.Labels["app"] = name

	if configMap.Data == nil {
		configMap.Data = make(map[string]string)
	}

	// command is POST request to trigger websocket
	command, err := registryScan.getRegistryScanScanCommand(registryName)
	if err != nil {
		return err
	}

	// command will be mounted into cronjob by using this configmap
	configMap.Data[requestBodyFile] = string(command)

	if _, err := k8sAPI.KubernetesClient.CoreV1().ConfigMaps(utils.Namespace).Create(context.Background(), &configMap, metav1.CreateOptions{}); err != nil {
		return err
	}
	glog.Infof("createTriggerRequestConfigMap: created configmap: %s", name)
	return nil
}

func (registryScan *registryScan) getImagesForScanning(reporter datastructures.IReporter) error {
	glog.Infof("getImagesForScanning: enumerating repoes...")
	errChan := make(chan error)
	repos, _, err := registryScan.enumerateRepoes()
	if err != nil {
		reporter.SetDetails(fmt.Sprintf("enumerateRepoes failed with err %v", err))
		reporter.SendStatus(reporterlib.JobFailed, true, errChan)
		return err
	}
	glog.Infof("GetImagesForScanning: enumerating repos successfully, found %d repos", len(repos))
	for _, repo := range repos {
		if err := registryScan.setImageToTagsMap(repo, reporter); err != nil {
			glog.Errorf("setImageToTagsMap failed with registry: %s repo: %s due to ERROR:: %s", registryScan.registry.hostname, repo, err.Error())
			return err
		}
	}
	if registryScan.isExceedScanLimit(imagesToScanLimit) {
		registryScan.filterScanLimit(imagesToScanLimit)
		errMsg := fmt.Sprintf("more than %d images provided. scanning only first %d images", imagesToScanLimit, imagesToScanLimit)
		if reporter != nil {
			err := errorWithDocumentationRef(errMsg)
			reporter.SendWarning(err.Error(), true, true, errChan)
			if err := <-errChan; err != nil {
				glog.Errorf("setImageToTagsMap failed to send error report: %s due to ERROR:: %s",
					registryScan.registry.hostname, err.Error())
			}
		}
		glog.Warning("GetImagesForScanning: %S", errMsg)
	}
	return nil
}

func (registryScan *registryScan) setImageToTagsMap(repo string, reporter datastructures.IReporter) error {
	glog.Infof("Fetching repository %s tags", repo)
	iRegistry, err := registryScan.makeRegistryInterface()
	if err != nil {
		return err
	}

	firstPage := regCommon.MakePagination(tagsPageSize)
	latestTagFound := false
	tagsDepth := registryScan.registryInfo.Depth
	tags := []string{}
	options := []remote.Option{}
	if registryScan.hasAuth() {
		options = append(options, remote.WithAuth(registryScan.registryCredentials()))
	}
	if latestTags, err := iRegistry.GetLatestTags(repo, tagsDepth, options...); err == nil {
		tags := []string{}
		for _, tag := range latestTags {
			tagsForDigest := strings.Split(tag, ",")
			tagsForDigestLen := len(tagsForDigest)
			if tagsForDigestLen == 1 {
				tags = append(tags, tagsForDigest[0])
			} else {
				if tagsForDigestLen > tagsDepth {
					tags = append(tags, tagsForDigest[:tagsDepth]...)
					errMsg := fmt.Sprintf("image %s has %d tags. scanning only first %d tags - %s", repo, tagsForDigestLen, tagsDepth, strings.Join(tagsForDigest[:tagsDepth], ","))
					if reporter != nil {
						errChan := make(chan error)
						err := errorWithDocumentationRef(errMsg)
						reporter.SendWarning(err.Error(), true, true, errChan)
						if err := <-errChan; err != nil {
							glog.Errorf("GetLatestTags failed to send error report: %s due to ERROR:: %s",
								registryScan.registry.hostname, err.Error())
						}
					}
					glog.Warningf("GetImagesForScanning: %s", errMsg)
				} else {
					tags = append(tags, tagsForDigest...)
				}
			}
		}
		registryScan.mapImageToTags[registryScan.registry.hostname+"/"+repo] = tags

	} else { //fallback to list images lexicographically
		glog.Errorf("get latestTags failed for repository %s with error:%s/n fetching lexicographical list of tags", repo, err.Error())
		for tagsPage, nextPage, err := iRegistry.List(repo, firstPage, options...); ; tagsPage, nextPage, err = iRegistry.List(repo, *nextPage) {
			if err != nil {
				return err
			}

			if !latestTagFound {
				latestTagFound = slices.Contains(tagsPage, "latest")
			}
			tags = updateTagsCandidates(tags, tagsPage, tagsDepth, latestTagFound)

			if tagsDepth == 1 && latestTagFound {
				break
			}

			if nextPage == nil {
				break
			}
		}
		registryScan.mapImageToTags[registryScan.registry.hostname+"/"+repo] = tags
	}
	return nil
}

func updateTagsCandidates(tagsCandidates []string, tagsPage []string, tagsDepth int, latestTagFound bool) []string {
	prevCandidates := tagsCandidates
	tagsCandidates = []string{}
	lastIndexInPage := len(tagsPage) - 1
	for i := 0; len(tagsCandidates) < tagsDepth && i <= lastIndexInPage; i++ {
		if tagsPage[lastIndexInPage-i] == "latest" {
			continue
		}
		tagsCandidates = append(tagsCandidates, tagsPage[lastIndexInPage-i])
	}

	for i := 0; i < len(prevCandidates) && len(tagsPage) < tagsDepth; i++ {
		if prevCandidates[i] == "latest" {
			continue
		}
		tagsCandidates = append(tagsCandidates, prevCandidates[i])
	}

	if latestTagFound {
		tagsCandidates = append([]string{"latest"}, tagsCandidates...)
	}
	if len(tagsCandidates) > tagsDepth {
		tagsCandidates = tagsCandidates[:tagsDepth]
	}

	return tagsCandidates
}

func (registryScan *registryScan) isExceedScanLimit(limit int) bool {
	return registryScan.getNumOfImagesToScan() > limit
}

func (registryScan *registryScan) getNumOfImagesToScan() int {
	numOfImgs := 0
	for _, v := range registryScan.mapImageToTags {
		numOfImgs += len(v)
	}
	return numOfImgs
}

func (registryScan *registryScan) filterScanLimit(limit int) {
	filteredImages := make(map[string][]string)
	counter := 0
	for k := range registryScan.mapImageToTags {
		for _, img := range registryScan.mapImageToTags[k] {
			if counter >= limit {
				break
			}
			filteredImages[k] = append(filteredImages[k], img)
			counter++
		}
	}
	registryScan.mapImageToTags = filteredImages
}

func (registryScan *registryScan) enumerateRepoes() ([]string, int, error) {
	// token sometimes includes a lot of dots, so we need to remove them
	i := strings.Index(registryScan.registryInfo.AuthMethod.Password, ".....")
	if i != -1 {
		registryScan.registryInfo.AuthMethod.Password = registryScan.registryInfo.AuthMethod.Password[:i]
	}

	repos, statusCode, err := registryScan.listReposInRegistry()
	if err != nil {
		glog.Errorf("listReposInRegistry failed with err %v", err)
		return []string{}, statusCode, err
	}
	return repos, statusCode, nil

}

func (registryScan *registryScan) listReposInRegistry() ([]string, int, error) {
	iRegistry, err := registryScan.makeRegistryInterface()
	if err != nil {
		return nil, 0, err
	}
	regCreds := registryScan.registryCredentials()
	var repos, pageRepos []string
	var nextPage *regCommon.PaginationOption

	var statusCode int

	firstPage := regCommon.MakePagination(iRegistry.GetMaxPageSize())
	ctx := context.Background()
	catalogOpts := regCommon.CatalogOption{IsPublic: !registryScan.hasAuth(), Namespaces: registryScan.registry.projectID}
	for pageRepos, nextPage, statusCode, err = iRegistry.Catalog(ctx, firstPage, catalogOpts, regCreds); ; pageRepos, nextPage, statusCode, err = iRegistry.Catalog(ctx, *nextPage, catalogOpts, regCreds) {
		if err != nil {
			return nil, statusCode, err
		}
		if statusCode > 299 {
			return nil, statusCode, fmt.Errorf("unexpected status code %d while listing repositories in registry %s", statusCode, registryScan.registryInfo.RegistryName)
		}
		if len(pageRepos) == 0 {
			break
		}
		repos = append(repos, registryScan.filterRepositories(pageRepos)...)
		total2Include := len(registryScan.registryInfo.Include)
		if total2Include != 0 && total2Include == len(repos) {
			break
		}
		if len(repos) >= imagesToScanLimit {
			break
		}
		if nextPage == nil {
			break
		}
	}
	return repos, statusCode, nil
}

func (registryScan *registryScan) getRegistryScanScanCommand(registryName string) (string, error) {
	scanRegistryCommand := apis.Command{}
	scanRegistryCommand.CommandName = apis.TypeScanRegistry
	registryInfo := map[string]string{registryNameField: registryName}

	scanRegistryCommand.Args = map[string]interface{}{armotypes.RegistryInfoArgKey: registryInfo}
	scanRegistryCommand.Args[armotypes.RegistryInfoArgKey] = registryInfo

	scanRegistryCommands := apis.Commands{}
	scanRegistryCommands.Commands = append(scanRegistryCommands.Commands, scanRegistryCommand)

	scanV1Bytes, err := json.Marshal(scanRegistryCommands)
	if err != nil {
		return "", err
	}

	return string(scanV1Bytes), nil
}

func (registryScan *registryScan) setCronJobTemplate(jobTemplateObj *v1.CronJob, name, schedule, jobID, registryName string) error {
	jobTemplateObj.Name = name
	if schedule == "" {
		return fmt.Errorf("schedule cannot be empty")
	}
	jobTemplateObj.Spec.Schedule = schedule

	// update volume name
	for i, v := range jobTemplateObj.Spec.JobTemplate.Spec.Template.Spec.Volumes {
		if v.Name == requestVolumeName {
			if jobTemplateObj.Spec.JobTemplate.Spec.Template.Spec.Volumes[i].ConfigMap != nil {
				jobTemplateObj.Spec.JobTemplate.Spec.Template.Spec.Volumes[i].ConfigMap.Name = name
			}
		}
	}

	// add annotations
	if jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations == nil {
		jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations = make(map[string]string)
	}

	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations[armotypes.CronJobTemplateAnnotationRegistryNameKey] = registryName

	// add annotations
	if jobTemplateObj.ObjectMeta.Labels == nil {
		jobTemplateObj.ObjectMeta.Labels = make(map[string]string)
	}
	jobTemplateObj.ObjectMeta.Labels["app"] = name

	return nil
}

func (registryScan *registryScan) parseRegistryFromCommand(sessionObj *utils.SessionObj) error {
	registryInfo, ok := sessionObj.Command.Args[armotypes.RegistryInfoArgKey].(map[string]interface{})
	if !ok {
		return fmt.Errorf("could not parse registry info")
	}
	err := mapstructure.Decode(registryInfo, &registryScan.registryInfo)
	if err != nil {
		return fmt.Errorf("could not decode registry info into registryInfo struct")
	}
	registryScan.registryInfo.Kind = registryScan.registryInfo.RegistryProvider
	registryScan.setHostnameAndProject()
	return nil
}

// checks if registry scan info is in command, or we need to fallback to secret and configmap
func (registryScan *registryScan) isParseRegistryFromCommand(command apis.Command) bool {
	registryInfo, ok := command.Args[armotypes.RegistryInfoArgKey].(map[string]interface{})
	if !ok {
		return false
	}
	if _, ok = registryInfo["kind"]; !ok {
		return false
	}
	return true
}

func (registryScan *registryScan) parseRegistryFromCluster(sessionObj *utils.SessionObj) error {
	// this will parse only registryName
	err := registryScan.parseRegistryFromCommand(sessionObj)
	if err != nil {
		return fmt.Errorf("get registry auth failed with err %v", err)
	}
	err = registryScan.parseRegistryAuthFromSecret()
	if err != nil {
		return fmt.Errorf("get registry auth failed with err %v", err)
	}
	sessionObj.Reporter.SendDetails("secret loaded", true, sessionObj.ErrChan)

	configMapMode, err := registryScan.getRegistryConfig(&registryScan.registryInfo)
	if err != nil {
		return fmt.Errorf("get registry(%s) config failed with err %v", registryScan.registryInfo.RegistryName, err)
	}
	glog.Infof("scanRegistries:registry(%s) %s configmap  successful", registryScan.registryInfo.RegistryName, configMapMode) // systest depedendent
	registryScan.setHostnameAndProject()
	return nil
}

func (registryScan *registryScan) createTriggerRequestCronJob(k8sAPI *k8sinterface.KubernetesApi, name, registryName string, command apis.Command) error {

	// cronjob template is stored as configmap in cluster
	jobTemplateObj, err := getCronJobTemplate(k8sAPI, registryCronjobTemplate)
	if err != nil {
		glog.Infof("setRegistryScanCronJob: error retrieving cronjob template : %s", err.Error())
		return err
	}

	err = registryScan.setCronJobTemplate(jobTemplateObj, name, getCronTabSchedule(command), command.JobTracking.JobID, registryName)
	if err != nil {
		return err
	}

	// create cronJob
	if _, err := k8sAPI.KubernetesClient.BatchV1().CronJobs(utils.Namespace).Create(context.Background(), jobTemplateObj, metav1.CreateOptions{}); err != nil {
		glog.Infof("setRegistryScanCronJob: cronjob: %s creation failed. err: %s", name, err.Error())
		return err
	}
	return nil
}

func (registryScan *registryScan) parseRegistryAuthFromSecret() error {
	secret, err := registryScan.getRegistryScanSecret()
	if err != nil {
		return err
	}
	secretData := secret.GetData()
	var registriesAuth []registryAuth
	registriesAuthStr, ok := secretData[registriesAuthFieldInSecret].(string)
	if !ok {
		return fmt.Errorf("error parsing Secret: %s field must be a string", registriesAuthFieldInSecret)
	}
	data, err := base64.StdEncoding.DecodeString(registriesAuthStr)
	if err != nil {
		return fmt.Errorf("error parsing Secret: %s", err.Error())
	}
	registriesAuthStr = strings.Replace(string(data), "\n", "", -1)
	err = json.Unmarshal([]byte(registriesAuthStr), &registriesAuth)
	if err != nil {
		return fmt.Errorf("error parsing Secret: %s", err.Error())
	}
	//try to find an auth with the same registry name from the request
	for _, auth := range registriesAuth {
		if auth.Registry == registryScan.registryInfo.RegistryName {
			if err := auth.initDefaultValues(); err != nil {
				return err
			}
			registryScan.setRegistryInfoFromAuth(auth, &registryScan.registryInfo)
			return nil
		}
	}
	//couldn't find auth with the full, check if there is an auth for the registry without the project name
	regAndProject := strings.Split(registryScan.registryInfo.RegistryName, "/")
	if len(regAndProject) > 1 {
		for _, auth := range registriesAuth {
			if auth.Registry == regAndProject[0] {
				if err := auth.initDefaultValues(); err != nil {
					return err
				}
				registryScan.setRegistryInfoFromAuth(auth, &registryScan.registryInfo)
				return nil
			}
		}

	}
	//no auth found for registry return a default one
	auth := makeRegistryAuth(registryScan.registryInfo.RegistryName)
	registryScan.setRegistryInfoFromAuth(auth, &registryScan.registryInfo)
	return nil
}

func (registryScan *registryScan) setRegistryInfoFromAuth(auth registryAuth, registryInfo *armotypes.RegistryInfo) {
	registryInfo.AuthMethod.Type = auth.AuthMethod
	registryInfo.AuthMethod.Username = auth.Username
	registryInfo.AuthMethod.Password = auth.Password
	registryInfo.SkipTLS = *auth.SkipTLSVerify
	registryInfo.IsHTTPs = !*auth.Insecure
	registryInfo.Kind = string(auth.Kind)
}

func (registryScan *registryScan) getRegistryConfig(registryInfo *armotypes.RegistryInfo) (string, error) {
	configMap, err := registryScan.k8sAPI.GetWorkload(armotypes.KubescapeNamespace, "ConfigMap", registryScanConfigmap)
	// in case of an error or missing configmap, fallback to the deprecated namespace
	if err != nil || configMap == nil {
		configMap, err = registryScan.k8sAPI.GetWorkload(armotypes.ArmoSystemNamespace, "ConfigMap", registryScanConfigmap)
	}

	if err != nil {
		// if configmap not found, it means we will use all images and default depth
		if strings.Contains(err.Error(), fmt.Sprintf("reason: configmaps \"%v\" not found", registryScanConfigmap)) {
			glog.Infof("configmap: %s does not exists, using default values", registryScanConfigmap)
			return string(cmDefaultMode), nil
		} else {
			return string(cmDefaultMode), err
		}
	}
	configData := configMap.GetData()
	var registriesConfigs []registryScanConfig
	registriesConfigStr, ok := configData["registries"].(string)
	if !ok {
		return string(cmDefaultMode), fmt.Errorf("error parsing %v confgimap: registries field not found", registryScanConfigmap)
	}
	registriesConfigStr = strings.Replace(registriesConfigStr, "\n", "", -1)
	err = json.Unmarshal([]byte(registriesConfigStr), &registriesConfigs)
	if err != nil {
		return string(cmDefaultMode), fmt.Errorf("error parsing ConfigMap: %s", err.Error())
	}
	for _, config := range registriesConfigs {
		if config.Registry == registryInfo.RegistryName {
			registryScan.setRegistryInfoFromConfigMap(registryInfo, config)
			return string(cmLoadedMode), nil
		}
	}
	registryConfig := NewRegistryScanConfig(registryInfo.RegistryName)
	registryScan.setRegistryInfoFromConfigMap(registryInfo, *registryConfig)
	return string(cmDefaultMode), nil

}

func (registryScan *registryScan) setRegistryInfoFromConfigMap(registryInfo *armotypes.RegistryInfo, registryConfig registryScanConfig) {
	registryInfo.Depth = registryConfig.Depth
	registryInfo.Include = registryConfig.Include
	registryInfo.Exclude = registryConfig.Exclude
}

func (registryScan *registryScan) getRegistryScanSecret() (k8sinterface.IWorkload, error) {
	secret, err := registryScan.k8sAPI.GetWorkload(armotypes.KubescapeNamespace, "Secret", armotypes.RegistryScanSecretName)
	if err == nil && secret != nil {
		return secret, err
	}

	// deprecated namespace
	secret, err = registryScan.k8sAPI.GetWorkload(armotypes.ArmoSystemNamespace, "Secret", armotypes.RegistryScanSecretName)
	return secret, err

}

func (registryScan *registryScan) setHostnameAndProject() {
	regAndProject := strings.Split(registryScan.registryInfo.RegistryName, "/")
	hostname := regAndProject[0]
	project := ""
	if len(regAndProject) > 1 {
		project = regAndProject[1]
	}
	registryScan.registry = registry{hostname: hostname, projectID: project}
}
