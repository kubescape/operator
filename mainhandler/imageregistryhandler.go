package mainhandler

import (
	"context"
	"encoding/json"
	"fmt"
	"k8s-ca-websocket/cautils"
	"strings"

	regCommon "github.com/armosec/registryx/common"
	regInterfaces "github.com/armosec/registryx/interfaces"
	regFactory "github.com/armosec/registryx/registries"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/logger-go/system-reports/datastructures"
	"github.com/docker/docker/api/types"
	"github.com/golang/glog"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/strings/slices"
)

type AuthMethods string

const (
	registryScanSecret                      = "kubescape-registry-scan"
	registryScanConfigmap                   = "kubescape-registry-scan"
	registryInfoV1                          = "registryInfo-v1"
	registryNameField                       = "registryName"
	imagesToScanLimit                       = 500
	defaultDepth                            = 1
	registriesAuthFieldInSecret             = "registriesAuth"
	armoNamespace                           = "armo-system"
	accessTokenAuth             AuthMethods = "accesstoken"
	registryCronjobTemplate                 = "registry-scan-cronjob-template"
	registryNameAnnotation                  = "armo.cloud/registryname"
	tagsPageSize                            = 1000
)

type registryScanConfig struct {
	Registry string   `json:"registry"`
	Depth    int      `json:"depth"`
	Include  []string `json:"include,omitempty"`
	Exclude  []string `json:"exclude,omitempty"`
}
type registryAuth struct {
	Registry      string                 `json:"registry"`
	AuthMethod    string                 `json:"auth_method,omitempty"`
	Username      string                 `json:"username,omitempty"`
	Password      string                 `json:"password,omitempty"`
	Kind          regCommon.RegistryKind `json:"kind,omitempty"`
	SkipTLSVerify *bool                  `json:"skipTLSVerify,omitempty"`
	Insecure      *bool                  `json:"http,omitempty"`
	//dockerRegistryAuth types.AuthConfig
}

type registry struct {
	hostname  string
	projectID string
}

type registryScan struct {
	registry           registry
	registryAuth       registryAuth
	registryScanConfig registryScanConfig
	mapImageToTags     map[string][]string
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

func NewRegistryScan(registryName string, auth registryAuth, config registryScanConfig) registryScan {
	regAndProject := strings.Split(registryName, "/")
	hostname := regAndProject[0]
	project := ""
	if len(regAndProject) > 1 {
		project = regAndProject[1]
	}
	return registryScan{
		registry:           registry{hostname: hostname, projectID: project},
		mapImageToTags:     make(map[string][]string),
		registryAuth:       auth,
		registryScanConfig: config,
	}
}

func makeRegistryAuth(registryName string) registryAuth {
	kind, _ := regCommon.GetRegistryKind(strings.Split(registryName, "/")[0])
	falseInsecure := false
	falseSkipTLS := false
	return registryAuth{SkipTLSVerify: &falseSkipTLS, Insecure: &falseInsecure, Kind: kind}
}

func (rs *registryScan) makeRegistryInterface() (regInterfaces.IRegistry, error) {
	return regFactory.Factory(&authn.AuthConfig{Username: rs.registryAuth.Username, Password: rs.registryAuth.Password}, rs.registry.hostname,
		regCommon.MakeRegistryOptions(false, *rs.registryAuth.Insecure, *rs.registryAuth.SkipTLSVerify, "", "", rs.registry.projectID, rs.registryAuth.Kind))
}

func (rs *registryScan) hasAuth() bool {
	//todo - support registry token
	return rs.registryAuth.Password != "" //|| rs.registryAuth.RegistryToken != ""
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
			Username: rs.registryAuth.Username,
			Password: rs.registryAuth.Password,
			Auth:     rs.registryAuth.AuthMethod,
			//TODO:addd tokens support
		}
	}
	return authConfig
}

func (reg *registryAuth) initDefaultValues() error {
	switch reg.AuthMethod {
	case "accesstoken", "":
		if reg.Password == "" || reg.Username == "" {
			return fmt.Errorf("auth_method accesstoken requirers username and password. Please refer to the documentation %s", "https://hub.armosec.io/docs/registry-vulnerability-scan")
		}
	case "public", "ips":
		//do nothing
		break
	case "identity_token", "registry_token":
		fallthrough
	default:
		return fmt.Errorf("auth_method (%s) not supported. Please refer to the documentation %s", reg.AuthMethod, "https://hub.armosec.io/docs/registry-vulnerability-scan")
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
	if len(rs.registryScanConfig.Include) == 0 && len(rs.registryScanConfig.Exclude) == 0 {
		return repos
	}
	filteredRepos := []string{}
	for _, repo := range repos {
		if rs.registry.projectID != "" {
			if !strings.Contains(repo, rs.registry.projectID+"/") {
				continue
			}
		}
		if len(rs.registryScanConfig.Include) != 0 && slices.Contains(rs.registryScanConfig.Include, strings.Replace(repo, rs.registry.projectID+"/", "", -1)) {
			filteredRepos = append(filteredRepos, repo)
		}
		if len(rs.registryScanConfig.Exclude) != 0 {
			if !slices.Contains(rs.registryScanConfig.Exclude, strings.Replace(repo, rs.registry.projectID+"/", "", -1)) {
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
	command, err := registryScan.getRegistryScanV1ScanCommand(registryName)
	if err != nil {
		return err
	}

	// command will be mounted into cronjob by using this configmap
	configMap.Data[requestBodyFile] = string(command)

	if _, err := k8sAPI.KubernetesClient.CoreV1().ConfigMaps(cautils.CA_NAMESPACE).Create(context.Background(), &configMap, metav1.CreateOptions{}); err != nil {
		return err
	}
	glog.Infof("createTriggerRequestConfigMap: created configmap: %s", name)
	return nil
}

func (registryScan *registryScan) getImagesForScanning(reporter datastructures.IReporter) error {

	glog.Infof("GetImagesForScanning: enumerating repoes...")
	repoes, err := registryScan.listReposInRegistry()
	if err != nil {
		glog.Errorf("ListRepoesInRegistry failed with err %v", err)
		return err
	}
	glog.Infof("GetImagesForScanning: enumerating repoes successfully, found %d repos", len(repoes))
	for _, repo := range repoes {
		if err := registryScan.setImageToTagsMap(repo); err != nil {
			glog.Errorf("setImageToTagsMap failed with registry: %s repo: %s due to ERROR:: %s", registryScan.registry.hostname, repo, err.Error())
		}
	}
	if registryScan.isExceedScanLimit(imagesToScanLimit) {
		registryScan.filterScanLimit(imagesToScanLimit)
		if reporter != nil {
			errChan := make(chan error)
			reporter.SendError(err, true, true, errChan)
			if err := <-errChan; err != nil {
				glog.Errorf("setImageToTagsMap failed to send error report: %s due to ERROR:: %s",
					registryScan.registry.hostname, err.Error())
			}
		}
		glog.Warning("GetImagesForScanning: more than 500 images provided. scanning only first 500 images")
	}
	return nil
}

func (registryScan *registryScan) setImageToTagsMap(repo string) error {
	iRegistry, err := registryScan.makeRegistryInterface()
	if err != nil {
		return err
	}

	firstPage := regCommon.MakePagination(tagsPageSize)
	latestTagFound := false
	tagsDepth := registryScan.registryScanConfig.Depth
	tags := []string{}
	options := []remote.Option{}
	if registryScan.hasAuth() {
		options = append(options, remote.WithAuth(registryScan.registryCredentials()))
	}
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

// Check if number of images (not repoes) to scan is more than limit
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

func (registryScan *registryScan) listReposInRegistry() ([]string, error) {
	iRegistry, err := registryScan.makeRegistryInterface()
	if err != nil {
		return nil, err
	}
	regCreds := registryScan.registryCredentials()
	var repos []string
	//TODO
	firstPage := regCommon.MakePagination(iRegistry.GetMaxPageSize())
	ctx := context.Background()
	catalogOpts := regCommon.CatalogOption{IsPublic: !registryScan.hasAuth(), Namespaces: registryScan.registry.projectID}
	for pageRepos, nextPage, err := iRegistry.Catalog(ctx, firstPage, catalogOpts, regCreds); ; pageRepos, nextPage, err = iRegistry.Catalog(ctx, *nextPage, catalogOpts, regCreds) {
		if err != nil {
			return nil, err
		}
		repos = append(repos, registryScan.filterRepositories(pageRepos)...)
		total2Include := len(registryScan.registryScanConfig.Include)
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
	return repos, nil
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

	jobTemplateObj.Spec.JobTemplate.Spec.Template.Annotations[registryNameAnnotation] = registryName

	// add annotations
	if jobTemplateObj.ObjectMeta.Labels == nil {
		jobTemplateObj.ObjectMeta.Labels = make(map[string]string)
	}
	jobTemplateObj.ObjectMeta.Labels["app"] = name

	return nil
}

func (registryScan *registryScan) getRegistryScanV1ScanCommand(registryName string) (string, error) {
	/*
			scan registry command:
			{
		    "commands": [{
		        "CommandName": "scanRegistry",
		        "args": {
		            "registryInfo-v1": {
		                "registryName": "gcr.io/project"
		            }
		        }
		    }]
		}
	*/
	scanRegistryCommand := apis.Command{}
	scanRegistryCommand.CommandName = apis.TypeScanRegistry
	registryInfo := map[string]string{registryNameField: registryName}

	scanRegistryCommand.Args = map[string]interface{}{registryInfoV1: registryInfo}
	scanRegistryCommand.Args[registryInfoV1] = registryInfo

	scanRegistryCommands := apis.Commands{}
	scanRegistryCommands.Commands = append(scanRegistryCommands.Commands, scanRegistryCommand)

	scanV1Bytes, err := json.Marshal(scanRegistryCommands)
	if err != nil {
		return "", err
	}

	return string(scanV1Bytes), nil
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
	if _, err := k8sAPI.KubernetesClient.BatchV1().CronJobs(cautils.CA_NAMESPACE).Create(context.Background(), jobTemplateObj, metav1.CreateOptions{}); err != nil {
		glog.Infof("setRegistryScanCronJob: cronjob: %s creation failed. err: %s", name, err.Error())
		return err
	}
	return nil
}
