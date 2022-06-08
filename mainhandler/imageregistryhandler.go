package mainhandler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"k8s-ca-websocket/cautils"
	"strings"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/docker/docker/api/types"
	"github.com/golang/glog"
	containerregistry "github.com/google/go-containerregistry/pkg/name"
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
)

type registryScanConfig struct {
	Registry string   `json:"registry"`
	Depth    int      `json:"depth"`
	Include  []string `json:"include,omitempty"`
	Exclude  []string `json:"exclude,omitempty"`
}

type registryAuth struct {
	Registry   string `json:"registry"`
	AuthMethod string `json:"auth_method"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}

type registry struct {
	hostname  string
	projectID string
}

type registryScan struct {
	registry           registry
	registryAuth       types.AuthConfig
	registryScanConfig registryScanConfig
	mapImageToTags     map[string][]string
}

type registryScanHandler struct {
	registryScan      []registryScan
	mapRegistryToAuth map[string]types.AuthConfig
}

type registryCreds struct {
	RegistryName string
	auth         *types.AuthConfig
}

func NewRegistryScanHandler() *registryScanHandler {
	return &registryScanHandler{
		registryScan:      make([]registryScan, 0),
		mapRegistryToAuth: make(map[string]types.AuthConfig),
	}
}

func NewRegistryScan() *registryScan {
	return &registryScan{
		mapImageToTags: make(map[string][]string, 0),
	}
}

func (registryScanHandler *registryScanHandler) ParseConfigMapData(configData map[string]interface{}) error {
	var registries []registryScanConfig
	registryScan := NewRegistryScan()
	registriesStr := configData["registries"].(string)
	registriesStr = strings.Replace(registriesStr, "\n", "", -1)
	err := json.Unmarshal([]byte(registriesStr), &registries)
	if err != nil {
		return fmt.Errorf("error parsing ConfigMap: %s", err.Error())
	}
	for _, reg := range registries {
		if len(reg.Include) > 0 && len(reg.Exclude) > 0 {
			return fmt.Errorf("configMap should contain either 'Include' or 'Exclude', not both. In registry: %v", reg.Registry)
		}
		if auth, ok := registryScanHandler.mapRegistryToAuth[reg.Registry]; ok {
			if reg.Depth == 0 {
				reg.Depth = defaultDepth
			}
			registryScan.registryAuth = auth
			registryScan.registryScanConfig = reg
		} else { // public registry
			registryScan.registryAuth = types.AuthConfig{}
			registryScan.registryScanConfig = reg
		}
		registrySpplited := strings.Split(reg.Registry, "/")
		registryScan.registry.hostname = registrySpplited[0]
		if len(registrySpplited) > 1 {
			registryScan.registry.projectID = registrySpplited[1]
		}
		registryScanHandler.registryScan = append(registryScanHandler.registryScan, *registryScan)
	}
	return nil
}

func (registryScanHandler *registryScanHandler) createTriggerRequestConfigMap(k8sAPI *k8sinterface.KubernetesApi, name, registryName string, webSocketScanCMD apis.Command) error {
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
	command, err := registryScanHandler.getRegistryScanV1ScanCommand(registryName)
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

// parse secret data according to convention
func (registryScanHandler *registryScanHandler) ParseSecretsData(secretData map[string]interface{}, registryName string) error {
	var registriesAuth []registryAuth
	registriesStr, ok := secretData[registriesAuthFieldInSecret].(string)
	if !ok {
		return fmt.Errorf("error parsing Secret: %s field must be a string", registriesAuthFieldInSecret)
	}
	data, err := base64.StdEncoding.DecodeString(registriesStr)
	if err != nil {
		return fmt.Errorf("error parsing Secret: %s", err.Error())
	}
	registriesStr = strings.Replace(string(data), "\n", "", -1)
	err = json.Unmarshal([]byte(registriesStr), &registriesAuth)
	if err != nil {
		return fmt.Errorf("error parsing Secret: %s", err.Error())
	}

	for _, reg := range registriesAuth {
		switch AuthMethods(reg.AuthMethod) {
		case accessTokenAuth:
			if registryName == reg.Registry {
				if reg.Registry != "" && reg.Username != "" && reg.Password != "" {
					registryScanHandler.mapRegistryToAuth[reg.Registry] = types.AuthConfig{
						Username: reg.Username,
						Password: reg.Password,
					}
				}
			}

		}

	}

	return err
}

func (registryScanHandler *registryScanHandler) GetImagesForScanning(registryScan registryScan) error {
	imgNameToTags := make(map[string][]string, 0)
	regCreds := &registryCreds{
		auth:         &registryScan.registryAuth,
		RegistryName: registryScan.registry.hostname,
	}
	glog.Infof("GetImagesForScanning: enumerating repoes...")
	repoes, err := registryScanHandler.ListRepoesInRegistry(regCreds, &registryScan)
	if err != nil {
		glog.Infof("ListRepoesInRegistry failed with err %v", err)
		return err
	}
	glog.Infof("GetImagesForScanning: enumerating repoes successfully")
	for _, repo := range repoes {
		registryScanHandler.setImageToTagsMap(regCreds, &registryScan, repo)
	}
	if registryScanHandler.isExceedScanLimit(imgNameToTags) {
		return fmt.Errorf("limit of images to scan exceeded. Limits: %d", imagesToScanLimit)
	}
	return nil
}

func (registryScanHandler *registryScanHandler) setImageToTagsMap(regCreds *registryCreds, registryScan *registryScan, repo string) {
	if len(registryScan.registryScanConfig.Include) > 0 {
		if slices.Contains(registryScan.registryScanConfig.Include, strings.Replace(repo, registryScan.registry.projectID+"/", "", -1)) {
			tags, _ := registryScanHandler.ListImageTagsInRepo(repo, regCreds)
			for i := 0; i < registryScan.registryScanConfig.Depth; i++ {
				registryScan.mapImageToTags[registryScan.registry.hostname+"/"+repo] = tags
			}

		}
	} else if len(registryScan.registryScanConfig.Exclude) > 0 {
		if !slices.Contains(registryScan.registryScanConfig.Exclude, strings.Replace(repo, registryScan.registry.projectID+"/", "", -1)) {
			tags, _ := registryScanHandler.ListImageTagsInRepo(repo, regCreds)
			for i := 0; i < registryScan.registryScanConfig.Depth; i++ {
				registryScan.mapImageToTags[registryScan.registry.hostname+"/"+repo] = tags
			}
		}
	}
}

// Check if number of images (not repoes) to scan is more than limit
func (registryScanHandler *registryScanHandler) isExceedScanLimit(imgNameToTags map[string][]string) bool {
	numOfImgs := 0
	for _, v := range imgNameToTags {
		numOfImgs += len(v)
	}
	return numOfImgs > imagesToScanLimit
}

func (registryScanHandler *registryScanHandler) ListRepoesInRegistry(regCreds *registryCreds, registryScan *registryScan) ([]string, error) {
	registry, err := containerregistry.NewRegistry(registryScan.registry.hostname)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	repos, err := remote.Catalog(ctx, registry, remote.WithAuth(regCreds))
	if err != nil {
		return nil, err
	}
	var reposInGivenRegistry []string
	for _, repo := range repos {
		if strings.Contains(repo, registryScan.registry.projectID+"/") {
			reposInGivenRegistry = append(reposInGivenRegistry, repo)
		}
	}
	return reposInGivenRegistry, nil
}

func (registryScanHandler *registryScanHandler) ListImageTagsInRepo(repo string, regCreds *registryCreds) ([]string, error) {
	fullRepoName := regCreds.RegistryName + "/" + repo
	repo_data, err := containerregistry.NewRepository(fullRepoName)
	if err != nil {
		return nil, err
	}
	imagestags, err := remote.List(repo_data, remote.WithAuth(regCreds))

	if err != nil {
		return nil, err
	}

	return imagestags, nil
}

func (registryScanHandler *registryScanHandler) setCronJobTemplate(jobTemplateObj *v1.CronJob, name, schedule, jobID, registryName string) error {

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

func (registryScanHandler *registryScanHandler) getRegistryScanV1ScanCommand(registryName string) (string, error) {
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

func (registryScanHandler *registryScanHandler) createTriggerRequestCronJob(k8sAPI *k8sinterface.KubernetesApi, name, registryName string, command apis.Command) error {

	// cronjob template is stored as configmap in cluster
	jobTemplateObj, err := getCronJobTemplate(k8sAPI, registryCronjobTemplate)
	if err != nil {
		glog.Infof("setRegistryScanCronJob: error retrieving cronjob template : %s", err.Error())
		return err
	}

	err = registryScanHandler.setCronJobTemplate(jobTemplateObj, name, getCronTabSchedule(command), command.JobTracking.JobID, registryName)
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
