package mainhandler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	"github.com/mitchellh/mapstructure"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/pager"

	regCommon "github.com/armosec/registryx/common"
	regInterfaces "github.com/armosec/registryx/interfaces"
	regFactory "github.com/armosec/registryx/registries"
	"github.com/kubescape/k8s-interface/cloudsupport"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	dockerregistry "github.com/docker/docker/api/types/registry"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	beClientV1 "github.com/kubescape/backend/pkg/client/v1"
	"github.com/kubescape/k8s-interface/k8sinterface"
	v1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/strings/slices"
)

type AuthMethods string

const (
	registryScanConfigmap                   = "kubescape-registry-scan"
	registryNameField                       = "registryName"
	secretNameField                         = "secretName"
	imagesToScanLimit                       = 500
	registriesAuthFieldInSecret             = "registriesAuth"
	accessTokenAuth             AuthMethods = "accesstoken"
	registryCronjobTemplate                 = "registry-scan-cronjob-template"
	tagsPageSize                            = 1000
	registryScanDocumentation               = "https://hub.armosec.io/docs/registry-vulnerability-scan"
)

type registryScanConfig struct {
	Registry string   `json:"registry"`
	Include  []string `json:"include,omitempty"`
	Exclude  []string `json:"exclude,omitempty"`
	Depth    int      `json:"depth"`
}
type registryAuth struct {
	SkipTLSVerify *bool                  `json:"skipTLSVerify,omitempty"`
	Insecure      *bool                  `json:"http,omitempty"`
	Registry      string                 `json:"registry,omitempty"`
	AuthMethod    string                 `json:"auth_method,omitempty"`
	Username      string                 `json:"username,omitempty"`
	Password      string                 `json:"password,omitempty"`
	RegistryToken string                 `json:"registryToken,omitempty"`
	Kind          regCommon.RegistryKind `json:"kind,omitempty"`
}

type registry struct {
	hostname  string
	projectID string
}

type registryScan struct {
	config         config.IConfig
	k8sAPI         *k8sinterface.KubernetesApi
	mapImageToTags map[string][]string
	registryInfo   armotypes.RegistryInfo
	registry       registry
	sendReport     bool
}

type RepositoriesAndTagsParams struct {
	CustomerGUID string                 `json:"customerGUID"`
	RegistryName string                 `json:"registryName"`
	JobID        string                 `json:"jobID"`
	Repositories []armotypes.Repository `json:"repositories"`
}

type registryCreds struct {
	auth         *dockerregistry.AuthConfig
	registryName string
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

func NewRegistryScan(config config.IConfig, k8sAPI *k8sinterface.KubernetesApi) registryScan {
	depth := new(int)
	isHTTPS := new(bool)
	skipTlsVerify := new(bool)
	*depth = 1
	*isHTTPS = true
	*skipTlsVerify = false
	return registryScan{
		registry:       registry{},
		mapImageToTags: make(map[string][]string),
		registryInfo: armotypes.RegistryInfo{
			Depth:         depth,
			IsHTTPS:       isHTTPS,
			SkipTLSVerify: skipTlsVerify,
		},
		k8sAPI:     k8sAPI,
		config:     config,
		sendReport: config.EventReceiverURL() != "",
	}
}

func (rs *registryScan) makeRegistryInterface() (regInterfaces.IRegistry, error) {
	return regFactory.Factory(&authn.AuthConfig{Username: rs.registryInfo.AuthMethod.Username, Password: rs.registryInfo.AuthMethod.Password, RegistryToken: rs.registryInfo.RegistryToken}, rs.registry.hostname,
		regCommon.MakeRegistryOptions(false, !*rs.registryInfo.IsHTTPS, *rs.registryInfo.SkipTLSVerify, "", "", rs.registry.projectID, regCommon.RegistryKind(rs.registryInfo.Kind)))
}

func (rs *registryScan) isPrivate() bool {
	//TODO: support registry token
	return rs.registryInfo.AuthMethod.Password != ""
}

func (rs *registryScan) registryCredentials() *registryCreds {
	var regCreds *registryCreds
	if rs.isPrivate() {
		regCreds = &registryCreds{
			auth:         rs.authConfig(),
			registryName: rs.registry.hostname,
		}
	}
	return regCreds
}

func (rs *registryScan) authConfig() *dockerregistry.AuthConfig {
	var authConfig *dockerregistry.AuthConfig
	if rs.isPrivate() {
		authConfig = &dockerregistry.AuthConfig{
			Username: rs.registryInfo.AuthMethod.Username,
			Password: rs.registryInfo.AuthMethod.Password,
			Auth:     rs.registryInfo.AuthMethod.Type,
			//TODO: add tokens support
		}
	}
	return authConfig
}

func (reg *registryAuth) initDefaultValues(ctx context.Context) error {
	switch reg.AuthMethod {
	case string(accessTokenAuth), "", "credentials":
		if reg.Password == "" || reg.Username == "" {
			return errorWithDocumentationRef("auth_method accesstoken requires username and password")
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
			logger.L().Ctx(ctx).Error("cannot validate registry kind", helpers.Error(err))
			return err
		}
	} else {
		//try to get the kind from the reg name - if not found it will fall back to default kind
		reg.Kind, _ = regCommon.GetRegistryKind(strings.Split(reg.Registry, "/")[0])
	}
	return err
}

func (rs *registryScan) filterRepositories(ctx context.Context, repos []string) []string {
	if len(rs.registryInfo.Include) == 0 && len(rs.registryInfo.Exclude) == 0 {
		return repos
	}
	var filteredRepos []string
	for _, repo := range repos {
		// if rs.registry.projectID != "" {
		// 	if !strings.Contains(repo, rs.registry.projectID+"/") {
		// 		continue
		// 	}
		// }
		if len(rs.registryInfo.Include) != 0 {
			if slices.Contains(rs.registryInfo.Include, strings.Replace(repo, rs.registry.projectID+"/", "", -1)) {
				filteredRepos = append(filteredRepos, repo)
				continue
			}
			if slices.Contains(rs.registryInfo.Include, repo) {
				filteredRepos = append(filteredRepos, repo)
				continue
			}
		}
		if len(rs.registryInfo.Exclude) != 0 {
			if !slices.Contains(rs.registryInfo.Exclude, strings.Replace(repo, rs.registry.projectID+"/", "", -1)) && !slices.Contains(rs.registryInfo.Exclude, repo) {
				filteredRepos = append(filteredRepos, repo)
			} else {
				repoMsg := rs.registry.hostname + "/"
				if rs.registry.projectID != "" {
					repoMsg += rs.registry.projectID + "/"
				}
				repoMsg += repo
				logger.L().Ctx(ctx).Warning(fmt.Sprintf("image registry scan::%s was excluded", repoMsg)) // systest dependent
			}

		}
	}
	return filteredRepos
}

func (registryScan *registryScan) createTriggerRequestSecret(k8sAPI *k8sinterface.KubernetesApi, name, registryName string) error {

	secret := corev1.Secret{}
	secret.Name = name
	secret.StringData = make(map[string]string)
	registryAuth := []registryAuth{
		{
			Registry:   registryName,
			Username:   registryScan.registryInfo.AuthMethod.Username,
			Password:   registryScan.registryInfo.AuthMethod.Password,
			AuthMethod: registryScan.registryInfo.AuthMethod.Type,
		},
	}
	registryAuthBytes, err := json.Marshal(registryAuth)
	if err != nil {
		return err
	}

	secret.StringData[registriesAuthFieldInSecret] = string(registryAuthBytes)
	if _, err := k8sAPI.KubernetesClient.CoreV1().Secrets(registryScan.config.Namespace()).Create(context.Background(), &secret, metav1.CreateOptions{}); err != nil {
		return err
	}
	registryScan.registryInfo.SecretName = name
	return nil
}

func (registryScan *registryScan) createTriggerRequestConfigMap(k8sAPI *k8sinterface.KubernetesApi, name string) error {
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
	command, err := registryScan.getCommandForConfigMap()
	if err != nil {
		return err
	}

	// command will be mounted into cronjob by using this configmap
	configMap.Data[requestBodyFile] = command

	if _, err := k8sAPI.KubernetesClient.CoreV1().ConfigMaps(registryScan.config.Namespace()).Create(context.Background(), &configMap, metav1.CreateOptions{}); err != nil {
		return err
	}
	return nil
}

func (registryScan *registryScan) getImagesForScanning(ctx context.Context, reporter beClientV1.IReportSender) error {
	logger.L().Info("getImagesForScanning: enumerating repos...")
	errChan := make(chan error)
	repos, err := registryScan.enumerateRepos(ctx)
	if err != nil {
		reporter.SetDetails("enumerateRepos failed")
		return err
	}
	logger.L().Info(fmt.Sprintf("GetImagesForScanning: enumerating repos successfully, found %d repos", len(repos)))

	for _, repo := range repos {
		if err := registryScan.setImageToTagsMap(ctx, repo, reporter, registryScan.mapImageToTags); err != nil {
			logger.L().Ctx(ctx).Error("setImageToTagsMap failed", helpers.String("registry", registryScan.registry.hostname), helpers.Error(err))
		}
	}

	if registryScan.isExceedScanLimit(imagesToScanLimit) {
		registryScan.filterScanLimit(imagesToScanLimit)
		errMsg := fmt.Sprintf("more than %d images provided. scanning only first %d images", imagesToScanLimit, imagesToScanLimit)
		if reporter != nil {
			err := errorWithDocumentationRef(errMsg)
			reporter.SendWarning(err.Error(), registryScan.sendReport, true)
			if err := <-errChan; err != nil {
				logger.L().Ctx(ctx).Error("setImageToTagsMap failed to send error report",
					helpers.String("registry", registryScan.registry.hostname), helpers.Error(err))
			}
		}
		logger.L().Ctx(ctx).Warning("GetImagesForScanning: " + errMsg)
	}
	return nil
}

func (registryScan *registryScan) setImageToTagsMap(ctx context.Context, repo string, sender beClientV1.IReportSender, imageToTags map[string][]string) error {
	logger.L().Info(fmt.Sprintf("Fetching repository %s tags", repo))
	iRegistry, err := registryScan.makeRegistryInterface()
	if err != nil {
		return err
	}

	firstPage := regCommon.MakePagination(tagsPageSize)
	latestTagFound := false
	tagsDepth := registryScan.registryInfo.Depth
	var tags []string
	var options []remote.Option
	if registryScan.isPrivate() {
		options = append(options, remote.WithAuth(registryScan.registryCredentials()))
	}
	if latestTags, err := iRegistry.GetLatestTags(repo, *tagsDepth, options...); err == nil {
		var tags []string
		for _, tag := range latestTags {
			// filter out signature tags
			if strings.HasSuffix(tag, ".sig") {
				continue
			}
			tagsForDigest := strings.Split(tag, ",")
			tagsForDigestLen := len(tagsForDigest)
			if tagsForDigestLen == 1 {
				tags = append(tags, tagsForDigest[0])
			} else {
				if tagsForDigestLen > *tagsDepth {
					tags = append(tags, tagsForDigest[:*tagsDepth]...)
					errMsg := fmt.Sprintf("image %s has %d tags. scanning only first %d tags - %s", repo, tagsForDigestLen, *tagsDepth, strings.Join(tagsForDigest[:*tagsDepth], ","))
					if sender != nil {
						err := errorWithDocumentationRef(errMsg)
						sender.SendWarning(err.Error(), registryScan.sendReport, true)
					}
					logger.L().Ctx(ctx).Warning("GetImagesForScanning: " + errMsg)
				} else {
					tags = append(tags, tagsForDigest...)
				}
			}
		}
		imageToTags[registryScan.registry.hostname+"/"+repo] = tags

	} else { //fallback to list images lexicographically
		logger.L().Ctx(ctx).Error("get latestTags failed, fetching lexicographical list of tags", helpers.String("repository", repo), helpers.Error(err))
		for tagsPage, nextPage, err := iRegistry.List(repo, firstPage, options...); ; tagsPage, nextPage, err = iRegistry.List(repo, *nextPage) {
			if err != nil {
				return err
			}

			if !latestTagFound {
				latestTagFound = slices.Contains(tagsPage, "latest")
			}
			tags = updateTagsCandidates(tags, tagsPage, *tagsDepth, latestTagFound)

			if *tagsDepth == 1 && latestTagFound {
				break
			}

			if nextPage == nil {
				break
			}
		}
		imageToTags[registryScan.registry.hostname+"/"+repo] = tags
	}
	return nil
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

func (registryScan *registryScan) enumerateRepos(ctx context.Context) ([]string, error) {
	// token sometimes includes a lot of dots, so we need to remove them
	i := strings.Index(registryScan.registryInfo.AuthMethod.Password, ".....")
	if i != -1 {
		registryScan.registryInfo.AuthMethod.Password = registryScan.registryInfo.AuthMethod.Password[:i]
	}

	repos, err := registryScan.listReposInRegistry(ctx)
	if err != nil {
		return []string{}, err
	}
	return repos, nil

}

func (registryScan *registryScan) listReposInRegistry(ctx context.Context) ([]string, error) {
	iRegistry, err := registryScan.makeRegistryInterface()
	if err != nil {
		return nil, err
	}
	regCreds := registryScan.registryCredentials()
	var repos, pageRepos []string
	var nextPage *regCommon.PaginationOption

	firstPage := regCommon.MakePagination(iRegistry.GetMaxPageSize())
	catalogOpts := regCommon.CatalogOption{IsPublic: !registryScan.isPrivate(), Namespaces: registryScan.registry.projectID}
	for pageRepos, nextPage, err = iRegistry.Catalog(ctx, firstPage, catalogOpts, regCreds); ; pageRepos, nextPage, err = iRegistry.Catalog(ctx, *nextPage, catalogOpts, regCreds) {
		if err != nil {
			return nil, err
		}
		if len(pageRepos) == 0 {
			break
		}
		repos = append(repos, registryScan.filterRepositories(ctx, pageRepos)...)
		total2Include := len(registryScan.registryInfo.Include)
		if total2Include != 0 && total2Include == len(repos) {
			break
		}
		if len(repos) >= imagesToScanLimit {
			break
		}
		if nextPage == nil || nextPage.Cursor == "" {
			break
		}
		logger.L().Info(fmt.Sprintf("Found %d repositories in registry %s, nextPage is %v\n", len(repos), registryScan.registry.hostname, nextPage))

	}
	return repos, nil
}

func (registryScan *registryScan) getCommandForConfigMap() (string, error) {
	scanRegistryCommand := apis.Command{}
	scanRegistryCommand.CommandName = apis.TypeScanRegistry

	scanRegistryCommand.Args = map[string]interface{}{}

	// credentials will not be in configmap
	registryScan.registryInfo.AuthMethod = armotypes.AuthMethod{
		Type: registryScan.registryInfo.AuthMethod.Type,
	}
	scanRegistryCommand.Args[armotypes.RegistryInfoArgKey] = registryScan.registryInfo

	scanRegistryCommands := apis.Commands{}
	scanRegistryCommands.Commands = append(scanRegistryCommands.Commands, scanRegistryCommand)

	scanV1Bytes, err := json.Marshal(scanRegistryCommands)
	if err != nil {
		return "", err
	}

	return string(scanV1Bytes), nil
}

func (registryScan *registryScan) setCronJobTemplate(jobTemplateObj *v1.CronJob, name, schedule, registryName string) error {
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

	if err := mapstructure.Decode(registryInfo, &registryScan.registryInfo); err != nil {
		return fmt.Errorf("could not decode registry info into registryInfo struct, reason: %w", err)
	}
	logRegistryInfoArgs(registryInfo)
	return nil
}

func logRegistryInfoArgs(registryInfo map[string]interface{}) {
	var logMsg string
	for k, v := range registryInfo {
		if k != "authMethod" {
			logMsg += fmt.Sprintf("%v: %v ", k, v)
		}
	}
	logger.L().Info(fmt.Sprintf("registryInfo args: %v", logMsg))
}

func (registryScan *registryScan) setRegistryKind() {
	registryScan.registryInfo.RegistryProvider = registryScan.getRegistryProvider()
	registryScan.registryInfo.Kind = registryScan.registryInfo.RegistryProvider
}

func (registryScan *registryScan) getRegistryProvider() string {
	if strings.Contains(registryScan.registryInfo.RegistryName, ".dkr.ecr") {
		return "ecr"
	}
	if strings.Contains(registryScan.registryInfo.RegistryName, "gcr.io") {
		return "gcr"
	}
	if strings.Contains(registryScan.registryInfo.RegistryName, "quay.io") {
		return "quay.io"
	}
	return registryScan.registryInfo.RegistryProvider
}

// parse registry information from secret, configmap and command, giving priority to command
func (registryScan *registryScan) parseRegistry(ctx context.Context, sessionObj *utils.SessionObj) error {
	registryScan.setRegistryKind()
	registryScan.setHostnameAndProject()

	if err := registryScan.setRegistryAuthFromSecret(ctx); err != nil {
		logger.L().Info("parseRegistry: could not parse auth from secret, parsing from command", helpers.Error(err))
	} else {
		sessionObj.Reporter.SendDetails("secret loaded", registryScan.sendReport)
	}

	configMapMode, err := registryScan.getRegistryConfig(&registryScan.registryInfo)
	if err != nil {
		logger.L().Info("parseRegistry: could not get registry config", helpers.Error(err))
	}
	logger.L().Info(fmt.Sprintf("scanRegistries:registry(%s) %s configmap  successful", registryScan.registryInfo.RegistryName, configMapMode)) // systest dependent

	if e := registryScan.parseRegistryFromCommand(sessionObj); e != nil {
		return fmt.Errorf("get registry auth failed with err %w", e)
	}
	registryScan.setRegistryKind()
	registryScan.setHostnameAndProject()
	return nil
}

func (registryScan *registryScan) createTriggerRequestCronJob(k8sAPI *k8sinterface.KubernetesApi, name, registryName string, command apis.Command) error {

	// cronjob template is stored as configmap in cluster
	jobTemplateObj, err := getCronJobTemplate(k8sAPI, registryCronjobTemplate, registryScan.config.Namespace())
	if err != nil {
		return err
	}

	err = registryScan.setCronJobTemplate(jobTemplateObj, name, getCronTabSchedule(command), registryName)
	if err != nil {
		return err
	}

	// create cronJob
	if _, err := k8sAPI.KubernetesClient.BatchV1().CronJobs(registryScan.config.Namespace()).Create(context.Background(), jobTemplateObj, metav1.CreateOptions{}); err != nil {
		return err
	}
	return nil
}

func makeRegistryAuth(registryName string) registryAuth {

	kind, _ := regCommon.GetRegistryKind(strings.Split(registryName, "/")[0])
	falseInsecure := false
	falseSkipTLS := false
	return registryAuth{SkipTLSVerify: &falseSkipTLS, Insecure: &falseInsecure, Kind: kind}
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

func (registryScan *registryScan) setRegistryAuthFromSecret(ctx context.Context) error {
	var secretName string

	// If the registry is ECR and the auth method is cloudProviderIAM, get the auth token from AWS
	if registryScan.registryInfo.AuthMethod.Type == "cloudProviderIAM" {
		logger.L().Debug("setRegistryAuthFromSecret", helpers.String("RegistryName", registryScan.registryInfo.RegistryName), helpers.String("RegistryProvider", registryScan.registryInfo.RegistryProvider), helpers.String("Type", registryScan.registryInfo.AuthMethod.Type))

		// retrieve token and consider it as regular accesstoken auth
		authConfig, err := cloudsupport.GetCloudVendorRegistryCredentials(registryScan.registryInfo.RegistryName)
		if err != nil {
			return fmt.Errorf("error getting credentials: %v", err)
		}
		var auth registryAuth
		if authConfigReg, ok := authConfig[registryScan.registryInfo.RegistryName]; ok {
			auth.Username = authConfigReg.Username
			auth.Password = authConfigReg.Password
			auth.AuthMethod = string(accessTokenAuth)
			auth.Insecure = aws.Bool(false)
		} else {
			return fmt.Errorf("error getting credentials for: %v", registryScan.registryInfo.RegistryName)
		}
		registryScan.setRegistryInfoFromAuth(auth, &registryScan.registryInfo)
		return nil

	}
	if registryScan.registryInfo.SecretName != "" {
		// in newer versions the secret is sent as part of the command
		secretName = registryScan.registryInfo.SecretName
	} else {
		// in older versions the secret is stored in the cluster (backward compatibility)
		secretName = armotypes.RegistryScanSecretName
	}

	// find secret in cluster
	secrets, err := getRegistryScanSecrets(registryScan.k8sAPI, registryScan.config.Namespace(), secretName)
	if err != nil || len(secrets) == 0 {
		return err
	}

	secret := secrets[0]

	registriesAuth, err := parseRegistryAuthSecret(secret)
	if err != nil {
		return err
	}

	//try to find an auth with the same registry name from the request
	for _, auth := range registriesAuth {
		if auth.Registry == registryScan.registryInfo.RegistryName {
			if err := auth.initDefaultValues(ctx); err != nil {
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
				if err := auth.initDefaultValues(ctx); err != nil {
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

func parseRegistryAuthSecret(secret k8sinterface.IWorkload) ([]registryAuth, error) {
	secretData := secret.GetData()
	var registriesAuth []registryAuth
	registriesAuthStr, ok := secretData[registriesAuthFieldInSecret].(string)
	if !ok {
		return nil, fmt.Errorf("error parsing Secret: %s field must be a string", registriesAuthFieldInSecret)
	}
	data, err := base64.StdEncoding.DecodeString(registriesAuthStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing Secret: %s", err.Error())
	}
	registriesAuthStr = strings.Replace(string(data), "\n", "", -1)

	if e := json.Unmarshal([]byte(registriesAuthStr), &registriesAuth); e != nil {
		return nil, fmt.Errorf("error parsing Secret: %s", e.Error())
	}

	return registriesAuth, nil
}

func (registryScan *registryScan) setRegistryInfoFromAuth(auth registryAuth, registryInfo *armotypes.RegistryInfo) {
	registryInfo.AuthMethod.Type = auth.AuthMethod
	registryInfo.AuthMethod.Username = auth.Username
	registryInfo.AuthMethod.Password = auth.Password
	registryInfo.SkipTLSVerify = auth.SkipTLSVerify
	*registryInfo.IsHTTPS = !*auth.Insecure
	registryInfo.Kind = string(auth.Kind)
}

func (registryScan *registryScan) getRegistryConfig(registryInfo *armotypes.RegistryInfo) (string, error) {
	configMap, err := registryScan.k8sAPI.GetWorkload(registryScan.config.Namespace(), "ConfigMap", registryScanConfigmap)
	if err != nil {
		// if configmap not found, it means we will use all images and default depth
		if strings.Contains(err.Error(), fmt.Sprintf("reason: configmaps \"%v\" not found", registryScanConfigmap)) {
			logger.L().Info(fmt.Sprintf("configmap: %s does not exists, using default values", registryScanConfigmap))
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
	for _, c := range registriesConfigs {
		if c.Registry == registryInfo.RegistryName {
			registryScan.setRegistryInfoFromConfigMap(registryInfo, c)
			return string(cmLoadedMode), nil
		}
	}
	registryConfig := NewRegistryScanConfig(registryInfo.RegistryName)
	registryScan.setRegistryInfoFromConfigMap(registryInfo, *registryConfig)
	return string(cmDefaultMode), nil

}

func (registryScan *registryScan) setRegistryInfoFromConfigMap(registryInfo *armotypes.RegistryInfo, registryConfig registryScanConfig) {
	// default is one
	if registryConfig.Depth != 0 {
		*registryInfo.Depth = registryConfig.Depth
	}
	registryInfo.Include = registryConfig.Include
	registryInfo.Exclude = registryConfig.Exclude
}

func getRegistryScanSecrets(k8sAPI *k8sinterface.KubernetesApi, namespace, secretName string) ([]k8sinterface.IWorkload, error) {
	if secretName != "" {
		secret, err := k8sAPI.GetWorkload(namespace, "Secret", secretName)
		if err == nil && secret != nil {
			return []k8sinterface.IWorkload{secret}, err
		}
	}

	// when secret name is not provided, we will try to find all secrets starting with kubescape-registry-scan
	var registryScanSecrets []k8sinterface.IWorkload
	err := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return k8sAPI.KubernetesClient.CoreV1().Secrets(namespace).List(ctx, opts)
	}).EachListItem(k8sAPI.Context, metav1.ListOptions{}, func(obj runtime.Object) error {
		secret := obj.(*corev1.Secret)
		if strings.HasPrefix(secret.GetName(), registryScanConfigmap) {
			unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(secret)
			if err == nil {
				wl := workloadinterface.NewWorkloadObj(unstructuredObj)
				registryScanSecrets = append(registryScanSecrets, wl)
			}
		}
		return nil
	})
	return registryScanSecrets, err
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

func (registryScan *registryScan) SendRepositoriesAndTags(params RepositoriesAndTagsParams) error {
	reqBody, err := json.Marshal(params.Repositories)
	if err != nil {
		return fmt.Errorf("in 'sendReport' failed to json.Marshal, reason: %v", err)
	}

	url, err := beClientV1.GetRegistryRepositoriesUrl(registryScan.config.EventReceiverURL(), params.CustomerGUID, params.RegistryName, params.JobID)
	if err != nil {
		return err
	}

	bodyReader := bytes.NewReader(reqBody)
	req, err := http.NewRequest(http.MethodPost, url.String(), bodyReader)
	if err != nil {
		return fmt.Errorf("in 'SendRepositoriesAndTags' failed to create request, reason: %v", err)
	}
	for k, v := range utils.GetRequestHeaders(registryScan.config.AccessKey()) {
		req.Header.Set(k, v)
	}

	_, err = http.DefaultClient.Do(req)

	if err != nil {
		return fmt.Errorf("in 'SendRepositoriesAndTags' failed to send request, reason: %v", err)
	}
	return nil
}

func (registryScan *registryScan) validateRegistryScanInformation() error {
	if registryScan.registryInfo.RegistryName == "" {
		return fmt.Errorf("registry name is missing")
	}

	if registryScan.isPrivate() {
		if registryScan.registryInfo.AuthMethod.Password == "" || registryScan.registryInfo.AuthMethod.Username == "" {
			return fmt.Errorf("username or password is missing")
		}
	}

	if len(registryScan.registryInfo.Exclude) > 0 && len(registryScan.registryInfo.Include) > 0 {
		return fmt.Errorf("cannot have both exclude and include lists")
	}

	return nil
}

func (registryScan *registryScan) setSecretName(secretName string) {
	registryScan.registryInfo.SecretName = secretName
}

func (registryScan *registryScan) setRegistryName(registryName string) {
	registryScan.registryInfo.RegistryName = registryName
}

func (registryScan *registryScan) setRegistryAuthType(registryAuthType string) {
	registryScan.registryInfo.AuthMethod.Type = registryAuthType
}
