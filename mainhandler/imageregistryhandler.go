package mainhandler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/golang/glog"
	containerregistry "github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"k8s.io/utils/strings/slices"
)

type AuthMethods string

const (
	REGISTRY_SCAN_SECRET                        = "kubescape-registry-scan"
	REGISTRY_SCAN_CONFIGMAP                     = "kubescape-registry-scan"
	IMAGES_TO_SCAN_LIMIT                        = 500
	DEFAULT_DEPTH                               = 1
	REGISTRIES_AUTH_FIELD_IN_SECRET             = "registriesAuth"
	ARMO_NAMESPACE                              = "armo-system"
	IPS_AUTH                        AuthMethods = "ips"
)

type RegistryScanConfig struct {
	Registry string   `json:"registry"`
	Depth    int      `json:"depth"`
	Include  []string `json:"include,omitempty"`
	Exclude  []string `json:"exclude,omitempty"`
}

type RegistryAuth struct {
	Registry   string `json:"registry"`
	AuthMethod string `json:"auth_method"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}

type Registry struct {
	Hostname  string
	ProjectID string
}

type RegistryScan struct {
	Registry           Registry
	RegistryAuth       types.AuthConfig
	RegistryScanConfig RegistryScanConfig
}

type RegistryScanHandler struct {
	registryScan      []RegistryScan
	mapRegistryToAuth map[string]types.AuthConfig
}

type registryCreds struct {
	RegistryName string
	auth         *types.AuthConfig
}

func NewRegistryHandler() *RegistryScanHandler {
	return &RegistryScanHandler{
		registryScan:      make([]RegistryScan, 0),
		mapRegistryToAuth: make(map[string]types.AuthConfig),
	}
}

func (registryScanHandler *RegistryScanHandler) ParseConfigMapData(configData map[string]interface{}) error {
	var registries []RegistryScanConfig
	var registryScan RegistryScan
	registriesStr := configData["registries"].(string)
	registriesStr = strings.Replace(registriesStr, "\n", "", -1)
	err := json.Unmarshal([]byte(registriesStr), &registries)
	if err != nil {
		return fmt.Errorf("error parsing ConfigMap: %s", err.Error())
	}
	for _, reg := range registries {
		if len(reg.Include) > 0 && len(reg.Exclude) > 0 {
			glog.Errorf("configMap should contain either 'Include' or 'Exclude', not both. In registry: %v", reg.Registry)
			continue
		}
		if auth, ok := registryScanHandler.mapRegistryToAuth[reg.Registry]; ok {
			if reg.Depth == 0 {
				reg.Depth = DEFAULT_DEPTH
			}
			registryScan = RegistryScan{
				RegistryScanConfig: reg,
				RegistryAuth:       auth,
			}
		} else { // public registry
			registryScan = RegistryScan{
				RegistryScanConfig: reg,
				RegistryAuth:       types.AuthConfig{},
			}
		}
		if registrySpplited := strings.Split(reg.Registry, "/"); len(registrySpplited) > 1 {
			registryScan.Registry.Hostname = registrySpplited[0]
			registryScan.Registry.ProjectID = registrySpplited[1]
		}
		registryScanHandler.registryScan = append(registryScanHandler.registryScan, registryScan)
	}
	return nil
}

// parse secret data according to convention
func (registryScanHandler *RegistryScanHandler) ParseSecretsData(secretData map[string]interface{}) error {
	var registriesAuth []RegistryAuth
	registriesStr, ok := secretData[REGISTRIES_AUTH_FIELD_IN_SECRET].(string)
	if !ok {
		return fmt.Errorf("error parsing Secret: %s field must be a string", REGISTRIES_AUTH_FIELD_IN_SECRET)
	}
	data, err := base64.StdEncoding.DecodeString(registriesStr)
	if err != nil {
		return fmt.Errorf("error parsing Secret: %s", err.Error())
	}
	registriesStr = strings.Replace(string(data), "\n", "", -1)
	err = json.Unmarshal([]byte(registriesStr), &registriesAuth)
	if err != nil {
		err = fmt.Errorf("error parsing Secret: %s", err.Error())
	}

	for _, reg := range registriesAuth {
		switch AuthMethods(reg.AuthMethod) {
		case IPS_AUTH:
			if reg.Registry != "" && reg.Username != "" && reg.Password != "" {
				registryScanHandler.mapRegistryToAuth[reg.Registry] = types.AuthConfig{
					Username: reg.Username,
					Password: reg.Password,
				}
			}

		}

	}

	return err
}

func (registryScanHandler *RegistryScanHandler) GetImagesForScanning(registryScan RegistryScan) (map[string][]string, error) {
	imgNameToTags := make(map[string][]string, 0)
	regCreds := &registryCreds{
		auth:         &registryScan.RegistryAuth,
		RegistryName: registryScan.Registry.Hostname,
	}
	repoes, err := registryScanHandler.ListRepoesInRegistry(regCreds, &registryScan)
	if err != nil {
		return imgNameToTags, err
	}
	for _, repo := range repoes {
		if len(registryScan.RegistryScanConfig.Include) > 0 {
			if slices.Contains(registryScan.RegistryScanConfig.Include, strings.Replace(repo, registryScan.Registry.ProjectID+"/", "", -1)) {
				tags, _ := registryScanHandler.ListImageTagsInRepo(repo, regCreds)
				for i := 0; i < registryScan.RegistryScanConfig.Depth; i++ {
					imgNameToTags[registryScan.Registry.Hostname+"/"+repo] = tags
				}

			}
		} else if len(registryScan.RegistryScanConfig.Exclude) > 0 {
			if !slices.Contains(registryScan.RegistryScanConfig.Exclude, strings.Replace(repo, registryScan.Registry.ProjectID+"/", "", -1)) {
				tags, _ := registryScanHandler.ListImageTagsInRepo(repo, regCreds)
				for i := 0; i < registryScan.RegistryScanConfig.Depth; i++ {
					imgNameToTags[registryScan.Registry.Hostname+"/"+repo] = tags
				}
			}
		}
	}
	if len(imgNameToTags) > IMAGES_TO_SCAN_LIMIT {
		return nil, fmt.Errorf("limit of images to scan exceeded. Limits: %d", IMAGES_TO_SCAN_LIMIT)
	}
	return imgNameToTags, nil
}

func (registryScanHandler *RegistryScanHandler) ListRepoesInRegistry(regCreds *registryCreds, registryScan *RegistryScan) ([]string, error) {
	registry, err := containerregistry.NewRegistry(registryScan.Registry.Hostname)
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
		if strings.Contains(repo, registryScan.Registry.ProjectID+"/") {
			reposInGivenRegistry = append(reposInGivenRegistry, repo)
		}
	}
	return reposInGivenRegistry, nil
}

func (registryScanHandler *RegistryScanHandler) ListImageTagsInRepo(repo string, regCreds *registryCreds) ([]string, error) {
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
