package mainhandler

import (
	"context"
	"fmt"

	"github.com/armosec/k8s-interface/cloudsupport"
	"github.com/docker/docker/api/types"
	"github.com/google/go-containerregistry/pkg/authn"
	containerregistry "github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type registryCreds struct {
	RegistryName string
	auth         *types.AuthConfig
}

// Authorization implements Authenticator.
func (regCreds *registryCreds) Authorization() (*authn.AuthConfig, error) {

	var err error
	var username string
	var password string

	if regCreds.auth != nil {
		return &authn.AuthConfig{
			Username:      regCreds.auth.Username,
			Password:      regCreds.auth.Password,
			Auth:          regCreds.auth.Auth,
			RegistryToken: regCreds.auth.RegistryToken,
			IdentityToken: regCreds.auth.IdentityToken,
		}, nil
	}

	/*
		in the registry
	*/
	if cloudsupport.CheckIsECRImage(regCreds.RegistryName) {
		username, password, err = cloudsupport.GetLoginDetailsForECR(regCreds.RegistryName)
		if err != nil {
			return nil, fmt.Errorf("ECR get Authorization failed with err %v", err.Error())
		}
		*regCreds.auth = types.AuthConfig{Username: username, Password: password}
	} else if cloudsupport.CheckIsGCRImage(regCreds.RegistryName + "/") {
		username, password, err = cloudsupport.GetLoginDetailsForGCR(regCreds.RegistryName)
		if err != nil {
			return nil, fmt.Errorf("GCR get Authorization failed with err %v", err.Error())
		}
		*regCreds.auth = types.AuthConfig{Username: username, Password: password}
	} else if cloudsupport.CheckIsACRImage(regCreds.RegistryName + "/") {
		username, password, err = cloudsupport.GetLoginDetailsForAzurCR(regCreds.RegistryName)
		if err != nil {
			return nil, fmt.Errorf("ACR get Authorization failed with err %v", err.Error())
		}
		*regCreds.auth = types.AuthConfig{Username: username, Password: password}
	} else {
		return &authn.AuthConfig{}, nil
	}

	return &authn.AuthConfig{Username: username, Password: password}, nil
}

func ListImagesInRegistry(registryName string, auth *types.AuthConfig) (map[string][]string, error) {

	imagesWithTags := make(map[string][]string)
	registry, err := containerregistry.NewRegistry(registryName)
	if err != nil {
		return nil, err
	}

	regCreds := &registryCreds{
		RegistryName: registryName,
		auth:         auth,
	}
	ctx := context.Background()
	repos, err := remote.Catalog(ctx, registry, remote.WithAuth(regCreds))
	if err != nil {
		return nil, err
	}
	for _, repo := range repos {
		fullRepoName := registryName + "/" + repo
		imagesWithTags[fullRepoName] = make([]string, 0)
		repo_data, err := containerregistry.NewRepository(fullRepoName)
		if err != nil {
			return nil, err
		}
		imagestags, err := remote.List(repo_data, remote.WithAuth(regCreds))
		if err != nil {
			return nil, err
		}
		imagesWithTags[fullRepoName] = append(imagesWithTags[fullRepoName], imagestags...)
	}

	return imagesWithTags, nil
}
