package mainhandler

import (
	"fmt"

	dockerregistry "github.com/docker/docker/api/types/registry"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/kubescape/k8s-interface/cloudsupport"
)

// Authorization implements Authenticator.
// Check if can be replaced with https://github.com/kubescape/k8s-interface/blob/227d2ab94a72086c86b0f5ce1bf222dc13e90d49/cloudsupport/cloudvendorregistrycreds.go#L209
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
	if cloudsupport.CheckIsECRImage(regCreds.registryName) {
		username, password, err = cloudsupport.GetLoginDetailsForECR(regCreds.registryName)
		if err != nil {
			return nil, fmt.Errorf("ECR get Authorization failed with err %v", err.Error())
		}
		*regCreds.auth = dockerregistry.AuthConfig{Username: username, Password: password}
	} else if cloudsupport.CheckIsGCRImage(regCreds.registryName + "/") {
		username, password, err = cloudsupport.GetLoginDetailsForGCR(regCreds.registryName)
		if err != nil {
			return nil, fmt.Errorf("GCR get Authorization failed with err %v", err.Error())
		}
		*regCreds.auth = dockerregistry.AuthConfig{Username: username, Password: password}
	} else if cloudsupport.CheckIsACRImage(regCreds.registryName + "/") {
		username, password, err = cloudsupport.GetLoginDetailsForAzurCR(regCreds.registryName)
		if err != nil {
			return nil, fmt.Errorf("ACR get Authorization failed with err %v", err.Error())
		}
		*regCreds.auth = dockerregistry.AuthConfig{Username: username, Password: password}
	} else {
		return &authn.AuthConfig{}, nil
	}

	return &authn.AuthConfig{Username: username, Password: password}, nil
}
