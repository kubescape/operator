package mainhandler

import (
	"fmt"

	"github.com/armosec/k8s-interface/cloudsupport"
	"github.com/docker/docker/api/types"
	"github.com/google/go-containerregistry/pkg/authn"
)

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
