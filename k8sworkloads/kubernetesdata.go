package k8sworkloads

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/docker/docker/api/types"
	corev1 "k8s.io/api/core/v1"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// DockerConfigJsonstructure -
type DockerConfigJsonstructure map[string]map[string]types.AuthConfig

// K8SConfig pointer to k8s config
var K8SConfig *restclient.Config

// PatchOperation -
type PatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`

	// Value corev1.Pod `json:"value,omitempty"`
}

// LoadK8sConfig load config from local file or from cluster
func LoadK8sConfig() error {
	kubeconfigpath := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	kubeconfig, err := clientcmd.BuildConfigFromFlags("", kubeconfigpath)
	if err != nil {
		kubeconfig, err = restclient.InClusterConfig()
		if err != nil {
			return fmt.Errorf("cant load config kubernetes (check config path), err: %v", err)
		}
	}
	K8SConfig = kubeconfig
	return nil
}

// GetK8sConfig get config. load if not loaded yer
func GetK8sConfig() *restclient.Config {
	if err := LoadK8sConfig(); err != nil {
		return nil
	}
	return K8SConfig
}

// GetSecretContent -
func GetSecretContent(secret *corev1.Secret) (interface{}, error) {

	// Secret types- https://github.com/kubernetes/kubernetes/blob/7693a1d5fe2a35b6e2e205f03ae9b3eddcdabc6b/pkg/apis/core/types.go#L4394-L4478
	switch secret.Type {
	case corev1.SecretTypeDockerConfigJson:
		sec := make(DockerConfigJsonstructure)
		if err := json.Unmarshal(secret.Data[corev1.DockerConfigJsonKey], &sec); err != nil {
			return nil, err
		}
		return sec, nil
	default:
		user, psw := "", ""
		if len(secret.Data) != 0 {
			user, psw = parseEncodedSecret(secret.Data)
		} else if len(secret.StringData) != 0 {
			userD, pswD := parseDecodedSecret(secret.StringData)
			if userD != "" {
				user = userD
			}
			if pswD != "" {
				psw = pswD
			}
		} else {
			return nil, fmt.Errorf("data not found in secret")
		}
		if user == "" || psw == "" {
			return nil, fmt.Errorf("username  or password not found")
		}

		return &types.AuthConfig{Username: user, Password: psw}, nil
	}
}

// ReadSecret -
func ReadSecret(secret interface{}, secretName string) (types.AuthConfig, error) {
	// Store secret based on it's structure
	var authConfig types.AuthConfig
	if sec, ok := secret.(*types.AuthConfig); ok {
		return *sec, nil
	}
	if sec, ok := secret.(map[string]string); ok {
		return types.AuthConfig{Username: sec["username"]}, nil
	}
	if sec, ok := secret.(DockerConfigJsonstructure); ok {
		if _, k := sec["auths"]; !k {
			return authConfig, fmt.Errorf("cant find auths")
		}
		for serverAddress, authConfig := range sec["auths"] {
			if authConfig.ServerAddress == "" {
				authConfig.ServerAddress = serverAddress
			}
			return authConfig, nil
		}
	}

	return authConfig, fmt.Errorf("cant find secret")
}

func parseEncodedSecret(sec map[string][]byte) (string, string) {
	buser, _ := sec[corev1.BasicAuthUsernameKey]
	bpsw, _ := sec[corev1.BasicAuthPasswordKey]
	duser, _ := b64.StdEncoding.DecodeString(string(buser))
	dpsw, _ := b64.StdEncoding.DecodeString(string(bpsw))
	return string(duser), string(dpsw)

}
func parseDecodedSecret(sec map[string]string) (string, string) {
	user, _ := sec[corev1.BasicAuthUsernameKey]
	psw, _ := sec[corev1.BasicAuthPasswordKey]
	return user, psw

}
