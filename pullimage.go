package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/golang/glog"
	"golang.org/x/net/context"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
)

type kubernetesData struct {
	unstructuredObj *unstructured.Unstructured
	kubeconfig      *restclient.Config
}

// DockerClient -
type DockerClient struct {
	cli *client.Client
	ctx context.Context
}

// DockerConfigJsonstructure -
type DockerConfigJsonstructure map[string]map[string]types.AuthConfig

// SetDockerClient -
func SetDockerClient(kubernetesData kubernetesData, imageName string) (DockerClient, error) {
	dc := DockerClient{ctx: context.Background()}
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return dc, err
	}
	dc.cli = cli

	// Get images from local docker registry
	imageList, err := dc.cli.ImageList(dc.ctx, types.ImageListOptions{})
	if err != nil {
		return dc, err
	}

	// Search image in registry. Run docker pull if not found
	if imageFound := imageFoundInLoaclRegistry(imageList, imageName); !imageFound {
		glog.Infof("Image %s not found, pulling image", imageName)

		// Pulling image using docker client.
		// If the image is from private registry, we will use the kubernetes "pullImageSecret"
		out, err := dc.pullImage(kubernetesData, imageName)
		if err != nil {
			return dc, err
		}
		defer out.Close()
		if _, err := ioutil.ReadAll(out); err != nil {
			return dc, err
		}
	}
	return dc, nil
}

func (dc *DockerClient) pullImage(kd kubernetesData, imageName string) (out io.ReadCloser, err error) {

	// image pull without docker registry credentials
	out, clearErr := dc.cli.ImagePull(dc.ctx, imageName, types.ImagePullOptions{})
	if clearErr == nil {
		return out, nil
	}

	// If image pull returnd error, try pulling using credentials
	// Get kubernetes secrets from podSpec
	glog.Infof("pulling image using secret")
	secrets, err := kd.getImagePullSecret()
	if err != nil {
		return out, err
	}
	if len(secrets) == 0 {
		return out, fmt.Errorf("No secrets found. check previous printed errors.\nerror received pulling image without secret: %v", clearErr)
	}

	for secretName, regAuth := range secrets {
		// If server address is known, then try pulling image based on sever address, otherwise try using all secretes
		if regAuth.ServerAddress == "" || strings.HasPrefix(imageName, regAuth.ServerAddress) {
			glog.Infof("Pulling image %s using %s secret", imageName, secretName)

			// convert to byte and encode to base 64
			encodedJSON, err := json.Marshal(regAuth)
			if err != nil {
				glog.Infof("Failed pulling image. reason: %v", err)
				continue
			}
			authStr := base64.URLEncoding.EncodeToString(encodedJSON)

			// Pulling image with credentials
			out, err = dc.cli.ImagePull(dc.ctx, imageName, types.ImagePullOptions{RegistryAuth: authStr})
			if err == nil {
				return out, nil
			}
		}
	}

	return out, fmt.Errorf("Failed to pull image %s", imageName)
}

func (kd *kubernetesData) getImagePullSecret() (map[string]types.AuthConfig, error) {

	secrets := make(map[string]types.AuthConfig)
	clientset, err := kubernetes.NewForConfig(kd.kubeconfig)
	if err != nil {
		err = fmt.Errorf("failed creating clientset. Error: %+v", err)
		return secrets, err
	}

	podImagePullSecrets, err := kd.getPodImagePullSecrets()
	if err != nil {
		return secrets, err
	}
	// Loop over imagePullSecrets configured in pod
	for _, i := range *podImagePullSecrets {
		res, err := clientset.CoreV1().Secrets(kd.unstructuredObj.GetNamespace()).Get(i.Name, metav1.GetOptions{})
		if err != nil {
			glog.Errorf("%v", err)
		}

		// Read secret
		secret, err := getSecretContent(res)
		if err != nil {
			glog.Error(err)
			continue
		}

		if secret == nil {
			glog.Errorf("Secret %s not found", i.Name)
			continue
		}
		saveSecret(&secrets, secret, i.Name)
	}
	return secrets, nil
}

func getSecretContent(secret *corev1.Secret) (interface{}, error) {

	// Secret types- https://github.com/kubernetes/kubernetes/blob/7693a1d5fe2a35b6e2e205f03ae9b3eddcdabc6b/pkg/apis/core/types.go#L4394-L4478
	switch secret.Type {
	case corev1.SecretTypeDockerConfigJson:
		sec := make(DockerConfigJsonstructure)
		if err := json.Unmarshal(secret.Data[corev1.DockerConfigJsonKey], &sec); err != nil {
			return nil, err
		}
		return sec, nil
	default:
		user, ok := secret.Data[corev1.BasicAuthUsernameKey]
		if !ok {
			return nil, fmt.Errorf("user not found in secret")
		}
		psw, ok := secret.Data[corev1.BasicAuthPasswordKey]
		if !ok {
			return nil, fmt.Errorf("password not found in secret")
		}
		encUser := base64.URLEncoding.EncodeToString(user)
		encPSW := base64.URLEncoding.EncodeToString(psw)

		return &types.AuthConfig{Username: encUser, Password: encPSW}, nil
	}
}

func saveSecret(secrets *map[string]types.AuthConfig, secret interface{}, secretName string) {
	// Store secret based on it's structure
	if sec, ok := secret.(DockerConfigJsonstructure); ok {
		if _, k := sec["auths"]; !k {
			glog.Errorf("cant find auths")
			return
		}
		for serverAddress, authConfig := range sec["auths"] {
			if authConfig.ServerAddress == "" {
				authConfig.ServerAddress = serverAddress
			}
			(*secrets)[secretName] = authConfig
		}
	}
}

func imageFoundInLoaclRegistry(imageList []types.ImageSummary, imageName string) bool {
	// if isLatestTag(imageName) {
	// 	return false
	// }
	for _, il := range imageList {
		for _, i := range il.RepoTags {
			if i == imageName {
				return true
			}
		}
	}
	return false
}

func (kd *kubernetesData) getPodImagePullSecrets() (*[]corev1.LocalObjectReference, error) {
	upperFields := []string{"spec", "template"}
	podFields := []string{"spec", "imagePullSecrets"}
	fields := []string{}
	secrets := []corev1.LocalObjectReference{}

	if kd.unstructuredObj.GetKind() != "Pod" {
		fields = append(fields, upperFields...)
	}
	fields = append(fields, podFields...)

	sec, found, err := unstructured.NestedSlice(kd.unstructuredObj.Object, fields...)
	if err != nil {
		return &secrets, fmt.Errorf("Error receiving imagePullSecrets: %s", err)
	}
	if !found {
		return &secrets, fmt.Errorf("No secret found")
	}

	for _, s := range sec {
		secret := corev1.LocalObjectReference{}

		secMap, ok := s.(map[string]interface{})
		if !ok {
			glog.Errorf("Cant convert imagePullSecrets interface{} to map[string]interface{}")
			continue
		}
		secName, ok := secMap["name"].(string)
		if !ok {
			glog.Errorf("Cant convert imagePullSecrets interface{} to string")
			continue
		}
		secret.Name = secName
		secrets = append(secrets, secret)

	}

	return &secrets, nil
}
