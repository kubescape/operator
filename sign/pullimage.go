package sign

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"k8s-ca-websocket/cautils"
	"k8s-ca-websocket/k8sworkloads"

	extutils "github.com/armosec/capacketsgo/cautils"
	"github.com/armosec/capacketsgo/k8sinterface"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/golang/glog"
	"golang.org/x/net/context"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DockerClient -
type DockerClient struct {
	cli *client.Client
	ctx context.Context
}

func NewDockerClient() (*DockerClient, error) {
	dc := DockerClient{ctx: context.Background()}
	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	dc.cli = cli
	return &dc, err
}

// DockerConfigJsonstructure -
type DockerConfigJsonstructure map[string]map[string]types.AuthConfig

// setDockerClient -
func (s *Sign) setDockerClient(workload *k8sinterface.Workload, imageName string) error {
	dc, err := NewDockerClient()
	if err != nil {
		return err
	}
	s.dockerClient = *dc

	// Get images from local docker registry
	imageList, err := dc.cli.ImageList(dc.ctx, types.ImageListOptions{})
	if err != nil {
		return err
	}

	// Search image in registry. Run docker pull if not found
	if imageFound := imageFoundInLocalRegistry(imageList, imageName); !imageFound {
		glog.Infof("Image %s not found, pulling image", imageName)

		// Pulling image using docker client.
		// If the image is from private registry, we will use the kubernetes "pullImageSecret"
		// if the image hosted in AMAZON ECR, we will tkae login details from there
		out, err := s.pullImage(workload, imageName)
		if err != nil {
			return err
		}
		defer out.Close()
		if _, err := ioutil.ReadAll(out); err != nil {
			return err
		}
	}
	return nil
}

func (s *Sign) pullImage(workload *k8sinterface.Workload, imageName string) (out io.ReadCloser, err error) {

	// image pull without docker registry credentials
	out, clearErr := s.dockerClient.cli.ImagePull(s.dockerClient.ctx, imageName, types.ImagePullOptions{})
	if clearErr == nil {
		return out, nil
	}

	// If image pull returnd error, try pulling using credentials
	// Get kubernetes secrets from podSpec
	glog.Infof("pulling image using secret")
	secrets, err := s.getImagePullSecret(workload)
	if err != nil {
		return out, err
	}
	if extutils.CheckIsECRImage(imageName) {
		glog.Infof("pulling image using ECR secrets for image: %s", imageName)
		userName, password, err := extutils.GetLoginDetailsForECR(imageName)
		if err != nil {
			glog.Errorf("Failed to GetLoginDetailsForECR(%s): %v", imageName, err)
		} else {
			secrets = map[string]types.AuthConfig{"ECR": {
				Username: userName,
				Password: password,
			}}
		}
	}
	if len(secrets) == 0 {
		return out, fmt.Errorf("No secrets found. check previous printed errors.\nerror received pulling image without secret: %v", clearErr)
	}

	for secretName, regAuth := range secrets {
		// If server address is known, then try pulling image based on sever address, otherwise try using all secretes
		// if regAuth.ServerAddress == "" || strings.HasPrefix(imageName, regAuth.ServerAddress) {
		glog.Infof("Pulling image %s using %s secret", imageName, secretName)

		// convert to byte and encode to base 64
		encodedJSON, err := json.Marshal(regAuth)
		if err != nil {
			glog.Infof("Failed pulling image. reason: %v", err)
			continue
		}
		authStr := base64.URLEncoding.EncodeToString(encodedJSON)

		// Pulling image with credentials
		out, err = s.dockerClient.cli.ImagePull(s.dockerClient.ctx, imageName, types.ImagePullOptions{RegistryAuth: authStr})
		if err == nil {
			return out, nil
		}
		// }
	}

	return out, fmt.Errorf("Failed to pull image %s", imageName)
}

func (s *Sign) getImagePullSecret(workload *k8sinterface.Workload) (map[string]types.AuthConfig, error) {
	podImagePullSecrets, err := workload.GetImagePullSecret()
	if err != nil {
		return nil, err
	}
	podImagePullSecretsTemp, err := s.getServiceAccountImagePullSecret(workload)
	if err != nil {
		glog.Errorf(err.Error())
		s.reporter.SendError(err, true, true)
	}
	podImagePullSecrets = append(podImagePullSecrets, podImagePullSecretsTemp...)

	return s.readSecrets(podImagePullSecrets, cautils.GetNamespaceFromWorkload(workload))
}

func (s *Sign) readSecrets(sec []corev1.LocalObjectReference, namespace string) (map[string]types.AuthConfig, error) {

	secrets := make(map[string]types.AuthConfig)
	for _, i := range sec {
		res, err := s.k8sAPI.KubernetesClient.CoreV1().Secrets(namespace).Get(context.Background(), i.Name, metav1.GetOptions{})
		if err != nil {
			glog.Errorf("%v", err)
			continue
		}

		// Read secret
		secret, err := k8sworkloads.GetSecretContent(res)
		if err != nil {
			glog.Error(err)
			continue
		}

		if secret == nil {
			glog.Errorf("Secret %s not found", i.Name)
			continue
		}
		ts, err := k8sworkloads.ReadSecret(secret, i.Name)
		if err != nil {
			return secrets, err
		}
		secrets[i.Name] = ts
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

func imageFoundInLocalRegistry(imageList []types.ImageSummary, imageName string) bool {

	for _, il := range imageList {
		for _, i := range il.RepoTags {
			if i == imageName {
				return true
			}
		}
	}
	return false
}

func (s *Sign) getServiceAccountImagePullSecret(workload *k8sinterface.Workload) ([]corev1.LocalObjectReference, error) {
	pullSecrets := []corev1.LocalObjectReference{}
	serviceA := workload.GetServiceAccountName()
	if serviceA == "" {
		return pullSecrets, nil
	}
	serviceAccount, err := s.k8sAPI.KubernetesClient.CoreV1().ServiceAccounts(workload.GetNamespace()).Get(context.Background(), serviceA, metav1.GetOptions{})
	if err != nil {
		return pullSecrets, fmt.Errorf("Failed to get serviceAccount '%s', reason: %s. Will not use credentials for pulling secrets", serviceA, err.Error())
	}
	if serviceAccount.ImagePullSecrets != nil {
		return serviceAccount.ImagePullSecrets, nil
	}
	return pullSecrets, nil
}
