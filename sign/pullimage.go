package sign

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/armosec/capacketsgo/k8sinterface"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/golang/glog"
	"golang.org/x/net/context"
	corev1 "k8s.io/api/core/v1"
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
func (s *Sign) setDockerClient(workload k8sinterface.IWorkload, imageName string) error {
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

func (s *Sign) pullImage(workload k8sinterface.IWorkload, imageName string) (out io.ReadCloser, err error) {

	// image pull without docker registry credentials
	out, clearErr := s.dockerClient.cli.ImagePull(s.dockerClient.ctx, imageName, types.ImagePullOptions{})
	if clearErr == nil {
		return out, nil
	}
	podSpec, err := workload.GetPodSpec()
	if err != nil {
		glog.Errorf("In pullImage failed to GetPodSpec: %v", err)
	}
	podObj := &corev1.Pod{Spec: *podSpec}
	podObj.ObjectMeta.Namespace = workload.GetNamespace()
	glog.Infof("pulling image using secret")
	secrets, err := k8sinterface.GetImageRegistryCredentials(imageName, podObj)
	if err != nil {
		glog.Errorf("In pullImage failed to GetImageRegistryCredentials: %v", err)
	}
	if len(secrets) == 0 {
		return out, fmt.Errorf("no secrets found. check previous printed errors.\nerror received pulling image without secret: %v", clearErr)
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

	return out, fmt.Errorf("failed to pull image %s", imageName)
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
