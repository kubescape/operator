package sign

import (
	"k8s-ca-websocket/cacli"

	"github.com/golang/glog"
)

// Sign -
type Sign struct {
	cacli *cacli.Cacli
	wlid  string
}

//NewSigner -
func NewSigner(wlid string) *Sign {
	return &Sign{
		cacli: cacli.NewCacli(),
		wlid:  wlid,
	}

}

// SignImage sign image usin cacli
func (s *Sign) SignImage(workload interface{}) error {

	// get images and credentials
	images, credentials, err := s.prepareForSign(workload)
	if err != nil {
		return err
	}

	// sign
	if err := s.sign(s.wlid, images, credentials); err != nil {
		return err
	}

	glog.Infof("signed %s", s.wlid)
	return nil
}

func (s *Sign) prepareForSign(workload interface{}) ([]string, map[string]string, error) {
	// get wt
	wt, err := s.cacli.Get(s.wlid)
	if err != nil {
		return nil, nil, err
	}

	credentials := map[string]string{}
	images := []string{}

	// get image and secrets
	secrets, err := getImagePullSecret(workload)
	for i := range secrets {
		credentials[secrets[i].Username] = credentials[secrets[i].Password]
	}

	// get list of images
	for _, i := range wt.Containers {
		images = append(images, i.ImageTag)
	}

	return images, credentials, nil
}

// run cacli sign
func (s *Sign) sign(wlid string, images []string, credentials map[string]string) error {
	for _, image := range images {
		for user, password := range credentials {
			if err := s.cacli.Sign(s.wlid, image, user, password); err == nil {
				break
			} else {
				// handle errors
			}
		}
	}
	return nil
}
