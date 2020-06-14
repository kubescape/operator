package sign

import (
	"fmt"
	"k8s-ca-websocket/cacli"

	"github.com/docker/docker/api/types"
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

// SignImageOcimage sign image usin cacli - ocimage
func (s *Sign) SignImageOcimage(workload interface{}) error {

	// get registry credentials from secrets
	credentials, err := getImagePullSecret(workload)
	if err != nil {
		return err
	}

	// sign
	if err := s.sign(s.wlid, credentials); err != nil {
		return err
	}

	glog.Infof("signed %s", s.wlid)
	return nil
}

// run cacli sign
func (s *Sign) sign(wlid string, credentials map[string]types.AuthConfig) error {
	// is cacli loggedin
	if !cacli.IsLoggedin() {
		if err := cacli.LoginCacli(); err != nil {
			return err
		}
	}
	for secret, data := range credentials {
		glog.Infof("siging image using registry credentials from secret: %s", secret)
		if err := s.cacli.Sign(s.wlid, data.Username, data.Password); err == nil {
			return nil
		}
		// } else {
		// 	// handle errors
		// }
	}

	glog.Infof("siging image without using registry credentials")
	if err := s.cacli.Sign(s.wlid, "", ""); err == nil {
		return nil
	}
	credNames := []string{}
	for i := range credentials {
		credNames = append(credNames, i)
	}
	return fmt.Errorf("did not sign image, wlid: %s. secrets found: %v", wlid, credNames)
}

// SignImageDocker sign image usin cacli - docker
func (s *Sign) SignImageDocker(workload interface{}) error {

	// pull images
	if err := s.prepareForSign(workload); err != nil {
		return err
	}

	// sign
	if err := s.cacli.Sign(s.wlid, "", ""); err != nil {
		return err
	}

	glog.Infof("signed %s", s.wlid)
	return nil
}

func (s *Sign) prepareForSign(workload interface{}) error {
	// get wt
	wt, err := s.cacli.Get(s.wlid)
	if err != nil {
		return err
	}

	// docker pull images
	for _, i := range wt.Containers {
		if err := setDockerClient(workload, i.ImageTag); err != nil {
			return err
		}

	}

	return nil
}
