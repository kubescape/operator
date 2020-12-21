package sign

import (
	"fmt"
	"k8s-ca-websocket/cacli"
	"strings"

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

func (s *Sign) triggerCacliSign(username, password string) error {
	// is cacli loggedin
	if !cacli.IsLoggedin() {
		if err := cacli.LoginCacli(); err != nil {
			return err
		}
	}
	glog.Infof("logged in")

	// sign
	if err := s.cacli.Sign(s.wlid, username, password); err != nil {
		if strings.Contains(err.Error(), "Signature has expired") {
			if err := cacli.LoginCacli(); err != nil {
				return err
			}
			err = s.cacli.Sign(s.wlid, username, password)
		}
		return err
	}
	return nil
}

// **************************************************************************************************
//                                   OCI image
// **************************************************************************************************

// SignImageOcimage sign image usin cacli - ocimage
func (s *Sign) SignImageOcimage(workload interface{}) error {

	// get registry credentials from secrets
	credentials, err := getImagePullSecret(workload)
	if err != nil {
		return err
	}

	// sign
	if err := s.triggerOCImageSign(s.wlid, credentials); err != nil {
		return err
	}

	glog.Infof("signed %s", s.wlid)
	return nil
}

// run cacli sign
func (s *Sign) triggerOCImageSign(wlid string, credentials map[string]types.AuthConfig) error {

	for secret, data := range credentials {
		glog.Infof("siging image using registry credentials from secret: %s", secret)
		if err := s.triggerCacliSign(data.Username, data.Password); err == nil {
			return nil
		}
	}

	glog.Infof("siging image without using registry credentials")
	if err := s.triggerCacliSign("", ""); err == nil {
		return nil
	}
	credNames := []string{}
	for i := range credentials {
		credNames = append(credNames, i)
	}
	return fmt.Errorf("did not sign image, wlid: %s. secrets found: %v", wlid, credNames)
}

// **************************************************************************************************
//                                   Docker
// **************************************************************************************************

// SignImageDocker sign image usin cacli - docker
func (s *Sign) SignImageDocker(workload interface{}) error {

	// pull images
	if err := s.prepareForSign(workload); err != nil {
		return err
	}

	// sign
	if err := s.triggerCacliSign("", ""); err != nil {
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
