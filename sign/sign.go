package sign

import (
	"fmt"
	"k8s-ca-websocket/cacli"
	"k8s-ca-websocket/cautils"
	"strings"

	reporterlib "github.com/armosec/capacketsgo/system-reports/datastructures"

	"github.com/docker/docker/api/types"
	"github.com/golang/glog"
)

// Sign -
type Sign struct {
	cacli    *cacli.Cacli
	wlid     string
	debug    bool
	reporter reporterlib.IReporter
}

//NewSigner -
func NewSigner(wlid string, reporter reporterlib.IReporter) *Sign {
	return &Sign{
		cacli:    cacli.NewCacli(),
		wlid:     wlid,
		debug:    cautils.CA_DEBUG_SIGNER,
		reporter: reporter,
	}

}

func (s *Sign) triggerCacliSign(username, password string) error {
	// is cacli loggedin
	if !cacli.IsLoggedin() {
		s.reporter.SendAction("Sign in cacli", true)
		if err := cacli.LoginCacli(); err != nil {
			return err
		}
		s.reporter.SendStatus(reporterlib.JobSuccess, true)
	}
	glog.Infof("logged in")

	// sign
	s.reporter.SendAction("Running cacli sign", true)
	if err := s.cacli.Sign(s.wlid, username, password, s.debug); err != nil {
		if strings.Contains(err.Error(), "Signature has expired") {
			if err := cacli.LoginCacli(); err != nil {
				return err
			}
			err = s.cacli.Sign(s.wlid, username, password, s.debug)
		}
		return err
	}
	s.reporter.SendStatus(reporterlib.JobSuccess, true)
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
		logs := fmt.Sprintf("Signing '%s' using oci engine and secret '%s' credentails", wlid, secret)
		glog.Infof(logs)
		s.reporter.SendAction(logs, true)
		if err := s.triggerCacliSign(data.Username, data.Password); err == nil {
			s.reporter.SendStatus(reporterlib.JobSuccess, true)
			return nil
		}
	}

	logs := fmt.Sprintf("Signing '%s' using oci engine without using registry credentials", wlid)
	glog.Infof(logs)
	s.reporter.SendAction(logs, true)
	err := s.triggerCacliSign("", "")
	if err == nil {
		s.reporter.SendStatus(reporterlib.JobSuccess, true)
		return nil
	}
	credNames := []string{}
	for i := range credentials {
		credNames = append(credNames, i)
	}
	return fmt.Errorf("did not sign image, wlid: %s. secrets found: %v, error: %s", wlid, credNames, err.Error())
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
		logs := fmt.Sprintf("Pulling image '%s' using docker engine for wlid: '%s'", i.ImageTag, wt.Wlid)
		glog.Infof(logs)
		s.reporter.SendAction(logs, true)
		if err := setDockerClient(workload, i.ImageTag); err != nil {
			return err
		}
		s.reporter.SendStatus(reporterlib.JobSuccess, true)
	}

	return nil
}
