package sign

import (
	"fmt"
	"k8s-ca-websocket/cacli"
	"k8s-ca-websocket/cautils"
	"os"
	"strings"

	icacli "github.com/armosec/capacketsgo/cacli"
	"github.com/armosec/capacketsgo/k8sinterface"
	reporterlib "github.com/armosec/capacketsgo/system-reports/datastructures"
	corev1 "k8s.io/api/core/v1"

	"github.com/docker/docker/api/types"
	"github.com/golang/glog"
)

// Sign -
type Sign struct {
	wlid         string
	debug        bool
	cacli        icacli.ICacli
	k8sAPI       *k8sinterface.KubernetesApi
	reporter     reporterlib.IReporter
	dockerClient DockerClient
}

//NewSigner -
func NewSigner(cacliObj icacli.ICacli, k8sAPI *k8sinterface.KubernetesApi, reporter reporterlib.IReporter, wlid string) *Sign {
	return &Sign{
		cacli:    cacliObj,
		k8sAPI:   k8sAPI,
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

	glog.Infof("wlid: %v user: %v use docker?: %v", s.wlid, username, cautils.CA_USE_DOCKER)
	url := ""
	if useDocker, ok := os.LookupEnv("CA_USE_DOCKER"); useDocker != "true" || !ok {
		url = cautils.CA_OCIMAGE_URL
	}

	if err := s.cacli.WTSign(s.wlid, username, password, url); err != nil {
		if strings.Contains(err.Error(), "Signature has expired") {
			if err := cacli.LoginCacli(); err != nil {
				return err
			}
			err = s.cacli.WTSign(s.wlid, username, password, "")
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
func (s *Sign) SignImageOcimage(workload *k8sinterface.Workload) error {
	podSpec, err := workload.GetPodSpec()
	if err != nil {
		glog.Errorf("In pullImage failed to GetPodSpec: %v", err)
	}
	podObj := &corev1.Pod{Spec: *podSpec}
	podObj.ObjectMeta.Namespace = workload.GetNamespace()
	glog.Infof("pulling image using secret")
	credentials, err := k8sinterface.GetImageRegistryCredentials("", podObj)
	if err != nil {
		return err
	}
	glog.Infof("signing wl:\n%v\nusing creds", workload)
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
		logs := fmt.Sprintf("Signing '%s' using oci engine and secret %s credentails", wlid, secret)
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
func (s *Sign) SignImageDocker(workload *k8sinterface.Workload) error {

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

func (s *Sign) prepareForSign(workload *k8sinterface.Workload) error {
	// get wt
	wt, err := s.cacli.WTGet(s.wlid)
	if err != nil {
		return err
	}

	// docker pull images
	for _, i := range wt.Containers {
		logs := fmt.Sprintf("Pulling image '%s' using docker engine for wlid: '%s'", i.ImageTag, wt.Wlid)
		glog.Infof(logs)
		s.reporter.SendAction(logs, true)

		if err := s.setDockerClient(workload, i.ImageTag); err != nil {
			return err
		}
		s.reporter.SendStatus(reporterlib.JobSuccess, true)
	}

	return nil
}
