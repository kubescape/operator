package sign

import (
	"fmt"
	// "k8s-ca-websocket/cacli"
	"k8s-ca-websocket/cautils"
	"strings"

	cacli "github.com/armosec/cacli-wrapper-go/cacli"

	"github.com/armosec/k8s-interface/cloudsupport"
	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/k8s-interface/workloadinterface"
	reporterlib "github.com/armosec/logger-go/system-reports/datastructures"
	corev1 "k8s.io/api/core/v1"

	"github.com/docker/docker/api/types"
	"github.com/golang/glog"
)

// Sign -
type Sign struct {
	wlid         string
	debug        bool
	cacli        cacli.ICacli
	k8sAPI       *k8sinterface.KubernetesApi
	reporter     reporterlib.IReporter
	dockerClient DockerClient
	ErrChan      chan error
}

//NewSigner -
func NewSigner(cacliObj cacli.ICacli, k8sAPI *k8sinterface.KubernetesApi, reporter reporterlib.IReporter, wlid string) *Sign {
	signerObj := &Sign{
		cacli:    cacliObj,
		k8sAPI:   k8sAPI,
		wlid:     wlid,
		debug:    cautils.CA_DEBUG_SIGNER,
		reporter: reporter,
		ErrChan:  make(chan error),
	}
	go signerObj.WatchErrors()
	return signerObj
}

func (s *Sign) WatchErrors() {
	for err := range s.ErrChan {
		if err != nil {
			glog.Errorf("failed to send job report due to: %s", err.Error())
		}
	}
}

func (s *Sign) triggerCacliSign(username, password, ociURL string) error {
	// is cacli loggedin
	if !s.IsLoggedIn() {
		s.reporter.SendAction("Sign in cacli", true, s.ErrChan)
		if err := s.cacli.Login(); err != nil {
			return err
		}
		s.reporter.SendStatus(reporterlib.JobSuccess, true, s.ErrChan)
	}
	glog.Infof("logged in")

	// sign
	s.reporter.SendAction("Running cacli sign", true, s.ErrChan)

	glog.Infof("wlid: %v user: %v use docker?: %v", s.wlid, username, cautils.CA_USE_DOCKER)

	if err := s.cacli.WTSign(s.wlid, username, password, ociURL); err != nil {
		if strings.Contains(err.Error(), "Signature has expired") {
			if err := s.cacli.Login(); err != nil {
				return err
			}
			err = s.cacli.WTSign(s.wlid, username, password, ociURL)
		}
		return err
	}
	s.reporter.SendStatus(reporterlib.JobSuccess, true, s.ErrChan)
	return nil
}

// **************************************************************************************************
//                                   OCI image
// **************************************************************************************************

// SignImageOcimage sign image usin cacli - ocimage
func (s *Sign) SignImageOcimage(workload workloadinterface.IWorkload) error {

	podSpec, err := workload.GetPodSpec()
	if err != nil {
		glog.Errorf("In pullImage failed to GetPodSpec: %v", err)
	}
	podObj := &corev1.Pod{Spec: *podSpec}
	podObj.ObjectMeta.Namespace = workload.GetNamespace()

	glog.Infof("pulling image using secret")
	credentials, err := cloudsupport.GetImageRegistryCredentials("", podObj)
	if err != nil {
		return err
	}

	glog.Infof("Signing workload with credentials. WorkloadID: %s", s.wlid)
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
		s.reporter.SendAction(logs, true, s.ErrChan)
		if err := s.triggerCacliSign(data.Username, data.Password, cautils.CA_OCIMAGE_URL); err == nil {
			s.reporter.SendStatus(reporterlib.JobSuccess, true, s.ErrChan)
			return nil
		}
	}

	logs := fmt.Sprintf("Signing '%s' using oci engine without using registry credentials", wlid)
	glog.Infof(logs)
	s.reporter.SendAction(logs, true, s.ErrChan)
	err := s.triggerCacliSign("", "", cautils.CA_OCIMAGE_URL)
	if err == nil {
		s.reporter.SendStatus(reporterlib.JobSuccess, true, s.ErrChan)
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
func (s *Sign) SignImageDocker(workload k8sinterface.IWorkload) error {

	// pull images
	if err := s.prepareForSign(workload); err != nil {
		return err
	}

	// sign
	if err := s.triggerCacliSign("", "", ""); err != nil {
		return err
	}

	glog.Infof("signed %s", s.wlid)
	return nil
}

func (s *Sign) prepareForSign(workload k8sinterface.IWorkload) error {
	// get wt
	wt, err := s.cacli.WTGet(s.wlid)
	if err != nil {
		return err
	}

	// docker pull images
	for _, i := range wt.Containers {
		logs := fmt.Sprintf("Pulling image '%s' using docker engine for wlid: '%s'", i.ImageTag, wt.Wlid)
		glog.Infof(logs)
		s.reporter.SendAction(logs, true, s.ErrChan)

		if err := s.setDockerClient(workload, i.ImageTag); err != nil {
			return err
		}
		s.reporter.SendStatus(reporterlib.JobSuccess, true, s.ErrChan)
	}

	return nil
}

// IsLoggedIn -
func (s *Sign) IsLoggedIn() bool {
	status, err := s.cacli.Status()
	if err != nil {
		return false
	}
	return status.LoggedIn
}
