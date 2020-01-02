package sign

import (
	"k8s-ca-websocket/cacli"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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
func (s *Sign) SignImage(unstructuredObj *unstructured.Unstructured) error {
	// pull images
	if err := s.prepareForSign(unstructuredObj); err != nil {
		return err
	}

	// sign
	if err := s.sign(s.wlid); err != nil {
		return err
	}

	glog.Infof("signed %s", s.wlid)
	return nil
}

func (s *Sign) prepareForSign(unstructuredObj *unstructured.Unstructured) error {
	// get wt
	wt, err := s.cacli.Get(s.wlid)
	if err != nil {
		return err
	}

	// docker pull images
	for _, i := range wt.Containers {
		if err := setDockerClient(unstructuredObj, i.ImageTag); err != nil {
			return err
		}

	}

	return nil
}

// run cacli sign
func (s *Sign) sign(wlid string) error {
	return s.cacli.Sign(s.wlid)
}
