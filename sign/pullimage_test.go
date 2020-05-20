package sign

import (
	"k8s-ca-websocket/cautils"
	"testing"
)

func TestGetSecretList(t *testing.T) {
	dep := cautils.GetWordpressDeployment()
	list, err := getSecretList(dep)
	if err != nil {
		t.Error(err)
	}
	if len(list) == 0 {
		t.Errorf("len should be more than 1")
	}
}

func TestGetSecretContent(t *testing.T) {
	sec := cautils.GetSecret()
	_, err := getSecretContent(sec)
	if err != nil {
		t.Error(err)
	}

}

// func TestGetImagePullSecret(t *testing.T) {
// 	dep := cautils.GetWordpressDeployment()
// 	list, err := getImagePullSecret(dep)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	if len(list) == 0 {
// 		t.Errorf("len should be more than 1")
// 	}
// }
