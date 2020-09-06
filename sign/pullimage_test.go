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

// THIS TEST NOT FOR CI CD
// func TestPullDockerImage(t *testing.T) {
// 	dc := DockerClient{ctx: context.Background()}
// 	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
// 	if err != nil {
// 		t.Fatal("NewClientWithOpts", err)
// 	}
// 	dc.cli = cli
// 	regAuth := types.AuthConfig{Auth: "Y3liZXJhcm1vci1zc3AtaW5zdGFsbEBjYTpmMjg1ZmEyNTkxMDkwZGQ5MmQyOWFjOTE5OTBkYjAxMGI1ZDFjYjFm",
// 		Username:      "cyberarmor-ssp-install@ca",
// 		Password:      "f285fa2591090dd92d29ac91990db010b5d1cb1f",
// 		ServerAddress: "https://securityservices.packages.ca.com/v2/"}
// 	encodedJSON, err := json.Marshal(regAuth)
// 	if err != nil {
// 		t.Fatal("Marshal", err)

// 	}
// 	authStr := base64.URLEncoding.EncodeToString(encodedJSON)
// 	_, err = dc.cli.ImagePull(dc.ctx, "securityservices.packages.ca.com/cadir/cadir:1.0.1517", types.ImagePullOptions{RegistryAuth: authStr})
// 	if err != nil {
// 		t.Fatal("ImagePull", err)
// 	}
// 	// t.Error(out)
// }
