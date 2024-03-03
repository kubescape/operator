package mainhandler

import (
	"testing"

	_ "embed"

	dockerregistry "github.com/docker/docker/api/types/registry"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
)

//go:embed testdata/vulnscan/registry-secret.json
var registrySecret []byte

type WorkloadsGetterMock struct{}

func (mock *WorkloadsGetterMock) GetWorkload(namespace, kind, name string) (k8sinterface.IWorkload, error) {
	wl, err := workloadinterface.NewWorkload(registrySecret)
	if err != nil {
		panic(err)
	}
	return wl, nil
}
func (mock *WorkloadsGetterMock) ListWorkloads2(namespace, kind string) ([]k8sinterface.IWorkload, error) {
	wl, _ := mock.GetWorkload(namespace, kind, "")
	return []k8sinterface.IWorkload{wl}, nil
}

func Test_ActionHandler_getImageScanConfig(t *testing.T) {
	expectedAuthConfigs := []dockerregistry.AuthConfig{
		{
			Username:      "test-user",
			Password:      "test-pass",
			ServerAddress: "docker.io",
		},
		{
			Username:      "test-user-quay",
			Password:      "test-pass-quay",
			ServerAddress: "quay.io",
		},
	}

	k8sApiMock := &WorkloadsGetterMock{}

	res, err := getImageScanConfig(k8sApiMock, "", &v1.Pod{}, "nginx:latest") // no registry treated as docker.io
	assert.NoError(t, err)
	assert.Equal(t, expectedAuthConfigs, res.authConfigs)
	assert.True(t, *res.insecure)
	assert.Nil(t, res.skipTLSVerify)

	res, err = getImageScanConfig(k8sApiMock, "", &v1.Pod{}, "quay.IO/kubescape/nginx:latest")
	assert.NoError(t, err)
	assert.Equal(t, expectedAuthConfigs, res.authConfigs)
	assert.Nil(t, res.insecure)
	assert.True(t, *res.skipTLSVerify)
}
