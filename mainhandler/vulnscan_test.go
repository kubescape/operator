package mainhandler

import (
	"context"
	"encoding/json"
	"testing"

	_ "embed"

	dockerregistry "github.com/docker/docker/api/types/registry"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

//go:embed testdata/vulnscan/registry-secret.json
var registrySecret []byte

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

	var secret *corev1.Secret
	require.NoError(t, json.Unmarshal(registrySecret, &secret))

	k8sApiMock := &k8sinterface.KubernetesApi{
		Context:          context.TODO(),
		KubernetesClient: k8sfake.NewSimpleClientset(secret),
	}

	res, err := getImageScanConfig(k8sApiMock, "", nil, "nginx:latest") // no registry treated as docker.io
	assert.NoError(t, err)
	assert.Equal(t, expectedAuthConfigs, res.authConfigs)
	assert.True(t, *res.insecure)
	assert.Nil(t, res.skipTLSVerify)

	res, err = getImageScanConfig(k8sApiMock, "", nil, "quay.IO/kubescape/nginx:latest")
	assert.NoError(t, err)
	assert.Equal(t, expectedAuthConfigs, res.authConfigs)
	assert.Nil(t, res.insecure)
	assert.True(t, *res.skipTLSVerify)
}
