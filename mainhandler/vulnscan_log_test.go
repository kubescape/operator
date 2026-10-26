package mainhandler

import (
	"context"
	"encoding/base64"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/docker/docker/api/types/registry"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/operator/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendWorkloadWithCredentialsKeepsRegistryCredentialsOutOfTheLog(t *testing.T) {
	logger.InitLogger("pretty")
	logFile, err := os.Create(filepath.Join(t.TempDir(), "operator.log"))
	require.NoError(t, err)
	defer logFile.Close()
	logger.L().SetWriter(logFile)
	defer logger.L().SetWriter(os.Stderr)
	require.NoError(t, logger.L().SetLevel("debug"))

	previous := VulnScanHttpClient
	VulnScanHttpClient = &utils.ClientMock{}
	defer func() { VulnScanHttpClient = previous }()

	scanURL, err := url.Parse("http://kubevuln:8080/v1/scanRegistryImage")
	require.NoError(t, err)
	username := "robot-account"
	password := strings.Join([]string{"wF9", "registry", "secret"}, "-")
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	command := &apis.RegistryScanCommand{ImageScanParams: apis.ImageScanParams{
		ImageTag:        "registry.example/team/app:1.0",
		JobID:           "7b04592b-665a-4e47-a9c9-65b2b3cabb49",
		Credentialslist: []registry.AuthConfig{{Username: username, Password: password, Auth: auth}},
	}}

	require.NoError(t, sendWorkloadWithCredentials(context.Background(), scanURL, command))

	logged, err := os.ReadFile(logFile.Name())
	require.NoError(t, err)
	assert.Contains(t, string(logged), "registry.example/team/app:1.0")
	assert.Contains(t, string(logged), "7b04592b-665a-4e47-a9c9-65b2b3cabb49")
	assert.NotContains(t, string(logged), password)
	assert.NotContains(t, string(logged), auth)
	assert.NotContains(t, string(logged), username)
}
