package mainhandler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func rejectingServer(t *testing.T, code int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func authTestConfig(t *testing.T, srv *httptest.Server) config.IConfig {
	t.Helper()
	cfg, err := config.NewOperatorConfig(
		config.CapabilitiesConfig{Components: config.Components{Kubescape: config.Component{Enabled: true}}},
		utilsmetadata.ClusterConfig{KubescapeURL: strings.TrimPrefix(srv.URL, "http://"), InstallationData: armotypes.InstallationData{DefaultFrameworks: []string{"nsa"}}},
		&beUtils.Credentials{}, config.Config{Namespace: "kubescape"},
	)
	require.NoError(t, err)
	return cfg
}

func TestKubescapeScanReportsRejectedToken(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := rejectingServer(t, code)
		previous := KubescapeHttpClient
		KubescapeHttpClient = srv.Client()
		t.Cleanup(func() { KubescapeHttpClient = previous })

		handler := &ActionHandler{config: authTestConfig(t, srv), sessionObj: &utils.SessionObj{Command: &apis.Command{Args: map[string]interface{}{utils.KubescapeScanV1: map[string]interface{}{"hostScanner": false}}}}}
		err := handler.kubescapeScan(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "kubescape rejected the API token")
	}
}

func TestHandleKubescapeResponseReportsRejectedToken(t *testing.T) {
	logger.InitLogger("pretty")
	logFile, err := os.Create(filepath.Join(t.TempDir(), "operator.log"))
	require.NoError(t, err)
	defer logFile.Close()
	logger.L().SetWriter(logFile)
	defer logger.L().SetWriter(os.Stderr)

	srv := rejectingServer(t, http.StatusUnauthorized)
	previous := KubescapeHttpClient
	KubescapeHttpClient = srv.Client()
	t.Cleanup(func() { KubescapeHttpClient = previous })

	retry, next := HandleKubescapeResponse(context.Background(), authTestConfig(t, srv), &kubescapeResponseData{scanID: "scan-1", sessionObj: &utils.SessionObj{}})
	assert.False(t, retry)
	assert.Nil(t, next)

	logged, err := os.ReadFile(logFile.Name())
	require.NoError(t, err)
	assert.Contains(t, string(logged), "kubescape rejected the API token")
}

func TestSendWorkloadWithCredentialsReportsRejectedToken(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := rejectingServer(t, code)
		previous := VulnScanHttpClient
		VulnScanHttpClient = srv.Client()
		t.Cleanup(func() { VulnScanHttpClient = previous })

		scanURL, err := url.Parse(srv.URL + "/v1/scanRegistryImage")
		require.NoError(t, err)
		err = sendWorkloadWithCredentials(context.Background(), scanURL, &apis.RegistryScanCommand{ImageScanParams: apis.ImageScanParams{ImageTag: "registry.example/app:1.0"}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "kubevuln rejected the API token")
	}
}
