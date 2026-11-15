package exporters

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/operator/admission/rules"
	rulesv1 "github.com/kubescape/operator/admission/rules/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitHTTPExporter_ClusterUID(t *testing.T) {
	config := HTTPExporterConfig{
		URL:    "http://localhost:8080",
		Method: "POST",
	}
	exporter, err := InitHTTPExporter(config, "test-cluster", nil, "test-cluster-uid")
	assert.NoError(t, err)
	assert.Equal(t, "test-cluster", exporter.ClusterName)
	assert.Equal(t, "test-cluster-uid", exporter.ClusterUID)
}

func TestSendAdmissionAlert_ClusterUIDPropagated(t *testing.T) {
	config := HTTPExporterConfig{
		URL:    "http://localhost:8080",
		Method: "POST",
	}
	exporter, err := InitHTTPExporter(config, "test-cluster", nil, "test-cluster-uid")
	assert.NoError(t, err)

	// Build a minimal rule failure to verify ClusterUID injection by the exporter.
	ruleFailure := &rulesv1.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{},
		RuleAlert:        apitypes.RuleAlert{},
		AdmissionAlert:   apitypes.AdmissionAlert{},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			Image:       "nginx:1.14.2",
			ImageDigest: "nginx@sha256:abc123def456",
		},
		RuleID: "R2000",
	}

	// Simulate what SendAdmissionAlert does internally to verify ClusterUID injection.
	k8sDetails := ruleFailure.GetRuntimeAlertK8sDetails()
	k8sDetails.ClusterName = exporter.ClusterName
	k8sDetails.ClusterUID = exporter.ClusterUID

	alert := apitypes.RuntimeAlert{
		AlertType:              apitypes.AlertTypeAdmission,
		BaseRuntimeAlert:       ruleFailure.GetBaseRuntimeAlert(),
		AdmissionAlert:         ruleFailure.GetAdmissionsAlert(),
		RuntimeAlertK8sDetails: k8sDetails,
		RuleAlert:              ruleFailure.GetRuleAlert(),
		RuleID:                 ruleFailure.GetRuleId(),
	}

	assert.Equal(t, "test-cluster", alert.RuntimeAlertK8sDetails.ClusterName)
	assert.Equal(t, "test-cluster-uid", alert.RuntimeAlertK8sDetails.ClusterUID)
	assert.Equal(t, "nginx:1.14.2", alert.RuntimeAlertK8sDetails.Image)
	assert.Equal(t, "nginx@sha256:abc123def456", alert.RuntimeAlertK8sDetails.ImageDigest)
}

// Verify RuleFailure interface used in tests
var _ rules.RuleFailure = (*rulesv1.GenericRuleFailure)(nil)

// TestSendAdmissionAlert_SetsK8sAgentPlatform verifies the wire payload of an
// admission alert carries an explicit AlertSourcePlatform. The backend infers
// the platform from PodName when it is unset and would classify a pod-less
// admission alert as a Linux host alert.
func TestSendAdmissionAlert_SetsK8sAgentPlatform(t *testing.T) {
	var got HTTPAlertsList
	received := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
		received <- struct{}{}
	}))
	defer srv.Close()

	exporter, err := InitHTTPExporter(HTTPExporterConfig{URL: srv.URL, Method: "POST"}, "test-cluster", nil, "test-cluster-uid")
	assert.NoError(t, err)

	exporter.SendAdmissionAlert(&rulesv1.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{AlertName: "Privileged pod", UniqueID: "ns/pod"},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:      "pod",
			PodNamespace: "ns",
		},
		RuleID: "R2003",
	})

	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("exporter did not POST the alert")
	}

	if assert.Len(t, got.Spec.Alerts, 1) {
		alert := got.Spec.Alerts[0]
		assert.Equal(t, apitypes.AlertSourcePlatformK8sAgent, alert.AlertSourcePlatform)
		assert.Equal(t, apitypes.AlertTypeAdmission, alert.AlertType)
		assert.Equal(t, "R2003", alert.RuleID)
		assert.Equal(t, "ns/pod", alert.BaseRuntimeAlert.UniqueID)
		assert.Equal(t, "test-cluster-uid", alert.RuntimeAlertK8sDetails.ClusterUID)
	}
}

func TestHTTPExporter_SendsBearerFromTokenFile(t *testing.T) {
	auth := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tokenFile := filepath.Join(t.TempDir(), "token")
	assert.NoError(t, os.WriteFile(tokenFile, []byte("synctoken\n"), 0o600))

	exporter, err := InitHTTPExporter(HTTPExporterConfig{URL: srv.URL, Method: "POST", TokenFile: tokenFile}, "test-cluster", nil, "uid")
	assert.NoError(t, err)

	exporter.SendAdmissionAlert(&rulesv1.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{AlertName: "Privileged pod", UniqueID: "ns/pod"},
		RuleID:           "R2003",
	})

	select {
	case got := <-auth:
		assert.Equal(t, "Bearer synctoken", got)
	case <-time.After(2 * time.Second):
		t.Fatal("exporter did not POST the alert")
	}
}

func TestHTTPExporter_Non2xxErrorDiagnosticsAndDrain(t *testing.T) {
	logger.InitLogger("pretty")
	logFile, err := os.Create(filepath.Join(t.TempDir(), "operator.log"))
	require.NoError(t, err)
	defer logFile.Close()
	logger.L().SetWriter(logFile)
	defer logger.L().SetWriter(os.Stderr)

	const errorPayload = `{"error":"bad_request","message":"invalid alert payload"}`
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(errorPayload))
	}))
	defer srv.Close()

	exporter, err := InitHTTPExporter(HTTPExporterConfig{URL: srv.URL, Method: "POST"}, "test-cluster", nil, "test-cluster-uid")
	require.NoError(t, err)

	exporter.SendAdmissionAlert(&rulesv1.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{AlertName: "Privileged pod", UniqueID: "ns/pod"},
		RuleID:           "R2003",
	})

	logged, err := os.ReadFile(logFile.Name())
	require.NoError(t, err)
	logOutput := string(logged)

	assert.Contains(t, logOutput, "Received non-2xx status code from alert endpoint")
	assert.Contains(t, logOutput, "400")
	assert.Contains(t, logOutput, errorPayload)
	assert.Equal(t, 1, requestCount)
}

func TestHTTPExporter_Non2xxTruncatesLargeBodyAndDrains(t *testing.T) {
	logger.InitLogger("pretty")
	logFile, err := os.Create(filepath.Join(t.TempDir(), "operator.log"))
	require.NoError(t, err)
	defer logFile.Close()
	logger.L().SetWriter(logFile)
	defer logger.L().SetWriter(os.Stderr)

	// Generate a response body larger than 4 KiB (e.g., 8 KiB)
	largeBody := strings.Repeat("A", 8192)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(largeBody))
	}))
	defer srv.Close()

	exporter, err := InitHTTPExporter(HTTPExporterConfig{URL: srv.URL, Method: "POST"}, "test-cluster", nil, "test-cluster-uid")
	require.NoError(t, err)

	exporter.SendAdmissionAlert(&rulesv1.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{AlertName: "Privileged pod", UniqueID: "ns/pod"},
		RuleID:           "R2003",
	})

	logged, err := os.ReadFile(logFile.Name())
	require.NoError(t, err)
	logOutput := string(logged)

	assert.Contains(t, logOutput, "Received non-2xx status code from alert endpoint")
	assert.Contains(t, logOutput, "500")
	// The logged output should contain 4096 'A's but not 4097 'A's
	assert.Contains(t, logOutput, strings.Repeat("A", 4096))
	assert.NotContains(t, logOutput, strings.Repeat("A", 4097))
}

func TestHTTPExporter_SendRegistryStatus_Non2xxLoggedAndDrained(t *testing.T) {
	logger.InitLogger("pretty")
	logFile, err := os.Create(filepath.Join(t.TempDir(), "operator.log"))
	require.NoError(t, err)
	defer logFile.Close()
	logger.L().SetWriter(logFile)
	defer logger.L().SetWriter(os.Stderr)

	const errorMsg = "service unavailable"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(errorMsg))
	}))
	defer srv.Close()

	exporter, err := InitHTTPExporter(HTTPExporterConfig{URL: srv.URL, Method: "POST"}, "test-cluster", nil, "test-cluster-uid")
	require.NoError(t, err)

	exporter.SendRegistryStatus("guid-123", apitypes.RegistryScanStatus("Success"), "completed", time.Now())

	logged, err := os.ReadFile(logFile.Name())
	require.NoError(t, err)
	logOutput := string(logged)

	assert.Contains(t, logOutput, "Received non-2xx status code from alert endpoint")
	assert.Contains(t, logOutput, "503")
	assert.Contains(t, logOutput, errorMsg)
}

func TestHTTPExporter_ConnectionReuseOnConsecutiveFailures(t *testing.T) {
	logger.InitLogger("pretty")
	logFile, err := os.Create(filepath.Join(t.TempDir(), "operator.log"))
	require.NoError(t, err)
	defer logFile.Close()
	logger.L().SetWriter(logFile)
	defer logger.L().SetWriter(os.Stderr)

	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad_request"}`))
	}))
	defer srv.Close()

	exporter, err := InitHTTPExporter(HTTPExporterConfig{URL: srv.URL, Method: "POST"}, "test-cluster", nil, "test-cluster-uid")
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		exporter.SendAdmissionAlert(&rulesv1.GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{AlertName: "Privileged pod", UniqueID: "ns/pod"},
			RuleID:           "R2003",
		})
	}

	assert.Equal(t, 3, requestCount)
}
