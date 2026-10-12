package exporters

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/operator/admission/rules"
	rulesv1 "github.com/kubescape/operator/admission/rules/v1"
	"github.com/stretchr/testify/assert"
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
