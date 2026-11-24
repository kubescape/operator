package exporters

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestHTTPExporterConfig_Validate_DefaultContentType(t *testing.T) {
	config := HTTPExporterConfig{
		URL: "http://localhost:8080",
	}
	err := config.Validate()
	assert.NoError(t, err)
	assert.Equal(t, "application/json", config.Headers["Content-Type"])
}

func TestHTTPExporterConfig_Validate_PreservesCustomContentType(t *testing.T) {
	config := HTTPExporterConfig{
		URL: "http://localhost:8080",
		Headers: map[string]string{
			"Content-Type": "application/custom+json",
		},
	}
	err := config.Validate()
	assert.NoError(t, err)
	assert.Equal(t, "application/custom+json", config.Headers["Content-Type"])
}

func TestHTTPExporterConfig_Validate_EmptyContentTypeDefaultsToJSON(t *testing.T) {
	config := HTTPExporterConfig{
		URL: "http://localhost:8080",
		Headers: map[string]string{
			"Content-Type": "",
		},
	}
	err := config.Validate()
	assert.NoError(t, err)
	assert.Equal(t, "application/json", config.Headers["Content-Type"])
}

func TestHTTPExporterConfig_Validate_PreservesCaseInsensitiveContentType(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		key     string
		want    string
	}{
		{
			name: "lowercase content-type",
			headers: map[string]string{
				"content-type": "application/custom+json",
			},
			key:  "content-type",
			want: "application/custom+json",
		},
		{
			name: "uppercase CONTENT-TYPE",
			headers: map[string]string{
				"CONTENT-TYPE": "application/custom+json",
			},
			key:  "CONTENT-TYPE",
			want: "application/custom+json",
		},
		{
			name: "empty content-type defaults to application/json",
			headers: map[string]string{
				"content-type": "",
			},
			key:  "content-type",
			want: "application/json",
		},
		{
			name: "empty Content-Type defaults to application/json",
			headers: map[string]string{
				"Content-Type": "",
			},
			key:  "Content-Type",
			want: "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := HTTPExporterConfig{
				URL:     "http://localhost:8080",
				Headers: tt.headers,
			}
			err := config.Validate()
			assert.NoError(t, err)
			assert.Equal(t, tt.want, config.Headers[tt.key])
			assert.Len(t, config.Headers, 1)
		})
	}
}

func TestHTTPExporter_OutgoingRequest_ContentTypeHeader(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		wantHeader string
		wantValues []string
	}{
		{
			name:       "default content-type when no headers configured",
			headers:    nil,
			wantHeader: "application/json",
			wantValues: []string{"application/json"},
		},
		{
			name: "preserves exact-case Content-Type",
			headers: map[string]string{
				"Content-Type": "application/custom+json",
			},
			wantHeader: "application/custom+json",
			wantValues: []string{"application/custom+json"},
		},
		{
			name: "preserves lowercase content-type without regression",
			headers: map[string]string{
				"content-type": "application/custom+json",
			},
			wantHeader: "application/custom+json",
			wantValues: []string{"application/custom+json"},
		},
		{
			name: "preserves uppercase CONTENT-TYPE",
			headers: map[string]string{
				"CONTENT-TYPE": "application/custom+json",
			},
			wantHeader: "application/custom+json",
			wantValues: []string{"application/custom+json"},
		},
		{
			name: "defaults empty lowercase content-type to application/json",
			headers: map[string]string{
				"content-type": "",
			},
			wantHeader: "application/json",
			wantValues: []string{"application/json"},
		},
		{
			name: "defaults empty exact-case Content-Type to application/json",
			headers: map[string]string{
				"Content-Type": "",
			},
			wantHeader: "application/json",
			wantValues: []string{"application/json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHeader := make(chan string, 1)
			gotValues := make(chan []string, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotHeader <- r.Header.Get("Content-Type")
				gotValues <- r.Header.Values("Content-Type")
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			exporter, err := InitHTTPExporter(HTTPExporterConfig{
				URL:     srv.URL,
				Method:  "POST",
				Headers: tt.headers,
			}, "test-cluster", nil, "uid")
			assert.NoError(t, err)

			exporter.SendAdmissionAlert(&rulesv1.GenericRuleFailure{
				BaseRuntimeAlert: apitypes.BaseRuntimeAlert{AlertName: "test-alert", UniqueID: "ns/pod"},
				RuleID:           "R2003",
			})

			select {
			case header := <-gotHeader:
				values := <-gotValues
				assert.Equal(t, tt.wantHeader, header)
				assert.Equal(t, tt.wantValues, values)
			case <-time.After(2 * time.Second):
				t.Fatal("exporter did not POST the alert")
			}
		})
	}
}

func TestHTTPExporter_RetryOnTransientFailure_Success(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var sleepDurations []time.Duration
	config := HTTPExporterConfig{
		URL:                  srv.URL,
		Method:               "POST",
		MaxRetries:           3,
		InitialRetryInterval: 10 * time.Millisecond,
		MaxRetryInterval:     100 * time.Millisecond,
	}
	exporter, err := InitHTTPExporter(config, "test-cluster", nil, "test-uid")
	assert.NoError(t, err)

	exporter.sleepFn = func(d time.Duration) {
		sleepDurations = append(sleepDurations, d)
	}

	exporter.SendAdmissionAlert(&rulesv1.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{AlertName: "test-alert", UniqueID: "ns/pod"},
		RuleID:           "R2003",
	})

	assert.Equal(t, 3, attempts)
	assert.Len(t, sleepDurations, 2)
	assert.Equal(t, 10*time.Millisecond, sleepDurations[0])
	assert.Equal(t, 20*time.Millisecond, sleepDurations[1])
}

func TestHTTPExporter_NonRetryableStatus_FailsFastWithoutRetry(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest) // 400 Bad Request
	}))
	defer srv.Close()

	var sleepDurations []time.Duration
	config := HTTPExporterConfig{
		URL:                  srv.URL,
		Method:               "POST",
		MaxRetries:           3,
		InitialRetryInterval: 10 * time.Millisecond,
	}
	exporter, err := InitHTTPExporter(config, "test-cluster", nil, "test-uid")
	assert.NoError(t, err)

	exporter.sleepFn = func(d time.Duration) {
		sleepDurations = append(sleepDurations, d)
	}

	exporter.SendAdmissionAlert(&rulesv1.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{AlertName: "test-alert", UniqueID: "ns/pod"},
		RuleID:           "R2003",
	})

	assert.Equal(t, 1, attempts)
	assert.Empty(t, sleepDurations)
}

func TestHTTPExporter_RetryAfterHeader_Seconds(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var sleepDurations []time.Duration
	config := HTTPExporterConfig{
		URL:                  srv.URL,
		Method:               "POST",
		MaxRetries:           2,
		InitialRetryInterval: 50 * time.Millisecond,
		MaxRetryInterval:     5 * time.Second,
	}
	exporter, err := InitHTTPExporter(config, "test-cluster", nil, "test-uid")
	assert.NoError(t, err)

	exporter.sleepFn = func(d time.Duration) {
		sleepDurations = append(sleepDurations, d)
	}

	exporter.SendAdmissionAlert(&rulesv1.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{AlertName: "test-alert", UniqueID: "ns/pod"},
		RuleID:           "R2003",
	})

	assert.Equal(t, 2, attempts)
	assert.Len(t, sleepDurations, 1)
	assert.Equal(t, 2*time.Second, sleepDurations[0])
}

func TestHTTPExporter_RetryAfterHeader_CappedAtMaxRetryInterval(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var sleepDurations []time.Duration
	config := HTTPExporterConfig{
		URL:                  srv.URL,
		Method:               "POST",
		MaxRetries:           1,
		InitialRetryInterval: 10 * time.Millisecond,
		MaxRetryInterval:     3 * time.Second,
	}
	exporter, err := InitHTTPExporter(config, "test-cluster", nil, "test-uid")
	assert.NoError(t, err)

	exporter.sleepFn = func(d time.Duration) {
		sleepDurations = append(sleepDurations, d)
	}

	exporter.SendAdmissionAlert(&rulesv1.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{AlertName: "test-alert", UniqueID: "ns/pod"},
		RuleID:           "R2003",
	})

	assert.Equal(t, 2, attempts)
	assert.Len(t, sleepDurations, 1)
	assert.Equal(t, 3*time.Second, sleepDurations[0])
}

func TestHTTPExporter_RetriesExhausted(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadGateway) // 502
	}))
	defer srv.Close()

	var sleepDurations []time.Duration
	config := HTTPExporterConfig{
		URL:                  srv.URL,
		Method:               "POST",
		MaxRetries:           2,
		InitialRetryInterval: 10 * time.Millisecond,
	}
	exporter, err := InitHTTPExporter(config, "test-cluster", nil, "test-uid")
	assert.NoError(t, err)

	exporter.sleepFn = func(d time.Duration) {
		sleepDurations = append(sleepDurations, d)
	}

	exporter.SendAdmissionAlert(&rulesv1.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{AlertName: "test-alert", UniqueID: "ns/pod"},
		RuleID:           "R2003",
	})

	assert.Equal(t, 3, attempts) // initial attempt + 2 retries
	assert.Len(t, sleepDurations, 2)
}

func TestHTTPExporterConfig_Validate_RetryDefaults(t *testing.T) {
	config := HTTPExporterConfig{
		URL: "http://localhost:8080",
	}
	err := config.Validate()
	assert.NoError(t, err)
	assert.Equal(t, defaultInitialRetryInterval, config.InitialRetryInterval)
	assert.Equal(t, defaultMaxRetryInterval, config.MaxRetryInterval)

	// Custom configuration preserved
	customConfig := HTTPExporterConfig{
		URL:                  "http://localhost:8080",
		MaxRetries:           5,
		InitialRetryInterval: 100 * time.Millisecond,
		MaxRetryInterval:     10 * time.Second,
	}
	err = customConfig.Validate()
	assert.NoError(t, err)
	assert.Equal(t, 5, customConfig.MaxRetries)
	assert.Equal(t, 100*time.Millisecond, customConfig.InitialRetryInterval)
	assert.Equal(t, 10*time.Second, customConfig.MaxRetryInterval)

	// Negative retries clamped to 0
	negativeConfig := HTTPExporterConfig{
		URL:        "http://localhost:8080",
		MaxRetries: -1,
	}
	err = negativeConfig.Validate()
	assert.NoError(t, err)
	assert.Equal(t, 0, negativeConfig.MaxRetries)
}
