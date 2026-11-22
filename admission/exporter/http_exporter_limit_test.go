package exporters

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	rulesv1 "github.com/kubescape/operator/admission/rules/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Once MaxAlertsPerMinute alerts have been sent, the next alert is replaced by
// a single AlertLimitReached notice and every later one in the window is
// dropped.
func TestSendAdmissionAlert_EnforcesMaxAlertsPerMinute(t *testing.T) {
	var mu sync.Mutex
	var sent []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		var list HTTPAlertsList
		assert.NoError(t, json.Unmarshal(body, &list))
		mu.Lock()
		for _, alert := range list.Spec.Alerts {
			sent = append(sent, alert.AlertName)
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exporter, err := InitHTTPExporter(HTTPExporterConfig{
		URL:                srv.URL,
		Method:             "POST",
		MaxAlertsPerMinute: 2,
	}, "test-cluster", nil, "uid")
	require.NoError(t, err)

	for i := 0; i < 10; i++ {
		exporter.SendAdmissionAlert(&rulesv1.GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{AlertName: "exec"},
			RuleID:           "R2000",
		})
	}

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"exec", "exec", "AlertLimitReached"}, sent)
}

// Concurrent alerts over the limit must still produce a single
// AlertLimitReached notice. The server holds the notice request open so that
// the other callers run while it is in flight.
func TestSendAdmissionAlert_ConcurrentAlertsSendOneLimitNotice(t *testing.T) {
	var mu sync.Mutex
	counts := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		var list HTTPAlertsList
		assert.NoError(t, json.Unmarshal(body, &list))
		for _, alert := range list.Spec.Alerts {
			if alert.AlertName == "AlertLimitReached" {
				time.Sleep(200 * time.Millisecond)
			}
			mu.Lock()
			counts[alert.AlertName]++
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exporter, err := InitHTTPExporter(HTTPExporterConfig{
		URL:                srv.URL,
		Method:             "POST",
		MaxAlertsPerMinute: 2,
	}, "test-cluster", nil, "uid")
	require.NoError(t, err)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			exporter.SendAdmissionAlert(&rulesv1.GenericRuleFailure{
				BaseRuntimeAlert: apitypes.BaseRuntimeAlert{AlertName: "exec"},
				RuleID:           "R2000",
			})
		}()
	}
	close(start)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, map[string]int{"exec": 2, "AlertLimitReached": 1}, counts)
}
