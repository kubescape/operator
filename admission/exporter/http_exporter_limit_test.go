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
// AlertLimitReached notice. The server holds the notice request open until
// every other caller has returned, so all of them run checkAlertLimit while
// the notice is in flight.
func TestSendAdmissionAlert_ConcurrentAlertsSendOneLimitNotice(t *testing.T) {
	const callers = 20
	var mu sync.Mutex
	counts := map[string]int{}
	noticeArrived := make(chan struct{}, callers)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseNotice := func() { releaseOnce.Do(func() { close(release) }) }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		var list HTTPAlertsList
		assert.NoError(t, json.Unmarshal(body, &list))
		for _, alert := range list.Spec.Alerts {
			mu.Lock()
			counts[alert.AlertName]++
			mu.Unlock()
			if alert.AlertName == "AlertLimitReached" {
				noticeArrived <- struct{}{}
				<-release
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	// Deferred calls run last in, first out: a held notice is released before
	// srv.Close waits for it, also when the test fails early.
	defer srv.Close()
	defer releaseNotice()

	exporter, err := InitHTTPExporter(HTTPExporterConfig{
		URL:                srv.URL,
		Method:             "POST",
		MaxAlertsPerMinute: 2,
	}, "test-cluster", nil, "uid")
	require.NoError(t, err)

	start := make(chan struct{})
	returned := make(chan struct{}, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			exporter.SendAdmissionAlert(&rulesv1.GenericRuleFailure{
				BaseRuntimeAlert: apitypes.BaseRuntimeAlert{AlertName: "exec"},
				RuleID:           "R2000",
			})
			returned <- struct{}{}
		}()
	}
	close(start)

	timeout := time.After(10 * time.Second)
	select {
	case <-noticeArrived:
	case <-timeout:
		t.Fatal("no AlertLimitReached notice was sent")
	}
	// Every caller except the one sending the notice must return while the
	// notice is held. A second notice would block its caller here as well.
wait:
	for i := 0; i < callers-1; i++ {
		select {
		case <-returned:
		case <-timeout:
			t.Errorf("only %d of %d other callers returned while the notice was in flight", i, callers-1)
			break wait
		}
	}
	releaseNotice()
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, map[string]int{"exec": 2, "AlertLimitReached": 1}, counts)
}
