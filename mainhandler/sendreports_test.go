package mainhandler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/operator/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

type dailyReportConfig struct {
	config.IConfig
}

func (dailyReportConfig) AccountID() string { return "test-account" }

type dailyReportTransport func(*http.Request) (*http.Response, error)

func (f dailyReportTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestSendReports(t *testing.T) {
	for _, tc := range []struct {
		name       string
		current    string
		deprecated string
		skip       bool
		failFirst  bool
	}{
		{name: "current skip", current: "true", skip: true},
		{name: "deprecated skip", deprecated: "true", skip: true},
		{name: "deprecated skip with current false", current: "false", deprecated: "true", skip: true},
		{name: "unset"},
		{name: "both false", current: "false", deprecated: "false"},
		{name: "continues after error", failFirst: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// These tests change process globals and must not run in parallel.
			for key, value := range map[string]string{
				versioncheck.SKIP_VERSION_CHECK_ENV:            tc.current,
				versioncheck.SKIP_VERSION_CHECK_DEPRECATED_ENV: tc.deprecated,
			} {
				t.Setenv(key, value)
				if value == "" {
					require.NoError(t, os.Unsetenv(key))
				}
			}
			t.Setenv(versioncheck.CLIENT_ENV, "operator-test")
			originalBuild, originalClient, originalLatest := versioncheck.BuildNumber, versioncheck.Client, versioncheck.LatestReleaseVersion
			originalHTTPClient := http.DefaultClient
			t.Cleanup(func() {
				versioncheck.BuildNumber, versioncheck.Client, versioncheck.LatestReleaseVersion = originalBuild, originalClient, originalLatest
				http.DefaultClient = originalHTTPClient
			})
			versioncheck.BuildNumber = "v0.2.172"
			var reports []versioncheck.VersionCheckRequest
			http.DefaultClient = &http.Client{Transport: dailyReportTransport(func(r *http.Request) (*http.Response, error) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "https://version-check.ks-services.co", r.URL.String())
				defer r.Body.Close()
				var report versioncheck.VersionCheckRequest
				if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
					t.Errorf("decode daily report: %v", err)
					return nil, err
				}
				reports = append(reports, report)
				body := `{"clientUpdate":"v99.0.0"}`
				if tc.failFirst && len(reports) == 1 {
					body = "invalid JSON"
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			client := k8sfake.NewSimpleClientset()
			handler := &MainHandler{config: dailyReportConfig{}, k8sAPI: &k8sinterface.KubernetesApi{KubernetesClient: client}}
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() {
					defer close(done)
					handler.SendReports(ctx, 24*time.Hour)
				}()
				defer func() {
					cancel()
					<-done
				}()
				for iteration := 1; iteration <= 3; iteration++ {
					synctest.Wait()
					// Request construction proves the loop ran even when HTTP is suppressed.
					assert.Len(t, client.Actions(), 2*iteration)
					if tc.skip {
						assert.Empty(t, reports)
					} else {
						assert.Len(t, reports, iteration)
					}
					if iteration < 3 {
						time.Sleep(24 * time.Hour)
					}
				}
				for _, report := range reports {
					assert.Equal(t, "test-account", report.AccountID)
					assert.Equal(t, "v0.2.172", report.ClientVersion)
					assert.Equal(t, "daily-report", report.ScanningContext)
				}
				assert.Empty(t, versioncheck.BuildNumber)
				cancel()
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Fatal("SendReports did not stop when canceled during its wait")
				}
			})
		})
	}
}

func TestSendReportsAlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	buildNumber := versioncheck.BuildNumber
	// A canceled call must return before accessing the handler or changing globals.
	(&MainHandler{}).SendReports(ctx, 24*time.Hour)
	assert.Equal(t, buildNumber, versioncheck.BuildNumber)
}
